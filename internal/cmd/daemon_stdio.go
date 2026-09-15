package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/raskrebs/sonar/internal/daemon"
	"github.com/raskrebs/sonar/internal/daemon/client"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
	"github.com/spf13/cobra"
)

var daemonStdioNoAutostart bool

var daemonStdioCmd = &cobra.Command{
	Use:   "stdio",
	Short: "Serve the daemon protocol over stdin/stdout",
	Long: `Serve the daemon's JSON-RPC protocol over this process's stdin and stdout.

The framing and the methods are identical to the socket: one JSON message per
line, the same daemon.hello handshake, the same state.subscribe stream. It is
the far end of a remote host's bridge, which the local daemon opens as

  ssh <host> sonar daemon stdio

and then drives with the ordinary client. Nothing new listens anywhere: the
daemon's socket stays 0600 to the SSH user, and this process is the only thing
that reaches it.

It connects to the daemon already running on this machine, starting one with
` + "`sonar serve --detach`" + ` if there is none, so a bridge shares state with
the CLI, the tray and the desktop app on the same host rather than running a
second scanner beside them.`,
	Args: cobra.NoArgs,
	RunE: runDaemonStdio,
}

func init() {
	daemonStdioCmd.Flags().BoolVar(&daemonStdioNoAutostart, "no-autostart", false,
		"Fail instead of starting a daemon when none is running")
	daemonCmd.AddCommand(daemonStdioCmd)
}

func runDaemonStdio(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true
	socket := daemon.SocketPath()

	conn, err := daemon.Dial(socket)
	if err != nil {
		if daemonStdioNoAutostart {
			return fmt.Errorf("%w (socket %s)", client.ErrNotRunning, socket)
		}
		if err := client.Autostart(cmd.Context(), "", socket); err != nil {
			return err
		}
		conn, err = daemon.Dial(socket)
		if err != nil {
			return fmt.Errorf("%w: started it but could not connect to %s: %v",
				client.ErrNotRunning, socket, err)
		}
	}
	defer conn.Close()

	buffered, err := markBridged(conn)
	if err != nil {
		return err
	}
	return pump(conn, buffered, os.Stdin, os.Stdout)
}

// bridgeMarkTimeout bounds the one exchange this command makes on its own
// behalf. The daemon answers it without touching disk or network, so a second
// is generous; the point is that a daemon that has wedged fails the bridge
// instead of hanging an ssh session forever.
const bridgeMarkTimeout = 5 * time.Second

// bridgeMarkID is the id of that one request. It is not a number, so it cannot
// collide with the ids of whatever client is about to speak over this bridge.
const bridgeMarkID = "sonar-daemon-stdio-bridged"

// markBridged tells the daemon that everything after this line comes from
// another machine, and hands back the reader the pump must use — buffered,
// because reading the reply may have pulled bytes in after it.
//
// It is sent before a single byte of stdin is copied, which is the whole
// guarantee: a client on the far side cannot get a local-only method in ahead
// of it, and cannot unsay it, because daemon.bridged only ever takes
// permissions away.
//
// A daemon that has never heard of the method is not an error. It is a daemon
// older than this binary, which has no local-only methods for the mark to
// protect — there was nothing on it to refuse.
func markBridged(conn net.Conn) (io.Reader, error) {
	_ = conn.SetDeadline(time.Now().Add(bridgeMarkTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	req, err := json.Marshal(rpc.Request{
		JSONRPC: rpc.Version,
		ID:      json.RawMessage(`"` + bridgeMarkID + `"`),
		Method:  "daemon.bridged",
		Params:  json.RawMessage(`{}`),
	})
	if err != nil {
		return nil, fmt.Errorf("marking the bridge: %w", err)
	}
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return nil, fmt.Errorf("marking the bridge: %w", err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("marking the bridge: %w", err)
	}
	var reply rpc.Response
	if err := json.Unmarshal(line, &reply); err != nil {
		return nil, fmt.Errorf("marking the bridge: the daemon answered with %s", line)
	}
	if string(reply.ID) != `"`+bridgeMarkID+`"` {
		return nil, fmt.Errorf("marking the bridge: the daemon answered something else first: %s", line)
	}
	if reply.Error != nil && reply.Error.Data.Code != "not_found" {
		return nil, fmt.Errorf("marking the bridge: %s", reply.Error.Message)
	}
	return br, nil
}

// pump copies bytes between the pipes and the socket until either side closes.
// It parses nothing: the protocol on the socket is the protocol on the wire,
// so a method this build has never heard of still works across the bridge. The
// one exchange that is parsed happens before this, in markBridged, and `from`
// is its leftover buffer.
func pump(conn net.Conn, from io.Reader, in io.Reader, out io.Writer) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(conn, in)
		// Our stdin ended: tell the daemon so it can finish what it is writing
		// and close, rather than waiting on a peer that is gone.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = conn.Close()
		}
	}()

	_, err := io.Copy(out, from)
	<-done
	if err != nil && !isClosedPipe(err) {
		return err
	}
	return nil
}

// isClosedPipe reports whether an error is the ordinary end of a bridge: the
// far side hung up, or our own stdout went away because ssh exited. Neither is
// worth a non-zero exit status.
func isClosedPipe(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE)
}
