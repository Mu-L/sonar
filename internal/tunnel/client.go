package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// State is what a share's connection is doing. A dropped control connection is
// "connecting", never "stopped": the share is still a share, the laptop is
// just briefly unreachable.
type State string

const (
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateStopped    State = "stopped"
)

// Status is one state change, for whatever is showing the share to a person.
type Status struct {
	State State
	// URL is where the share is reachable, once connected.
	URL string
	// Attempt counts consecutive failed connections; zero once connected.
	Attempt int
	// Err is why, on a failed attempt or a stop.
	Err error
}

// The errors that end a run rather than being retried.
var (
	// ErrUnauthorized: the key is wrong. Retrying cannot fix a wrong key.
	ErrUnauthorized = errors.New("tunnel: the relay refused this key")
	// ErrReplaced: another daemon took this share. Reconnecting would take it
	// back, and the two would do that to each other forever.
	ErrReplaced = errors.New("tunnel: another daemon took this share")
	// ErrUnsupportedVersion: the relay speaks a protocol this build does not.
	ErrUnsupportedVersion = errors.New("tunnel: the relay speaks a different tunnel protocol")
)

// Config is one share: where the relay is, what to prove, and what to serve.
type Config struct {
	// RelayURL is the relay's base URL ("https://relay.trysonar.dev") or the
	// control route itself ("wss://relay.trysonar.dev/v1/tunnel").
	RelayURL string
	// Key authorises the control route. It comes from the environment or the
	// keychain, never from a command line, where ps would read it.
	Key string
	// LocalPort is the port on this machine being shared.
	LocalPort int
	// LocalHost is what to dial it on. Empty means "localhost", which covers
	// the dev server that bound ::1 and the one that bound 127.0.0.1.
	LocalHost string
	// Client is what to call this daemon in hello. Logged by the relay.
	Client string
	// OnStatus, when set, is called on every state change, from the run
	// goroutine: it must not block.
	OnStatus func(Status)
	Logger   *slog.Logger
	// MinBackoff, MaxBackoff bound the reconnect wait. Zero means 500ms and
	// 30s.
	MinBackoff, MaxBackoff time.Duration
	// HandshakeTimeout bounds the dial and the hello exchange. Zero means 15s.
	HandshakeTimeout time.Duration
	// DialTimeout bounds connecting to the local app. Zero means 5s.
	DialTimeout time.Duration
	// Linger is how long a connection that said going_away keeps serving what
	// it already has. Zero means 30s.
	Linger time.Duration
	// HTTPClient performs the WebSocket handshake. Zero means the default.
	HTTPClient *http.Client
}

const (
	defaultMinBackoff       = 500 * time.Millisecond
	defaultMaxBackoff       = 30 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
	defaultDialTimeout      = 5 * time.Second
	defaultLinger           = 30 * time.Second
	// stableAfter is how long a connection must last before the next failure
	// starts counting from zero again. Without it, a relay that accepts and
	// immediately drops would be retried as fast as it can accept.
	stableAfter = 10 * time.Second
)

// Run holds one share open until ctx is cancelled or something terminal
// happens: a refused key, a protocol mismatch, or another daemon taking the
// share. Everything else — a dropped connection, a relay restart, a laptop
// that closed its lid — is reconnected with backoff and jitter.
//
// It returns nil when ctx ends it.
func Run(ctx context.Context, cfg Config) error {
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	return c.run(ctx)
}

type client struct {
	cfg   Config
	url   string
	local string
	log   *slog.Logger
	// wg covers the per-request goroutines, so Run does not return while a
	// request is still being forwarded.
	wg sync.WaitGroup
}

func newClient(cfg Config) (*client, error) {
	if strings.TrimSpace(cfg.Key) == "" {
		return nil, errors.New("tunnel: a key is required")
	}
	if cfg.LocalPort < 1 || cfg.LocalPort > 65535 {
		return nil, fmt.Errorf("tunnel: %d is not a port", cfg.LocalPort)
	}
	u, err := ControlURL(cfg.RelayURL)
	if err != nil {
		return nil, err
	}
	if cfg.LocalHost == "" {
		cfg.LocalHost = "localhost"
	}
	if cfg.Client == "" {
		cfg.Client = "sonar"
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = defaultMinBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.Linger <= 0 {
		cfg.Linger = defaultLinger
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &client{
		cfg:   cfg,
		url:   u,
		local: net.JoinHostPort(cfg.LocalHost, fmt.Sprint(cfg.LocalPort)),
		log:   cfg.Logger,
	}, nil
}

// ControlURL turns whatever the caller has — a relay base URL or the control
// route itself, http or ws — into the WebSocket URL to dial.
func ControlURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("tunnel: a relay URL is required")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("tunnel: %q is not a URL: %w", raw, err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("tunnel: %q is not an http or ws URL", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("tunnel: %q has no host", raw)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = Path
	}
	return u.String(), nil
}

func (c *client) run(ctx context.Context) error {
	defer c.wg.Wait()
	attempt := 0
	for {
		c.status(Status{State: StateConnecting, Attempt: attempt})
		cn, err := c.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				c.status(Status{State: StateStopped})
				return nil
			}
			if terminal(err) {
				c.status(Status{State: StateStopped, Err: err})
				return err
			}
			c.log.Warn("the tunnel could not connect", "err", err, "attempt", attempt)
			c.status(Status{State: StateConnecting, Attempt: attempt, Err: err})
			if !sleep(ctx, jitter(c.backoff(attempt))) {
				c.status(Status{State: StateStopped})
				return nil
			}
			attempt++
			continue
		}

		c.log.Info("the share is live", "url", cn.url)
		c.status(Status{State: StateConnected, URL: cn.url})
		started := time.Now()
		reason, retryAfter, err := c.serve(ctx, cn)
		if ctx.Err() != nil {
			c.status(Status{State: StateStopped})
			return nil
		}

		var wait time.Duration
		switch {
		case reason == GoingAwayReplaced:
			c.status(Status{State: StateStopped, Err: ErrReplaced})
			return ErrReplaced
		case reason != "":
			// A relay restart is not a failure: come back when it said to.
			c.log.Info("the relay is going away", "reason", reason, "retry_after", retryAfter)
			attempt = 0
			if retryAfter <= 0 {
				retryAfter = c.cfg.MinBackoff
			}
			wait = jitter(retryAfter)
		default:
			c.log.Warn("the tunnel dropped", "err", err, "up", time.Since(started).Round(time.Millisecond))
			if time.Since(started) >= stableAfter {
				attempt = 0
			}
			wait = jitter(c.backoff(attempt))
			attempt++
		}
		if !sleep(ctx, wait) {
			c.status(Status{State: StateStopped})
			return nil
		}
	}
}

// serve runs one connection, forwarding requests until it ends. It returns the
// going_away reason when there was one.
func (c *client) serve(ctx context.Context, cn *conn) (string, time.Duration, error) {
	go func() {
		for {
			stream, err := cn.sess.AcceptStream()
			if err != nil {
				return
			}
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				c.forward(ctx, stream)
			}()
		}
	}()

	frames := make(chan Frame, 4)
	go func() {
		defer close(frames)
		for {
			var f Frame
			if err := cn.dec.Decode(&f); err != nil {
				return
			}
			frames <- f
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cn.close()
			return "", 0, ctx.Err()
		case <-cn.sess.CloseChan():
			cn.close()
			return "", 0, errors.New("the control connection dropped")
		case f, ok := <-frames:
			if !ok {
				// The control stream ended; the session close follows.
				frames = nil
				continue
			}
			if f.Type != FrameGoingAway {
				continue
			}
			// Do not close: requests already in flight keep being served
			// until the relay closes the connection itself.
			c.linger(ctx, cn)
			return f.Reason, time.Duration(f.RetryAfterMS) * time.Millisecond, nil
		}
	}
}

// linger keeps a going-away connection alive for what it already has, and
// closes it if the relay never does.
func (c *client) linger(ctx context.Context, cn *conn) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTimer(c.cfg.Linger)
		defer t.Stop()
		select {
		case <-cn.sess.CloseChan():
		case <-ctx.Done():
		case <-t.C:
		}
		cn.close()
	}()
}

// conn is one control connection and the session on it.
type conn struct {
	sess   *yamux.Session
	dec    *json.Decoder
	url    string
	cancel context.CancelFunc
	once   sync.Once
}

func (cn *conn) close() {
	cn.once.Do(func() {
		_ = cn.sess.Close()
		cn.cancel()
	})
}

func (c *client) connect(ctx context.Context) (*conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.cfg.HandshakeTimeout)
	defer cancel()

	ws, resp, err := websocket.Dial(dctx, c.url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.cfg.Key}},
		HTTPClient: c.cfg.HTTPClient,
	})
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return nil, fmt.Errorf("%w (%s)", ErrUnauthorized, resp.Status)
		}
		return nil, err
	}

	// The session's life is its own, not the handshake's.
	sctx, scancel := context.WithCancel(context.Background())
	nc := websocket.NetConn(sctx, ws, websocket.MessageBinary)
	sess, err := yamux.Client(nc, yamuxConfig())
	if err != nil {
		scancel()
		_ = ws.CloseNow()
		return nil, err
	}
	cn := &conn{sess: sess, cancel: scancel}

	ctrl, err := sess.OpenStream()
	if err != nil {
		cn.close()
		return nil, fmt.Errorf("opening the control stream: %w", err)
	}
	_ = ctrl.SetDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	if err := json.NewEncoder(ctrl).Encode(Frame{
		Type: FrameHello, Version: ProtocolVersion, Client: c.cfg.Client}); err != nil {
		cn.close()
		return nil, fmt.Errorf("sending hello: %w", err)
	}
	dec := json.NewDecoder(ctrl)
	var f Frame
	if err := dec.Decode(&f); err != nil {
		cn.close()
		return nil, fmt.Errorf("reading the relay's answer: %w", err)
	}
	_ = ctrl.SetDeadline(time.Time{})

	switch f.Type {
	case FrameWelcome:
	case FrameError:
		cn.close()
		if f.Reason == ErrReasonUnsupportedVersion {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedVersion, f.Message)
		}
		return nil, fmt.Errorf("the relay refused the connection: %s (%s)", f.Message, f.Reason)
	default:
		cn.close()
		return nil, fmt.Errorf("the relay answered a hello with %q", f.Type)
	}
	cn.dec = dec
	cn.url = f.URL
	return cn, nil
}

func (c *client) status(s Status) {
	if c.cfg.OnStatus != nil {
		c.cfg.OnStatus(s)
	}
}

func terminal(err error) bool {
	return errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrUnsupportedVersion) ||
		errors.Is(err, ErrReplaced)
}

// backoff doubles from MinBackoff to MaxBackoff.
func (c *client) backoff(attempt int) time.Duration {
	d := c.cfg.MinBackoff
	for i := 0; i < attempt && d < c.cfg.MaxBackoff; i++ {
		d *= 2
	}
	return min(d, c.cfg.MaxBackoff)
}

// jitter spreads a wait over [d/2, d], so a relay coming back up is not met by
// every daemon it dropped at the same millisecond.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// sleep waits, and reports false if ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// yamuxConfig matches the relay's: keepalives often enough to sit under every
// idle timeout between here and it, and a stream the relay never finishes
// closing is given up on after a minute.
func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.StreamCloseTimeout = time.Minute
	cfg.LogOutput = io.Discard
	return cfg
}
