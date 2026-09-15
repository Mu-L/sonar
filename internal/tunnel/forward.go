package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// forward serves one stream: one HTTP exchange from the relay.
//
// It reads the request, rewrites the headers a local dev server cares about,
// opens a fresh connection to the app and then splices the two together. The
// splice is the point: after the request headers this code does not parse
// anything, so a WebSocket upgrade, an SSE stream, a chunked upload and a
// gigabyte download are all the same bytes going both ways. Nothing here has
// to know that Vite's HMR socket exists.
//
// One request per connection, and a fresh connection each time: the relay
// opens one stream per request, a connection to localhost costs nothing, and
// reuse would put a keep-alive pool on both sides of the same exchange.
func (c *client) forward(ctx context.Context, stream *yamux.Stream) {
	defer stream.Close()

	started := time.Now()
	br := bufio.NewReader(stream)
	req, err := http.ReadRequest(br)
	if err != nil {
		if err != io.EOF {
			c.log.Debug("could not read a request from the relay", "err", err)
		}
		return
	}

	entry := RequestLog{At: started, Method: req.Method}
	if req.URL != nil {
		entry.Path = req.URL.RequestURI()
	}

	dialer := &net.Dialer{Timeout: c.cfg.DialTimeout}
	local, err := dialer.DialContext(ctx, "tcp", c.local)
	if err != nil {
		c.log.Warn("the shared app did not answer", "addr", c.local, "err", err)
		writeGatewayError(stream, c.local)
		entry.Err = err
		c.logRequest(entry, started)
		return
	}

	upgrade := isUpgrade(req)
	entry.Upgrade = upgrade
	c.rewrite(req)
	if !upgrade {
		// One exchange per connection, so the app closes when it is done and
		// the copy below ends on its own.
		req.Close = true
	}

	done := make(chan struct{}, 2)
	var out atomic.Int64

	// The app's answer, and after an upgrade everything it says afterwards.
	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(stream, local)
		out.Add(n)
		// The response is finished: half-close, so the relay reads EOF.
		_ = stream.Close()
	}()

	// The request, and after an upgrade everything the visitor says afterwards.
	go func() {
		defer func() { done <- struct{}{} }()
		bw := bufio.NewWriterSize(local, 32<<10)
		err := req.Write(bw)
		if err == nil {
			err = bw.Flush()
		}
		if err == nil {
			// Whatever follows the request on this stream belongs to the app.
			// For an ordinary request that is nothing, and this blocks until
			// the relay closes the stream — which is its way of saying the
			// exchange is over, however it ended.
			_, err = io.Copy(local, br)
		}
		if err != nil {
			c.log.Debug("the request stream ended", "err", err)
		}
		// The relay is done, or something broke: either way the app's
		// connection goes, which unblocks the copy above.
		_ = local.Close()
	}()

	<-done
	<-done
	entry.BytesOut = out.Load()
	c.logRequest(entry, started)
}

// logRequest hands one finished exchange to whatever is watching. It is called
// from the exchange's own goroutine, which is why the contract on OnRequest is
// that it must not block.
func (c *client) logRequest(entry RequestLog, started time.Time) {
	if c.cfg.OnRequest == nil {
		return
	}
	entry.Duration = time.Since(started)
	c.cfg.OnRequest(entry)
}

// rewrite makes the request look local.
//
// Host becomes the address the app is listening on, because a dev server
// checks it: Vite answers an unknown Host with "Blocked request. This host is
// not allowed", which through a tunnel is every request. What the visitor
// actually asked for is preserved in X-Forwarded-Host, which is what a
// framework building absolute URLs should read.
//
// The X-Forwarded-* values the relay set are authoritative and are left alone;
// these are only filled in when a relay did not set them.
func (c *client) rewrite(req *http.Request) {
	if req.Header.Get("X-Forwarded-Host") == "" && req.Host != "" {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}
	if req.Header.Get("X-Forwarded-Proto") == "" {
		// A share is only reachable over TLS from outside.
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	req.Host = c.local
	if req.URL != nil {
		req.URL.Scheme = "http"
		req.URL.Host = c.local
	}
	// Without this, Request.Write invents a Go user agent for a request that
	// deliberately had none.
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{""}
	}
}

// isUpgrade reports whether this request is a protocol switch — a WebSocket,
// in practice, which is how every dev server pushes a hot reload.
func isUpgrade(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// writeGatewayError answers on the stream itself, so a visitor sees why rather
// than a bare connection reset. This is the common failure by far: the dev
// server was stopped and the share was not.
func writeGatewayError(w io.Writer, addr string) {
	body := fmt.Sprintf("Nothing is listening on %s.\n\n"+
		"The shared app is not running on this machine any more.\n", addr)
	fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n%s", len(body), body)
}
