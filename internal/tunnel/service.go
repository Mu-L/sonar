package tunnel

import (
	"context"
	"net"
	"time"
)

// Watching the shared service.
//
// A share points at one local port. When that port stops listening the tunnel
// is still perfectly healthy, which is the problem: a public hostname is
// knocked on constantly by scanners looking for /.env and /.git/config, and
// every knock would become a dial attempt at a dead port. So the daemon tells
// the relay, and the relay answers those visitors itself.
//
// The states are LIVE, DEGRADED and STOPPED:
//
//   - LIVE to DEGRADED the moment the port stops answering. The relay serves a
//     503 "restarting" page. This is the ordinary dev-server restart and it
//     must not cost the tunnel.
//   - DEGRADED back to LIVE if the port answers again inside the window. That
//     window is the entire point.
//   - DEGRADED to STOPPED once the window passes. The daemon closes the
//     control connection and does not reconnect.
//
// The boundary that matters, and the reason STOPPED is terminal:
//
// INSIDE the window a returning listener is ASSUMED to be the same service
// coming back — the dev server that was restarting. AFTER the stop nothing is
// assumed. A port is not an identity: the next thing to bind it may be an
// entirely different project, and resuming would hand that project the public
// URL someone already shared. So there is no automatic resume, ever, however
// quickly the port returns. Sharing again is a person's decision.
//
// Why polling is acceptable here: this is the user's own machine dialling its
// own loopback port every couple of seconds. It is a connect and an immediate
// close on 127.0.0.1 or ::1 — cheaper than the file watch it would replace,
// and it needs no privileges and nothing platform-specific. The relay never
// probes anything; it only ever hears what the daemon reports.
func (c *client) watchService(ctx context.Context, cn *conn, gone chan<- struct{}) {
	t := time.NewTicker(c.cfg.WatchInterval)
	defer t.Stop()

	degradedSince := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-cn.sess.CloseChan():
			return
		case <-t.C:
		}

		if c.serviceAnswers(ctx) {
			if !degradedSince.IsZero() {
				// Inside the window: assumed to be the same service.
				degradedSince = time.Time{}
				c.log.Info("the shared service is answering again", "addr", c.local)
				c.status(Status{State: StateConnected, URL: cn.url})
				if err := cn.send(Frame{Type: FrameStatus, State: ServiceLive}); err != nil {
					c.log.Debug("could not report the service is live", "err", err)
				}
			}
			continue
		}

		if degradedSince.IsZero() {
			degradedSince = time.Now()
			c.log.Warn("the shared service stopped answering",
				"addr", c.local, "grace", c.cfg.ServiceGrace)
			c.status(Status{State: StateDegraded})
			if err := cn.send(Frame{Type: FrameStatus, State: ServiceDegraded}); err != nil {
				c.log.Debug("could not report the service is degraded", "err", err)
			}
			continue
		}

		if time.Since(degradedSince) >= c.cfg.ServiceGrace {
			select {
			case gone <- struct{}{}:
			case <-ctx.Done():
			}
			return
		}
	}
}

// serviceAnswers reports whether something is listening on the shared port.
// Accepting the connection is the whole test: what answers is not inspected,
// because a dev server mid-boot may not speak HTTP yet and is still the
// service coming back.
func (c *client) serviceAnswers(ctx context.Context) bool {
	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.WatchInterval)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", c.local)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
