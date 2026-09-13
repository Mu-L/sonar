// Command devclient drives internal/tunnel by hand, for developing the share
// transport before the daemon has any of it.
//
// It is not part of the sonar binary and is not released: `sonar share` and
// the daemon's side of this come later, and this exists so the transport can
// be proved against a real relay and a real browser first.
//
//	SONAR_TUNNEL_KEY=… go run ./internal/tunnel/devclient \
//	    -relay http://127.0.0.1:8788 -port 5173
//
// The key comes from the environment, never a flag: anyone who can run ps can
// read a command line.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/raskrebs/sonar/internal/tunnel"
)

func main() {
	relay := flag.String("relay", "http://127.0.0.1:8788",
		"The relay's base URL, or its /v1/tunnel route")
	port := flag.Int("port", 0, "The local port to share (required)")
	host := flag.String("local-host", "localhost", "The host the local app is on")
	debug := flag.Bool("v", false, "Log every forwarded request")
	flag.Parse()

	if *port == 0 {
		fmt.Fprintln(os.Stderr, "devclient: -port is required")
		os.Exit(2)
	}
	key := os.Getenv("SONAR_TUNNEL_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "devclient: set SONAR_TUNNEL_KEY to the relay's tunnel key")
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := tunnel.Run(ctx, tunnel.Config{
		RelayURL:  *relay,
		Key:       key,
		LocalPort: *port,
		LocalHost: *host,
		Client:    "sonar-devclient",
		Logger:    log,
		OnStatus: func(s tunnel.Status) {
			switch s.State {
			case tunnel.StateConnected:
				fmt.Printf("share is live at %s -> %s:%d\n", s.URL, *host, *port)
			case tunnel.StateConnecting:
				if s.Err != nil {
					fmt.Printf("connecting (attempt %d): %v\n", s.Attempt+1, s.Err)
				} else {
					fmt.Println("connecting…")
				}
			case tunnel.StateStopped:
				fmt.Println("stopped")
			}
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "devclient: %v\n", err)
		os.Exit(1)
	}
}
