package cmd

import (
	"net"
	"testing"
)

// `sonar map` is a loopback convenience: its help says localhost, so the
// listen side must not be reachable from the network. Reaching a port from
// elsewhere is `sonar share`, where the reach is written down.
func TestMapListensOnLoopbackOnly(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	l, err := listenMap(port)
	if err != nil {
		t.Fatalf("listenMap(%d): %v", port, err)
	}
	defer l.Close()

	addr := l.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("map listens on %s, want 127.0.0.1", addr)
	}
	if addr.Port != port {
		t.Fatalf("map listens on port %d, want %d", addr.Port, port)
	}
}
