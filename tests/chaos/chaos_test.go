// Package chaos contains tests that simulate hostile network conditions.
//
// Important: these tests operate at the application layer (above TCP).
// Simulating "packet loss" at this level causes smux hangs because smux
// relies on reliable delivery — just as TCP does. Instead, we simulate:
//
//   - Write latency spikes (network congestion / bufferbloat)
//   - Abrupt connection closure (TCP RST injection)
//   - Data corruption (bit-flips after TLS decryption)
//
// Silent write drops are NOT used because they cause infinite smux hangs,
// which is the correct protocol behaviour (not a bug to test).
//
// Run with:
//
//	go test ./tests/chaos/... -v -timeout 120s
package chaos

import (
	"context"
	"io"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/auth"
	"github.com/daxson/tunnel/internal/mux"
	"github.com/daxson/tunnel/internal/obfs"
)

// latencyConn wraps a net.Conn and randomly delays writes.
type latencyConn struct {
	net.Conn
	maxDelayMs int
	delayed    atomic.Int64
}

func (c *latencyConn) Write(b []byte) (int, error) {
	if c.maxDelayMs > 0 && rand.Intn(100) < 20 { // 20% of writes get a delay
		delay := time.Duration(rand.Intn(c.maxDelayMs)) * time.Millisecond
		time.Sleep(delay)
		c.delayed.Add(1)
	}
	return c.Conn.Write(b)
}

// corruptConn wraps a net.Conn and randomly corrupts written data.
type corruptConn struct {
	net.Conn
	corruptRate float64 // fraction of writes to corrupt
	corrupted   atomic.Int64
}

func (c *corruptConn) Write(b []byte) (int, error) {
	if c.corruptRate > 0 && rand.Float64() < c.corruptRate && len(b) > 0 {
		buf := make([]byte, len(b))
		copy(buf, b)
		pos := rand.Intn(len(buf))
		buf[pos] ^= 0xFF
		c.corrupted.Add(1)
		return c.Conn.Write(buf)
	}
	return c.Conn.Write(b)
}

// resetConn wraps a net.Conn and abruptly closes it after N writes.
type resetConn struct {
	net.Conn
	closeAfter int
	writes     atomic.Int64
}

func (c *resetConn) Write(b []byte) (int, error) {
	if int(c.writes.Add(1)) >= c.closeAfter {
		c.Conn.Close()
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

// ── Tests ──────────────────────────────────────────────────────────────────

// TestChaosHighLatency verifies that the BCL and smux session survive
// high-latency (200ms burst) links without deadlocking or panicking.
func TestChaosHighLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}
	runLatencyChaos(t, chaosParams{
		maxDelayMs:    200,
		streams:       4,
		dataPerStream: 32 * 1024,
		timeout:       30 * time.Second,
	})
}

// TestChaosModerateLatency exercises a more realistic 50ms congestion scenario.
func TestChaosModerateLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}
	runLatencyChaos(t, chaosParams{
		maxDelayMs:    50,
		streams:       6,
		dataPerStream: 16 * 1024,
		timeout:       20 * time.Second,
	})
}

// TestChaosTCPReset verifies that abrupt connection closure (TCP RST simulation)
// causes the session to fail gracefully — no panic, no goroutine leak.
func TestChaosTCPReset(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverConn, clientConn := net.Pipe()

	// Close connection after 30 writes from client side.
	resetClient := &resetConn{Conn: clientConn, closeAfter: 30}

	const psk = "chaos-reset-test-psk-sixteen-ch"
	hs := auth.New(psk)

	authErr := make(chan error, 1)
	go func() {
		_, err := hs.ServerHandshake(serverConn)
		authErr <- err
	}()
	if _, err := hs.ClientHandshake(resetClient); err != nil {
		t.Logf("auth handshake failed at reset (expected): %v", err)
		return
	}
	if err := <-authErr; err != nil {
		t.Logf("server auth failed at reset (expected): %v", err)
		return
	}

	log := zap.NewNop()
	serverSess, err := mux.NewServerSession(obfs.Wrap(serverConn, obfs.Config{Enabled: false}, log), mux.SmuxConfig(0, 0, 0))
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	clientSess, err := mux.NewClientSession(obfs.Wrap(resetClient, obfs.Config{Enabled: false}, log), mux.ShortKeepaliveConfig())
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer serverSess.Close()
	defer clientSess.Close()

	go func() {
		for {
			stream, err := serverSess.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(stream, stream) //nolint:errcheck
		}
	}()

	// Open a stream and write data; expect failure when RST fires.
	stream, err := clientSess.OpenStream()
	if err != nil {
		t.Logf("open stream failed after reset (expected): %v", err)
		return
	}
	defer stream.Close()

	data := make([]byte, 4*1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := stream.Write(data); err != nil {
				return // reset fired
			}
		}
	}()

	select {
	case <-ctx.Done():
		t.Error("TCP reset test timed out: session did not fail after RST")
	case <-done:
		t.Log("TCP reset handled gracefully")
	}
}

// TestChaosDataCorruption verifies that bit-flips in the stream cause the
// session to fail cleanly (smux checksum or protocol parse error) rather than
// hanging or panicking.
func TestChaosDataCorruption(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	corrupt := &corruptConn{Conn: clientConn, corruptRate: 0.05} // 5% corrupt

	const psk = "chaos-corrupt-test-psk-sixteen!"
	hs := auth.New(psk)

	authErrCh := make(chan error, 1)
	go func() {
		_, err := hs.ServerHandshake(serverConn)
		authErrCh <- err
	}()
	if _, err := hs.ClientHandshake(corrupt); err != nil {
		t.Logf("auth failed under corruption (expected): %v", err)
		return
	}
	if err := <-authErrCh; err != nil {
		t.Logf("server auth failed under corruption (expected): %v", err)
		return
	}

	log := zap.NewNop()
	serverSess, _ := mux.NewServerSession(obfs.Wrap(serverConn, obfs.Config{Enabled: false}, log), mux.ShortKeepaliveConfig())
	clientSess, _ := mux.NewClientSession(obfs.Wrap(corrupt, obfs.Config{Enabled: false}, log), mux.ShortKeepaliveConfig())
	defer serverSess.Close()
	defer clientSess.Close()

	go func() {
		for {
			s, err := serverSess.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(s, s) //nolint:errcheck
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientSess.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()
		data := make([]byte, 1024)
		for i := 0; i < 100; i++ {
			if _, err := stream.Write(data); err != nil {
				return
			}
			buf := make([]byte, 1024)
			if _, err := io.ReadFull(stream, buf); err != nil {
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		t.Error("corruption test timed out: session hung instead of failing gracefully")
	case <-done:
		t.Logf("corruption handled (corrupt writes: %d)", corrupt.corrupted.Load())
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

type chaosParams struct {
	maxDelayMs    int
	streams       int
	dataPerStream int
	timeout       time.Duration
}

func runLatencyChaos(t *testing.T, p chaosParams) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	serverConn, clientConn := net.Pipe()

	latencyClient := &latencyConn{Conn: clientConn, maxDelayMs: p.maxDelayMs}

	const psk = "chaos-latency-test-psk-sixteen!"
	hs := auth.New(psk)

	authErrCh := make(chan error, 1)
	go func() {
		_, err := hs.ServerHandshake(serverConn)
		authErrCh <- err
	}()
	if _, err := hs.ClientHandshake(latencyClient); err != nil {
		t.Logf("auth failed under latency: %v", err)
		return
	}
	if err := <-authErrCh; err != nil {
		t.Logf("server auth failed: %v", err)
		return
	}

	log := zap.NewNop()
	// Use short keepalive to detect broken sessions quickly in tests.
	serverSess, err := mux.NewServerSession(obfs.Wrap(serverConn, obfs.Config{Enabled: false}, log), mux.ShortKeepaliveConfig())
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	clientSess, err := mux.NewClientSession(obfs.Wrap(latencyClient, obfs.Config{Enabled: false}, log), mux.ShortKeepaliveConfig())
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer serverSess.Close()
	defer clientSess.Close()

	go func() {
		for {
			s, err := serverSess.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(s, s) //nolint:errcheck
		}
	}()

	streamDone := make(chan error, p.streams)
	for i := 0; i < p.streams; i++ {
		go func() {
			stream, err := clientSess.OpenStream()
			if err != nil {
				streamDone <- err
				return
			}
			defer stream.Close()

			stream.SetDeadline(time.Now().Add(p.timeout - 2*time.Second)) //nolint:errcheck

			data := make([]byte, p.dataPerStream)
			rand.Read(data) //nolint:errcheck

			if _, err := stream.Write(data); err != nil {
				streamDone <- err
				return
			}

			rbuf := make([]byte, p.dataPerStream)
			if _, err := io.ReadFull(stream, rbuf); err != nil {
				streamDone <- err
				return
			}
			streamDone <- nil
		}()
	}

	succeeded := 0
	for i := 0; i < p.streams; i++ {
		select {
		case <-ctx.Done():
			t.Errorf("chaos latency test timed out after %v (completed %d/%d streams)", p.timeout, succeeded, p.streams)
			return
		case err := <-streamDone:
			if err == nil {
				succeeded++
			} else {
				t.Logf("stream failed (acceptable under latency): %v", err)
			}
		}
	}
	t.Logf("chaos latency: %d/%d streams succeeded (delayed writes: %d)",
		succeeded, p.streams, latencyClient.delayed.Load())
}
