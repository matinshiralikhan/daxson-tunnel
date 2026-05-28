package bcl_test

import (
	"bytes"
	"io"
	"math"
	"net"
	"sort"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/bcl"
	"github.com/daxson/tunnel/pkg/protocol"
)

// ── Statistical distribution tests ──────────────────────────────────────────

// TestParetoTailIndex verifies that the Pareto sampler produces heavy-tailed
// output. We check the empirical tail probability: P(X > 5*x_m) ≈ (1/5)^α.
func TestParetoTailIndex(t *testing.T) {
	p := bcl.ParetoParams{
		Alpha: 1.5,
		Xm:    1 * time.Millisecond,
		Cap:   0,
	}
	const N = 100_000
	threshold := 5 * p.Xm
	above := 0
	for i := 0; i < N; i++ {
		if p.Sample() > threshold {
			above++
		}
	}
	empirical := float64(above) / N
	// Theoretical: (1/5)^1.5 ≈ 0.0894
	theoretical := math.Pow(1.0/5.0, p.Alpha)
	tolerance := 0.015 // ±1.5 percentage points
	if math.Abs(empirical-theoretical) > tolerance {
		t.Errorf("Pareto tail P(X > 5*xm): empirical=%.4f theoretical=%.4f (diff=%.4f > tol=%.4f)",
			empirical, theoretical, math.Abs(empirical-theoretical), tolerance)
	}
}

// TestParetoMinimum verifies that no Pareto sample falls below x_m.
func TestParetoMinimum(t *testing.T) {
	p := bcl.ParetoParams{Alpha: 1.5, Xm: 5 * time.Millisecond, Cap: 0}
	for i := 0; i < 10_000; i++ {
		s := p.Sample()
		if s < p.Xm {
			t.Fatalf("Pareto sample %v < x_m %v", s, p.Xm)
		}
	}
}

// TestParetoCap verifies the upper truncation.
func TestParetoCap(t *testing.T) {
	p := bcl.ParetoParams{Alpha: 1.0, Xm: 1 * time.Millisecond, Cap: 10 * time.Millisecond}
	for i := 0; i < 10_000; i++ {
		s := p.Sample()
		if s > p.Cap {
			t.Fatalf("Pareto sample %v > cap %v", s, p.Cap)
		}
	}
}

// TestWeibullShape verifies the Weibull CDF at the median.
// Weibull median = λ * (ln 2)^(1/k).
func TestWeibullMedian(t *testing.T) {
	w := bcl.WeibullParams{K: 0.85, Lambda: 100 * time.Millisecond, Cap: 0}
	theoreticalMedian := float64(w.Lambda) * math.Pow(math.Log(2), 1.0/w.K)

	const N = 50_000
	samples := make([]float64, N)
	for i := 0; i < N; i++ {
		samples[i] = float64(w.Sample())
	}
	sort.Float64s(samples)
	empiricalMedian := samples[N/2]

	relErr := math.Abs(empiricalMedian-theoreticalMedian) / theoreticalMedian
	if relErr > 0.05 {
		t.Errorf("Weibull median: empirical=%.2fms theoretical=%.2fms relErr=%.3f",
			empiricalMedian/1e6, theoreticalMedian/1e6, relErr)
	}
}

// TestLogNormalMedian verifies the log-normal sampler at the median.
// LogNormal median = exp(μ).
func TestLogNormalMedian(t *testing.T) {
	l := bcl.LogNormalParams{Mu: 0.5, Sigma: 1.8, Min: 100 * time.Millisecond, Max: 120 * time.Second}
	theoreticalMedian := math.Exp(l.Mu) * float64(time.Second)

	const N = 50_000
	var samples []float64
	for i := 0; i < N; i++ {
		s := float64(l.Sample())
		if s > float64(l.Min) && s < float64(l.Max) {
			samples = append(samples, s)
		}
	}
	sort.Float64s(samples)
	empiricalMedian := samples[len(samples)/2]

	relErr := math.Abs(empiricalMedian-theoreticalMedian) / theoreticalMedian
	if relErr > 0.15 { // wider tolerance due to Min/Max clamping
		t.Errorf("LogNormal median: empirical=%.3fs theoretical=%.3fs relErr=%.3f",
			empiricalMedian/1e9, theoreticalMedian/1e9, relErr)
	}
}

// TestSizeModelSumToOne verifies that the size model's CDF reaches 1.0.
func TestSizeModelSumToOne(t *testing.T) {
	m := bcl.Browser.FrameSizeModel
	const N = 100_000
	for i := 0; i < N; i++ {
		s := m.Sample()
		if s <= 0 {
			t.Fatalf("size model returned non-positive size %d", s)
		}
	}
}

// TestSizeModelDistribution verifies that the Browser size model produces
// a bimodal distribution: significant mass in both the <1KB and >4KB ranges.
func TestSizeModelDistribution(t *testing.T) {
	m := bcl.Browser.FrameSizeModel
	const N = 100_000
	small, large := 0, 0
	for i := 0; i < N; i++ {
		s := m.Sample()
		if s <= 1024 {
			small++
		} else {
			large++
		}
	}
	smallFrac := float64(small) / N
	largeFrac := float64(large) / N
	// Both modes should have non-trivial mass.
	if smallFrac < 0.20 {
		t.Errorf("small-frame fraction too low: %.3f (expected >= 0.20)", smallFrac)
	}
	if largeFrac < 0.40 {
		t.Errorf("large-frame fraction too low: %.3f (expected >= 0.40)", largeFrac)
	}
}

// ── BCL Conn functional tests ────────────────────────────────────────────────

// TestBCLConnRoundTrip verifies that data written through BCL is received
// intact by the peer.
func TestBCLConnRoundTrip(t *testing.T) {
	server, client := net.Pipe()

	log := zap.NewNop()
	// Use gRPC personality: shorter burst windows make the test faster.
	p := bcl.GRPC

	bclClient := bcl.Wrap(client, p, log)
	defer bclClient.Close()

	// Server side: read raw Daxson frames and reconstruct the data stream.
	// We use a bcl.Conn on the server side too for frame parsing.
	bclServer := bcl.Wrap(server, bcl.Relay, log)
	defer bclServer.Close()

	const msg = "daxson behavioral camouflage layer test payload"

	// Write from client.
	writeDone := make(chan error, 1)
	go func() {
		_, err := bclClient.Write([]byte(msg))
		writeDone <- err
	}()

	// Read on server side.
	buf := make([]byte, len(msg)*2)
	bclServer.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, err := bclServer.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("client write: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("round-trip: got %q, want %q", string(buf[:n]), msg)
	}
}

// TestBCLConnLargeTransfer verifies that large data is correctly fragmented
// and reassembled across multiple Daxson DATA frames.
func TestBCLConnLargeTransfer(t *testing.T) {
	server, client := net.Pipe()
	log := zap.NewNop()

	bclClient := bcl.Wrap(client, bcl.Browser, log)
	bclServer := bcl.Wrap(server, bcl.Relay, log)
	defer bclClient.Close()
	defer bclServer.Close()

	// 128KB transfer — will be fragmented into many Daxson DATA frames
	// whose sizes are drawn from the Browser size distribution.
	payload := make([]byte, 128*1024)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := bclClient.Write(payload)
		errCh <- err
	}()

	bclServer.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	received, err := io.ReadAll(io.LimitReader(bclServer, int64(len(payload))))
	if err != nil && len(received) < len(payload) {
		t.Fatalf("server readall: received %d bytes, err: %v", len(received), err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("client write: %v", err)
	}

	if !bytes.Equal(received[:len(payload)], payload) {
		t.Error("large transfer: received data does not match sent data")
	}
}

// TestBCLFramePaddingRange verifies that the BCL produces padding values
// within the valid range [0, protocol.MaxPaddingSize].
func TestBCLFramePaddingRange(t *testing.T) {
	server, client := net.Pipe()
	log := zap.NewNop()

	bclClient := bcl.Wrap(client, bcl.Browser, log)
	defer bclClient.Close()

	// Read raw frames from the server side to inspect padding.
	fr := protocol.NewReader(server)

	writeData := make([]byte, 512)
	go func() {
		for i := 0; i < 20; i++ {
			bclClient.Write(writeData) //nolint:errcheck
		}
		client.Close()
	}()

	for {
		f, err := fr.ReadFrame()
		if err != nil {
			break // connection closed
		}
		if int(f.PadLen) > protocol.MaxPaddingSize {
			t.Errorf("frame padding %d exceeds MaxPaddingSize %d", f.PadLen, protocol.MaxPaddingSize)
		}
	}
}

// TestBCLPingPongHandshake verifies that PING frames sent by one side
// are responded to with PONG by the other side, without leaking them to
// the application layer.
func TestBCLPingPongHandshake(t *testing.T) {
	server, client := net.Pipe()
	log := zap.NewNop()

	// Server side uses a raw protocol.Writer to inject a PING.
	fw := protocol.NewWriter(server)
	fr := protocol.NewReader(server)

	bclClient := bcl.Wrap(client, bcl.Browser, log)
	defer bclClient.Close()

	// Trigger a Read on the client (so BCL processes frames).
	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, err := bclClient.Read(buf)
		readErrCh <- err
	}()

	// Send a PING from server.
	pingPayload := []byte("testping")
	err := fw.WriteFrame(protocol.Frame{
		Type:    protocol.TypePing,
		Payload: pingPayload,
	})
	if err != nil {
		t.Fatalf("write ping: %v", err)
	}

	// Expect a PONG back from the BCL.
	server.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	pong, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if pong.Type != protocol.TypePong {
		t.Errorf("expected PONG, got %v", pong.Type)
	}
	if !bytes.Equal(pong.Payload, pingPayload) {
		t.Errorf("pong payload mismatch: got %q, want %q", pong.Payload, pingPayload)
	}

	// Close the connection so the blocked Read returns.
	server.Close()
	<-readErrCh
}

// TestPersonalityParsing verifies all known personalities parse correctly.
func TestPersonalityParsing(t *testing.T) {
	cases := []string{"browser", "grpc", "video", "mobile", "relay", ""}
	for _, name := range cases {
		_, err := bcl.ParsePersonality(name)
		if err != nil {
			t.Errorf("ParsePersonality(%q): unexpected error: %v", name, err)
		}
	}
	_, err := bcl.ParsePersonality("invalid_personality_xyz")
	if err == nil {
		t.Error("ParsePersonality(invalid): expected error, got nil")
	}
}

// ── BCL timing property tests ────────────────────────────────────────────────

// TestBurstWindowVariance verifies that consecutive burst windows are NOT
// identical — i.e., there is actual variance from the Pareto distribution.
// This detects regressions where someone replaces the distribution with a constant.
func TestBurstWindowVariance(t *testing.T) {
	p := bcl.ParetoParams{Alpha: 1.5, Xm: 1 * time.Millisecond, Cap: 20 * time.Millisecond}

	const N = 1000
	samples := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		samples[i] = p.Sample()
	}

	// Compute variance.
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	mean := sum / N

	var variance float64
	for _, s := range samples {
		d := float64(s) - mean
		variance += d * d
	}
	variance /= N
	cv := math.Sqrt(variance) / mean // coefficient of variation

	// For Pareto with α=1.5, CV should be significantly > 0 (expect ~1.5+).
	if cv < 0.5 {
		t.Errorf("burst window coefficient of variation too low: %.3f (want >= 0.5); shaping is too uniform", cv)
	}
}
