// Package benchmarks measures throughput, latency, and BCL overhead.
//
// Run all:
//
//	go test ./tests/benchmarks/... -bench=. -benchmem -benchtime=10s
//
// Compare BCL vs raw:
//
//	go test ./tests/benchmarks/... -bench=BenchmarkBCL -benchmem -benchtime=5s
package benchmarks

import (
	"bytes"
	"io"
	"net"
	"testing"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/bcl"
	"github.com/daxson/tunnel/internal/obfs"
	"github.com/daxson/tunnel/pkg/protocol"
)

// ── Protocol frame benchmarks ────────────────────────────────────────────────

// BenchmarkFrameWrite measures raw frame serialisation throughput (no BCL overhead).
func BenchmarkFrameWrite(b *testing.B) {
	var buf bytes.Buffer
	fw := protocol.NewWriter(&buf)
	payload := make([]byte, 4096)

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		buf.Reset()
		fw.WriteFrame(protocol.Frame{ //nolint:errcheck
			Type:     protocol.TypeData,
			StreamID: 0,
			Payload:  payload,
			PadLen:   0,
		})
	}
}

// BenchmarkFrameWriteWithPadding measures frame write overhead with 128-byte padding.
func BenchmarkFrameWriteWithPadding(b *testing.B) {
	var buf bytes.Buffer
	fw := protocol.NewWriter(&buf)
	payload := make([]byte, 4096)

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		buf.Reset()
		fw.WriteFrame(protocol.Frame{ //nolint:errcheck
			Type:     protocol.TypeData,
			StreamID: 0,
			Payload:  payload,
			PadLen:   128,
		})
	}
}

// BenchmarkFrameRead measures frame deserialisation throughput.
func BenchmarkFrameRead(b *testing.B) {
	var buf bytes.Buffer
	fw := protocol.NewWriter(&buf)
	payload := make([]byte, 4096)
	fw.WriteFrame(protocol.Frame{ //nolint:errcheck
		Type:    protocol.TypeData,
		Payload: payload,
	})
	encoded := buf.Bytes()

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		fr := protocol.NewReader(r)
		fr.ReadFrame() //nolint:errcheck
	}
}

// ── BCL overhead benchmarks ──────────────────────────────────────────────────

// BenchmarkBCLWriteBrowser measures BCL throughput with the "browser" personality.
// This is the primary anti-detection mode: measures cost of shaping.
func BenchmarkBCLWriteBrowser(b *testing.B) {
	benchmarkBCLWrite(b, "browser")
}

// BenchmarkBCLWriteGRPC measures BCL throughput with the "grpc" personality.
// Shorter burst windows → lower latency but still shaped.
func BenchmarkBCLWriteGRPC(b *testing.B) {
	benchmarkBCLWrite(b, "grpc")
}

// BenchmarkBCLWriteRelay measures BCL throughput with the "relay" personality.
// Minimal shaping → closest to raw throughput.
func BenchmarkBCLWriteRelay(b *testing.B) {
	benchmarkBCLWrite(b, "relay")
}

func benchmarkBCLWrite(b *testing.B, personality string) {
	b.Helper()
	log := zap.NewNop()

	p, err := bcl.ParsePersonality(personality)
	if err != nil {
		b.Fatalf("parse personality: %v", err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	bclClient := bcl.Wrap(client, p, log)
	defer bclClient.Close()

	// Drain server: BCL frames arrive here; we must consume them or net.Pipe blocks.
	go io.Copy(io.Discard, server) //nolint:errcheck

	payload := make([]byte, 4096)

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		bclClient.Write(payload) //nolint:errcheck
	}
}

// BenchmarkRawConnWrite measures raw net.Pipe write throughput for comparison.
func BenchmarkRawConnWrite(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go io.Copy(io.Discard, server) //nolint:errcheck

	payload := make([]byte, 4096)

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		client.Write(payload) //nolint:errcheck
	}
}

// BenchmarkObfsWrapDisabled measures the zero-overhead path when BCL is disabled.
func BenchmarkObfsWrapDisabled(b *testing.B) {
	log := zap.NewNop()
	cfg := obfs.Config{Enabled: false}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wrapped := obfs.Wrap(client, cfg, log)

	go io.Copy(io.Discard, server) //nolint:errcheck

	payload := make([]byte, 4096)

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		wrapped.Write(payload) //nolint:errcheck
	}
}

// ── Padding and size model benchmarks ───────────────────────────────────────

// BenchmarkSizeModelSample measures how fast the size distribution sampler is.
func BenchmarkSizeModelSample(b *testing.B) {
	m := bcl.Browser.FrameSizeModel
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Sample()
	}
}

// ── Address encoding benchmarks ─────────────────────────────────────────────

// BenchmarkStreamOpenPayloadMarshal benchmarks address encoding.
func BenchmarkStreamOpenPayloadMarshal(b *testing.B) {
	p := protocol.StreamOpenPayload{
		AddrType: protocol.AddrDomain,
		Addr:     "www.example.com",
		Port:     443,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Marshal()
	}
}

// BenchmarkStreamOpenPayloadUnmarshal benchmarks address decoding.
func BenchmarkStreamOpenPayloadUnmarshal(b *testing.B) {
	p := protocol.StreamOpenPayload{
		AddrType: protocol.AddrDomain,
		Addr:     "www.example.com",
		Port:     443,
	}
	encoded := p.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protocol.UnmarshalStreamOpenPayload(encoded) //nolint:errcheck
	}
}
