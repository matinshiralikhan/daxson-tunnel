package bcl

import (
	"fmt"
	"time"
)

// Personality encodes the complete statistical model of a traffic class.
//
// A personality controls how the BCL shapes traffic to match a specific
// real-world application type. Parameters are derived from empirical
// measurement of real traffic; see inline references.
//
// Design note: "realism not randomness" — every parameter here should be
// traceable to a measured distribution, not an aesthetic guess.
type Personality struct {
	Name string

	// ── Burst collection window ────────────────────────────────────────────
	// How long the sender waits to coalesce incoming writes before flushing.
	// Heavy-tailed: most bursts are flushed quickly; rare bursts coalesce longer.
	// Source: inter-packet gaps in TCP bulk transfer traces (Savage et al., 1999).
	BurstWindow ParetoParams

	// ── Maximum burst byte count ───────────────────────────────────────────
	// Force-flush after accumulating this many bytes regardless of burst window.
	// Prevents unbounded latency during high-throughput transfers.
	MaxBurstBytes int

	// ── Drain phase ────────────────────────────────────────────────────────
	// After flushing a burst, the connection "drains" — no new large sends —
	// simulating TCP ACK processing and CWND recovery.
	// Weibull with k < 1 gives the heavy right tail seen in TCP drain traces.
	DrainDuration WeibullParams

	// ── Think phase ────────────────────────────────────────────────────────
	// After draining, the connection goes quiet (user/app think time).
	// Log-normal matches empirical web session idle periods (Paxson & Floyd 1995).
	// Set Max to a small value for server/relay roles where think time is minimal.
	ThinkTime LogNormalParams

	// ── Frame size model ───────────────────────────────────────────────────
	// The apparent TLS record size distribution. Each frame is padded to match
	// a size sampled from this model. Derived from Chrome HTTP/2 packet traces.
	FrameSizeModel SizeModel

	// ── Keepalive ──────────────────────────────────────────────────────────
	// Chrome sends a PING after this much idle time (no data frames).
	// Uniform jitter is added to prevent a periodic signature.
	// Chrome behaviour: ~45s base, ±10-15s observed jitter.
	KeepaliveIdle    time.Duration
	KeepaliveJitter  time.Duration

	// ── Congestion response ────────────────────────────────────────────────
	// Write-latency EWMA threshold above which the BCL considers the path congested
	// and begins rate reduction. Tuned to match BBR's congestion detection window.
	CongestionThreshold time.Duration

	// ── Traffic asymmetry ─────────────────────────────────────────────────
	// 0.0 = pure download (client to server traffic is negligible)
	// 1.0 = perfectly symmetric (equal upload and download)
	// Used by the sender to decide how aggressively to inject padding frames
	// in the quiet direction to maintain realism.
	// Note: this does NOT add artificial traffic; it governs padding policy.
	UploadFraction float64

	// ── Max pending inbox bytes ────────────────────────────────────────────
	// Write() blocks if this many unprocessed bytes are queued.
	// Sized to hold ~2 smux window sizes.
	MaxInboxBytes int
}

// ── Pre-defined personalities ───────────────────────────────────────────────

// Browser models an HTTP/2 web browser session (Chrome/Firefox).
//
// Characteristics:
//   - Asymmetric: large downloads, small uploads (HEADERS + ACKs)
//   - Bursty: page loads cause rapid bursts; reading causes long idle
//   - TLS records: bimodal (small HEADERS, large DATA)
//   - Keepalive: ~45s idle PING
//
// Key sources: Erman et al. 2009 (browser traffic characteristics);
// Butkiewicz et al. 2011 (web object size distributions).
var Browser = Personality{
	Name: "browser",
	BurstWindow: ParetoParams{
		Alpha: 1.5,
		Xm:    1 * time.Millisecond,
		Cap:   18 * time.Millisecond,
	},
	MaxBurstBytes: 512 * 1024,
	DrainDuration: WeibullParams{
		K:      0.85,
		Lambda: 80 * time.Millisecond,
		Cap:    500 * time.Millisecond,
	},
	ThinkTime: LogNormalParams{
		Mu:    0.5,
		Sigma: 1.8,
		Min:   200 * time.Millisecond,
		Max:   120 * time.Second,
	},
	FrameSizeModel: NewSizeModel([]SizeBucket{
		// HEADERS / small control frames (common in HTTP/2)
		{Size: 128, Weight: 0.06},
		{Size: 256, Weight: 0.08},
		{Size: 512, Weight: 0.09},
		// Medium DATA (compressed JS/CSS, JSON API responses)
		{Size: 1024, Weight: 0.12},
		{Size: 2048, Weight: 0.11},
		{Size: 4096, Weight: 0.15},
		// Large DATA (images, fonts, video segments, file downloads)
		{Size: 8192, Weight: 0.14},
		{Size: 16384, Weight: 0.25}, // peak at TLS max record size
	}),
	KeepaliveIdle:       45 * time.Second,
	KeepaliveJitter:     14 * time.Second,
	CongestionThreshold: 50 * time.Millisecond,
	UploadFraction:      0.05,
	MaxInboxBytes:       4 * 1024 * 1024,
}

// GRPC models a bidirectional gRPC streaming session.
//
// Characteristics:
//   - Nearly symmetric: telemetry/monitoring pushes data in both directions
//   - Short burst windows: RPC messages are sent promptly
//   - Small-to-medium message sizes (protobuf-encoded)
//   - Short think time: gRPC streams are long-lived with regular activity
//   - gRPC keepalive: 30s default (configurable server-side)
//
// Key sources: gRPC HTTP/2 transport spec; Google SRE whitepaper.
var GRPC = Personality{
	Name: "grpc",
	BurstWindow: ParetoParams{
		Alpha: 1.8,
		Xm:    500 * time.Microsecond,
		Cap:   8 * time.Millisecond,
	},
	MaxBurstBytes: 128 * 1024,
	DrainDuration: WeibullParams{
		K:      0.9,
		Lambda: 30 * time.Millisecond,
		Cap:    200 * time.Millisecond,
	},
	ThinkTime: LogNormalParams{
		Mu:    -1.2,
		Sigma: 0.9,
		Min:   50 * time.Millisecond,
		Max:   10 * time.Second,
	},
	FrameSizeModel: NewSizeModel([]SizeBucket{
		// Small protobuf messages (status updates, heartbeats)
		{Size: 64, Weight: 0.10},
		{Size: 128, Weight: 0.15},
		{Size: 256, Weight: 0.18},
		{Size: 512, Weight: 0.20},
		// Medium messages (query responses, metric batches)
		{Size: 1024, Weight: 0.17},
		{Size: 2048, Weight: 0.12},
		{Size: 4096, Weight: 0.08},
	}),
	KeepaliveIdle:       30 * time.Second,
	KeepaliveJitter:     8 * time.Second,
	CongestionThreshold: 30 * time.Millisecond,
	UploadFraction:      0.45,
	MaxInboxBytes:       2 * 1024 * 1024,
}

// VideoStream models a video streaming client (HLS/DASH adaptive bitrate).
//
// Characteristics:
//   - Highly asymmetric: large download chunks, minimal upload
//   - Predictable chunk timing (2–8 second video segments)
//   - Large DATA frames (video segments are 1–5 MB)
//   - Regular but jittered chunk delivery (ABR algorithm jitter)
//   - No PING keepalive during active streaming
//
// Key sources: Huang et al. 2012 (DASH buffering); Mok et al. 2012 (video QoE).
var VideoStream = Personality{
	Name: "video",
	BurstWindow: ParetoParams{
		Alpha: 1.3,
		Xm:    2 * time.Millisecond,
		Cap:   30 * time.Millisecond,
	},
	MaxBurstBytes: 4 * 1024 * 1024,
	DrainDuration: WeibullParams{
		K:      0.7,
		Lambda: 1 * time.Second,
		Cap:    5 * time.Second,
	},
	ThinkTime: LogNormalParams{
		Mu:    0.8,
		Sigma: 0.6,
		Min:   1 * time.Second,
		Max:   8 * time.Second,
	},
	FrameSizeModel: NewSizeModel([]SizeBucket{
		// Video segments arrive as large TLS records
		{Size: 4096, Weight: 0.05},
		{Size: 8192, Weight: 0.10},
		{Size: 16384, Weight: 0.85}, // almost always max TLS record
	}),
	KeepaliveIdle:       90 * time.Second, // players wait longer before PING
	KeepaliveJitter:     20 * time.Second,
	CongestionThreshold: 100 * time.Millisecond,
	UploadFraction:      0.01,
	MaxInboxBytes:       8 * 1024 * 1024,
}

// Mobile models a mobile app making REST API calls.
//
// Characteristics:
//   - Short bursts at app interactions, long idle between interactions
//   - Small frames (JSON API responses)
//   - Battery-aware: tends to batch requests, then go idle
//   - Long think time (mobile user patterns)
//
// Key sources: Falaki et al. 2010 (diversity in smartphone usage).
var Mobile = Personality{
	Name: "mobile",
	BurstWindow: ParetoParams{
		Alpha: 1.6,
		Xm:    2 * time.Millisecond,
		Cap:   15 * time.Millisecond,
	},
	MaxBurstBytes: 64 * 1024,
	DrainDuration: WeibullParams{
		K:      0.8,
		Lambda: 100 * time.Millisecond,
		Cap:    600 * time.Millisecond,
	},
	ThinkTime: LogNormalParams{
		Mu:    1.5,
		Sigma: 2.0,
		Min:   500 * time.Millisecond,
		Max:   300 * time.Second,
	},
	FrameSizeModel: NewSizeModel([]SizeBucket{
		{Size: 128, Weight: 0.15},
		{Size: 256, Weight: 0.20},
		{Size: 512, Weight: 0.25},
		{Size: 1024, Weight: 0.20},
		{Size: 2048, Weight: 0.12},
		{Size: 4096, Weight: 0.08},
	}),
	KeepaliveIdle:       60 * time.Second,
	KeepaliveJitter:     20 * time.Second,
	CongestionThreshold: 80 * time.Millisecond,
	UploadFraction:      0.15,
	MaxInboxBytes:       1 * 1024 * 1024,
}

// Relay models the server-relay link where we want minimal shaping overhead
// but still need realistic TLS record sizing.
// Used on server and relay nodes where absolute throughput matters more
// and the adversary has less visibility into the connection's context.
var Relay = Personality{
	Name: "relay",
	BurstWindow: ParetoParams{
		Alpha: 2.0,
		Xm:    500 * time.Microsecond,
		Cap:   5 * time.Millisecond,
	},
	MaxBurstBytes: 1 * 1024 * 1024,
	DrainDuration: WeibullParams{
		K:      1.0, // exponential (neutral)
		Lambda: 20 * time.Millisecond,
		Cap:    100 * time.Millisecond,
	},
	ThinkTime: LogNormalParams{
		Mu:    -2.0, // very short think time for server
		Sigma: 0.5,
		Min:   10 * time.Millisecond,
		Max:   2 * time.Second,
	},
	FrameSizeModel: NewSizeModel([]SizeBucket{
		{Size: 512, Weight: 0.10},
		{Size: 1024, Weight: 0.10},
		{Size: 2048, Weight: 0.15},
		{Size: 4096, Weight: 0.20},
		{Size: 8192, Weight: 0.20},
		{Size: 16384, Weight: 0.25},
	}),
	KeepaliveIdle:       60 * time.Second,
	KeepaliveJitter:     15 * time.Second,
	CongestionThreshold: 40 * time.Millisecond,
	UploadFraction:      0.40,
	MaxInboxBytes:       8 * 1024 * 1024,
}

// ParsePersonality returns a pre-defined personality by name.
func ParsePersonality(name string) (Personality, error) {
	switch name {
	case "browser", "":
		return Browser, nil
	case "grpc":
		return GRPC, nil
	case "video":
		return VideoStream, nil
	case "mobile":
		return Mobile, nil
	case "relay":
		return Relay, nil
	default:
		return Personality{}, fmt.Errorf("bcl: unknown personality %q (browser|grpc|video|mobile|relay)", name)
	}
}
