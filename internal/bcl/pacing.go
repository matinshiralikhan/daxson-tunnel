package bcl

import (
	"math"
	"sync"
	"time"
)

// Pacer manages the send rate based on congestion signals observed from
// write latency. It implements a simplified AIMD (Additive Increase,
// Multiplicative Decrease) algorithm similar to TCP's congestion control,
// making our traffic appear to respond to network conditions the way a
// real TCP connection would.
//
// Why this matters for anti-detection: a censorship system doing active
// throughput analysis expects traffic to slow down under congestion.
// Tunnel traffic that maintains a steady rate regardless of latency looks
// synthetic and is a detection signal.
type Pacer struct {
	mu sync.Mutex

	// EWMA of per-write latency. Updated on every call to ObserveWrite.
	// Uses a fast alpha (0.25) to track recent conditions without being
	// too sensitive to single spikes.
	ewmaLatencyNs float64
	alpha         float64 // EWMA smoothing factor

	// congestionThresholdNs is derived from personality.CongestionThreshold.
	thresholdNs float64

	// rate is the current "congestion window" as a fraction of full speed [0.1, 1.0].
	// rate = 1.0 → no extra delay; rate = 0.1 → inter-frame gaps 9× longer.
	rate float64

	// interFrameBase is the baseline delay between frames within a burst.
	// This is not zero even at rate=1.0: real TCP sends have small inter-segment
	// gaps due to ACK clocking. Drawn from Pareto on each sample.
	interFrameBase ParetoParams
}

// NewPacer creates a Pacer calibrated to the given personality.
func NewPacer(p Personality) *Pacer {
	return &Pacer{
		ewmaLatencyNs: 1e6, // start optimistic: 1ms
		alpha:         0.25,
		thresholdNs:   float64(p.CongestionThreshold.Nanoseconds()),
		rate:           1.0,
		interFrameBase: ParetoParams{
			// Inter-segment gap: median ~0.3ms, heavy-tailed tail up to 2ms.
			// Models ACK-clocked segment transmission.
			Alpha: 1.8,
			Xm:    300 * time.Microsecond,
			Cap:   2 * time.Millisecond,
		},
	}
}

// ObserveWrite updates the congestion estimate after a write of byteCount bytes
// that took wallTime to complete.
func (p *Pacer) ObserveWrite(wallTime time.Duration, byteCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ns := float64(wallTime.Nanoseconds())
	p.ewmaLatencyNs = p.alpha*ns + (1-p.alpha)*p.ewmaLatencyNs

	if p.ewmaLatencyNs > p.thresholdNs {
		// Multiplicative decrease: halve the rate, floor at 10%.
		p.rate = math.Max(0.10, p.rate*0.5)
	} else if p.rate < 1.0 {
		// Additive increase: recover slowly (0.05 per observation).
		p.rate = math.Min(1.0, p.rate+0.05)
	}
}

// IsCongested reports whether the path is currently congested.
func (p *Pacer) IsCongested() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ewmaLatencyNs > p.thresholdNs
}

// InterFrameDelay returns how long to wait between frames within a burst.
// Even at full rate this is non-zero (ACK-clocking simulation).
// Under congestion this grows proportionally to simulate CWND reduction.
func (p *Pacer) InterFrameDelay() time.Duration {
	p.mu.Lock()
	r := p.rate
	p.mu.Unlock()

	base := p.interFrameBase.Sample()
	if r >= 1.0 {
		return base
	}
	// Scale: rate=0.5 → 2× base; rate=0.1 → 10× base.
	scale := 1.0 / r
	return time.Duration(float64(base) * scale)
}

// BurstDelay returns additional delay to inject before flushing a burst
// when congested. Returns zero when not congested.
func (p *Pacer) BurstDelay() time.Duration {
	p.mu.Lock()
	r := p.rate
	congested := p.ewmaLatencyNs > p.thresholdNs
	p.mu.Unlock()

	if !congested || r >= 1.0 {
		return 0
	}
	// Add a proportional hold-off that scales with congestion severity.
	base := 10 * time.Millisecond
	return time.Duration(float64(base) * (1.0 / r))
}

// ── State machine ────────────────────────────────────────────────────────────

// connState represents the BCL connection lifecycle state.
// The machine tracks the "mood" of the connection which controls when and how
// aggressively the sender flushes data.
type connState uint8

const (
	// stateIdle: no data pending, no activity. BCL will send keepalive
	// PINGs after the idle timeout expires.
	stateIdle connState = iota

	// stateBurst: data is arriving; BCL is collecting writes within the
	// burst window before flushing. This is the active transfer state.
	stateBurst

	// stateDrain: a burst was just sent; BCL is simulating TCP drain —
	// the brief quiet period while ACKs return and CWND recovers.
	// New data arriving during drain is held until drain expires.
	stateDrain

	// stateThink: the application is idle (user reading, page rendering,
	// app processing). Connection is open but quiet. PING keepalives may
	// be sent in this state.
	stateThink

	// stateCongested: write latency exceeded the threshold. BCL rate-limits
	// sends aggressively. Overlaid on any other state.
	stateCongested
)

func (s connState) String() string {
	switch s {
	case stateIdle:
		return "IDLE"
	case stateBurst:
		return "BURST"
	case stateDrain:
		return "DRAIN"
	case stateThink:
		return "THINK"
	case stateCongested:
		return "CONGESTED"
	default:
		return "UNKNOWN"
	}
}
