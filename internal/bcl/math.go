// Package bcl implements the Behavioral Camouflage Layer.
//
// The BCL sits between the smux multiplexing session and the TLS connection.
// It makes the traffic timing and sizing indistinguishable from real browser
// HTTP/2 or gRPC traffic by modelling the full statistical structure of
// authentic application traffic — not just adding random noise.
//
// This file provides the statistical distributions used by the BCL.
// All distributions are sampled by inverse-CDF transform for efficiency.
package bcl

import (
	"math"
	"math/rand"
	"time"
)

// ── Pareto distribution ─────────────────────────────────────────────────────
//
// Used for: burst window durations, inter-burst gaps, ON/OFF period durations.
//
// Theoretical basis: Leland et al. (1994) showed Ethernet traffic is
// self-similar because multiplexed ON/OFF sources with heavy-tailed Pareto
// sojourn times produce aggregate traffic with Hurst parameter H = (3-α)/2.
// For H ≈ 0.8 (empirically observed), α ≈ 1.4.
//
// PDF:  f(x) = α * x_m^α / x^(α+1)  for x >= x_m
// CDF:  F(x) = 1 - (x_m/x)^α
// Inv:  x = x_m / (1-U)^(1/α)        for U ~ Uniform(0,1)

// ParetoParams parameterises a Pareto(α, x_m) distribution.
type ParetoParams struct {
	Alpha float64       // shape (tail index). α < 2 → infinite variance; α < 1 → infinite mean
	Xm    time.Duration // location (minimum value)
	Cap   time.Duration // upper truncation (0 = uncapped)
}

// Sample draws one value from the Pareto distribution.
func (p ParetoParams) Sample() time.Duration {
	u := rand.Float64()
	if u >= 1.0 {
		u = 1.0 - 1e-9
	}
	x := float64(p.Xm) / math.Pow(1.0-u, 1.0/p.Alpha)
	if p.Cap > 0 && time.Duration(x) > p.Cap {
		return p.Cap
	}
	return time.Duration(x)
}

// ── Weibull distribution ────────────────────────────────────────────────────
//
// Used for: burst sizes, drain durations.
//
// The Weibull distribution with shape k < 1 is heavy-tailed (more so than
// exponential); k > 1 is lighter-tailed. Burst sizes in LAN traffic are
// well-fit by Weibull with k ≈ 0.5–0.85.
//
// CDF:  F(x) = 1 - exp(-(x/λ)^k)
// Inv:  x = λ * (-ln(1-U))^(1/k)

// WeibullParams parameterises a Weibull(k, λ) distribution.
type WeibullParams struct {
	K      float64       // shape. k < 1 → heavy tail; k = 1 → exponential; k > 1 → lighter
	Lambda time.Duration // scale
	Cap    time.Duration // upper truncation (0 = uncapped)
}

// Sample draws one value from the Weibull distribution.
func (w WeibullParams) Sample() time.Duration {
	u := rand.Float64()
	if u >= 1.0 {
		u = 1.0 - 1e-9
	}
	x := float64(w.Lambda) * math.Pow(-math.Log(1.0-u), 1.0/w.K)
	if w.Cap > 0 && time.Duration(x) > w.Cap {
		return w.Cap
	}
	return time.Duration(x)
}

// ── Log-normal distribution ─────────────────────────────────────────────────
//
// Used for: human/app think times between bursts.
//
// Empirical studies of web browsing session timing show inter-page intervals
// fit log-normal distributions (Paxson & Floyd, 1995). The log-normal is also
// used to model HTTP response sizes and connection lifetimes.
//
// X = exp(μ + σ * Z)  where Z ~ Normal(0,1)

// LogNormalParams parameterises a log-normal distribution (in seconds).
type LogNormalParams struct {
	Mu    float64       // mean of the underlying normal (log seconds)
	Sigma float64       // std dev of the underlying normal
	Min   time.Duration // lower clamp
	Max   time.Duration // upper clamp (0 = uncapped)
}

// Sample draws one value from the log-normal distribution.
func (l LogNormalParams) Sample() time.Duration {
	z := rand.NormFloat64()
	logSeconds := l.Mu + l.Sigma*z
	seconds := math.Exp(logSeconds)
	d := time.Duration(seconds * float64(time.Second))
	if d < l.Min {
		d = l.Min
	}
	if l.Max > 0 && d > l.Max {
		d = l.Max
	}
	return d
}

// ── Bimodal TLS record size model ──────────────────────────────────────────
//
// Real TLS record sizes are bimodal:
//   - "Control" mode: small records (HEADERS, RST_STREAM, WINDOW_UPDATE).
//     Observed distribution: roughly log-normal with median ~300B.
//   - "Data" mode: large records (DATA frames for file/video content).
//     Observed distribution: peaks strongly at 16384B (the TLS max record
//     size); sub-peaks at 4096B and 8192B from application write boundaries.
//
// We model this as a weighted mixture of discrete quantized sizes.
// The weights are derived from empirical CDFs of Chrome HTTPS traffic.

// SizeBucket is a quantized apparent frame size (FrameHeaderSize + payload + padding).
type SizeBucket struct {
	Size   int     // apparent frame size in bytes
	Weight float64 // relative probability weight (unnormalised)
}

// SizeModel holds a discrete mixture of size buckets.
type SizeModel struct {
	buckets    []SizeBucket
	cumWeights []float64 // normalised cumulative weights for fast sampling
}

// NewSizeModel builds a SizeModel from the given buckets.
func NewSizeModel(buckets []SizeBucket) SizeModel {
	total := 0.0
	for _, b := range buckets {
		total += b.Weight
	}
	cum := make([]float64, len(buckets))
	running := 0.0
	for i, b := range buckets {
		running += b.Weight / total
		cum[i] = running
	}
	return SizeModel{buckets: buckets, cumWeights: cum}
}

// Sample draws a size from the model using the alias/bisect method.
func (m SizeModel) Sample() int {
	u := rand.Float64()
	lo, hi := 0, len(m.cumWeights)-1
	for lo < hi {
		mid := (lo + hi) / 2
		if m.cumWeights[mid] < u {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return m.buckets[lo].Size
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// uniformJitter returns a random duration in [-spread, +spread].
func uniformJitter(spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(2*spread))) - spread
}

// clampDuration clamps d to [lo, hi].
func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
