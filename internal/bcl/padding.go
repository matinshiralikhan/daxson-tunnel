package bcl

import (
	"math/rand"

	"github.com/daxson/tunnel/pkg/protocol"
)

// PaddingSelector selects the padding length for a Daxson frame such that
// the total apparent frame size matches a sample from the personality's
// TLS record size model.
//
// The core idea: instead of adding random bytes to every frame, we normalise
// the apparent frame size to fall within a realistic distribution of TLS
// record sizes. This makes our traffic's size histogram match real traffic.
//
// Design notes:
//   - Padding is applied at the Daxson frame level. One Daxson frame ≈ one
//     TLS record (since Daxson frames are written atomically to TLS).
//   - When the payload is larger than the sampled apparent size, we do NOT
//     pad — the payload is split across multiple frames upstream (in Conn.fragmentAndSend).
//   - We introduce a "zero-pad" probability to model the fraction of real TLS
//     records that are sent at exact payload size with no padding.
//   - The size model is correlation-aware: consecutive samples from the same
//     "mode" (small/large) tend to cluster, matching the temporal correlation
//     in real traffic (request bursts all produce similar-sized frames).

// PaddingSelector holds the size model and sampling state.
type PaddingSelector struct {
	sizeModel SizeModel

	// State for temporal correlation: track which "mode" we're in.
	// Large frames tend to cluster (during a large file download) and small
	// frames tend to cluster (during header exchange). We model this as a
	// 2-state Markov chain with a configurable transition probability.
	inLargeMode    bool
	modeTransitionP float64 // probability of switching mode per frame

	// zeroPadProb is the probability of selecting zero padding even when
	// the sampled target size would add some. Real TLS stacks often don't pad.
	zeroPadProb float64
}

// NewPaddingSelector creates a selector calibrated to the personality's size model.
func NewPaddingSelector(p Personality) *PaddingSelector {
	return &PaddingSelector{
		sizeModel:       p.FrameSizeModel,
		inLargeMode:     false,
		modeTransitionP: 0.15, // 15% chance of switching mode per frame
		zeroPadProb:     0.20, // 20% of frames have zero padding
	}
}

// SelectPadding returns the padding length (uint16) to append to a Daxson
// DATA frame whose payload is payloadLen bytes.
//
// The apparent frame size = protocol.FrameHeaderSize + payloadLen + padding.
// We target apparentSize ≈ sizeModel.Sample(), adding padding to fill the gap.
//
// If the payload already exceeds the sampled target, returns 0 (no padding needed;
// the Conn layer handles fragmentation to prevent oversized frames).
func (ps *PaddingSelector) SelectPadding(payloadLen int) uint16 {
	// Probabilistically skip padding to model frames with no padding (common
	// in real TLS implementations that don't use record-layer padding).
	if rand.Float64() < ps.zeroPadProb {
		return 0
	}

	target := ps.sampleCorrelatedSize()

	gap := target - protocol.FrameHeaderSize - payloadLen
	if gap <= 0 {
		// Payload already at or past the target; no padding.
		return 0
	}
	if gap > protocol.MaxPaddingSize {
		gap = protocol.MaxPaddingSize
	}
	return uint16(gap)
}

// SampleApparentSize returns the target total frame size (header + payload + padding)
// for the next frame, taking temporal correlation into account.
func (ps *PaddingSelector) SampleApparentSize() int {
	return ps.sampleCorrelatedSize()
}

// sampleCorrelatedSize samples a size from the model with Markov mode persistence.
// The 2-state (small/large) correlation prevents the independent sampling that
// makes synthetic traffic distinguishable: real traffic clusters in size modes.
func (ps *PaddingSelector) sampleCorrelatedSize() int {
	// Maybe switch modes.
	if rand.Float64() < ps.modeTransitionP {
		ps.inLargeMode = !ps.inLargeMode
	}

	// Sample from the appropriate sub-range of the size model.
	if ps.inLargeMode {
		// Bias toward the larger end of the distribution.
		return ps.sampleBiased(0.6) // treat sizes >= 60th percentile as "large"
	}
	return ps.sampleBiased(0.0) // full distribution
}

// sampleBiased samples with a minimum quantile floor.
// floor=0.0 → full distribution; floor=0.6 → only top 40% of sizes.
func (ps *PaddingSelector) sampleBiased(floor float64) int {
	if floor <= 0 {
		return ps.sizeModel.Sample()
	}
	// Draw until we get a size above the floor quantile.
	// With floor=0.6 and 8 buckets, expected iterations ≈ 2.5 (fast).
	for {
		s := ps.sizeModel.Sample()
		if ps.sizeModel.quantile(s) >= floor {
			return s
		}
	}
}

// quantile returns the approximate CDF value of size s in the model.
// Used for the biased sampler.
func (m SizeModel) quantile(size int) float64 {
	for i, b := range m.buckets {
		if b.Size >= size {
			if i == 0 {
				return 0.0
			}
			return m.cumWeights[i-1]
		}
	}
	return 1.0
}
