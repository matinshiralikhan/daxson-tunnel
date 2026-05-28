package protocol

import (
	"bytes"
	"testing"
)

// FuzzFrameRead fuzzes the frame reader against arbitrary byte sequences.
// Run with: go test ./pkg/protocol -fuzz=FuzzFrameRead -fuzztime=60s
//
// The only allowed outcomes are:
// 1. A valid frame is returned.
// 2. An error is returned.
// The reader must NEVER panic or hang.
func FuzzFrameRead(f *testing.F) {
	// Seed corpus: valid frames.
	f.Add(validFrameBytes(TypeData, 1, []byte("hello"), 0))
	f.Add(validFrameBytes(TypePing, 0, nil, 0))
	f.Add(validFrameBytes(TypeStreamOpen, 42, []byte{0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}, 17))
	// Short/empty inputs.
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(make([]byte, FrameHeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		fr := NewReader(r)
		// Must not panic. Errors are acceptable.
		fr.ReadFrame() //nolint:errcheck
	})
}

// FuzzStreamOpenPayloadUnmarshal fuzzes address payload decoding.
func FuzzStreamOpenPayloadUnmarshal(f *testing.F) {
	f.Add([]byte{0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb})
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(make([]byte, 4))

	f.Fuzz(func(t *testing.T, data []byte) {
		UnmarshalStreamOpenPayload(data) //nolint:errcheck
	})
}

func validFrameBytes(ft FrameType, sid uint32, payload []byte, padLen uint16) []byte {
	var buf bytes.Buffer
	fw := NewWriter(&buf)
	fw.WriteFrame(Frame{ //nolint:errcheck
		Type:     ft,
		StreamID: sid,
		Payload:  payload,
		PadLen:   padLen,
	})
	return buf.Bytes()
}
