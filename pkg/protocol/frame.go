// Package protocol defines the Daxson wire protocol.
//
// Frame layout (inside TLS — fully opaque to network observers):
//
//	┌──────────┬────────────────┬──────────────┬──────────────┐
//	│ Type(1B) │  StreamID(4B)  │  Length(4B)  │ PadLen(2B)  │
//	└──────────┴────────────────┴──────────────┴──────────────┘
//	Frame body: [Payload: Length bytes][Random Padding: PadLen bytes]
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	FrameHeaderSize = 11
	MaxPayloadSize  = 65535
	MaxPaddingSize  = 1024

	// Version byte sent in the auth handshake.
	ProtocolVersion = 0x01

	// Auth handshake sizes.
	AuthRequestSize  = 49 // version(1) + nonce(16) + token(32)
	AuthResponseSize = 17 // status(1) + sessionID(16)

	AuthStatusOK   = 0x00
	AuthStatusFail = 0xFF
)

// FrameType identifies the purpose of a frame.
type FrameType uint8

const (
	TypeData        FrameType = 0x01
	TypeStreamOpen  FrameType = 0x02
	TypeStreamClose FrameType = 0x03
	TypeStreamReset FrameType = 0x04
	TypePing        FrameType = 0x05
	TypePong        FrameType = 0x06
	TypeSettings    FrameType = 0x07
	TypePadding     FrameType = 0x08
)

func (t FrameType) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeStreamOpen:
		return "STREAM_OPEN"
	case TypeStreamClose:
		return "STREAM_CLOSE"
	case TypeStreamReset:
		return "STREAM_RESET"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeSettings:
		return "SETTINGS"
	case TypePadding:
		return "PADDING"
	default:
		return "UNKNOWN"
	}
}

// AddrType mirrors SOCKS5 address types.
type AddrType uint8

const (
	AddrIPv4   AddrType = 0x01
	AddrDomain AddrType = 0x03
	AddrIPv6   AddrType = 0x04
)

// Frame is a single Daxson protocol frame.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
	PadLen   uint16
}

// Errors returned by Read/Write.
var (
	ErrFrameTooLarge   = errors.New("protocol: frame payload exceeds maximum size")
	ErrPaddingTooLarge = errors.New("protocol: frame padding exceeds maximum size")
	ErrUnknownType     = errors.New("protocol: unknown frame type")
	ErrShortRead       = errors.New("protocol: short read on frame body")
)

// Writer writes frames to an io.Writer.
// Not safe for concurrent use; the caller must serialize writes.
type Writer struct {
	w   io.Writer
	buf []byte
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w, buf: make([]byte, 4096)}
}

func (fw *Writer) WriteFrame(f Frame) error {
	if len(f.Payload) > MaxPayloadSize {
		return ErrFrameTooLarge
	}
	if int(f.PadLen) > MaxPaddingSize {
		return ErrPaddingTooLarge
	}

	total := FrameHeaderSize + len(f.Payload) + int(f.PadLen)
	if cap(fw.buf) < total {
		fw.buf = make([]byte, total*2)
	}
	buf := fw.buf[:total]

	buf[0] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[1:5], f.StreamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(f.Payload)))
	binary.BigEndian.PutUint16(buf[9:11], f.PadLen)
	copy(buf[FrameHeaderSize:], f.Payload)

	if f.PadLen > 0 {
		if _, err := rand.Read(buf[FrameHeaderSize+len(f.Payload):]); err != nil {
			return err
		}
	}

	_, err := fw.w.Write(buf)
	return err
}

// Reader reads frames from an io.Reader.
// Not safe for concurrent use.
type Reader struct {
	r      io.Reader
	hdr    [FrameHeaderSize]byte
	padbuf [MaxPaddingSize]byte
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

func (fr *Reader) ReadFrame() (Frame, error) {
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		return Frame{}, err
	}

	ft := FrameType(fr.hdr[0])
	sid := binary.BigEndian.Uint32(fr.hdr[1:5])
	length := binary.BigEndian.Uint32(fr.hdr[5:9])
	padLen := binary.BigEndian.Uint16(fr.hdr[9:11])

	if length > MaxPayloadSize {
		return Frame{}, ErrFrameTooLarge
	}
	if int(padLen) > MaxPaddingSize {
		return Frame{}, ErrPaddingTooLarge
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return Frame{}, err
		}
	}

	if padLen > 0 {
		if _, err := io.ReadFull(fr.r, fr.padbuf[:padLen]); err != nil {
			return Frame{}, err
		}
	}

	return Frame{
		Type:     ft,
		StreamID: sid,
		Payload:  payload,
		PadLen:   padLen,
	}, nil
}

// StreamOpenPayload encodes the target address for a STREAM_OPEN frame.
//
// Format: [AddrType:1][AddrLen:1][Addr:N][Port:2]
type StreamOpenPayload struct {
	AddrType AddrType
	Addr     string
	Port     uint16
}

func (p StreamOpenPayload) Marshal() []byte {
	addr := []byte(p.Addr)
	out := make([]byte, 4+len(addr))
	out[0] = byte(p.AddrType)
	out[1] = byte(len(addr))
	copy(out[2:], addr)
	binary.BigEndian.PutUint16(out[2+len(addr):], p.Port)
	return out
}

func UnmarshalStreamOpenPayload(b []byte) (StreamOpenPayload, error) {
	if len(b) < 4 {
		return StreamOpenPayload{}, errors.New("protocol: stream open payload too short")
	}
	addrType := AddrType(b[0])
	addrLen := int(b[1])
	if len(b) < 2+addrLen+2 {
		return StreamOpenPayload{}, errors.New("protocol: stream open payload truncated")
	}
	addr := string(b[2 : 2+addrLen])
	port := binary.BigEndian.Uint16(b[2+addrLen:])
	return StreamOpenPayload{AddrType: addrType, Addr: addr, Port: port}, nil
}
