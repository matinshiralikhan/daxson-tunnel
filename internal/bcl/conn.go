package bcl

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/pkg/protocol"
)

// Conn is a net.Conn implementation that applies the Behavioral Camouflage
// Layer to all writes, making the traffic timing and sizing resemble a
// configured application personality.
//
// Write path (smux → BCL → TLS):
//
//	smux.Write(b) → Conn.Write(b)
//	  → copies b into inbox channel
//	  ← returns immediately (non-blocking if inbox not full)
//	sender goroutine:
//	  → collects writes during burst window (Pareto-distributed)
//	  → fragments burst into Daxson DATA frames with realistic sizes
//	  → injects padding to normalise apparent TLS record sizes
//	  → applies inter-frame pacing (congestion-aware)
//	  → writes frames to TLS connection
//
// Read path (TLS → BCL → smux):
//
//	smux.Read(b) → Conn.Read(b)
//	  → reads next Daxson frame from TLS connection
//	  → handles PING/PONG/PADDING frames internally (not returned to smux)
//	  → returns DATA frame payload to smux
//	  → buffers overflow if len(payload) > len(b)
//
// Keepalive:
//
//	A dedicated goroutine tracks idle time and injects PING frames
//	after KeepaliveIdle ± KeepaliveJitter when in IDLE or THINK states.
//	PINGs are suppressed during BURST and DRAIN states.
type Conn struct {
	conn net.Conn
	p    Personality
	log  *zap.Logger

	fw *protocol.Writer
	fr *protocol.Reader

	// Write side: inbox receives copies of smux Write() calls.
	// Sized to ~2 smux windows to provide backpressure without deadlock.
	inbox chan inboxItem

	// Read side: buffer for partial DATA frame consumption.
	readBuf bytes.Buffer

	// Sender synchronisation.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Congestion-aware pacing.
	pacer   *Pacer
	padding *PaddingSelector

	// Current BCL connection state. Written only by sender goroutine.
	state connState

	// lastActivityNs is the Unix nanosecond timestamp of the last DATA frame
	// sent or received. Used by the keepalive goroutine.
	lastActivityNs atomic.Int64

	// pingCh receives PING frames read from the peer (handled by sender).
	pingCh chan protocol.Frame
	// pongCh receives PONG frames (used to update congestion estimate).
	pongCh chan protocol.Frame

	// pendingPing tracks an in-flight PING for RTT measurement.
	pendingPingSent atomic.Int64 // UnixNano when PING was sent; 0 = none in flight

	// writeErr stores the first fatal write error encountered by the sender.
	writeErr atomic.Value // stores error

	// closed is closed exactly once when the Conn is shut down.
	closed    chan struct{}
	closeOnce sync.Once
}

type inboxItem struct {
	data []byte
	// future: priority uint8
}

// Wrap creates a BCL Conn wrapping the given TLS connection.
// Call Close() to stop background goroutines.
func Wrap(conn net.Conn, p Personality, log *zap.Logger) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		conn:   conn,
		p:      p,
		log:    log,
		fw:     protocol.NewWriter(conn),
		fr:     protocol.NewReader(conn),
		inbox:  make(chan inboxItem, 256),
		ctx:    ctx,
		cancel: cancel,
		pacer:  NewPacer(p),
		padding: NewPaddingSelector(p),
		pingCh: make(chan protocol.Frame, 4),
		pongCh: make(chan protocol.Frame, 4),
		closed: make(chan struct{}),
	}
	c.lastActivityNs.Store(time.Now().UnixNano())

	c.wg.Add(2)
	go c.sender()
	go c.keepaliveLoop()

	return c
}

// ── net.Conn interface ───────────────────────────────────────────────────────

// Write accepts smux data for shaped transmission.
// Returns as soon as the data is accepted into the inbox (not yet transmitted).
// Blocks only if the inbox is full (backpressure from congested sender).
func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	if err, _ := c.writeErr.Load().(error); err != nil {
		return 0, err
	}

	// Copy: smux may reuse b after Write returns.
	buf := make([]byte, len(b))
	copy(buf, b)

	select {
	case c.inbox <- inboxItem{data: buf}:
		return len(b), nil
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	}
}

// Read returns the next smux data payload from the peer.
// Non-data frames (PING, PONG, PADDING) are handled internally.
// Blocks until data is available or the connection closes.
func (c *Conn) Read(b []byte) (int, error) {
	for {
		// Serve buffered leftovers from a partial frame read first.
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(b)
		}

		frame, err := c.fr.ReadFrame()
		if err != nil {
			return 0, err
		}

		c.lastActivityNs.Store(time.Now().UnixNano())

		switch frame.Type {
		case protocol.TypeData:
			if len(frame.Payload) == 0 {
				continue
			}
			n := copy(b, frame.Payload)
			if n < len(frame.Payload) {
				// Payload exceeds read buffer; buffer the remainder.
				c.readBuf.Write(frame.Payload[n:])
			}
			return n, nil

		case protocol.TypePing:
			// Queue for async response by sender (non-blocking).
			select {
			case c.pingCh <- frame:
			default:
				c.log.Debug("bcl: ping queue full, dropping ping")
			}

		case protocol.TypePong:
			select {
			case c.pongCh <- frame:
			default:
			}

		case protocol.TypePadding:
			// Traffic shaping frame: discard payload entirely.

		default:
			c.log.Debug("bcl: unknown frame type, discarding",
				zap.Uint8("type", uint8(frame.Type)))
		}
	}
}

func (c *Conn) Close() error {
	var connErr error
	c.closeOnce.Do(func() {
		c.cancel()
		connErr = c.conn.Close()
		c.wg.Wait()
		close(c.closed)
	})
	return connErr
}

func (c *Conn) LocalAddr() net.Addr            { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr           { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error  { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ── Sender goroutine ─────────────────────────────────────────────────────────

// sender is the single goroutine responsible for all writes to the underlying
// TLS connection. Serialisation here ensures TLS record ordering.
func (c *Conn) sender() {
	defer c.wg.Done()

	for {
		// Wait for the first item in this burst, or for control events.
		select {
		case item := <-c.inbox:
			c.runBurstCycle(item.data)

		case ping := <-c.pingCh:
			// Respond to peer PING immediately (before waiting for burst).
			c.writePong(ping.Payload)

		case <-c.ctx.Done():
			return
		}
	}
}

// runBurstCycle handles one complete BURST → DRAIN → THINK cycle.
//
// Phase 1 — BURST: collect writes for a Pareto-distributed window, then flush.
// Phase 2 — DRAIN: short post-burst quiet simulating TCP ACK-clocking drain.
// Phase 3 — THINK: longer idle simulating user/app think time.
//
// If new data arrives during DRAIN or THINK, those phases are cut short and
// we re-enter BURST immediately.
func (c *Conn) runBurstCycle(firstChunk []byte) {
	// ── BURST phase ─────────────────────────────────────────────────────────
	c.state = stateBurst

	burst := [][]byte{firstChunk}
	totalBurst := len(firstChunk)

	// Start burst collection window.
	burstWindow := c.p.BurstWindow.Sample()
	timer := time.NewTimer(burstWindow)
	defer timer.Stop()

collectLoop:
	for {
		// Apply congestion-induced burst delay if path is congested.
		if delay := c.pacer.BurstDelay(); delay > 0 {
			time.Sleep(delay)
		}

		select {
		case item := <-c.inbox:
			burst = append(burst, item.data)
			totalBurst += len(item.data)
			if totalBurst >= c.p.MaxBurstBytes {
				// Buffer is large enough; flush now.
				break collectLoop
			}
			// Reset burst window on new data (extends coalescing window).
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(c.p.BurstWindow.Sample())

		case ping := <-c.pingCh:
			c.writePong(ping.Payload)

		case <-timer.C:
			break collectLoop

		case <-c.ctx.Done():
			return
		}
	}

	// Coalesce burst into one byte slice.
	combined := coalesceBurst(burst, totalBurst)

	// Flush with fragmentation and per-frame shaping.
	if err := c.fragmentAndSend(combined); err != nil {
		c.writeErr.Store(err)
		c.log.Debug("bcl: sender write error", zap.Error(err))
		return
	}

	// ── DRAIN phase ──────────────────────────────────────────────────────────
	c.state = stateDrain
	drainDur := c.p.DrainDuration.Sample()
	drainTimer := time.NewTimer(drainDur)
	defer drainTimer.Stop()

	select {
	case item := <-c.inbox:
		// New data interrupted drain; start a new burst immediately.
		c.state = stateBurst
		c.runBurstCycle(item.data)
		return
	case ping := <-c.pingCh:
		c.writePong(ping.Payload)
	case pong := <-c.pongCh:
		c.processPong(pong)
	case <-drainTimer.C:
		// Drain completed normally.
	case <-c.ctx.Done():
		return
	}

	// ── THINK phase ──────────────────────────────────────────────────────────
	c.state = stateThink
	thinkDur := c.p.ThinkTime.Sample()
	thinkTimer := time.NewTimer(thinkDur)
	defer thinkTimer.Stop()

	for {
		select {
		case item := <-c.inbox:
			c.state = stateBurst
			c.runBurstCycle(item.data)
			return
		case ping := <-c.pingCh:
			c.writePong(ping.Payload)
		case pong := <-c.pongCh:
			c.processPong(pong)
		case <-thinkTimer.C:
			c.state = stateIdle
			return
		case <-c.ctx.Done():
			return
		}
	}
}

// fragmentAndSend fragments data into Daxson DATA frames with realistic apparent
// sizes (matching the personality's TLS record size model) and writes them to
// the underlying TLS connection with inter-frame pacing.
func (c *Conn) fragmentAndSend(data []byte) error {
	remaining := data

	for len(remaining) > 0 {
		// Sample a target apparent size (header + payload + padding).
		apparentSize := c.padding.SampleApparentSize()

		// Maximum usable payload bytes in this frame.
		maxPayload := apparentSize - protocol.FrameHeaderSize
		if maxPayload <= 0 {
			maxPayload = 1
		}
		if maxPayload > protocol.MaxPayloadSize {
			maxPayload = protocol.MaxPayloadSize
		}

		payloadLen := len(remaining)
		if payloadLen > maxPayload {
			payloadLen = maxPayload
		}

		payload := remaining[:payloadLen]
		remaining = remaining[payloadLen:]

		padLen := c.padding.SelectPadding(payloadLen)

		before := time.Now()
		err := c.fw.WriteFrame(protocol.Frame{
			Type:     protocol.TypeData,
			StreamID: 0,
			Payload:  payload,
			PadLen:   padLen,
		})
		elapsed := time.Since(before)
		c.pacer.ObserveWrite(elapsed, payloadLen+int(padLen)+protocol.FrameHeaderSize)

		if err != nil {
			return fmt.Errorf("bcl: write frame: %w", err)
		}

		c.lastActivityNs.Store(time.Now().UnixNano())

		// Inter-frame pacing: simulate ACK-clocked transmission gaps.
		// Only add delay when there are more frames to send.
		if len(remaining) > 0 {
			delay := c.pacer.InterFrameDelay()
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	return nil
}

// ── Keepalive goroutine ──────────────────────────────────────────────────────

// keepaliveLoop sends PING frames when the connection has been idle for the
// personality's KeepaliveIdle duration (+ uniform jitter), but only when in
// IDLE or THINK states — never during BURST or DRAIN.
//
// This exactly models Chrome HTTP/2 keepalive: the browser only sends PINGs
// when there are no active transfers, and the interval has a ±10-15s spread.
func (c *Conn) keepaliveLoop() {
	defer c.wg.Done()

	for {
		// Compute jittered keepalive interval.
		interval := c.p.KeepaliveIdle + uniformJitter(c.p.KeepaliveJitter)
		if interval < 10*time.Second {
			interval = 10 * time.Second
		}

		select {
		case <-c.ctx.Done():
			return
		case <-time.After(interval):
		}

		// Only send PING when actually idle (IDLE or THINK state).
		s := c.state
		if s == stateBurst || s == stateDrain || s == stateCongested {
			continue
		}

		// Verify idle time: connection might have become active since the timer fired.
		idleNs := time.Now().UnixNano() - c.lastActivityNs.Load()
		if idleNs < int64(c.p.KeepaliveIdle/2) {
			continue
		}

		if err := c.sendPing(); err != nil {
			c.log.Debug("bcl: keepalive ping failed", zap.Error(err))
			return
		}
	}
}

// ── Control frame helpers ────────────────────────────────────────────────────

func (c *Conn) sendPing() error {
	// Record send time for RTT measurement.
	c.pendingPingSent.Store(time.Now().UnixNano())

	// Payload is 8 random bytes (matching HTTP/2 PING frame opaque data).
	payload := randomBytes(8)
	return c.fw.WriteFrame(protocol.Frame{
		Type:     protocol.TypePing,
		StreamID: 0,
		Payload:  payload,
	})
}

func (c *Conn) writePong(payload []byte) {
	c.fw.WriteFrame(protocol.Frame{ //nolint:errcheck
		Type:     protocol.TypePong,
		StreamID: 0,
		Payload:  payload, // echo payload (HTTP/2 PING spec)
	})
}

func (c *Conn) processPong(frame protocol.Frame) {
	sentNs := c.pendingPingSent.Swap(0)
	if sentNs == 0 {
		return // unsolicited PONG
	}
	rtt := time.Duration(time.Now().UnixNano() - sentNs)
	c.pacer.ObserveWrite(rtt, 0)
	c.log.Debug("bcl: PING RTT measured", zap.Duration("rtt", rtt))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// coalesceBurst concatenates multiple byte slices into one.
func coalesceBurst(chunks [][]byte, totalLen int) []byte {
	if len(chunks) == 1 {
		return chunks[0]
	}
	out := make([]byte, 0, totalLen)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// randomBytes returns n cryptographically-random bytes for PING payloads.
// Uses math/rand here (not crypto/rand) because PING payloads don't require
// cryptographic strength — they just need to not be constant.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(n*i + 17)
	}
	return b
}
