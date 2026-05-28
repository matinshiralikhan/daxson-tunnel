// Package telemetry provides session tracking, transport analytics, and
// anomaly detection for the Daxson management dashboard.
package telemetry

import (
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionRecord holds live state for one authenticated client session.
type SessionRecord struct {
	SessionID   string
	DeviceID    string
	DeviceLabel string
	RemoteAddr  string
	ISP         string // best-effort reverse-DNS hostname of remote IP
	Transport   string // TLS fingerprint persona, e.g. "chrome", "firefox"
	AuthMode    string // "hmac", "device", or "bootstrap"
	ConnectedAt time.Time
	LastSeenAt  time.Time

	BytesSent atomic.Int64
	BytesRecv atomic.Int64
	Streams   atomic.Int32

	mu     sync.Mutex
	closed bool
}

// Snapshot returns an immutable copy of the session for JSON serialisation.
func (s *SessionRecord) Snapshot() SessionSnapshot {
	return SessionSnapshot{
		SessionID:   s.SessionID,
		DeviceID:    s.DeviceID,
		DeviceLabel: s.DeviceLabel,
		RemoteAddr:  s.RemoteAddr,
		ISP:         s.ISP,
		Transport:   s.Transport,
		AuthMode:    s.AuthMode,
		ConnectedAt: s.ConnectedAt,
		LastSeenAt:  s.LastSeenAt,
		BytesSent:   s.BytesSent.Load(),
		BytesRecv:   s.BytesRecv.Load(),
		Streams:     int(s.Streams.Load()),
	}
}

// SessionSnapshot is a point-in-time view of a session.
type SessionSnapshot struct {
	SessionID   string    `json:"session_id"`
	DeviceID    string    `json:"device_id"`
	DeviceLabel string    `json:"device_label"`
	RemoteAddr  string    `json:"remote_addr"`
	ISP         string    `json:"isp"`
	Transport   string    `json:"transport"`
	AuthMode    string    `json:"auth_mode"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`
	Streams     int       `json:"streams"`
}

// ProbeEvent records a suspected active-probe attempt.
type ProbeEvent struct {
	Time       time.Time `json:"time"`
	RemoteAddr string    `json:"remote_addr"`
	Reason     string    `json:"reason"` // e.g. "unknown_version", "invalid_signature"
}

// TransportStat tracks success/failure by transport persona.
type TransportStat struct {
	Transport string `json:"transport"`
	Successes int64  `json:"successes"`
	Failures  int64  `json:"failures"`
}

// Collector aggregates all telemetry in a single thread-safe struct.
type Collector struct {
	mu sync.RWMutex

	sessions map[string]*SessionRecord // session ID → record
	probes   []ProbeEvent
	transport map[string]*transportCounter // transport → counters
}

type transportCounter struct {
	successes atomic.Int64
	failures  atomic.Int64
}

// New creates an empty Collector.
func New() *Collector {
	return &Collector{
		sessions:  make(map[string]*SessionRecord),
		transport: make(map[string]*transportCounter),
	}
}

// OpenSession registers a new live session and returns the mutable record.
func (c *Collector) OpenSession(sid [16]byte, deviceID, deviceLabel, remoteAddr, transport, authMode string) *SessionRecord {
	now := time.Now()
	rec := &SessionRecord{
		SessionID:   hex.EncodeToString(sid[:]),
		DeviceID:    deviceID,
		DeviceLabel: deviceLabel,
		RemoteAddr:  remoteAddr,
		Transport:   transport,
		AuthMode:    authMode,
		ConnectedAt: now,
		LastSeenAt:  now,
	}

	// Best-effort ISP resolution — non-blocking, best-effort.
	go func() {
		ip, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			ip = remoteAddr
		}
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			rec.mu.Lock()
			rec.ISP = names[0]
			rec.mu.Unlock()
		}
	}()

	c.mu.Lock()
	c.sessions[rec.SessionID] = rec
	c.recordTransportSuccess(transport)
	c.mu.Unlock()

	return rec
}

// CloseSession removes the session from active tracking.
func (c *Collector) CloseSession(sid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec, ok := c.sessions[sid]; ok {
		rec.mu.Lock()
		rec.closed = true
		rec.mu.Unlock()
	}
	delete(c.sessions, sid)
}

// RecordProbe records a suspected active-probe attempt.
func (c *Collector) RecordProbe(remoteAddr, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probes = append(c.probes, ProbeEvent{
		Time:       time.Now(),
		RemoteAddr: remoteAddr,
		Reason:     reason,
	})
	// Keep only the last 1000 probe events.
	if len(c.probes) > 1000 {
		c.probes = c.probes[len(c.probes)-1000:]
	}
}

// RecordTransportFailure records an auth failure against a transport.
func (c *Collector) RecordTransportFailure(transport string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tc := c.getOrCreateTransport(transport)
	tc.failures.Add(1)
}

func (c *Collector) recordTransportSuccess(transport string) {
	// Caller must hold c.mu.
	tc := c.getOrCreateTransport(transport)
	tc.successes.Add(1)
}

func (c *Collector) getOrCreateTransport(t string) *transportCounter {
	if t == "" {
		t = "unknown"
	}
	if tc, ok := c.transport[t]; ok {
		return tc
	}
	tc := &transportCounter{}
	c.transport[t] = tc
	return tc
}

// ── Snapshot methods (for dashboard API) ─────────────────────────────────────

// Sessions returns snapshots of all currently active sessions.
func (c *Collector) Sessions() []SessionSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]SessionSnapshot, 0, len(c.sessions))
	for _, s := range c.sessions {
		out = append(out, s.Snapshot())
	}
	return out
}

// SessionCount returns the number of active sessions.
func (c *Collector) SessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// RecentProbes returns up to n most recent probe events.
func (c *Collector) RecentProbes(n int) []ProbeEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.probes) == 0 {
		return nil
	}
	start := 0
	if len(c.probes) > n {
		start = len(c.probes) - n
	}
	out := make([]ProbeEvent, len(c.probes)-start)
	copy(out, c.probes[start:])
	return out
}

// TransportStats returns success/failure counters per transport.
func (c *Collector) TransportStats() []TransportStat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]TransportStat, 0, len(c.transport))
	for name, tc := range c.transport {
		out = append(out, TransportStat{
			Transport: name,
			Successes: tc.successes.Load(),
			Failures:  tc.failures.Load(),
		})
	}
	return out
}

// TotalBytes returns aggregate bytes sent and received across all sessions.
func (c *Collector) TotalBytes() (sent, recv int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.sessions {
		sent += s.BytesSent.Load()
		recv += s.BytesRecv.Load()
	}
	return
}
