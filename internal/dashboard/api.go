package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/daxson/tunnel/internal/registry"
	"github.com/daxson/tunnel/internal/telemetry"
	"github.com/daxson/tunnel/pkg/identity"
	"github.com/daxson/tunnel/pkg/invite"
)

type api struct {
	reg       *registry.Registry
	collector *telemetry.Collector
	serverKey *identity.KeyPair
	version   string
}

func newAPI(reg *registry.Registry, collector *telemetry.Collector, serverKey *identity.KeyPair, version string) *api {
	return &api{reg: reg, collector: collector, serverKey: serverKey, version: version}
}

func (a *api) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/status", a.handleStatus)
	mux.HandleFunc("/api/v1/sessions", a.handleSessions)
	mux.HandleFunc("/api/v1/devices", a.handleDevices)
	mux.HandleFunc("/api/v1/invites", a.handleInvites)
	mux.HandleFunc("/api/v1/transport-stats", a.handleTransportStats)
	mux.HandleFunc("/api/v1/probes", a.handleProbes)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

// GET /api/v1/status
func (a *api) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	type statusResp struct {
		Version  string `json:"version"`
		Sessions int    `json:"sessions"`
		Devices  int    `json:"devices"`
		ServerID string `json:"server_id"`
	}
	resp := statusResp{
		Version:  a.version,
		Sessions: a.collector.SessionCount(),
		Devices:  a.reg.DeviceCount(),
	}
	if a.serverKey != nil {
		resp.ServerID = a.serverKey.Fingerprint()
	}
	writeJSON(w, resp)
}

// GET /api/v1/sessions
func (a *api) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, a.collector.Sessions())
}

// GET|DELETE /api/v1/devices[/{id}]
func (a *api) handleDevices(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/devices")
	path = strings.Trim(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		writeJSON(w, a.reg.ListDevices())

	case r.Method == http.MethodDelete && path != "":
		if err := a.reg.RevokeDevice(path); err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "revoked"})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// GET|POST|DELETE /api/v1/invites[/{id}]
func (a *api) handleInvites(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/invites")
	path = strings.Trim(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		writeJSON(w, a.reg.ListInvites())

	case r.Method == http.MethodPost && path == "":
		a.createInvite(w, r)

	case r.Method == http.MethodDelete && path != "":
		if err := a.reg.RevokeInvite(path); err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, map[string]string{"status": "revoked"})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *api) createInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label       string `json:"label"`
		MaxUses     int    `json:"max_uses"`
		ExpiresHours int   `json:"expires_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Label == "" {
		body.Label = "invite"
	}
	if body.ExpiresHours <= 0 {
		body.ExpiresHours = 24
	}
	if body.MaxUses <= 0 {
		body.MaxUses = 1
	}

	ttl := time.Duration(body.ExpiresHours) * time.Hour
	rec, err := a.reg.CreateInvite(body.Label, body.MaxUses, ttl)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build the invite link if we have a server key and address.
	var link string
	if a.serverKey != nil {
		payload := &invite.Payload{
			Version:   1,
			Token:     rec.Token,
			Label:     rec.Label,
			MaxUses:   rec.MaxUses,
			ExpiresAt: rec.ExpiresAt,
			ServerKey: a.serverKey.PublicKey,
		}
		payload.Sign(a.serverKey.PrivateKey) //nolint:errcheck
		link = invite.Encode(payload)
	}

	type createResp struct {
		TokenID string `json:"token_id"`
		Label   string `json:"label"`
		Link    string `json:"link,omitempty"`
	}
	writeJSON(w, createResp{TokenID: rec.TokenID, Label: rec.Label, Link: link})
}

// GET /api/v1/transport-stats
func (a *api) handleTransportStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, a.collector.TransportStats())
}

// GET /api/v1/probes
func (a *api) handleProbes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, a.collector.RecentProbes(200))
}
