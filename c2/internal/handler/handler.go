package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"de-voidlink/c2/internal/cadence"
	"de-voidlink/c2/internal/camouflage"
	"de-voidlink/c2/internal/protocol"
	"de-voidlink/c2/internal/server"
)

// Known VoidLink User-Agent strings (from Sysdig TRT samples).
var knownUserAgents = map[string]bool{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36": true,
	"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0":                                true,
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                              true,
	"curl/8.4.0": true,
}

// --- Request/Response types matching VoidLink protocol ---

// HandshakeRequest is the client registration payload.
type HandshakeRequest struct {
	Hostname      string   `json:"hostname"`
	OS            string   `json:"os"`
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	UID           int      `json:"uid"`
	CloudProvider string   `json:"cloud_provider"`
	Container     bool     `json:"container"`
	EDRDetected   []string `json:"edr_detected"`
}

// HandshakeResponse is the server registration response (encrypted via VoidStream).
type HandshakeResponse struct {
	SessionID        string        `json:"session_id"`
	BeaconIntervalMS int           `json:"beacon_interval_ms"`
	JitterPct        int           `json:"jitter_pct"`
	Tasks            []interface{} `json:"tasks"`
}

// SyncRequest is the task synchronization payload from the client.
type SyncRequest struct {
	SessionID   string        `json:"session_id"`
	TaskResults []interface{} `json:"task_results"`
}

// SyncResponse returns pending tasks and updated timing.
type SyncResponse struct {
	Tasks            []interface{} `json:"tasks"`
	BeaconIntervalMS int           `json:"beacon_interval_ms"`
}

// HeartbeatResponse is the keep-alive response.
type HeartbeatResponse struct {
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

// CompileRequest is the SRC simulation payload.
type CompileRequest struct {
	KernelRelease string `json:"kernel_release"`
	HiddenPorts   []int  `json:"hidden_ports"`
	HasGCC        bool   `json:"has_gcc"`
}

// Handler implements all VoidLink C2 API endpoints.
type Handler struct {
	store      *server.SessionStore
	cadenceMgr *cadence.Manager
	verbose    bool
	mode       string
	shutdownFn func()
}

// New creates a handler with all required dependencies.
func New(store *server.SessionStore, cadenceMgr *cadence.Manager, verbose bool, mode string, shutdownFn func()) *Handler {
	return &Handler{
		store:      store,
		cadenceMgr: cadenceMgr,
		verbose:    verbose,
		mode:       mode,
		shutdownFn: shutdownFn,
	}
}

// RegisterRoutes binds all VoidLink endpoints to the mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v2/handshake", h.methodGuard("POST", h.handleHandshake))
	mux.HandleFunc("/api/v2/sync", h.methodGuard("POST", h.handleSync))
	mux.HandleFunc("/api/v2/heartbeat", h.methodGuard("GET", h.handleHeartbeat))
	mux.HandleFunc("/compile", h.methodGuard("POST", h.handleCompile))
	mux.HandleFunc("/stage1.bin", h.methodGuard("GET", h.handleStage1))
	mux.HandleFunc("/implant.bin", h.methodGuard("GET", h.handleImplant))
	mux.HandleFunc("/api/v2/kill", h.methodGuard("POST", h.handleKill))
}

// methodGuard rejects requests that don't match the expected HTTP method.
func (h *Handler) methodGuard(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// logEvent writes a structured JSON log line to stdout.
func (h *Handler) logEvent(fields map[string]interface{}) {
	fields["ts"] = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(fields)
	if err != nil {
		log.Printf("log marshal error: %v", err)
		return
	}
	fmt.Println(string(data))
}

// logVerbose logs additional detail when --verbose is enabled.
func (h *Handler) logVerbose(format string, args ...interface{}) {
	if h.verbose {
		log.Printf("[VERBOSE] "+format, args...)
	}
}

// maxBodySize limits request body reads to prevent memory exhaustion (1 MB).
const maxBodySize = 1 << 20

// handleHandshake implements POST /api/v2/handshake — client registration.
func (h *Handler) handleHandshake(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req HandshakeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Check User-Agent
	ua := r.Header.Get("User-Agent")
	h.logVerbose("handshake from %s, UA known: %v, UA: %s", r.RemoteAddr, knownUserAgents[ua], ua)

	// Set cadence profile based on EDR detection
	h.cadenceMgr.SetProfile(req.EDRDetected)
	profile := h.cadenceMgr.GetProfile()

	// Create session
	sess, err := h.store.Create(req.Hostname, req.OS, req.Kernel, req.Arch, profile.Mode)
	if err != nil {
		log.Printf("session creation error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := HandshakeResponse{
		SessionID:        sess.ID,
		BeaconIntervalMS: h.cadenceMgr.BeaconIntervalMS(),
		JitterPct:        h.cadenceMgr.JitterPercent(),
		Tasks:            []interface{}{},
	}

	respJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Encrypt with VoidStream protocol
	encrypted, err := protocol.Encrypt(respJSON)
	if err != nil {
		log.Printf("encryption error: %v", err)
		http.Error(w, "encryption error", http.StatusInternalServerError)
		return
	}

	// Apply HTTP camouflage
	mode := camouflage.NextMode()
	wrapped, contentType := camouflage.Wrap(encrypted, mode)

	h.logEvent(map[string]interface{}{
		"event":        "handshake",
		"session_id":   sess.ID,
		"remote_addr":  r.RemoteAddr,
		"edr_detected": req.EDRDetected,
		"profile":      profile.Mode,
		"user_agent":   ua,
	})

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(wrapped); err != nil {
		h.logVerbose("write error: %v", err)
	}
}

// handleSync implements POST /api/v2/sync — task synchronization.
func (h *Handler) handleSync(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req SyncRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if _, ok := h.store.Get(req.SessionID); !ok {
		http.Error(w, "unknown session", http.StatusUnauthorized)
		return
	}
	h.store.Touch(req.SessionID)

	resp := SyncResponse{
		Tasks:            []interface{}{},
		BeaconIntervalMS: h.cadenceMgr.BeaconIntervalMS(),
	}

	respJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	encrypted, err := protocol.Encrypt(respJSON)
	if err != nil {
		log.Printf("encryption error: %v", err)
		http.Error(w, "encryption error", http.StatusInternalServerError)
		return
	}

	mode := camouflage.NextMode()
	wrapped, contentType := camouflage.Wrap(encrypted, mode)

	resultsCount := 0
	if req.TaskResults != nil {
		resultsCount = len(req.TaskResults)
	}

	h.logEvent(map[string]interface{}{
		"event":            "sync",
		"session_id":       req.SessionID,
		"tasks_sent":       0,
		"results_received": resultsCount,
	})

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(wrapped); err != nil {
		h.logVerbose("write error: %v", err)
	}
}

// handleHeartbeat implements GET /api/v2/heartbeat — keep-alive.
func (h *Handler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}

	if !h.store.Touch(sessionID) {
		http.Error(w, "unknown session", http.StatusUnauthorized)
		return
	}

	resp := HeartbeatResponse{
		Status:    "ok",
		Timestamp: time.Now().Unix(),
	}

	interval := h.cadenceMgr.NextInterval(h.mode)

	h.logEvent(map[string]interface{}{
		"event":       "heartbeat",
		"session_id":  sessionID,
		"remote_addr": r.RemoteAddr,
		"interval_ms": interval.Milliseconds(),
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logVerbose("encode error: %v", err)
	}
}

// handleCompile implements POST /compile — SRC simulation.
func (h *Handler) handleCompile(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req CompileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	h.logEvent(map[string]interface{}{
		"event":          "compile",
		"kernel_release": req.KernelRelease,
		"hidden_ports":   req.HiddenPorts,
		"has_gcc":        req.HasGCC,
		"remote_addr":    r.RemoteAddr,
	})

	payload := CompilePayload(req.KernelRelease, req.HiddenPorts, req.HasGCC)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload); err != nil {
		h.logVerbose("write error: %v", err)
	}
}

// handleStage1 implements GET /stage1.bin — stage 1 dropper delivery.
func (h *Handler) handleStage1(w http.ResponseWriter, r *http.Request) {
	h.logEvent(map[string]interface{}{
		"event":       "stage1_download",
		"remote_addr": r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=stage1.bin")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(Stage1Bytes()); err != nil {
		h.logVerbose("write error: %v", err)
	}
}

// handleImplant implements GET /implant.bin — implant binary delivery.
func (h *Handler) handleImplant(w http.ResponseWriter, r *http.Request) {
	h.logEvent(map[string]interface{}{
		"event":       "implant_download",
		"remote_addr": r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=implant.bin")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(ImplantBytes()); err != nil {
		h.logVerbose("write error: %v", err)
	}
}

// handleKill implements POST /api/v2/kill — safety kill switch.
func (h *Handler) handleKill(w http.ResponseWriter, r *http.Request) {
	h.logEvent(map[string]interface{}{
		"event":       "kill_switch",
		"remote_addr": r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"shutting_down"}`)); err != nil {
		h.logVerbose("write error: %v", err)
	}

	// Initiate graceful shutdown after response is flushed
	go func() {
		time.Sleep(100 * time.Millisecond)
		h.shutdownFn()
	}()
}
