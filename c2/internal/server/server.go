package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Session represents an active C2 client session.
type Session struct {
	ID             string
	Hostname       string
	OS             string
	Kernel         string
	Arch           string
	Profile        string
	ConnectedAt    time.Time
	LastSeen       time.Time
	HeartbeatCount int64
}

// SessionStore provides thread-safe in-memory session management.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create registers a new session and returns it.
func (s *SessionStore) Create(hostname, osName, kernel, arch, profile string) (*Session, error) {
	id, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}
	now := time.Now().UTC()
	sess := &Session{
		ID:          id,
		Hostname:    hostname,
		OS:          osName,
		Kernel:      kernel,
		Arch:        arch,
		Profile:     profile,
		ConnectedAt: now,
		LastSeen:    now,
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get retrieves a session by ID. Returns nil, false if not found.
func (s *SessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	return sess, ok
}

// Touch updates LastSeen and increments HeartbeatCount for the session.
// Returns false if the session doesn't exist.
func (s *SessionStore) Touch(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if ok {
		sess.LastSeen = time.Now().UTC()
		sess.HeartbeatCount++
	}
	return ok
}

// CleanStale removes sessions that haven't been seen within maxAge.
// Returns the number of sessions removed.
func (s *SessionStore) CleanStale(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	count := 0
	for id, sess := range s.sessions {
		if now.Sub(sess.LastSeen) > maxAge {
			delete(s.sessions, id)
			count++
		}
	}
	return count
}

// Count returns the number of active sessions.
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// generateUUID creates a UUIDv4-like string using crypto/rand.
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	// Set version 4 bits
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits (RFC 4122)
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Config holds server configuration from CLI flags.
type Config struct {
	Bind       string
	MaxRuntime int
	Verbose    bool
	TLS        bool
}

// Server wraps the HTTP server with lifecycle management.
type Server struct {
	httpServer *http.Server
	store      *SessionStore
	config     Config
	shutdown   chan struct{}
	once       sync.Once
}

// New creates a server with the given configuration and handler.
func New(cfg Config, handler http.Handler, store *SessionStore) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Bind,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		store:    store,
		config:   cfg,
		shutdown: make(chan struct{}),
	}
}

// Start begins listening and serving. Blocks until shutdown.
func (s *Server) Start() error {
	// Validate bind address is localhost
	host, _, err := net.SplitHostPort(s.config.Bind)
	if err != nil {
		return fmt.Errorf("invalid bind address: %w", err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		log.Printf("WARNING: binding to non-localhost address %s", host)
	}

	log.Println("SAFETY: de-voidlink C2 server — adversary simulation only")
	log.Printf("Listening on %s", s.config.Bind)

	// Start stale session cleanup goroutine
	go s.cleanupLoop()

	// Start max-runtime auto-shutdown timer
	if s.config.MaxRuntime > 0 {
		go func() {
			timer := time.NewTimer(time.Duration(s.config.MaxRuntime) * time.Second)
			select {
			case <-timer.C:
				log.Printf("Max runtime (%ds) reached, shutting down", s.config.MaxRuntime)
				s.Shutdown()
			case <-s.shutdown:
				timer.Stop()
			}
		}()
	}

	err = s.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown initiates graceful server shutdown.
func (s *Server) Shutdown() {
	s.once.Do(func() {
		close(s.shutdown)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	})
}

// cleanupLoop periodically removes stale sessions (not seen in 5 minutes).
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleaned := s.store.CleanStale(5 * time.Minute)
			if cleaned > 0 {
				log.Printf("Cleaned %d stale session(s), %d active", cleaned, s.store.Count())
			}
		case <-s.shutdown:
			return
		}
	}
}
