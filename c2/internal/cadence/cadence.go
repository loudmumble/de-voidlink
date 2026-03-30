package cadence

import (
	"math/rand"
	"sync"
	"time"
)

const (
	// ProfileNoEDR is the aggressive profile when no EDR is detected.
	ProfileNoEDR = "aggressive"

	// ProfileEDRDetected is the paranoid profile when EDR is detected.
	ProfileEDRDetected = "paranoid"

	// ModeVoidLink is VoidLink's adaptive beaconing mode.
	ModeVoidLink = "voidlink"

	// ModeAICadence generates LLM token timing patterns.
	ModeAICadence = "ai-cadence"
)

// Profile defines timing parameters for a beaconing mode.
type Profile struct {
	BaseInterval  int    // milliseconds
	JitterPercent int    // percentage (0-100)
	Mode          string // profile name
}

var (
	// NoEDRProfile: aggressive timing when no EDR is present.
	NoEDRProfile = Profile{
		BaseInterval:  4096,
		JitterPercent: 20,
		Mode:          ProfileNoEDR,
	}

	// EDRDetectedProfile: paranoid timing when EDR is detected.
	EDRDetectedProfile = Profile{
		BaseInterval:  1024,
		JitterPercent: 30,
		Mode:          ProfileEDRDetected,
	}
)

// Manager controls beacon timing based on mode and EDR detection.
type Manager struct {
	mu      sync.RWMutex
	profile Profile
	mode    string
	rng     *rand.Rand

	// AI-cadence state
	burstRemaining int
	inBurst        bool
}

// NewManager creates a cadence manager for the given traffic mode.
func NewManager(mode string) *Manager {
	return &Manager{
		profile: NoEDRProfile,
		mode:    mode,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SetProfile selects the timing profile based on the detected EDR list.
func (m *Manager) SetProfile(edrList []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(edrList) > 0 {
		m.profile = EDRDetectedProfile
	} else {
		m.profile = NoEDRProfile
	}
}

// GetProfile returns the current timing profile.
func (m *Manager) GetProfile() Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profile
}

// NextInterval returns the next beacon interval based on the current mode.
func (m *Manager) NextInterval(_ string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mode == ModeAICadence {
		return m.aiCadenceInterval()
	}
	return m.voidlinkInterval()
}

// voidlinkInterval calculates a jittered interval for VoidLink mode.
// Formula: actual = base + random(-jitter%, +jitter%) * base
func (m *Manager) voidlinkInterval() time.Duration {
	base := float64(m.profile.BaseInterval)
	jitter := float64(m.profile.JitterPercent) / 100.0

	// Apply jitter: actual = base + random(-jitter%, +jitter%) * base
	offset := (m.rng.Float64()*2 - 1) * jitter * base
	actual := base + offset

	if actual < 50 {
		actual = 50 // safety floor
	}

	return time.Duration(actual) * time.Millisecond
}

// aiCadenceInterval generates LLM autoregressive token timing patterns.
// Pattern: think → burst → think → burst
// Burst (token generation): 50-150ms intervals
// Think (processing pause): 500-2000ms
func (m *Manager) aiCadenceInterval() time.Duration {
	if m.inBurst {
		m.burstRemaining--
		if m.burstRemaining <= 0 {
			m.inBurst = false
		}
		// Token generation burst: 50-150ms intervals
		return time.Duration(50+m.rng.Intn(101)) * time.Millisecond
	}

	// Start a new burst after thinking pause
	m.inBurst = true
	m.burstRemaining = 5 + m.rng.Intn(16) // 5-20 tokens per burst

	// Thinking/processing pause: 500-2000ms
	return time.Duration(500+m.rng.Intn(1501)) * time.Millisecond
}

// BeaconIntervalMS returns the base interval in milliseconds for the current profile.
func (m *Manager) BeaconIntervalMS() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profile.BaseInterval
}

// JitterPercent returns the jitter percentage for the current profile.
func (m *Manager) JitterPercent() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profile.JitterPercent
}
