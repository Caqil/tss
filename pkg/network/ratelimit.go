// Package network - Rate limiting and DoS protection
package network

import (
	"sync"
	"time"
)

// rateLimiter implements token bucket rate limiting
type rateLimiter struct {
	rate       int       // messages per second
	burst      int       // maximum burst size
	tokens     int       // current tokens
	lastUpdate time.Time // last token update
	mu         sync.Mutex
}

// newRateLimiter creates a new rate limiter
func newRateLimiter(messagesPerSecond int) *rateLimiter {
	return &rateLimiter{
		rate:       messagesPerSecond,
		burst:      messagesPerSecond * 2, // Allow 2x burst
		tokens:     messagesPerSecond * 2,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a message is allowed under rate limit
func (rl *rateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate)

	// Refill tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds() * float64(rl.rate))
	rl.tokens += tokensToAdd
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}

	rl.lastUpdate = now

	// Check if we have tokens available
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// SetRate updates the rate limit
func (rl *rateLimiter) SetRate(messagesPerSecond int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.rate = messagesPerSecond
	rl.burst = messagesPerSecond * 2
}

// Reset resets the rate limiter
func (rl *rateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.tokens = rl.burst
	rl.lastUpdate = time.Now()
}

// RateLimitManager manages rate limiters for multiple peers
type RateLimitManager struct {
	limiters map[int]*rateLimiter
	mu       sync.RWMutex
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager() *RateLimitManager {
	return &RateLimitManager{
		limiters: make(map[int]*rateLimiter),
	}
}

// SetLimit sets the rate limit for a specific party
func (rlm *RateLimitManager) SetLimit(partyID, messagesPerSecond int) {
	rlm.mu.Lock()
	defer rlm.mu.Unlock()

	if limiter, exists := rlm.limiters[partyID]; exists {
		limiter.SetRate(messagesPerSecond)
	} else {
		rlm.limiters[partyID] = newRateLimiter(messagesPerSecond)
	}
}

// CheckLimit checks if a message from a party is allowed
func (rlm *RateLimitManager) CheckLimit(partyID int) bool {
	rlm.mu.RLock()
	limiter, exists := rlm.limiters[partyID]
	rlm.mu.RUnlock()

	if !exists {
		return true // No limit set
	}

	return limiter.Allow()
}

// ResetLimit resets the rate limiter for a party
func (rlm *RateLimitManager) ResetLimit(partyID int) {
	rlm.mu.RLock()
	limiter, exists := rlm.limiters[partyID]
	rlm.mu.RUnlock()

	if exists {
		limiter.Reset()
	}
}

// RemoveLimit removes the rate limit for a party
func (rlm *RateLimitManager) RemoveLimit(partyID int) {
	rlm.mu.Lock()
	defer rlm.mu.Unlock()

	delete(rlm.limiters, partyID)
}

// GetStats returns rate limiting statistics
func (rlm *RateLimitManager) GetStats() map[int]*RateLimitStats {
	rlm.mu.RLock()
	defer rlm.mu.RUnlock()

	stats := make(map[int]*RateLimitStats)

	for partyID, limiter := range rlm.limiters {
		limiter.mu.Lock()
		stats[partyID] = &RateLimitStats{
			PartyID:         partyID,
			Rate:            limiter.rate,
			Burst:           limiter.burst,
			AvailableTokens: limiter.tokens,
			LastUpdate:      limiter.lastUpdate,
		}
		limiter.mu.Unlock()
	}

	return stats
}

// RateLimitStats contains rate limiting statistics
type RateLimitStats struct {
	PartyID         int
	Rate            int
	Burst           int
	AvailableTokens int
	LastUpdate      time.Time
}

// AdaptiveRateLimiter implements adaptive rate limiting based on network conditions
type AdaptiveRateLimiter struct {
	baseRate       int
	currentRate    int
	maxRate        int
	minRate        int
	increaseStep   int
	decreaseStep   int
	errorThreshold int
	successCount   int
	errorCount     int
	mu             sync.Mutex
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(baseRate, minRate, maxRate int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseRate:       baseRate,
		currentRate:    baseRate,
		maxRate:        maxRate,
		minRate:        minRate,
		increaseStep:   baseRate / 10, // Increase by 10%
		decreaseStep:   baseRate / 5,  // Decrease by 20%
		errorThreshold: 10,
	}
}

// RecordSuccess records a successful message
func (arl *AdaptiveRateLimiter) RecordSuccess() {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	arl.successCount++
	arl.errorCount = 0

	// Increase rate after consistent successes
	if arl.successCount >= 100 && arl.currentRate < arl.maxRate {
		arl.currentRate += arl.increaseStep
		if arl.currentRate > arl.maxRate {
			arl.currentRate = arl.maxRate
		}
		arl.successCount = 0
	}
}

// RecordError records a failed message
func (arl *AdaptiveRateLimiter) RecordError() {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	arl.errorCount++
	arl.successCount = 0

	// Decrease rate after errors
	if arl.errorCount >= arl.errorThreshold && arl.currentRate > arl.minRate {
		arl.currentRate -= arl.decreaseStep
		if arl.currentRate < arl.minRate {
			arl.currentRate = arl.minRate
		}
		arl.errorCount = 0
	}
}

// CurrentRate returns the current rate
func (arl *AdaptiveRateLimiter) CurrentRate() int {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	return arl.currentRate
}

// ConnectionThrottler prevents connection flooding
type ConnectionThrottler struct {
	connections map[string]*connectionAttempt
	maxAttempts int
	window      time.Duration
	mu          sync.RWMutex
}

type connectionAttempt struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// NewConnectionThrottler creates a new connection throttler
func NewConnectionThrottler(maxAttempts int, window time.Duration) *ConnectionThrottler {
	return &ConnectionThrottler{
		connections: make(map[string]*connectionAttempt),
		maxAttempts: maxAttempts,
		window:      window,
	}
}

// AllowConnection checks if a connection from an address is allowed
func (ct *ConnectionThrottler) AllowConnection(addr string) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()

	attempt, exists := ct.connections[addr]
	if !exists {
		ct.connections[addr] = &connectionAttempt{
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		return true
	}

	// Reset if window expired
	if now.Sub(attempt.firstSeen) > ct.window {
		attempt.count = 1
		attempt.firstSeen = now
		attempt.lastSeen = now
		return true
	}

	// Check if limit exceeded
	if attempt.count >= ct.maxAttempts {
		attempt.lastSeen = now
		return false
	}

	attempt.count++
	attempt.lastSeen = now
	return true
}

// Cleanup removes old connection attempts
func (ct *ConnectionThrottler) Cleanup() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()

	for addr, attempt := range ct.connections {
		if now.Sub(attempt.lastSeen) > ct.window*2 {
			delete(ct.connections, addr)
		}
	}
}
