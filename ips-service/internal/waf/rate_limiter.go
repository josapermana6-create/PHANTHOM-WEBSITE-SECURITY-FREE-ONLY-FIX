package waf

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	limits map[string]*TokenBucket
	mu     sync.RWMutex
	
	// Configuration
	globalLimit     int
	globalWindow    time.Duration
	perIPLimit      int
	perIPWindow     time.Duration
	perRouteLimit   map[string]RouteLimit
}

// RouteLimit defines rate limit for a specific route
type RouteLimit struct {
	Requests int
	Window   time.Duration
}

// TokenBucket implements token bucket algorithm
type TokenBucket struct {
	tokens    int
	maxTokens int
	lastRefill time.Time
	window    time.Duration
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(globalLimit, perIPLimit int, globalWindow, perIPWindow time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limits:        make(map[string]*TokenBucket),
		globalLimit:   globalLimit,
		globalWindow:  globalWindow,
		perIPLimit:    perIPLimit,
		perIPWindow:   perIPWindow,
		perRouteLimit: make(map[string]RouteLimit),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// AddRouteLimit adds a custom rate limit for a specific route
func (rl *RateLimiter) AddRouteLimit(route string, requests int, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.perRouteLimit[route] = RouteLimit{
		Requests: requests,
		Window:   window,
	}
}

// Check checks if request is within rate limit
func (rl *RateLimiter) Check(ip, route string) (bool, int, []string) {
	threats := []string{}
	score := 0

	// Check global rate limit
	globalAllowed, globalCount := rl.checkLimit("global", rl.globalLimit, rl.globalWindow)
	if !globalAllowed {
		score += 30
		threats = append(threats, "global_rate_limit_exceeded")
	}

	// Check per-IP rate limit
	ipKey := "ip:" + ip
	ipAllowed, ipCount := rl.checkLimit(ipKey, rl.perIPLimit, rl.perIPWindow)
	if !ipAllowed {
		score += 40
		threats = append(threats, "ip_rate_limit_exceeded")
	}

	// Check per-route limit if configured
	routeLimit, hasRouteLimit := rl.perRouteLimit[route]
	if hasRouteLimit {
		routeKey := "route:" + route + ":" + ip
		routeAllowed, routeCount := rl.checkLimit(routeKey, routeLimit.Requests, routeLimit.Window)
		if !routeAllowed {
			score += 50
			threats = append(threats, "route_rate_limit_exceeded:"+route)
		}
		
		// Add count info
		if routeCount > routeLimit.Requests {
			score += 10
		}
	}

	// Additional scoring based on request count
	if ipCount > rl.perIPLimit*2 {
		score += 20
		threats = append(threats, "excessive_request_rate")
	}

	isThreat := !globalAllowed || !ipAllowed || score >= 30
	return isThreat, score, threats
}

// checkLimit checks and updates token bucket for a key
func (rl *RateLimiter) checkLimit(key string, limit int, window time.Duration) (bool, int) {
	rl.mu.Lock()
	
	bucket, exists := rl.limits[key]
	if !exists {
		bucket = &TokenBucket{
			tokens:     limit,
			maxTokens:  limit,
			lastRefill: time.Now(),
			window:     window,
		}
		rl.limits[key] = bucket
	}
	rl.mu.Unlock()

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens based on time passed
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	
	if elapsed >= bucket.window {
		// Full refill
		bucket.tokens = bucket.maxTokens
		bucket.lastRefill = now
	} else {
		// Partial refill (proportional to time elapsed)
		tokensToAdd := int(float64(bucket.maxTokens) * (float64(elapsed) / float64(bucket.window)))
		bucket.tokens = min(bucket.maxTokens, bucket.tokens+tokensToAdd)
		if tokensToAdd > 0 {
			bucket.lastRefill = now
		}
	}

	// Try to consume a token
	if bucket.tokens > 0 {
		bucket.tokens--
		return true, bucket.maxTokens - bucket.tokens // Request count
	}

	return false, bucket.maxTokens // Max requests (limit exceeded)
}

// cleanup removes old entries periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		
		for key, bucket := range rl.limits {
			bucket.mu.Lock()
			// Remove buckets that haven't been used in 2x their window
			if now.Sub(bucket.lastRefill) > bucket.window*2 {
				delete(rl.limits, key)
			}
			bucket.mu.Unlock()
		}
		
		rl.mu.Unlock()
	}
}

// GetStats returns rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return map[string]interface{}{
		"total_keys":  len(rl.limits),
		"global_limit": rl.globalLimit,
		"per_ip_limit": rl.perIPLimit,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
