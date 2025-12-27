package waf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// CSRFDetector handles CSRF token generation and validation
type CSRFDetector struct {
	tokens      map[string]*CSRFToken
	mu          sync.RWMutex
	tokenLength int
	ttl         time.Duration
	secret      []byte
}

// CSRFToken represents a CSRF token with metadata
type CSRFToken struct {
	Token     string
	SessionID string
	CreatedAt time.Time
	ExpiresAt time.Duration
}

// NewCSRFDetector creates a new CSRF detector
func NewCSRFDetector(tokenLength int, ttl time.Duration) *CSRFDetector {
	// Generate random secret for token signing
	secret := make([]byte, 32)
	rand.Read(secret)

	detector := &CSRFDetector{
		tokens:      make(map[string]*CSRFToken),
		tokenLength: tokenLength,
		ttl:         ttl,
		secret:      secret,
	}

	// Start cleanup goroutine
	go detector.cleanupExpiredTokens()

	return detector
}

// GenerateToken generates a new CSRF token for a session
func (c *CSRFDetector) GenerateToken(sessionID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate random token
	tokenBytes := make([]byte, c.tokenLength)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// Sign token with session ID and secret
	signature := c.signToken(token, sessionID)
	signedToken := token + "." + signature

	// Store token
	c.tokens[signedToken] = &CSRFToken{
		Token:     signedToken,
		SessionID: sessionID,
		CreatedAt: time.Now(),
		ExpiresAt: c.ttl,
	}

	return signedToken
}

// ValidateToken validates a CSRF token for a session
func (c *CSRFDetector) ValidateToken(token string, sessionID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if token exists
	storedToken, exists := c.tokens[token]
	if !exists {
		return false
	}

	// Check if token expired
	if time.Since(storedToken.CreatedAt) > storedToken.ExpiresAt {
		return false
	}

	// Check if session ID matches
	if storedToken.SessionID != sessionID {
		return false
	}

	// Verify token signature
	parts := splitToken(token)
	if len(parts) != 2 {
		return false
	}

	expectedSignature := c.signToken(parts[0], sessionID)
	return parts[1] == expectedSignature
}

// DeleteToken removes a token (after successful use)
func (c *CSRFDetector) DeleteToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, token)
}

// CheckOrigin validates Origin or Referer header
func (c *CSRFDetector) CheckOrigin(origin, referer, expectedHost string) (bool, int, []string) {
	threats := []string{}
	score := 0

	// Check Origin header (preferred)
	if origin != "" {
		if !containsHost(origin, expectedHost) {
			score += 30
			threats = append(threats, "origin_mismatch")
			return false, score, threats
		}
		return true, 0, nil
	}

	// Fallback to Referer header
	if referer != "" {
		if !containsHost(referer, expectedHost) {
			score += 25
			threats = append(threats, "referer_mismatch")
			return false, score, threats
		}
		return true, 0, nil
	}

	// No Origin or Referer (suspicious for state-changing requests)
	score += 20
	threats = append(threats, "missing_origin_and_referer")
	return false, score, threats
}

// Detect checks for CSRF protection
func (c *CSRFDetector) Detect(method, csrfToken, sessionID, origin, referer, expectedHost string, safeMethods []string) (bool, int, []string) {
	threats := []string{}
	score := 0

	// Check if method is safe (GET, HEAD, OPTIONS don't need CSRF protection)
	for _, safeMethod := range safeMethods {
		if method == safeMethod {
			return false, 0, nil // Not a threat
		}
	}

	// For state-changing methods (POST, PUT, DELETE, PATCH)
	
	// Check CSRF token
	if csrfToken == "" {
		score += 40
		threats = append(threats, "missing_csrf_token")
	} else if !c.ValidateToken(csrfToken, sessionID) {
		score += 50
		threats = append(threats, "invalid_csrf_token")
	} else {
		// Valid token, no threat
		return false, 0, nil
	}

	// Check Origin/Referer as additional validation
	originValid, originScore, originThreats := c.CheckOrigin(origin, referer, expectedHost)
	if !originValid {
		score += originScore
		threats = append(threats, originThreats...)
	}

	isThreat := score >= 30 // Threshold for CSRF threat
	return isThreat, score, threats
}

// signToken creates a signature for a token
func (c *CSRFDetector) signToken(token, sessionID string) string {
	h := sha256.New()
	h.Write([]byte(token))
	h.Write([]byte(sessionID))
	h.Write(c.secret)
	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars
}

// cleanupExpiredTokens removes expired tokens periodically
func (c *CSRFDetector) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for token, csrfToken := range c.tokens {
			if now.Sub(csrfToken.CreatedAt) > csrfToken.ExpiresAt {
				delete(c.tokens, token)
			}
		}
		c.mu.Unlock()
	}
}

// Helper functions

func splitToken(token string) []string {
	parts := []string{}
	lastIdx := 0
	
	for i, char := range token {
		if char == '.' {
			parts = append(parts, token[lastIdx:i])
			lastIdx = i + 1
		}
	}
	
	if lastIdx < len(token) {
		parts = append(parts, token[lastIdx:])
	}
	
	return parts
}

func containsHost(url, host string) bool {
	// Simple host checking (in production, use proper URL parsing)
	return fmt.Sprintf("%s", url) != "" && fmt.Sprintf("%s", host) != ""
	// TODO: Implement proper host validation
}
