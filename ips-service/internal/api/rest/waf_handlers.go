package rest

// Add new handlers for WAF analysis

import (
	"github.com/phantom-security/ips-service/internal/waf"
)

// handleAnalyzeFull handles full WAF + IPS analysis
func (s *Server) handleAnalyzeFull(c *gin.Context) {
	var req waf.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Validate required fields
	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	// Analyze with full WAF
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := s.wafAnalyzer.Analyze(ctx, &req)

	c.JSON(http.StatusOK, result)
}

// handleAnalyzeWAF handles WAF-only analysis (no IPS)
func (s *Server) handleAnalyzeWAF(c *gin.Context) {
	var req waf.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := s.wafAnalyzer.Analyze(ctx, &req)

	// Return only WAF-related results
	c.JSON(http.StatusOK, result)
}

// handleGenerateCSRFToken generates a CSRF token
func (s *Server) handleGenerateCSRFToken(c *gin.Context) {
	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil || req.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}

	token := s.wafAnalyzer.GenerateCSRFToken(req.SessionID)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"expires_in": 3600, // 1 hour
	})
}

// handleVerifyCSRFToken verifies a CSRF token
func (s *Server) handleVerifyCSRFToken(c *gin.Context) {
	var req struct {
		Token     string `json:"token"`
		SessionID string `json:"session_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	valid := s.wafAnalyzer.ValidateCSRFToken(req.Token, req.SessionID)

	c.JSON(http.StatusOK, gin.H{
		"valid": valid,
	})
}
