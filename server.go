package rest

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phantom-security/ips-service/internal/config"
	"github.com/phantom-security/ips-service/internal/detector"
	"github.com/phantom-security/ips-service/internal/models"
	"github.com/phantom-security/ips-service/internal/storage"
	"github.com/sirupsen/logrus"
)

// Server handles REST API requests
type Server struct {
	config       *config.Config
	detector     *detector.IPDetector
	wafAnalyzer  *waf.RequestAnalyzer
	dbStore      *storage.DatabaseStore
	redisStore   *storage.RedisStore
	logger       *logrus.Logger
	router       *gin.Engine
}

// NewServer creates a new REST API server
func NewServer(
	cfg *config.Config,
	detector *detector.IPDetector,
	wafAnalyzer *waf.RequestAnalyzer,
	dbStore *storage.DatabaseStore,
	redisStore *storage.RedisStore,
	logger *logrus.Logger,
) *Server {
	// Set Gin mode based on log level
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(corsMiddleware())

	server := &Server{
		config:      cfg,
		detector:    detector,
		wafAnalyzer: wafAnalyzer,
		dbStore:     dbStore,
		redisStore:  redisStore,
		logger:      logger,
		router:      router,
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures API routes
func (s *Server) setupRoutes() {
	// Health check
	s.router.GET("/health", s.handleHealth)
	s.router.GET("/", s.handleRoot)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// WAF Analysis (NEW - Full protection)
		v1.POST("/analyze/full", s.handleAnalyzeFull)      // WAF + IPS
		v1.POST("/analyze/waf", s.handleAnalyzeWAF)        // WAF only
		v1.POST("/analyze/ips", s.handleAnalyzeIP)         // IPS only (backward compat)
		
		// CSRF Protection
		v1.POST("/csrf/token", s.handleGenerateCSRFToken)
		v1.POST("/csrf/verify", s.handleVerifyCSRFToken)
		
		// IP Analysis (Legacy endpoints, still supported)
		v1.POST("/analyze", s.handleAnalyzeIP)
		v1.GET("/reputation/:ip", s.handleGetReputation)
		
		// Blacklist/Whitelist Management
		v1.POST("/block/:ip", s.handleBlockIP)
		v1.DELETE("/block/:ip", s.handleUnblockIP)
		v1.POST("/whitelist/:ip", s.handleWhitelistIP)
		v1.DELETE("/whitelist/:ip", s.handleRemoveWhitelist)
		
		// Violations
		v1.POST("/violation", s.handleRecordViolation)
		v1.GET("/violations/:ip", s.handleGetViolations)
		
		// Statistics
		v1.GET("/stats", s.handleGetStats)
		v1.GET("/threats/top", s.handleGetTopThreats)
	}
}

// Start starts the REST API server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.RESTPort)
	s.logger.Infof("Starting REST API server on %s", addr)
	return s.router.Run(addr)
}

// handleRoot handles root endpoint
func (s *Server) handleRoot(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "Phantom IPS",
		"version": "1.0.0",
		"status":  "running",
	})
}

// handleHealth handles health check
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now().Unix(),
	})
}

// handleAnalyzeIP handles IP analysis requests
func (s *Server) handleAnalyzeIP(c *gin.Context) {
	var req models.IPAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.IPAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip_address is required"})
		return
	}

	// Analyze IP
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.detector.AnalyzeIP(ctx, req.IPAddress, req.Metadata)
	if err != nil {
		s.logger.Errorf("IP analysis failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "analysis failed"})
		return
	}

	// Get reputation details
	reputation, _ := s.detector.GetOrCreateReputation(ctx, req.IPAddress)

	response := models.IPAnalysisResponse{
		IPAddress:  req.IPAddress,
		Result:     *result,
		Reputation: *reputation,
		Timestamp:  time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// handleGetReputation handles reputation lookup
func (s *Server) handleGetReputation(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reputation, err := s.detector.GetOrCreateReputation(ctx, ip)
	if err != nil {
		s.logger.Errorf("Failed to get reputation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	c.JSON(http.StatusOK, reputation)
}

// handleBlockIP handles IP blocking
func (s *Server) handleBlockIP(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Add to blacklist
	duration := 24 * time.Hour // Default 24 hours
	if err := s.redisStore.AddToBlacklist(ctx, ip, duration); err != nil {
		s.logger.Errorf("Failed to block IP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "block failed"})
		return
	}

	// Update reputation
	reputation, _ := s.detector.GetOrCreateReputation(ctx, ip)
	reputation.IsBlacklisted = true
	reputation.ReputationScore = 100
	reputation.ThreatLevel = "critical"
	s.dbStore.CreateOrUpdateIPReputation(reputation)

	c.JSON(http.StatusOK, gin.H{
		"status":  "blocked",
		"ip":      ip,
		"expires": time.Now().Add(duration).Unix(),
	})
}

// handleUnblockIP handles IP unblocking
func (s *Server) handleUnblockIP(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Update reputation
	reputation, _ := s.detector.GetOrCreateReputation(ctx, ip)
	reputation.IsBlacklisted = false
	reputation.ReputationScore = 0
	reputation.ThreatLevel = "low"
	s.dbStore.CreateOrUpdateIPReputation(reputation)

	c.JSON(http.StatusOK, gin.H{
		"status": "unblocked",
		"ip":     ip,
	})
}

// handleWhitelistIP handles IP whitelisting
func (s *Server) handleWhitelistIP(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.redisStore.AddToWhitelist(ctx, ip); err != nil {
		s.logger.Errorf("Failed to whitelist IP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "whitelist failed"})
		return
	}

	// Update reputation
	reputation, _ := s.detector.GetOrCreateReputation(ctx, ip)
	reputation.IsWhitelisted = true
	s.dbStore.CreateOrUpdateIPReputation(reputation)

	c.JSON(http.StatusOK, gin.H{
		"status": "whitelisted",
		"ip":     ip,
	})
}

// handleRemoveWhitelist handles whitelist removal
func (s *Server) handleRemoveWhitelist(c *gin.Context) {
	ip := c.Param("ip")
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reputation, _ := s.detector.GetOrCreateReputation(ctx, ip)
	reputation.IsWhitelisted = false
	s.dbStore.CreateOrUpdateIPReputation(reputation)

	c.JSON(http.StatusOK, gin.H{"status": "removed", "ip": ip})
}

// handleRecordViolation handles violation recording
func (s *Server) handleRecordViolation(c *gin.Context) {
	var req struct {
		IPAddress     string `json:"ip_address"`
		ViolationType string `json:"violation_type"`
		Severity      int    `json:"severity"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.detector.RecordViolation(ctx, req.IPAddress, req.ViolationType, req.Severity); err != nil {
		s.logger.Errorf("Failed to record violation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "recording failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "recorded"})
}

// handleGetViolations handles violation retrieval
func (s *Server) handleGetViolations(c *gin.Context) {
	ip := c.Param("ip")
	since := time.Now().Add(-24 * time.Hour) // Last 24 hours

	violations, err := s.dbStore.GetViolations(ip, since)
	if err != nil {
		s.logger.Errorf("Failed to get violations: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ip":         ip,
		"violations": violations,
		"count":      len(violations),
	})
}

// handleGetStats handles statistics retrieval
func (s *Server) handleGetStats(c *gin.Context) {
	stats, err := s.dbStore.GetStatistics()
	if err != nil {
		s.logger.Errorf("Failed to get stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stats failed"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// handleGetTopThreats handles top threats retrieval
func (s *Server) handleGetTopThreats(c *gin.Context) {
	threats, err := s.dbStore.GetTopThreatIPs(10)
	if err != nil {
		s.logger.Errorf("Failed to get top threats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"threats": threats,
		"count":   len(threats),
	})
}

// corsMiddleware adds CORS headers
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}
