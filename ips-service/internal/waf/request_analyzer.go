package waf

import (
	"context"
	"sync"
	"time"

	"github.com/phantom-security/ips-service/internal/config"
	"github.com/phantom-security/ips-service/internal/detector"
	"github.com/phantom-security/ips-service/internal/models"
)

// Request represents an incoming HTTP request
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Params  map[string]string `json:"params"`
	Body    string            `json:"body"`
	IP      string            `json:"ip"`
}

// WAFResult represents the analysis result
type WAFResult struct {
	Action          string            `json:"action"`           // allow, block, challenge
	ThreatScore     int               `json:"threat_score"`     // 0-100
	IsSuspicious    bool              `json:"is_suspicious"`
	IsBlocked       bool              `json:"is_blocked"`
	Threats         []string          `json:"threats"`
	ModuleResults   map[string]ModuleResult `json:"module_results"`
	ProcessingTime  float64           `json:"processing_time_ms"`
	FromCache       bool              `json:"from_cache"`
}

// ModuleResult represents result from a single detection module
type ModuleResult struct {
	IsThreat bool     `json:"is_threat"`
	Score    int      `json:"score"`
	Threats  []string `json:"threats"`
}

// RequestAnalyzer orchestrates all WAF detection modules
type RequestAnalyzer struct {
	// Detection modules
	sqliDetector     *SQLInjectionDetector
	xssDetector      *XSSDetector
	cmdiDetector     *CMDIDetector
	pathDetector     *PathTraversalDetector
	csrfDetector     *CSRFDetector
	rateLimiter      *RateLimiter
	botDetector      *BotDetector
	portFilter       *PortFilter
	ipDetector       *detector.IPDetector

	// Configuration
	config          *config.Config
	threshold       int
	concurrentModules bool
}

// NewRequestAnalyzer creates a new request analyzer
func NewRequestAnalyzer(
	cfg *config.Config,
	ipDetector *detector.IPDetector,
) *RequestAnalyzer {
	// Create all detection modules
	sqliDetector := NewSQLInjectionDetector("medium", 7)
	xssDetector := NewXSSDetector("medium", 7)
	cmdiDetector := NewCMDIDetector("high", 8)
	pathDetector := NewPathTraversalDetector("high", 8, 3)
	csrfDetector := NewCSRFDetector(32, 1*time.Hour)
	rateLimiter := NewRateLimiter(1000, 100, 60*time.Second, 60*time.Second)
	
	// Configure good bots
	goodBots := []string{"googlebot", "bingbot", "slackbot", "facebookexternalhit"}
	botDetector := NewBotDetector(goodBots)

	// Configure port filter
	allowedPorts := []int{80, 443, 8080, 8443}
	blockedPorts := []int{23, 445, 3389}
	suspiciousPorts := []int{22, 3306, 5432, 6379, 27017}
	portFilter := NewPortFilter(allowedPorts, blockedPorts, suspiciousPorts, 10, 60*time.Second)

	// Add per-route rate limits
	rateLimiter.AddRouteLimit("/api/login", 5, 5*time.Minute)
	rateLimiter.AddRouteLimit("/api/register", 3, 10*time.Minute)

	return &RequestAnalyzer{
		sqliDetector:     sqliDetector,
		xssDetector:      xssDetector,
		cmdiDetector:     cmdiDetector,
		pathDetector:     pathDetector,
		csrfDetector:     csrfDetector,
		rateLimiter:      rateLimiter,
		botDetector:      botDetector,
		portFilter:       portFilter,
		ipDetector:       ipDetector,
		config:          cfg,
		threshold:       70,
		concurrentModules: true,
	}
}

// Analyze performs full WAF analysis on a request
func (ra *RequestAnalyzer) Analyze(ctx context.Context, req *Request) *WAFResult {
	startTime := time.Now()

	result := &WAFResult{
		Action:        "allow",
		ThreatScore:   0,
		IsSuspicious:  false,
		IsBlocked:     false,
		Threats:       []string{},
		ModuleResults: make(map[string]ModuleResult),
		FromCache:     false,
	}

	if ra.concurrentModules {
		ra.analyzeConcurrent(ctx, req, result)
	} else {
		ra.analyzeSequential(ctx, req, result)
	}

	// Determine final action
	result.Action = ra.determineAction(result.ThreatScore)
	result.IsSuspicious = result.ThreatScore >= ra.threshold
	result.IsBlocked = result.Action == "block"

	result.ProcessingTime = time.Since(startTime).Seconds() * 1000
	return result
}

// analyzeConcurrent runs all detection modules in parallel
func (ra *RequestAnalyzer) analyzeConcurrent(ctx context.Context, req *Request, result *WAFResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// IP-based detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		ipsResult, err := ra.ipDetector.AnalyzeIP(ctx, req.IP, models.RequestMetadata{
			Method:    req.Method,
			Path:      req.Path,
			UserAgent: req.Headers["User-Agent"],
		})
		
		if err == nil {
			mu.Lock()
			result.ModuleResults["ips"] = ModuleResult{
				IsThreat: ipsResult.IsBlocked || ipsResult.IsSuspicious,
				Score:    ipsResult.ThreatScore,
				Threats:  ipsResult.Reasons,
			}
			result.ThreatScore += ipsResult.ThreatScore
			result.Threats = append(result.Threats, ipsResult.Reasons...)
			mu.Unlock()
		}
	}()

	// SQL Injection detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		isThreat, score, threats := ra.sqliDetector.DetectInRequest(req.Params, req.Headers, req.Body)
		
		mu.Lock()
		result.ModuleResults["sql_injection"] = ModuleResult{
			IsThreat: isThreat,
			Score:    score,
			Threats:  threats,
		}
		if isThreat {
			result.ThreatScore += score
			result.Threats = append(result.Threats, threats...)
		}
		mu.Unlock()
	}()

	// XSS detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		isThreat, score, threats := ra.xssDetector.DetectInRequest(req.Params, req.Headers, req.Body)
		
		mu.Lock()
		result.ModuleResults["xss"] = ModuleResult{
			IsThreat: isThreat,
			Score:    score,
			Threats:  threats,
		}
		if isThreat {
			result.ThreatScore += score
			result.Threats = append(result.Threats, threats...)
		}
		mu.Unlock()
	}()

	// Command Injection detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		isThreat, score, threats := ra.cmdiDetector.DetectInRequest(req.Params, req.Headers, req.Body)
		
		mu.Lock()
		result.ModuleResults["command_injection"] = ModuleResult{
			IsThreat: isThreat,
			Score:    score,
			Threats:  threats,
		}
		if isThreat {
			result.ThreatScore += score
			result.Threats = append(result.Threats, threats...)
		}
		mu.Unlock()
	}()

	// Path Traversal detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		isThreat, score, threats := ra.pathDetector.DetectInRequest(req.Params, req.Headers, req.Body, req.Path)
		
		mu.Lock()
		result.ModuleResults["path_traversal"] = ModuleResult{
			IsThreat: isThreat,
			Score:    score,
			Threats:  threats,
		}
		if isThreat {
			result.ThreatScore += score
			result.Threats = append(result.Threats, threats...)
		}
		mu.Unlock()
	}()

	// Rate Limiting
	wg.Add(1)
	go func() {
		defer wg.Done()
		isThreat, score, threats := ra.rateLimiter.Check(req.IP, req.Path)
		
		mu.Lock()
		result.ModuleResults["rate_limiter"] = ModuleResult{
			IsThreat: isThreat,
			Score:    score,
			Threats:  threats,
		}
		if isThreat {
			result.ThreatScore += score
			result.Threats = append(result.Threats, threats...)
		}
		mu.Unlock()
	}()

	// Bot Detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		isThreat, score, threats, botType := ra.botDetector.Detect(req.Headers["User-Agent"], req.Headers)
		
		mu.Lock()
		result.ModuleResults["bot_detector"] = ModuleResult{
			IsThreat: isThreat,
			Score:    score,
			Threats:  append(threats, "bot_type:"+botType),
		}
		if isThreat && botType == "malicious" {
			result.ThreatScore += score
			result.Threats = append(result.Threats, threats...)
		}
		mu.Unlock()
	}()

	// Wait for all modules to complete
	wg.Wait()
}

// analyzeSequential runs detection modules one by one
func (ra *RequestAnalyzer) analyzeSequential(ctx context.Context, req *Request, result *WAFResult) {
	// Run IPS first (can early-terminate if IP is blacklisted)
	ipsResult, _ := ra.ipDetector.AnalyzeIP(ctx, req.IP, models.RequestMetadata{
		Method:    req.Method,
		Path:      req.Path,
		UserAgent: req.Headers["User-Agent"],
	})
	
	if ipsResult != nil {
		result.ModuleResults["ips"] = ModuleResult{
			IsThreat: ipsResult.IsBlocked,
			Score:    ipsResult.ThreatScore,
			Threats:  ipsResult.Reasons,
		}
		result.ThreatScore += ipsResult.ThreatScore
		result.Threats = append(result.Threats, ipsResult.Reasons...)
		
		// Early termination if IP is blacklisted
		if ipsResult.IsBlocked {
			return
		}
	}

	// Continue with other modules...
	// (Similar to concurrent version but sequential)
}

// determineAction determines the action based on threat score
func (ra *RequestAnalyzer) determineAction(threatScore int) string {
	if threatScore >= 90 {
		return "block"
	} else if threatScore >= 70 {
		return "challenge"
	}
	return "allow"
}

//GenerateCSRFToken generates a CSRF token
func (ra *RequestAnalyzer) GenerateCSRFToken(sessionID string) string {
	return ra.csrfDetector.GenerateToken(sessionID)
}

// ValidateCSRFToken validates a CSRF token
func (ra *RequestAnalyzer) ValidateCSRFToken(token, sessionID string) bool {
	return ra.csrfDetector.ValidateToken(token, sessionID)
}
