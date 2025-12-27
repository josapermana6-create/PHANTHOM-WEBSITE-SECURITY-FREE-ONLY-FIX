package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/phantom-security/ips-service/internal/config"
	"github.com/phantom-security/ips-service/internal/intelligence"
	"github.com/phantom-security/ips-service/internal/models"
	"github.com/phantom-security/ips-service/internal/storage"
	"github.com/sirupsen/logrus"
)

// IPDetector handles IP threat detection
type IPDetector struct {
	config         *config.Config
	dbStore        *storage.DatabaseStore
	redisStore     *storage.RedisStore
	threatIntel    *intelligence.ThreatIntelligence
	anomalyDetector *AnomalyDetector
	logger         *logrus.Logger
}

// NewIPDetector creates a new IP detector
func NewIPDetector(
	cfg *config.Config,
	dbStore *storage.DatabaseStore,
	redisStore *storage.RedisStore,
	threatIntel *intelligence.ThreatIntelligence,
	logger *logrus.Logger,
) *IPDetector {
	return &IPDetector{
		config:          cfg,
		dbStore:         dbStore,
		redisStore:      redisStore,
		threatIntel:     threatIntel,
		anomalyDetector: NewAnomalyDetector(cfg, redisStore),
		logger:          logger,
	}
}

// AnalyzeIP performs comprehensive IP threat analysis
func (d *IPDetector) AnalyzeIP(ctx context.Context, ip string, metadata models.RequestMetadata) (*models.ThreatResult, error) {
	startTime := time.Now()

	// Initialize result
	result := &models.ThreatResult{
		IsBlocked:       false,
		IsSuspicious:    false,
		ThreatScore:     0,
		ReputationScore: 0,
		Reasons:         []string{},
		Action:          "allow",
		ThreatLevel:     "low",
		FromCache:       false,
	}

	// Validate IP address
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check whitelist first
	isWhitelisted, err := d.IsWhitelisted(ctx, ip)
	if err != nil {
		d.logger.Warnf("Whitelist check failed for %s: %v", ip, err)
	}
	if isWhitelisted {
		result.Reasons = append(result.Reasons, "whitelisted")
		result.ProcessingTime = time.Since(startTime).Seconds() * 1000
		return result, nil
	}

	// Check blacklist
	isBlacklisted, err := d.IsBlacklisted(ctx, ip)
	if err != nil {
		d.logger.Warnf("Blacklist check failed for %s: %v", ip, err)
	}
	if isBlacklisted {
		result.IsBlocked = true
		result.IsSuspicious = true
		result.ThreatScore = 100
		result.ReputationScore = 100
		result.Reasons = append(result.Reasons, "blacklisted")
		result.Action = "block"
		result.ThreatLevel = "critical"
		result.ProcessingTime = time.Since(startTime).Seconds() * 1000
		return result, nil
	}

	// Check cache
	cachedRep, err := d.redisStore.GetIPReputation(ctx, ip)
	if err == nil && cachedRep != nil {
		result.ReputationScore = cachedRep.ReputationScore
		result.ThreatScore = cachedRep.ReputationScore
		result.FromCache = true
		
		if cachedRep.IsBlacklisted {
			result.IsBlocked = true
			result.IsSuspicious = true
			result.Reasons = append(result.Reasons, "cached_blacklist")
		}
	} else {
		// Get or create reputation
		reputation, err := d.GetOrCreateReputation(ctx, ip)
		if err != nil {
			d.logger.Errorf("Failed to get reputation for %s: %v", ip, err)
		} else {
			result.ReputationScore = reputation.ReputationScore
			result.ThreatScore = reputation.ReputationScore
		}
	}

	// Check threat intelligence
	isThreat, source, err := d.threatIntel.IsKnownThreat(ctx, ip)
	if err != nil {
		d.logger.Warnf("Threat intel check failed for %s: %v", ip, err)
	}
	if isThreat {
		result.ThreatScore += 40
		result.IsSuspicious = true
		result.Reasons = append(result.Reasons, fmt.Sprintf("threat_intel:%s", source))
	}

	// Rate limiting check
	count, err := d.redisStore.IncrementRequestCount(ctx, ip, time.Duration(d.config.Detection.RateLimitWindow)*time.Second)
	if err != nil {
		d.logger.Warnf("Rate limit check failed for %s: %v", ip, err)
	}
	if count > int64(d.config.Detection.RateLimitThreshold) {
		result.ThreatScore += 30
		result.IsSuspicious = true
		result.Reasons = append(result.Reasons, fmt.Sprintf("rate_limit_exceeded:%d", count))
	}

	// Anomaly detection
	if d.config.Detection.BehavioralAnalysisEnabled {
		isAnomaly, anomalyScore := d.anomalyDetector.DetectAnomaly(ctx, ip, metadata)
		if isAnomaly {
			result.ThreatScore += anomalyScore
			result.IsSuspicious = true
			result.Reasons = append(result.Reasons, "behavioral_anomaly")
		}
	}

	// Private IP check
	if d.isPrivateIP(ip) {
		result.ThreatScore = max(0, result.ThreatScore-20) // Reduce score for private IPs
		result.Reasons = append(result.Reasons, "private_ip")
	}

	// Determine final action
	result.ThreatScore = min(100, result.ThreatScore)
	result.Action = models.GetAction(result.ThreatScore, d.config.Detection.AutoBlockThreshold)
	result.ThreatLevel = models.GetThreatLevel(result.ThreatScore)
	
	if result.ThreatScore >= d.config.Detection.AutoBlockThreshold {
		result.IsBlocked = true
	}
	
	if result.ThreatScore >= d.config.Detection.ReputationThreshold {
		result.IsSuspicious = true
	}

	result.ProcessingTime = time.Since(startTime).Seconds() * 1000

	// Update reputation asynchronously
	go d.updateReputation(ip, result)

	return result, nil
}

// GetOrCreateReputation gets or creates IP reputation
func (d *IPDetector) GetOrCreateReputation(ctx context.Context, ip string) (*models.IPReputation, error) {
	// Try to get from database
	rep, err := d.dbStore.GetIPReputation(ip)
	if err != nil {
		return nil, err
	}

	if rep != nil {
		rep.LastSeen = time.Now()
		return rep, nil
	}

	// Create new reputation
	rep = &models.IPReputation{
		IPAddress:       ip,
		ReputationScore: 0,
		ThreatLevel:     "low",
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		ViolationCount:  0,
		IsBlacklisted:   false,
		IsWhitelisted:   false,
	}

	return rep, nil
}

// RecordViolation records a security violation for an IP
func (d *IPDetector) RecordViolation(ctx context.Context, ip string, violationType string, severity int) error {
	// Create violation record
	violation := &models.Violation{
		IPAddress:     ip,
		ViolationType: violationType,
		Severity:      severity,
		Timestamp:     time.Now(),
		Metadata:      "{}",
	}

	if err := d.dbStore.RecordViolation(violation); err != nil {
		return err
	}

	// Update reputation
	rep, err := d.GetOrCreateReputation(ctx, ip)
	if err != nil {
		return err
	}

	rep.ViolationCount++
	rep.ReputationScore = min(100, rep.ReputationScore+severity*5)
	rep.ThreatLevel = models.GetThreatLevel(rep.ReputationScore)
	rep.LastSeen = time.Now()

	// Auto-blacklist if threshold exceeded
	if rep.ViolationCount >= d.config.Detection.AutoBlockThreshold {
		rep.IsBlacklisted = true
		d.redisStore.AddToBlacklist(ctx, ip, time.Duration(3600)*time.Second)
	}

	return d.dbStore.CreateOrUpdateIPReputation(rep)
}

// IsBlacklisted checks if IP is blacklisted
func (d *IPDetector) IsBlacklisted(ctx context.Context, ip string) (bool, error) {
	// Check Redis cache
	cached, err := d.redisStore.IsBlacklisted(ctx, ip)
	if err == nil && cached {
		return true, nil
	}

	// Check configured blacklist
	for _, blacklistedIP := range d.config.Blacklist {
		if d.matchIPPattern(ip, blacklistedIP) {
			return true, nil
		}
	}

	// Check database
	rep, err := d.dbStore.GetIPReputation(ip)
	if err != nil {
		return false, err
	}
	
	return rep != nil && rep.IsBlacklisted, nil
}

// IsWhitelisted checks if IP is whitelisted
func (d *IPDetector) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	// Check Redis cache
	cached, err := d.redisStore.IsWhitelisted(ctx, ip)
	if err == nil && cached {
		return true, nil
	}

	// Check configured whitelist
	for _, whitelistedIP := range d.config.Whitelist {
		if d.matchIPPattern(ip, whitelistedIP) {
			return true, nil
		}
	}

	return false, nil
}

// updateReputation updates IP reputation in background
func (d *IPDetector) updateReputation(ip string, result *models.ThreatResult) {
	ctx := context.Background()
	
	rep, err := d.GetOrCreateReputation(ctx, ip)
	if err != nil {
		d.logger.Errorf("Failed to get reputation for update: %v", err)
		return
	}

	rep.ReputationScore = result.ReputationScore
	rep.ThreatLevel = result.ThreatLevel
	rep.LastSeen = time.Now()

	if err := d.dbStore.CreateOrUpdateIPReputation(rep); err != nil {
		d.logger.Errorf("Failed to update reputation: %v", err)
	}

	// Cache in Redis
	if err := d.redisStore.SetIPReputation(ctx, rep, 5*time.Minute); err != nil {
		d.logger.Warnf("Failed to cache reputation: %v", err)
	}
}

// isPrivateIP checks if IP is in private range
func (d *IPDetector) isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}

	ipAddr := net.ParseIP(ip)
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ipAddr) {
			return true
		}
	}

	return false
}

// matchIPPattern matches IP against pattern (supports CIDR)
func (d *IPDetector) matchIPPattern(ip, pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		ipAddr := net.ParseIP(ip)
		return network.Contains(ipAddr)
	}
	return ip == pattern
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
