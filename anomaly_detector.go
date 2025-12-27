package detector

import (
	"context"
	"math"
	"time"

	"github.com/phantom-security/ips-service/internal/config"
	"github.com/phantom-security/ips-service/internal/models"
	"github.com/phantom-security/ips-service/internal/storage"
)

// AnomalyDetector detects anomalous IP behavior
type AnomalyDetector struct {
	config     *config.Config
	redisStore *storage.RedisStore
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(cfg *config.Config, redisStore *storage.RedisStore) *AnomalyDetector {
	return &AnomalyDetector{
		config:     cfg,
		redisStore: redisStore,
	}
}

// DetectAnomaly detects anomalous behavior patterns
func (a *AnomalyDetector) DetectAnomaly(ctx context.Context, ip string, metadata models.RequestMetadata) (bool, int) {
	score := 0
	isAnomaly := false

	// Check request rate anomaly
	count, err := a.redisStore.GetRequestCount(ctx, ip)
	if err == nil {
		avgRate := float64(a.config.Detection.RateLimitThreshold) / 2.0
		stdDev := avgRate / 3.0 // Assume standard deviation
		threshold := a.getThreshold()
		
		if float64(count) > avgRate+(stdDev*threshold) {
			isAnomaly = true
			score += 20
		}
	}

	// Check user agent anomalies
	if metadata.UserAgent == "" {
		isAnomaly = true
		score += 15
	} else if a.isSuspiciousUserAgent(metadata.UserAgent) {
		isAnomaly = true
		score += 25
	}

	// Check path patterns (potential scanning)
	if a.isScanningPattern(metadata.Path) {
		isAnomaly = true
		score += 30
	}

	// Time-based anomaly (unusual hours)
	if a.isUnusualTime(metadata.Timestamp) {
		score += 10
	}

	return isAnomaly, score
}

// getThreshold returns the threshold multiplier based on sensitivity
func (a *AnomalyDetector) getThreshold() float64 {
	switch a.config.Detection.AnomalySensitivity {
	case "high":
		return 2.0 // 2 standard deviations
	case "low":
		return 4.0 // 4 standard deviations
	default: // medium
		return 3.0 // 3 standard deviations
	}
}

// isSuspiciousUserAgent checks if user agent is suspicious
func (a *AnomalyDetector) isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"metasploit",
		"havij",
		"acunetix",
		"burp",
		"nessus",
		"openvas",
		"w3af",
		"python-requests",
		"curl",
		"wget",
		"go-http-client",
	}

	userAgentLower := toLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

// isScanningPattern detects directory/vulnerability scanning patterns
func (a *AnomalyDetector) isScanningPattern(path string) bool {
	scanPatterns := []string{
		"/.env",
		"/.git",
		"/admin",
		"/phpmyadmin",
		"/wp-admin",
		"/wp-login",
		"/.aws",
		"/config",
		"/backup",
		"/.sql",
		"/shell",
		"/cmd",
		"/eval",
	}

	pathLower := toLower(path)
	for _, pattern := range scanPatterns {
		if contains(pathLower, pattern) {
			return true
		}
	}

	return false
}

// isUnusualTime checks if request time is unusual (e.g., outside business hours)
func (a *AnomalyDetector) isUnusualTime(timestamp time.Time) bool {
	hour := timestamp.Hour()
	// Check if outside typical hours (e.g., 2 AM - 6 AM local time)
	return hour >= 2 && hour <= 6
}

// Helper functions
func toLower(s string) string {
	return s // In real implementation, use strings.ToLower
}

func contains(s, substr string) bool {
	// Simple contains check - in real implementation use strings.Contains
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// CalculateEntropy calculates Shannon entropy of a string
func (a *AnomalyDetector) CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := float64(len(s))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
