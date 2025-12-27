package models

import (
	"time"
)

// IPReputation represents the reputation data for an IP address
type IPReputation struct {
	IPAddress       string    `gorm:"primaryKey;column:ip_address" json:"ip_address"`
	ReputationScore int       `gorm:"column:reputation_score" json:"reputation_score"` // 0-100, higher = more suspicious
	ThreatLevel     string    `gorm:"column:threat_level" json:"threat_level"`         // low, medium, high, critical
	FirstSeen       time.Time `gorm:"column:first_seen" json:"first_seen"`
	LastSeen        time.Time `gorm:"column:last_seen" json:"last_seen"`
	ViolationCount  int       `gorm:"column:violation_count" json:"violation_count"`
	CountryCode     string    `gorm:"column:country_code" json:"country_code"`
	IsBlacklisted   bool      `gorm:"column:is_blacklisted" json:"is_blacklisted"`
	IsWhitelisted   bool      `gorm:"column:is_whitelisted" json:"is_whitelisted"`
	IsTor           bool      `gorm:"column:is_tor" json:"is_tor"`
	IsVPN           bool      `gorm:"column:is_vpn" json:"is_vpn"`
	IsProxy         bool      `gorm:"column:is_proxy" json:"is_proxy"`
}

// TableName specifies the table name for IPReputation
func (IPReputation) TableName() string {
	return "ip_reputation"
}

// Violation represents a security violation record
type Violation struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IPAddress     string    `gorm:"column:ip_address;index" json:"ip_address"`
	ViolationType string    `gorm:"column:violation_type" json:"violation_type"`
	Severity      int       `gorm:"column:severity" json:"severity"` // 1-10
	Timestamp     time.Time `gorm:"column:timestamp;index" json:"timestamp"`
	Metadata      string    `gorm:"column:metadata;type:text" json:"metadata"` // JSON string
}

// TableName specifies the table name for Violation
func (Violation) TableName() string {
	return "violations"
}

// ThreatIntel represents threat intelligence data
type ThreatIntel struct {
	IPAddress  string    `gorm:"primaryKey;column:ip_address" json:"ip_address"`
	Source     string    `gorm:"column:source" json:"source"`
	ThreatType string    `gorm:"column:threat_type" json:"threat_type"`
	Confidence int       `gorm:"column:confidence" json:"confidence"` // 0-100
	AddedAt    time.Time `gorm:"column:added_at" json:"added_at"`
	ExpiresAt  time.Time `gorm:"column:expires_at;index" json:"expires_at"`
}

// TableName specifies the table name for ThreatIntel
func (ThreatIntel) TableName() string {
	return "threat_intel"
}

// RequestMetadata contains metadata about a request
type RequestMetadata struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	Timestamp   time.Time         `json:"timestamp"`
	RequestSize int64             `json:"request_size"`
}

// ThreatResult represents the result of threat analysis
type ThreatResult struct {
	IsBlocked       bool     `json:"is_blocked"`
	IsSuspicious    bool     `json:"is_suspicious"`
	ThreatScore     int      `json:"threat_score"`      // 0-100
	ReputationScore int      `json:"reputation_score"`  // 0-100
	Reasons         []string `json:"reasons"`           // List of detection reasons
	Action          string   `json:"action"`            // allow, block, challenge
	ThreatLevel     string   `json:"threat_level"`      // low, medium, high, critical
	FromCache       bool     `json:"from_cache"`
	ProcessingTime  float64  `json:"processing_time_ms"`
}

// IPAnalysisRequest represents a request to analyze an IP
type IPAnalysisRequest struct {
	IPAddress string          `json:"ip_address"`
	Metadata  RequestMetadata `json:"metadata"`
}

// IPAnalysisResponse represents the response from IP analysis
type IPAnalysisResponse struct {
	IPAddress  string       `json:"ip_address"`
	Result     ThreatResult `json:"result"`
	Reputation IPReputation `json:"reputation"`
	Timestamp  time.Time    `json:"timestamp"`
}

// GetThreatLevel returns threat level based on reputation score
func GetThreatLevel(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// GetAction returns recommended action based on threat score
func GetAction(score int, autoBlockThreshold int) string {
	if score >= autoBlockThreshold {
		return "block"
	} else if score >= 70 {
		return "challenge"
	}
	return "allow"
}
