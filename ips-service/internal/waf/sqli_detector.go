package waf

import (
	"regexp"
	"strings"
)

// SQLInjectionDetector detects SQL injection attacks
type SQLInjectionDetector struct {
	patterns    []*regexp.Regexp
	sensitivity string
	threshold   int
}

// NewSQLInjectionDetector creates a new SQL injection detector
func NewSQLInjectionDetector(sensitivity string, threshold int) *SQLInjectionDetector {
	detector := &SQLInjectionDetector{
		sensitivity: sensitivity,
		threshold:   threshold,
		patterns:    make([]*regexp.Regexp, 0),
	}

	// Compile regex patterns for performance
	patterns := []string{
		// Union-based SQLi
		`(?i)(union.*select)`,
		`(?i)(union.*all.*select)`,
		
		// Boolean-based SQLi
		`(?i)(or\s+\d+\s*=\s*\d+)`,
		`(?i)(and\s+\d+\s*=\s*\d+)`,
		`(?i)(or\s+true)`,
		`(?i)(or\s+false)`,
		`(?i)(or\s+'.*'='.*)`,
		`(?i)(and\s+'.*'='.*)`,
		
		// Time-based SQLi
		`(?i)(sleep\s*\()`,
		`(?i)(benchmark\s*\()`,
		`(?i)(waitfor\s+delay)`,
		
		// Stacked queries
		`(?i)(;\s*(drop|alter|create|insert|update|delete)\s+)`,
		
		// Comment-based
		`(--\s*)`,
		`(/\*.*\*/)`,
		`(#\s*)`,
		
		// SQL commands
		`(?i)(select.*from)`,
		`(?i)(insert.*into)`,
		`(?i)(delete.*from)`,
		`(?i)(update.*set)`,
		`(?i)(drop.*table)`,
		`(?i)(create.*table)`,
		`(?i)(alter.*table)`,
		
		// SQL functions
		`(?i)(concat\s*\()`,
		`(?i)(group_concat\s*\()`,
		`(?i)(cast\s*\()`,
		`(?i)(convert\s*\()`,
		`(?i)(substring\s*\()`,
		`(?i)(ascii\s*\()`,
		`(?i)(char\s*\()`,
		
		// System functions
		`(?i)(exec(ute)?\s+)`,
		`(?i)(sp_executesql)`,
		`(?i)(xp_cmdshell)`,
		`(?i)(information_schema)`,
		`(?i)(sys\.)`,
		
		// Blind SQLi
		`(?i)(extractvalue\s*\()`,
		`(?i)(updatexml\s*\()`,
		
		// Error-based SQLi
		`(?i)(having\s+\d+=\d+)`,
		`(?i)(group\s+by.*having)`,
	}

	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			detector.patterns = append(detector.patterns, compiled)
		}
	}

	return detector
}

// Detect checks for SQL injection patterns
func (d *SQLInjectionDetector) Detect(input string) (bool, int, []string) {
	if input == "" {
		return false, 0, nil
	}

	threats := []string{}
	score := 0

	// Normalize input
	normalized := strings.ToLower(input)

	// Check each pattern
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			score += 10
			threats = append(threats, "sql_injection_pattern_detected")
		}
	}

	// Check for SQL keywords
	sqlKeywords := []string{
		"select", "union", "insert", "update", "delete", "drop",
		"create", "alter", "exec", "execute", "sp_",
	}

	keywordCount := 0
	for _, keyword := range sqlKeywords {
		if strings.Contains(normalized, keyword) {
			keywordCount++
		}
	}

	if keywordCount >= 2 {
		score += 15
		threats = append(threats, "multiple_sql_keywords")
	}

	// Check for suspicious characters
	suspiciousChars := []string{"'", "\"", ";", "--", "/*", "*/", "#", "="}
	suspiciousCount := 0
	for _, char := range suspiciousChars {
		if strings.Contains(input, char) {
			suspiciousCount++
		}
	}

	if suspiciousCount >= 3 {
		score += 10
		threats = append(threats, "suspicious_characters")
	}

	// Adjust score based on sensitivity
	switch d.sensitivity {
	case "high":
		score = int(float64(score) * 1.3)
	case "low":
		score = int(float64(score) * 0.7)
	}

	isThreat := score >= d.threshold
	return isThreat, score, threats
}

// DetectInRequest checks all parts of a request for SQL injection
func (d *SQLInjectionDetector) DetectInRequest(params map[string]string, headers map[string]string, body string) (bool, int, []string) {
	maxScore := 0
	allThreats := []string{}
	isThreat := false

	// Check parameters
	for key, value := range params {
		threat, score, threats := d.Detect(key + value)
		if threat {
			isThreat = true
			allThreats = append(allThreats, threats...)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	// Check headers (selected ones)
	checkHeaders := []string{"User-Agent", "Referer", "Cookie"}
	for _, headerName := range checkHeaders {
		if value, ok := headers[headerName]; ok {
			threat, score, threats := d.Detect(value)
			if threat {
				isThreat = true
				allThreats = append(allThreats, threats...)
			}
			if score > maxScore {
				maxScore = score
			}
		}
	}

	// Check body
	if body != "" {
		threat, score, threats := d.Detect(body)
		if threat {
			isThreat = true
			allThreats = append(allThreats, threats...)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	// Remove duplicates
	uniqueThreats := removeDuplicates(allThreats)
	
	return isThreat, maxScore, uniqueThreats
}

// Helper function to remove duplicates
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	unique := []string{}
	
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			unique = append(unique, entry)
		}
	}
	
	return unique
}
