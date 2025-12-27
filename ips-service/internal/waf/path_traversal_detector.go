package waf

import (
	"path/filepath"
	"regexp"
	"strings"
)

// PathTraversalDetector detects path traversal attacks
type PathTraversalDetector struct {
	patterns    []*regexp.Regexp
	sensitivity string
	threshold   int
	maxDepth    int
}

// NewPathTraversalDetector creates a new path traversal detector
func NewPathTraversalDetector(sensitivity string, threshold int, maxDepth int) *PathTraversalDetector {
	detector := &PathTraversalDetector{
		sensitivity: sensitivity,
		threshold:   threshold,
		maxDepth:    maxDepth,
		patterns:    make([]*regexp.Regexp, 0),
	}

	// Compile regex patterns
	patterns := []string{
		// Standard traversal
		`\.\.[\\/]`,
		`\.\.[\\/]\.\.[\\/]`,
		
		// URL encoded
		`%2e%2e[%2f%5c]`,
		`%252e%252e[%252f%255c]`, // Double URL encoded
		
		// Unicode encoded
		`\.\.\u002f`,
		`\.\.\u005c`,
		
		// Absolute paths (Unix)
		`^/etc/`,
		`^/var/`,
		`^/usr/`,
		`^/root/`,
		`^/home/`,
		`^/proc/`,
		`^/sys/`,
		
		// Absolute paths (Windows)
		`^[a-zA-Z]:\\`,
		`^\\\\`,
		
		// Sensitive files
		`(?i)/etc/passwd`,
		`(?i)/etc/shadow`,
		`(?i)/etc/hosts`,
		`(?i)\.\..*\.\..*\.\.`, // Multiple traversals
		`(?i)\.\..*\.\..*\.\..*\.\.`, // Deep traversals
		
		// Windows sensitive files
		`(?i)c:[\\\/]windows`,
		`(?i)\.ini$`,
		`(?i)\.config$`,
		
		// Null byte injection
		`%00`,
		`\x00`,
	}

	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			detector.patterns = append(detector.patterns, compiled)
		}
	}

	return detector
}

// Detect checks for path traversal patterns
func (d *PathTraversalDetector) Detect(input string) (bool, int, []string) {
	if input == "" {
		return false, 0, nil
	}

	threats := []string{}
	score := 0

	// Normalize the path for analysis
	normalized := filepath.Clean(input)
	
	// URL decode variants
	decoded := strings.ReplaceAll(input, "%2e", ".")
	decoded = strings.ReplaceAll(decoded, "%2f", "/")
	decoded = strings.ReplaceAll(decoded, "%5c", "\\")
	decoded = strings.ReplaceAll(decoded, "%252e", ".")
	decoded = strings.ReplaceAll(decoded, "%252f", "/")

	// Check all variants
	toCheck := []string{input, normalized, decoded}

	for _, path := range toCheck {
		lowerPath := strings.ToLower(path)

		// Check patterns
		for _, pattern := range d.patterns {
			if pattern.MatchString(path) || pattern.MatchString(lowerPath) {
				score += 15
				threats = append(threats, "path_traversal_pattern")
				break
			}
		}

		// Count traversal depth
		traversalCount := strings.Count(path, "..") + strings.Count(path, "%2e%2e")
		if traversalCount > 0 {
			score += traversalCount * 10
			threats = append(threats, "directory_traversal")
			
			if traversalCount > d.maxDepth {
				score += 20
				threats = append(threats, "excessive_traversal_depth")
			}
		}

		// Check for absolute paths
		if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
			score += 10
			threats = append(threats, "absolute_path")
		}

		// Check for Windows drive letters
		if len(path) >= 2 && path[1] == ':' {
			score += 15
			threats = append(threats, "windows_drive_path")
		}

		// Check for sensitive file access
		sensitiveFiles := []string{
			"passwd", "shadow", "hosts", ".htaccess",
			".env", "web.config", "applicationhost.config",
			".git/config", ".ssh/",
		}
		for _, file := range sensitiveFiles {
			if strings.Contains(lowerPath, file) {
				score += 25
				threats = append(threats, "sensitive_file_access:"+file)
			}
		}

		// Check for null byte
		if strings.Contains(path, "%00") || strings.Contains(path, "\x00") {
			score += 20
			threats = append(threats, "null_byte_injection")
		}

		// Check for UNC paths (Windows network paths)
		if strings.HasPrefix(path, "\\\\") {
			score += 15
			threats = append(threats, "unc_path")
		}
	}

	// Adjust score based on sensitivity
	switch d.sensitivity {
	case "high":
		score = int(float64(score) * 1.3)
	case "low":
		score = int(float64(score) * 0.7)
	}

	uniqueThreats := removeDuplicates(threats)

	isThreat := score >= d.threshold
	return isThreat, score, uniqueThreats
}

// DetectInRequest checks all parts of a request for path traversal
func (d *PathTraversalDetector) DetectInRequest(params map[string]string, headers map[string]string, body, path string) (bool, int, []string) {
	maxScore := 0
	allThreats := []string{}
	isThreat := false

	// Check URL path itself
	threat, score, threats := d.Detect(path)
	if threat {
		isThreat = true
		allThreats = append(allThreats, threats...)
	}
	if score > maxScore {
		maxScore = score
	}

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

	// Check body for file paths
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

	uniqueThreats := removeDuplicates(allThreats)
	
	return isThreat, maxScore, uniqueThreats
}
