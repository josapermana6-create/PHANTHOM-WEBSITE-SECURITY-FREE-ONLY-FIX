package waf

import (
	"regexp"
	"strings"
)

// CMDIDetector detects Command Injection attacks
type CMDIDetector struct {
	patterns        []*regexp.Regexp
	dangerousCommands []string
	sensitivity     string
	threshold       int
}

// NewCMDIDetector creates a new command injection detector
func NewCMDIDetector(sensitivity string, threshold int) *CMDIDetector {
	detector := &CMDIDetector{
		sensitivity: sensitivity,
		threshold:   threshold,
		patterns:    make([]*regexp.Regexp, 0),
		dangerousCommands: []string{
			"bash", "sh", "cmd", "powershell", "pwsh",
			"eval", "exec", "system", "popen",
			"wget", "curl", "nc", "netcat",
			"chmod", "chown", "sudo", "su",
		},
	}

	// Compile regex patterns
	patterns := []string{
		// Command chaining
		`[;&|]+\s*(ls|cat|whoami|id|pwd|uname)`,
		
		// Pipe operators
		`\|\s*(ls|cat|grep|awk|sed)`,
		
		// Backticks and command substitution
		"` + "`" + `.*` + "`" + `",
		`\$\(.*\)`,
		
		// Redirection operators
		`[<>]+\s*/`,
		
		// Shell metacharacters with commands
		`[;&|]\s*(bash|sh|cmd|powershell)`,
		
		// Network tools
		`(?i)(wget|curl)\s+http`,
		`(?i)(nc|netcat)\s+-`,
		
		// File operations
		`(?i)(cat|type|more|less)\s+/`,
		`(?i)(chmod|chown)\s+`,
		
		// System info commands
		`(?i)(whoami|id|uname|hostname)`,
		
		// Process commands
		`(?i)(ps|top|kill|killall)`,
		
		// Windows-specific
		`(?i)(cmd\.exe|powershell\.exe)`,
		`(?i)(net\s+user|net\s+localgroup)`,
		
		// Encoded commands
		`(?i)base64.*decode`,
		
		// Environment variables
		`\$\{.*\}`,
		`%.*%`,
	}

	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			detector.patterns = append(detector.patterns, compiled)
		}
	}

	return detector
}

// Detect checks for command injection patterns
func (d *CMDIDetector) Detect(input string) (bool, int, []string) {
	if input == "" {
		return false, 0, nil
	}

	threats := []string{}
	score := 0

	normalized := strings.ToLower(input)

	// Check for dangerous commands
	for _, cmd := range d.dangerousCommands {
		if strings.Contains(normalized, cmd) {
			score += 15
			threats = append(threats, "dangerous_command:"+cmd)
		}
	}

	// Check patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			score += 12
			threats = append(threats, "cmdi_pattern_detected")
		}
	}

	// Check for shell metacharacters
	metacharacters := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"}
	metacharCount := 0
	for _, char := range metacharacters {
		if strings.Contains(input, char) {
			metacharCount++
		}
	}

	if metacharCount >= 2 {
		score += 10
		threats = append(threats, "multiple_shell_metacharacters")
	}

	// Check for command substitution
	if strings.Contains(input, "$(") || strings.Contains(input, "`") {
		score += 20
		threats = append(threats, "command_substitution")
	}

	// Check for command chaining
	chainOperators := []string{";", "&&", "||", "|"}
	for _, op := range chainOperators {
		if strings.Contains(input, op) {
			score += 15
			threats = append(threats, "command_chaining")
			break
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

// DetectInRequest checks all parts of a request for command injection
func (d *CMDIDetector) DetectInRequest(params map[string]string, headers map[string]string, body string) (bool, int, []string) {
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

	// Check headers (User-Agent, Referer most common)
	checkHeaders := []string{"User-Agent", "Referer", "X-Forwarded-For"}
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

	uniqueThreats := removeDuplicates(allThreats)
	
	return isThreat, maxScore, uniqueThreats
}
