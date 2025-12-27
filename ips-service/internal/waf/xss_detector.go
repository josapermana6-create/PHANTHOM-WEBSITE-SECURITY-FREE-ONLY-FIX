package waf

import (
	"html"
	"regexp"
	"strings"
)

// XSSDetector detects Cross-Site Scripting (XSS) attacks
type XSSDetector struct {
	patterns    []*regexp.Regexp
	sensitivity string
	threshold   int
}

// NewXSSDetector creates a new XSS detector
func NewXSSDetector(sensitivity string, threshold int) *XSSDetector {
	detector := &XSSDetector{
		sensitivity: sensitivity,
		threshold:   threshold,
		patterns:    make([]*regexp.Regexp, 0),
	}

	// Compile regex patterns
	patterns := []string{
		// Script tags
		`(?i)<script[^>]*>`,
		`(?i)</script>`,
		`(?i)<script.*?>.*?</script>`,
		
		// JavaScript execution
		`(?i)javascript:`,
		`(?i)on\w+\s*=`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)onclick\s*=`,
		`(?i)onmouseover\s*=`,
		`(?i)onfocus\s*=`,
		`(?i)onblur\s*=`,
		
		// Iframe injection
		`(?i)<iframe`,
		`(?i)</iframe>`,
		
		// Object/Embed tags
		`(?i)<object`,
		`(?i)<embed`,
		
		// Meta refresh
		`(?i)<meta.*http-equiv.*refresh`,
		
		// Expression (IE)
		`(?i)expression\s*\(`,
		
		// Import styles
		`(?i)@import`,
		`(?i)<link.*stylesheet`,
		
		// Data URLs
		`(?i)data:text/html`,
		
		// JavaScript functions
		`(?i)eval\s*\(`,
		`(?i)alert\s*\(`,
		`(?i)confirm\s*\(`,
		`(?i)prompt\s*\(`,
		
		// DOM manipulation
		`(?i)document\.`,
		`(?i)window\.`,
		`(?i)\.innerHTML`,
		`(?i)\.outerHTML`,
		
		// Cookie stealing
		`(?i)document\.cookie`,
		`(?i)document\.domain`,
		
		// Event handlers via HTML attributes
		`(?i)formaction\s*=`,
		`(?i)<form.*action\s*=\s*["']?javascript:`,
		
		// SVG-based XSS
		`(?i)<svg.*onload`,
		
		// Base64 encoded scripts
		`(?i)base64.*script`,
	}

	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			detector.patterns = append(detector.patterns, compiled)
		}
	}

	return detector
}

// Detect checks for XSS patterns
func (d *XSSDetector) Detect(input string) (bool, int, []string) {
	if input == "" {
		return false, 0, nil
	}

	threats := []string{}
	score := 0

	// Decode HTML entities to catch encoded attacks
	decoded := html.UnescapeString(input)
	
	// Also check URL-decoded version
	urlDecoded := strings.ReplaceAll(decoded, "%3C", "<")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%3E", ">")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%22", "\"")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%27", "'")

	// Combine all versions to check
	toCheck := []string{input, decoded, urlDecoded}

	for _, text := range toCheck {
		normalized := strings.ToLower(text)

		// Check patterns
		for _, pattern := range d.patterns {
			if pattern.MatchString(normalized) {
				score += 12
				threats = append(threats, "xss_pattern_detected")
				break // Count once per input variant
			}
		}

		// Check for script tags specifically
		if strings.Contains(normalized, "<script") {
			score += 20
			threats = append(threats, "script_tag_detected")
		}

		// Check for event handlers
		eventHandlers := []string{
			"onerror", "onload", "onclick", "onmouseover",
			"onfocus", "onblur", "onchange", "onsubmit",
		}
		for _, handler := range eventHandlers {
			if strings.Contains(normalized, handler) {
				score += 15
				threats = append(threats, "event_handler_detected")
				break
			}
		}

		// Check for javascript: protocol
		if strings.Contains(normalized, "javascript:") {
			score += 18
			threats = append(threats, "javascript_protocol")
		}

		// Check for dangerous DOM methods
		dangerousMethods := []string{
			"document.write", "document.cookie", "eval(",
			"innerhtml", "outerhtml",
		}
		for _, method := range dangerousMethods {
			if strings.Contains(normalized, method) {
				score += 15
				threats = append(threats, "dangerous_dom_method")
				break
			}
		}
	}

	// Check for HTML tag structure
	if strings.Contains(input, "<") && strings.Contains(input, ">") {
		score += 5
		threats = append(threats, "html_structure")
	}

	// Adjust score based on sensitivity
	switch d.sensitivity {
	case "high":
		score = int(float64(score) * 1.3)
	case "low":
		score = int(float64(score) * 0.7)
	}

	// Remove duplicates
	uniqueThreats := removeDuplicates(threats)

	isThreat := score >= d.threshold
	return isThreat, score, uniqueThreats
}

// DetectInRequest checks all parts of a request for XSS
func (d *XSSDetector) DetectInRequest(params map[string]string, headers map[string]string, body string) (bool, int, []string) {
	maxScore := 0
	allThreats := []string{}
	isThreat := false

	// Check parameters
	for key, value := range params {
		// Check both key and value
		threat, score, threats := d.Detect(key + value)
		if threat {
			isThreat = true
			allThreats = append(allThreats, threats...)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	// Check common XSS vectors in headers
	checkHeaders := []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For"}
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
