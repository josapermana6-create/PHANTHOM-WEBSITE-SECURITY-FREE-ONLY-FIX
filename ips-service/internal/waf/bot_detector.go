package waf

import (
	"regexp"
	"strings"
)

// BotDetector detects bot and automated traffic
type BotDetector struct {
	goodBots       []string
	badBots        []*regexp.Regexp
	suspiciousBots []*regexp.Regexp
}

// NewBotDetector creates a new bot detector
func NewBotDetector(knownGoodBots []string) *BotDetector {
	detector := &BotDetector{
		goodBots:       knownGoodBots,
		badBots:        make([]*regexp.Regexp, 0),
		suspiciousBots: make([]*regexp.Regexp, 0),
	}

	// Malicious bot patterns
	badPatterns := []string{
		`(?i)sqlmap`,
		`(?i)nikto`,
		`(?i)nmap`,
		`(?i)masscan`,
		`(?i)metasploit`,
		`(?i)havij`,
		`(?i)acunetix`,
		`(?i)nessus`,
		`(?i)openvas`,
		`(?i)w3af`,
		`(?i)skip=`,
		`(?i)grabber`,
		`(?i)libwww-perl`,
		`(?i)zmeu`,
		`(?i)morfeus`,
	}

	for _, pattern := range badPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			detector.badBots = append(detector.badBots, compiled)
		}
	}

	// Suspicious bot patterns (scrapers, etc.)
	suspiciousPatterns := []string{
		`(?i)python-requests`,
		`(?i)curl`,
		`(?i)wget`,
		`(?i)scrapy`,
		`(?i)beautifulsoup`,
		`(?i)selenium`,
		`(?i)phantomjs`,
		`(?i)headless`,
		`(?i)bot[^a-z]`, // Generic "bot" but not part of known good bots
		`(?i)spider`,
		`(?i)crawler`,
		`(?i)scraper`,
		`(?i)go-http-client`,
		`(?i)java/`,
		`(?i)httpclient`,
		`(?i)okhttp`,
	}

	for _, pattern := range suspiciousPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			detector.suspiciousBots = append(detector.suspiciousBots, compiled)
		}
	}

	return detector
}

// Detect checks if request is from a bot
func (d *BotDetector) Detect(userAgent string, headers map[string]string) (bool, int, []string, string) {
	if userAgent == "" {
		return true, 25, []string{"missing_user_agent"}, "suspicious"
	}

	threats := []string{}
	score := 0
	botType := "none"

	// Check for known good bots first
	for _, goodBot := range d.goodBots {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(goodBot)) {
			return false, 0, nil, "good_bot"
		}
	}

	// Check for malicious bots
	for _, pattern := range d.badBots {
		if pattern.MatchString(userAgent) {
			score += 50
			threats = append(threats, "malicious_bot_detected")
			botType = "malicious"
			return true, score, threats, botType
		}
	}

	// Check for suspicious bots
	for _, pattern := range d.suspiciousBots {
		if pattern.MatchString(userAgent) {
			score += 30
			threats = append(threats, "suspicious_bot_detected")
			if botType == "none" {
				botType = "suspicious"
			}
		}
	}

	// Behavioral checks
	behaviorScore, behaviorThreats := d.checkBehavior(userAgent, headers)
	score += behaviorScore
	threats = append(threats, behaviorThreats...)
	
	if behaviorScore > 0 && botType == "none" {
		botType = "suspicious"
	}

	isThreat := score >= 25
	return isThreat, score, threats, botType
}

// checkBehavior performs behavioral analysis
func (d *BotDetector) checkBehavior(userAgent string, headers map[string]string) (int, []string) {
	score := 0
	threats := []string{}

	// Very short or generic user agent
	if len(userAgent) < 20 {
		score += 15
		threats = append(threats, "short_user_agent")
	}

	// Missing Accept header (normal browsers send this)
	if _, hasAccept := headers["Accept"]; !hasAccept {
		score += 10
		threats = append(threats, "missing_accept_header")
	}

	// Missing Accept-Language (normal browsers send this)
	if _, hasLang := headers["Accept-Language"]; !hasLang {
		score += 10
		threats = append(threats, "missing_accept_language")
	}

	// Check for automation frameworks in headers
	suspiciousHeaders := []string{
		"X-Requested-With",          // XMLHttpRequest might be automated
		"X-Automated",
		"X-Scanner",
	}

	for _, header := range suspiciousHeaders {
		if val, exists := headers[header]; exists {
			if strings.Contains(strings.ToLower(val), "automation") ||
				strings.Contains(strings.ToLower(val), "scanner") {
				score += 20
				threats = append(threats, "automation_header_detected")
			}
		}
	}

	// Check for headless browser indicators
	if strings.Contains(strings.ToLower(userAgent), "headless") {
		score += 25
		threats = append(threats, "headless_browser")
	}

	// Check for very old browsers (might be spoofed)
	oldBrowsers := []string{"msie 6.0", "msie 7.0", "msie 8.0"}
	userAgentLower := strings.ToLower(userAgent)
	for _, old := range oldBrowsers {
		if strings.Contains(userAgentLower, old) {
			score += 15
			threats = append(threats, "outdated_browser")
			break
		}
	}

	return score, threats
}

// IsGoodBot checks if it's a known good bot (search engines, etc.)
func (d *BotDetector) IsGoodBot(userAgent string) bool {
	userAgentLower := strings.ToLower(userAgent)
	for _, goodBot := range d.goodBots {
		if strings.Contains(userAgentLower, strings.ToLower(goodBot)) {
			return true
		}
	}
	return false
}
