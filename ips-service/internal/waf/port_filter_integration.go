// Add port filter detection to concurrent analysis

// Port Filter (if enabled)
wg.Add(1)
go func() {
	defer wg.Done()
	
	// Extract port from headers or default to 80/443
	port := 80 // Default HTTP
	if req.Headers["X-Forwarded-Port"] != "" {
		if p, err := strconv.Atoi(req.Headers["X-Forwarded-Port"]); err == nil {
			port = p
		}
	} else if req.Headers["Host"] != "" {
		// Check if port is in Host header (e.g., "example.com:8080")
		if idx := strings.LastIndex(req.Headers["Host"], ":"); idx > 0 {
			if p, err := strconv.Atoi(req.Headers["Host"][idx+1:]); err == nil {
				port = p
			}
		}
	}
	
	// Assume HTTPS if X-Forwarded-Proto is https
	if req.Headers["X-Forwarded-Proto"] == "https" {
		port = 443
	}
	
	isThreat, score, threats := ra.portFilter.Detect(req.IP, port, req.Path)
	
	mu.Lock()
	result.ModuleResults["port_filter"] = ModuleResult{
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
