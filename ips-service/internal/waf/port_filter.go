package waf

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortFilter detects suspicious port access and port scanning
type PortFilter struct {
	allowedPorts    map[int]bool
	blockedPorts    map[int]bool
	suspiciousPorts map[int]bool
	
	// Port scan detection
	portAccessHistory map[string]*PortAccessRecord
	mu                sync.RWMutex
	
	scanThreshold   int           // Number of different ports to trigger scan alert
	scanWindow      time.Duration // Time window for scan detection
}

// PortAccessRecord tracks port access history per IP
type PortAccessRecord struct {
	Ports      map[int]time.Time // Port -> Last access time
	FirstAccess time.Time
	mu         sync.Mutex
}

// NewPortFilter creates a new port filter
func NewPortFilter(allowedPorts, blockedPorts, suspiciousPorts []int, scanThreshold int, scanWindow time.Duration) *PortFilter {
	pf := &PortFilter{
		allowedPorts:      make(map[int]bool),
		blockedPorts:      make(map[int]bool),
		suspiciousPorts:   make(map[int]bool),
		portAccessHistory: make(map[string]*PortAccessRecord),
		scanThreshold:     scanThreshold,
		scanWindow:        scanWindow,
	}

	// Convert slices to maps for fast lookup
	for _, port := range allowedPorts {
		pf.allowedPorts[port] = true
	}
	
	for _, port := range blockedPorts {
		pf.blockedPorts[port] = true
	}
	
	for _, port := range suspiciousPorts {
		pf.suspiciousPorts[port] = true
	}

	// Start cleanup goroutine
	go pf.cleanup()

	return pf
}

// Detect checks for suspicious port access
func (pf *PortFilter) Detect(ip string, port int, path string) (bool, int, []string) {
	threats := []string{}
	score := 0

	// Check if port is blocked
	if pf.blockedPorts[port] {
		score += 50
		threats = append(threats, "blocked_port_access:"+strconv.Itoa(port))
		return true, score, threats
	}

	// Check if accessing allowed ports only mode (if configured)
	if len(pf.allowedPorts) > 0 && !pf.allowedPorts[port] {
		score += 30
		threats = append(threats, "non_allowed_port:"+strconv.Itoa(port))
	}

	// Check if port is suspicious
	if pf.suspiciousPorts[port] {
		score += 25
		threats = append(threats, "suspicious_port:"+strconv.Itoa(port))
	}

	// Detect port scanning behavior
	scanDetected, scanScore, scanThreats := pf.detectPortScan(ip, port)
	if scanDetected {
		score += scanScore
		threats = append(threats, scanThreats...)
	}

	// Check for common attack patterns on specific ports
	if attackScore, attackThreats := pf.checkPortAttackPatterns(port, path); attackScore > 0 {
		score += attackScore
		threats = append(threats, attackThreats...)
	}

	isThreat := score >= 25
	return isThreat, score, threats
}

// detectPortScan detects port scanning behavior
func (pf *PortFilter) detectPortScan(ip string, port int) (bool, int, []string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	threats := []string{}
	score := 0

	// Get or create access record for this IP
	record, exists := pf.portAccessHistory[ip]
	if !exists {
		record = &PortAccessRecord{
			Ports:       make(map[int]time.Time),
			FirstAccess: time.Now(),
		}
		pf.portAccessHistory[ip] = record
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	// Record this port access
	now := time.Now()
	record.Ports[port] = now

	// Clean old entries outside scan window
	for p, accessTime := range record.Ports {
		if now.Sub(accessTime) > pf.scanWindow {
			delete(record.Ports, p)
		}
	}

	// Update first access if needed
	if now.Sub(record.FirstAccess) > pf.scanWindow {
		record.FirstAccess = now
	}

	// Check if scanning (accessing many different ports)
	uniquePorts := len(record.Ports)
	
	if uniquePorts >= pf.scanThreshold {
		score += 40
		threats = append(threats, "port_scanning_detected:"+strconv.Itoa(uniquePorts)+"_ports")
		
		// Additional scoring based on scan intensity
		if uniquePorts >= pf.scanThreshold*2 {
			score += 20
			threats = append(threats, "aggressive_port_scan")
		}
	} else if uniquePorts >= pf.scanThreshold/2 {
		score += 15
		threats = append(threats, "potential_port_scan")
	}

	// Check scan speed (very fast scanning is more suspicious)
	scanDuration := now.Sub(record.FirstAccess)
	if uniquePorts > 5 && scanDuration < time.Second*10 {
		score += 25
		threats = append(threats, "high_speed_scan")
	}

	isScanning := score >= 30
	return isScanning, score, threats
}

// checkPortAttackPatterns checks for known attack patterns on specific ports
func (pf *PortFilter) checkPortAttackPatterns(port int, path string) (int, []string) {
	score := 0
	threats := []string{}

	// Check for common attack ports
	attackPorts := map[int]string{
		22:    "ssh_access",        // SSH
		23:    "telnet_access",      // Telnet (insecure)
		3306:  "mysql_direct",       // MySQL
		5432:  "postgres_direct",    // PostgreSQL
		6379:  "redis_direct",       // Redis
		27017: "mongodb_direct",     // MongoDB
		3389:  "rdp_access",         // RDP
		445:   "smb_access",         // SMB
		135:   "rpc_access",         // RPC
		1433:  "mssql_direct",       // MS SQL
		5900:  "vnc_access",         // VNC
		8080:  "proxy_access",       // Common proxy
		9090:  "management_access",  // Management ports
	}

	if attackType, exists := attackPorts[port]; exists {
		score += 20
		threats = append(threats, "direct_service_access:"+attackType)
	}

	// Check for admin panel access on non-standard ports
	adminPaths := []string{"/admin", "/phpmyadmin", "/wp-admin", "/login", "/console"}
	pathLower := strings.ToLower(path)
	
	for _, adminPath := range adminPaths {
		if strings.Contains(pathLower, adminPath) && port != 80 && port != 443 {
			score += 15
			threats = append(threats, "admin_access_nonstandard_port")
			break
		}
	}

	// Unusual port for web traffic
	if port < 1024 && port != 80 && port != 443 {
		score += 10
		threats = append(threats, "privileged_port_access")
	}

	// Very high port numbers (sometimes used for backdoors)
	if port > 49152 {
		score += 5
		threats = append(threats, "high_port_number")
	}

	return score, threats
}

// GetPortScanStats returns port scanning statistics for an IP
func (pf *PortFilter) GetPortScanStats(ip string) map[string]interface{} {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	record, exists := pf.portAccessHistory[ip]
	if !exists {
		return map[string]interface{}{
			"unique_ports": 0,
			"scanning":     false,
		}
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	return map[string]interface{}{
		"unique_ports": len(record.Ports),
		"first_access": record.FirstAccess,
		"scanning":     len(record.Ports) >= pf.scanThreshold,
	}
}

// cleanup removes old port access records
func (pf *PortFilter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		pf.mu.Lock()
		now := time.Now()
		
		for ip, record := range pf.portAccessHistory {
			record.mu.Lock()
			
			// Remove if no activity in 2x scan window
			if now.Sub(record.FirstAccess) > pf.scanWindow*2 {
				delete(pf.portAccessHistory, ip)
			}
			
			record.mu.Unlock()
		}
		
		pf.mu.Unlock()
	}
}

// IsAllowedPort checks if a port is explicitly allowed
func (pf *PortFilter) IsAllowedPort(port int) bool {
	if len(pf.allowedPorts) == 0 {
		return true // No whitelist, all ports allowed
	}
	return pf.allowedPorts[port]
}

// IsBlockedPort checks if a port is explicitly blocked
func (pf *PortFilter) IsBlockedPort(port int) bool {
	return pf.blockedPorts[port]
}

// AddAllowedPort adds a port to the allowed list
func (pf *PortFilter) AddAllowedPort(port int) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.allowedPorts[port] = true
}

// AddBlockedPort adds a port to the blocked list
func (pf *PortFilter) AddBlockedPort(port int) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.blockedPorts[port] = true
}
