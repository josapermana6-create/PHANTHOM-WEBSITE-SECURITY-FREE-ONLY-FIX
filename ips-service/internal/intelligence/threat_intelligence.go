package intelligence

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phantom-security/ips-service/internal/config"
	"github.com/phantom-security/ips-service/internal/models"
	"github.com/phantom-security/ips-service/internal/storage"
	"github.com/sirupsen/logrus"
)

// ThreatIntelligence manages threat intelligence feeds
type ThreatIntelligence struct {
	config      *config.ThreatIntelligenceConfig
	dbStore     *storage.DatabaseStore
	redisStore  *storage.RedisStore
	threatCache map[string]bool // In-memory cache
	mu          sync.RWMutex
	logger      *logrus.Logger
}

// NewThreatIntelligence creates a new threat intelligence manager
func NewThreatIntelligence(
	cfg *config.ThreatIntelligenceConfig,
	dbStore *storage.DatabaseStore,
	redisStore *storage.RedisStore,
	logger *logrus.Logger,
) *ThreatIntelligence {
	return &ThreatIntelligence{
		config:      cfg,
		dbStore:     dbStore,
		redisStore:  redisStore,
		threatCache: make(map[string]bool),
		logger:      logger,
	}
}

// Start begins periodic threat intelligence updates
func (ti *ThreatIntelligence) Start(ctx context.Context) {
	if !ti.config.Enabled {
		ti.logger.Info("Threat intelligence disabled")
		return
	}

	// Initial update
	ti.logger.Info("Performing initial threat intelligence update")
	if err := ti.UpdateFeeds(ctx); err != nil {
		ti.logger.Errorf("Initial threat feed update failed: %v", err)
	}

	// Periodic updates
	ticker := time.NewTicker(time.Duration(ti.config.UpdateInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			ti.logger.Info("Stopping threat intelligence updates")
			return
		case <-ticker.C:
			ti.logger.Info("Updating threat intelligence feeds")
			if err := ti.UpdateFeeds(ctx); err != nil {
				ti.logger.Errorf("Threat feed update failed: %v", err)
			}
		}
	}
}

// UpdateFeeds updates all enabled threat intelligence feeds
func (ti *ThreatIntelligence) UpdateFeeds(ctx context.Context) error {
	var wg sync.WaitGroup
	errors := make(chan error, len(ti.config.Feeds))

	for _, feed := range ti.config.Feeds {
		if !feed.Enabled {
			continue
		}

		wg.Add(1)
		go func(f config.ThreatFeed) {
			defer wg.Done()
			
			ti.logger.Infof("Updating feed: %s", f.Name)
			if err := ti.updateSingleFeed(ctx, f); err != nil {
				ti.logger.Errorf("Failed to update feed %s: %v", f.Name, err)
				errors <- fmt.Errorf("feed %s: %w", f.Name, err)
			} else {
				ti.logger.Infof("Successfully updated feed: %s", f.Name)
			}
		}(feed)
	}

	wg.Wait()
	close(errors)

	// Collect errors
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("feed update errors: %v", errs)
	}

	return nil
}

// updateSingleFeed updates a single threat feed
func (ti *ThreatIntelligence) updateSingleFeed(ctx context.Context, feed config.ThreatFeed) error {
	// Fetch feed data
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return err
	}

	// Add API key if provided
	if feed.APIKey != "" {
		req.Header.Set("Key", feed.APIKey)
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Parse feed based on type
	ips, err := ti.parseFeed(resp.Body, feed.Type)
	if err != nil {
		return err
	}

	// Store threat intelligence
	count := 0
	expiresAt := time.Now().Add(time.Duration(ti.config.UpdateInterval*2) * time.Second)

	for _, ip := range ips {
		// Validate IP address
		if net.ParseIP(ip) == nil {
			continue
		}

		// Store in database
		intel := &models.ThreatIntel{
			IPAddress:  ip,
			Source:     feed.Name,
			ThreatType: "malicious",
			Confidence: 80,
			AddedAt:    time.Now(),
			ExpiresAt:  expiresAt,
		}

		if err := ti.dbStore.AddThreatIntel(intel); err != nil {
			ti.logger.Warnf("Failed to store threat intel for %s: %v", ip, err)
			continue
		}

		// Cache in Redis
		if err := ti.redisStore.AddThreatIntel(ctx, ip, time.Duration(ti.config.UpdateInterval*2)*time.Second); err != nil {
			ti.logger.Warnf("Failed to cache threat intel for %s: %v", ip, err)
		}

		// Add to memory cache
		ti.mu.Lock()
		ti.threatCache[ip] = true
		ti.mu.Unlock()

		count++
	}

	ti.logger.Infof("Loaded %d threat IPs from feed: %s", count, feed.Name)
	return nil
}

// parseFeed parses threat feed based on format
func (ti *ThreatIntelligence) parseFeed(body interface{}, feedType string) ([]string, error) {
	var ips []string

	switch feedType {
	case "text":
		scanner := bufio.NewScanner(body.(interface{ Read([]byte) (int, error) }))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			
			// Skip comments and empty lines
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}

			// Extract IP (some feeds have format: IP	confidence	...other fields)
			parts := strings.Fields(line)
			if len(parts) > 0 {
				ip := parts[0]
				// Remove CIDR notation if present (for now, we'll handle individual IPs)
				if idx := strings.Index(ip, "/"); idx > 0 {
					ip = ip[:idx]
				}
				ips = append(ips, ip)
			}
		}
		return ips, scanner.Err()

	default:
		return nil, fmt.Errorf("unsupported feed type: %s", feedType)
	}
}

// IsKnownThreat checks if an IP is in threat intelligence
func (ti *ThreatIntelligence) IsKnownThreat(ctx context.Context, ip string) (bool, string, error) {
	// Check memory cache first
	ti.mu.RLock()
	if ti.threatCache[ip] {
		ti.mu.RUnlock()
		return true, "memory_cache", nil
	}
	ti.mu.RUnlock()

	// Check Redis cache
	isThreat, err := ti.redisStore.IsThreatIntel(ctx, ip)
	if err == nil && isThreat {
		return true, "redis_cache", nil
	}

	// Check database
	intel, err := ti.dbStore.GetThreatIntel(ip)
	if err != nil {
		return false, "", err
	}

	if intel != nil {
		// Add to caches
		ti.mu.Lock()
		ti.threatCache[ip] = true
		ti.mu.Unlock()

		ti.redisStore.AddThreatIntel(ctx, ip, time.Duration(ti.config.UpdateInterval)*time.Second)
		
		return true, intel.Source, nil
	}

	return false, "", nil
}

// GetCacheSize returns the size of the in-memory threat cache
func (ti *ThreatIntelligence) GetCacheSize() int {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	return len(ti.threatCache)
}
