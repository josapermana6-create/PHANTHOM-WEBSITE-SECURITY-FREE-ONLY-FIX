package storage

import (
	"fmt"
	"time"

	"github.com/phantom-security/ips-service/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DatabaseStore handles persistent database operations
type DatabaseStore struct {
	db *gorm.DB
}

// NewDatabaseStore creates a new database store
func NewDatabaseStore(dbType, dsn string) (*DatabaseStore, error) {
	var dialector gorm.Dialector

	switch dbType {
	case "sqlite":
		dialector = sqlite.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate schemas
	if err := db.AutoMigrate(
		&models.IPReputation{},
		&models.Violation{},
		&models.ThreatIntel{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &DatabaseStore{db: db}, nil
}

// GetIPReputation retrieves IP reputation from database
func (d *DatabaseStore) GetIPReputation(ip string) (*models.IPReputation, error) {
	var rep models.IPReputation
	result := d.db.Where("ip_address = ?", ip).First(&rep)
	
	if result.Error == gorm.ErrRecordNotFound {
		return nil, nil
	}
	
	return &rep, result.Error
}

// CreateOrUpdateIPReputation creates or updates IP reputation
func (d *DatabaseStore) CreateOrUpdateIPReputation(rep *models.IPReputation) error {
	return d.db.Save(rep).Error
}

// RecordViolation records a security violation
func (d *DatabaseStore) RecordViolation(violation *models.Violation) error {
	return d.db.Create(violation).Error
}

// GetViolations retrieves violations for an IP
func (d *DatabaseStore) GetViolations(ip string, since time.Time) ([]models.Violation, error) {
	var violations []models.Violation
	result := d.db.Where("ip_address = ? AND timestamp >= ?", ip, since).
		Order("timestamp DESC").
		Find(&violations)
	
	return violations, result.Error
}

// GetViolationCount gets violation count for an IP
func (d *DatabaseStore) GetViolationCount(ip string, since time.Time) (int64, error) {
	var count int64
	result := d.db.Model(&models.Violation{}).
		Where("ip_address = ? AND timestamp >= ?", ip, since).
		Count(&count)
	
	return count, result.Error
}

// AddThreatIntel adds threat intelligence data
func (d *DatabaseStore) AddThreatIntel(intel *models.ThreatIntel) error {
	return d.db.Save(intel).Error
}

// GetThreatIntel retrieves threat intel for an IP
func (d *DatabaseStore) GetThreatIntel(ip string) (*models.ThreatIntel, error) {
	var intel models.ThreatIntel
	result := d.db.Where("ip_address = ? AND expires_at > ?", ip, time.Now()).
		First(&intel)
	
	if result.Error == gorm.ErrRecordNotFound {
		return nil, nil
	}
	
	return &intel, result.Error
}

// CleanupExpiredThreatIntel removes expired threat intelligence
func (d *DatabaseStore) CleanupExpiredThreatIntel() error {
	return d.db.Where("expires_at < ?", time.Now()).
		Delete(&models.ThreatIntel{}).Error
}

// GetTopThreatIPs gets top threatening IPs
func (d *DatabaseStore) GetTopThreatIPs(limit int) ([]models.IPReputation, error) {
	var ips []models.IPReputation
	result := d.db.Where("reputation_score >= ?", 70).
		Order("reputation_score DESC").
		Limit(limit).
		Find(&ips)
	
	return ips, result.Error
}

// GetStatistics returns database statistics
func (d *DatabaseStore) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalIPs int64
	d.db.Model(&models.IPReputation{}).Count(&totalIPs)
	stats["total_ips"] = totalIPs

	var blacklistedIPs int64
	d.db.Model(&models.IPReputation{}).Where("is_blacklisted = ?", true).Count(&blacklistedIPs)
	stats["blacklisted_ips"] = blacklistedIPs

	var totalViolations int64
	d.db.Model(&models.Violation{}).Count(&totalViolations)
	stats["total_violations"] = totalViolations

	var threatIntelCount int64
	d.db.Model(&models.ThreatIntel{}).Where("expires_at > ?", time.Now()).Count(&threatIntelCount)
	stats["threat_intel_count"] = threatIntelCount

	return stats, nil
}

// Close closes the database connection
func (d *DatabaseStore) Close() error {
	db, err := d.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
