package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server             ServerConfig             `yaml:"server"`
	Redis              RedisConfig              `yaml:"redis"`
	Database           DatabaseConfig           `yaml:"database"`
	ThreatIntelligence ThreatIntelligenceConfig `yaml:"threat_intelligence"`
	Detection          DetectionConfig          `yaml:"detection"`
	GeoIP              GeoIPConfig              `yaml:"geoip"`
	Logging            LoggingConfig            `yaml:"logging"`
	Whitelist          []string                 `yaml:"whitelist"`
	Blacklist          []string                 `yaml:"blacklist"`
}

type ServerConfig struct {
	GRPCPort   int    `yaml:"grpc_port"`
	RESTPort   int    `yaml:"rest_port"`
	Host       string `yaml:"host"`
	EnableGRPC bool   `yaml:"enable_grpc"`
	EnableREST bool   `yaml:"enable_rest"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	Enabled  bool   `yaml:"enabled"`
}

type DatabaseConfig struct {
	Type       string `yaml:"type"`
	SQLitePath string `yaml:"sqlite_path"`
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	Name       string `yaml:"name"`
	User       string `yaml:"user"`
	Password   string `yaml:"password"`
}

type ThreatIntelligenceConfig struct {
	Enabled        bool         `yaml:"enabled"`
	UpdateInterval int          `yaml:"update_interval"`
	Feeds          []ThreatFeed `yaml:"feeds"`
}

type ThreatFeed struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Type    string `yaml:"type"`
	APIKey  string `yaml:"api_key"`
}

type DetectionConfig struct {
	ReputationThreshold       int    `yaml:"reputation_threshold"`
	AutoBlockThreshold        int    `yaml:"auto_block_threshold"`
	AnomalySensitivity        string `yaml:"anomaly_sensitivity"`
	RateLimitWindow           int    `yaml:"rate_limit_window"`
	RateLimitThreshold        int    `yaml:"rate_limit_threshold"`
	ScanDetectionEnabled      bool   `yaml:"scan_detection_enabled"`
	ScanThreshold             int    `yaml:"scan_threshold"`
	BehavioralAnalysisEnabled bool   `yaml:"behavioral_analysis_enabled"`
	UnusualPatternThreshold   int    `yaml:"unusual_pattern_threshold"`
}

type GeoIPConfig struct {
	Enabled        bool     `yaml:"enabled"`
	DatabasePath   string   `yaml:"database_path"`
	BlockCountries []string `yaml:"block_countries"`
	AllowCountries []string `yaml:"allow_countries"`
	BlockVPN       bool     `yaml:"block_vpn"`
	BlockTor       bool     `yaml:"block_tor"`
	BlockProxy     bool     `yaml:"block_proxy"`
}

type LoggingConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path"`
}

// Load loads configuration from a YAML file
func Load(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in config
	configStr := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(configStr), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if !c.Server.EnableGRPC && !c.Server.EnableREST {
		return fmt.Errorf("at least one server type (gRPC or REST) must be enabled")
	}

	if c.Server.GRPCPort < 1 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPCPort)
	}

	if c.Server.RESTPort < 1 || c.Server.RESTPort > 65535 {
		return fmt.Errorf("invalid REST port: %d", c.Server.RESTPort)
	}

	if c.Database.Type != "sqlite" && c.Database.Type != "postgres" {
		return fmt.Errorf("unsupported database type: %s", c.Database.Type)
	}

	sensitivityLevels := map[string]bool{"low": true, "medium": true, "high": true}
	if !sensitivityLevels[strings.ToLower(c.Detection.AnomalySensitivity)] {
		return fmt.Errorf("invalid anomaly sensitivity: %s", c.Detection.AnomalySensitivity)
	}

	return nil
}

// GetDatabaseDSN returns the database connection string
func (c *Config) GetDatabaseDSN() string {
	if c.Database.Type == "sqlite" {
		return c.Database.SQLitePath
	}

	// PostgreSQL DSN
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
	)
}
