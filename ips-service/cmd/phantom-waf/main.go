package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/phantom-security/ips-service/internal/api/rest"
	"github.com/phantom-security/ips-service/internal/config"
	"github.com/phantom-security/ips-service/internal/detector"
	"github.com/phantom-security/ips-service/internal/intelligence"
	"github.com/phantom-security/ips-service/internal/storage"
	"github.com/phantom-security/ips-service/internal/waf"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	logger.Info("Starting Phantom WAF Service (IPS + WAF)...")

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config/config.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Set log level from config
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err == nil {
		logger.SetLevel(level)
	}

	logger.Info("Configuration loaded successfully")

	// Initialize database
	logger.Info("Initializing database...")
	dbStore, err := storage.NewDatabaseStore(cfg.Database.Type, cfg.GetDatabaseDSN())
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer dbStore.Close()
	logger.Info("Database initialized")

	// Initialize Redis
	logger.Info("Initializing Redis cache...")
	redisStore, err := storage.NewRedisStore(
		cfg.Redis.Host,
		cfg.Redis.Password,
		cfg.Redis.DB,
		cfg.Redis.Enabled,
	)
	if err != nil {
		logger.Warnf("Failed to initialize Redis (continuing without cache): %v", err)
		redisStore, _ = storage.NewRedisStore("", "", 0, false)
	} else {
		defer redisStore.Close()
		logger.Info("Redis cache initialized")
	}

	// Initialize threat intelligence
	logger.Info("Initializing threat intelligence...")
	threatIntel := intelligence.NewThreatIntelligence(
		&cfg.ThreatIntelligence,
		dbStore,
		redisStore,
		logger,
	)

	// Start threat intelligence updates in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go threatIntel.Start(ctx)

	// Initialize IP detector
	logger.Info("Initializing IP detector...")
	ipDetector := detector.NewIPDetector(
		cfg,
		dbStore,
		redisStore,
		threatIntel,
		logger,
	)
	logger.Info("IP detector initialized")

	// Initialize WAF Request Analyzer
	logger.Info("Initializing WAF analyzer...")
	wafAnalyzer := waf.NewRequestAnalyzer(cfg, ipDetector)
	logger.Info("WAF analyzer initialized with all detection modules")

	// Initialize whitelist/blacklist from config
	logger.Info("Configuring IP lists...")
	for _, ip := range cfg.Whitelist {
		if err := redisStore.AddToWhitelist(ctx, ip); err != nil {
			logger.Warnf("Failed to whitelist %s: %v", ip, err)
		}
	}
	for _, ip := range cfg.Blacklist {
		if err := redisStore.AddToBlacklist(ctx, ip, 0); err != nil {
			logger.Warnf("Failed to blacklist %s: %v", ip, err)
		}
	}
	logger.Infof("Configured %d whitelisted and %d blacklisted IPs", len(cfg.Whitelist), len(cfg.Blacklist))

	// Start REST API server
	if cfg.Server.EnableREST {
		logger.Info("Starting REST API server...")
		restServer := rest.NewServer(cfg, ipDetector, wafAnalyzer, dbStore, redisStore, logger)
		
		// Start server in goroutine
		go func() {
			if err := restServer.Start(); err != nil {
				logger.Fatalf("REST server error: %v", err)
			}
		}()

		logger.Infof("REST API server started on port %d", cfg.Server.RESTPort)
		logger.Info("Available endpoints:")
		logger.Info("  POST /api/v1/analyze/full - Full WAF + IPS analysis")
		logger.Info("  POST /api/v1/analyze/waf  - WAF-only analysis")
		logger.Info("  POST /api/v1/analyze/ips  - IPS-only analysis")
		logger.Info("  POST /api/v1/csrf/token   - Generate CSRF token")
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	logger.Info("Phantom WAF Service is running. Press Ctrl+C to stop.")
	
	<-sigChan
	logger.Info("Shutdown signal received, cleaning up...")

	// Graceful shutdown
	cancel()
	logger.Info("Phantom WAF Service stopped")
}
