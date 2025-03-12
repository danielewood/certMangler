package internal

import (
	"flag"
	"os"

	"github.com/cloudflare/cfssl/log"
)

func parseLogLevel(level string) int {
	switch level {
	case "debug":
		return log.LevelDebug
	case "info":
		return log.LevelInfo
	case "warning":
		return log.LevelWarning
	case "error":
		return log.LevelError
	case "critical":
		return log.LevelCritical
	case "fatal":
		return log.LevelFatal
	default:
		return log.LevelDebug // Default to debug level
	}
}

func ParseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.InputPath, "path", "", "Path to certificate file or directory (use '-' for stdin)")
	flag.StringVar(&cfg.BundlesConfigPath, "bundles-config", "./bundles.yaml", "Path to bundles configuration YAML")
	flag.StringVar(&cfg.LogLevel, "loglevel", "debug", "Log level (debug, info, warning, error)")
	flag.StringVar(&cfg.PasswordFile, "password-file", "", "File containing passwords (one per line)")
	flag.StringVar(&cfg.PasswordList, "passwords", "", "Comma-separated list of passwords")
	flag.BoolVar(&cfg.ExportBundles, "exportbundles", false, "Export certificate bundles")
	flag.StringVar(&cfg.OutDir, "out", "./bundles", "Directory to write exported bundles")
	flag.StringVar(&cfg.DBPath, "dbpath", "", "Path to SQLite database file (leave empty for in-memory)")
	flag.Parse()

	// Set up global logger
	level := parseLogLevel(cfg.LogLevel)
	log.Level = level

	cfg.Passwords = ProcessPasswords(cfg.PasswordList, cfg.PasswordFile)

	// Initialize the database
	db, err := NewDB(cfg.DBPath)
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		os.Exit(1)
	}
	cfg.DB = db

	// Load bundle configurations
	bundleConfigs, err := LoadBundleConfigs(cfg.BundlesConfigPath)
	if err != nil {
		log.Warningf("Failed to load bundle configurations: %v", err)
		bundleConfigs = []BundleConfig{}
	}
	cfg.BundleConfigs = bundleConfigs

	// Handle stdin
	if cfg.InputPath == "-" {
		cfg.IsStdinSet = true
	} else if cfg.InputPath == "" {
		flag.Usage()
		log.Fatal("No input path specified")
	} else if _, err := os.Stat(cfg.InputPath); os.IsNotExist(err) {
		log.Fatalf("Input path %s does not exist", cfg.InputPath)
	} else if _, err := os.Stat(cfg.InputPath); err != nil {
		log.Fatalf("Error accessing input path %s: %v", cfg.InputPath, err)
	}
	return cfg
}
