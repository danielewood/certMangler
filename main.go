package main

import (
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"

	"github.com/danielewood/certmangler/internal"
)

func main() {
	cfg := internal.ParseFlags()

	// Handle stdin
	if cfg.IsStdinSet {
		if err := internal.ProcessFile("-", cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Walk directory
	err := filepath.Walk(cfg.InputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := internal.ProcessFile(path, cfg); err != nil {
				log.Warningf("Error processing %s: %v", path, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	// If the exportbundles flag is set, run the bundling exporter and exit.
	if cfg.ExportBundles {
		// Load bundle configuration from bundles.yaml.
		cfgs, err := internal.LoadBundleConfigs(cfg.BundlesConfigPath)
		if err != nil {
			log.Fatalf("Failed to load bundle configurations: %v", err)
		}

		// Ensure the output directory exists.
		if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
			log.Fatalf("Failed to create output directory %s: %v", cfg.OutDir, err)
		}

		if err := internal.ExportBundles(cfgs, cfg.OutDir, cfg.DB); err != nil {
			log.Fatalf("Failed to export bundles: %v", err)
		}

		if err := cfg.DB.DumpDB(); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Otherwise, continue with normal file processing and dump the database.
	if err := cfg.DB.DumpDB(); err != nil {
		log.Fatal(err)
	}
}
