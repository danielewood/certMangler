package internal

import (
	"os"

	"gopkg.in/yaml.v3"
)

// BundleConfig represents one bundle configuration entry from the YAML file.
type BundleConfig struct {
	CommonNames []string `yaml:"commonNames"`
	BundleName  string   `yaml:"bundleName"`
	Custodian   string   `yaml:"custodian"`
	Usage       []string `yaml:"usage"`
}

// LoadBundleConfigs loads bundle configuration from the specified YAML file.
func LoadBundleConfigs(path string) ([]BundleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var configs []BundleConfig
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}
