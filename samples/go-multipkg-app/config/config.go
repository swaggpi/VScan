// Package config parses application config with the external yaml dependency.
// It is a local package reached cross-package from handlers.Import.
package config

import "gopkg.in/yaml.v2"

// Config is the structure decoded from request bodies.
type Config struct {
	Name string `yaml:"name"`
}

// Load parses YAML into a Config using the yaml dependency. This is the leaf of
// the cross-package chain that reaches the external dependency.
func Load(data []byte) *Config {
	var cfg Config
	yaml.Unmarshal(data, &cfg)
	return &cfg
}
