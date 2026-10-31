// parse.go is a SEPARATE file of the SAME package (main). parseConfig is the
// leaf of the cross-file chain: it holds the yaml sink and is reached only by
// the bare same-package call from importHandler in handler.go.
package main

import "gopkg.in/yaml.v2"

// Config is the structure decoded from request bodies.
type Config struct {
	Name string `yaml:"name"`
}

// parseConfig parses YAML into a Config with the yaml dependency. Its parameter
// carries the attacker value that flowed in, cross-file, from importHandler.
func parseConfig(data string) *Config {
	var cfg Config
	yaml.Unmarshal([]byte(data), &cfg)
	return &cfg
}
