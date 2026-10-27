// Package main is a tiny web app used as a fixture for the Go analyzer.
//
// It wires one Gin route to a handler, which calls a local helper that parses
// input with a dependency (yaml). It also contains one method call on a value
// of unknown type, which the analyzer must leave unresolved (no edge).
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

// Config is the structure decoded from request bodies.
type Config struct {
	Name string `yaml:"name"`
}

func main() {
	r := gin.Default()
	r.POST("/import", importHandler)
	http.ListenAndServe(":8080", r)
}

// importHandler is the Gin handler for POST /import. It delegates parsing to a
// local helper and also performs a method call on the request context whose
// type the single-file analyzer does not track.
func importHandler(c *gin.Context) {
	data := []byte("name: example")
	loadConfig(data)
	c.somethingUnknown()
}

// loadConfig parses YAML into a Config using the yaml dependency.
func loadConfig(data []byte) *Config {
	var cfg Config
	yaml.Unmarshal(data, &cfg)
	return &cfg
}
