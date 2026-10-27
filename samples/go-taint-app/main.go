// Package main is a hand-verified fixture for the Go taint adapter.
//
// It wires several web routes to handlers and exercises the taint pass end to
// end. The ground-truth verdicts (see README.md) are:
//
//	POST /import -> importHandler -> parseYAML -> yaml.Unmarshal   TAINTED
//	POST /safe   -> safeHandler   -> parseTOML -> toml.Unmarshal   not_proven (rebind)
//	POST /static -> staticHandler -> parseTOML -> toml.Unmarshal   not_proven (constant)
//	GET  /echo   -> echoHandler                                     not_proven (no dep sink)
//
// So the dependency gopkg.in/yaml.v2 is TAINTED and github.com/BurntSushi/toml
// stays not_proven. Everything is offline: the dep nodes, calls edges and
// resolved symbols all come from the analyzer with no network.
package main

import (
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

// Config is the structure decoded from request bodies.
type Config struct {
	Name string `yaml:"name" toml:"name"`
}

func main() {
	r := gin.Default()
	r.POST("/import", importHandler)
	r.POST("/safe", safeHandler)
	r.POST("/static", staticHandler)
	http.HandleFunc("/echo", echoHandler)
	http.ListenAndServe(":8080", r)
}

// importHandler (POSITIVE): attacker-controlled PostForm data flows, through a
// cross-function argument binding and a []byte conversion, into yaml.Unmarshal.
func importHandler(c *gin.Context) {
	data := c.PostForm("data")
	parseYAML(data)
}

// parseYAML holds the yaml sink; its parameter carries the attacker value.
func parseYAML(data string) *Config {
	var cfg Config
	yaml.Unmarshal([]byte(data), &cfg)
	return &cfg
}

// safeHandler (NEGATIVE, rebind-to-constant): the source is overwritten by a
// constant before the sink, so no attacker value reaches toml.Unmarshal.
func safeHandler(c *gin.Context) {
	data := c.PostForm("data")
	data = "name = \"default\""
	parseTOML(data)
}

// staticHandler (NEGATIVE, constant-only): the sink sees only a literal.
func staticHandler(c *gin.Context) {
	parseTOML("name = \"static\"")
}

// parseTOML holds the toml sink; reached only by the two negative routes.
func parseTOML(data string) *Config {
	var cfg Config
	toml.Unmarshal([]byte(data), &cfg)
	return &cfg
}

// echoHandler (NEGATIVE, net/http no dep sink): reads an attacker source but
// only echoes it back -- it never reaches a dependency call.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Write([]byte(name))
}
