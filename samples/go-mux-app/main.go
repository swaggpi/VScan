// Package main is a hand-verified fixture for gorilla/mux route detection.
//
// The mux router registers a route with the chained
// ``HandleFunc(path, handler).Methods("POST")`` pattern. The analyzer must:
//
//	POST /import -> importHandler -> parseYAML -> yaml.Unmarshal   TAINTED
//
// ``importHandler`` reads attacker-controlled ``r.FormValue("data")`` and flows
// it, via a cross-function argument binding and a []byte conversion, into
// ``yaml.Unmarshal``. So gopkg.in/yaml.v2 is TAINTED. Everything is offline.
package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v2"
)

// Config is the structure decoded from request bodies.
type Config struct {
	Name string `yaml:"name"`
}

func main() {
	r := mux.NewRouter()
	// Chained .Methods pins the verb: this registers exactly POST /import.
	r.HandleFunc("/import", importHandler).Methods("POST")
	http.ListenAndServe(":8080", r)
}

// importHandler (POSITIVE): attacker-controlled form data flows into
// yaml.Unmarshal via the parseYAML helper.
func importHandler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	parseYAML(data)
}

// parseYAML holds the yaml sink; its parameter carries the attacker value.
func parseYAML(data string) *Config {
	var cfg Config
	yaml.Unmarshal([]byte(data), &cfg)
	return &cfg
}
