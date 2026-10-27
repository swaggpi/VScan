// Package main is a hand-verified fixture for gofiber/fiber route detection.
//
// fiber registers routes with verb methods (``app.Post(path, handler)``) just
// like gin, and its handler signature is ``func(c *fiber.Ctx) error``. The
// analyzer must:
//
//	POST /import -> importHandler -> parseYAML -> yaml.Unmarshal   TAINTED
//
// ``importHandler`` reads attacker-controlled ``c.FormValue("data")`` and flows
// it, via a cross-function argument binding and a []byte conversion, into
// ``yaml.Unmarshal``. So gopkg.in/yaml.v2 is TAINTED. Everything is offline.
package main

import (
	"github.com/gofiber/fiber/v2"
	"gopkg.in/yaml.v2"
)

// Config is the structure decoded from request bodies.
type Config struct {
	Name string `yaml:"name"`
}

func main() {
	app := fiber.New()
	app.Post("/import", importHandler)
	app.Listen(":8080")
}

// importHandler (POSITIVE): attacker-controlled form data flows into
// yaml.Unmarshal via the parseYAML helper.
func importHandler(c *fiber.Ctx) error {
	data := c.FormValue("data")
	parseYAML(data)
	return nil
}

// parseYAML holds the yaml sink; its parameter carries the attacker value.
func parseYAML(data string) *Config {
	var cfg Config
	yaml.Unmarshal([]byte(data), &cfg)
	return &cfg
}
