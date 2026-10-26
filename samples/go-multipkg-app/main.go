// Package main is a tiny multi-package web app used as a fixture for the Go
// analyzer's SOUND cross-package resolution.
//
// It wires one Gin route to a handler that lives in a LOCAL subpackage
// (handlers.Import), which in turn calls into another local package (config)
// that parses input with an external dependency (yaml). The full chain
//
//	POST /import -> handlers.Import -> config.Load -> yaml.Unmarshal
//
// therefore crosses two package boundaries before reaching the dependency.
package main

import (
	"net/http"

	"github.com/example/multipkg/handlers"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	// Cross-package handler: handlers.Import lives in the local handlers pkg.
	r.POST("/import", handlers.Import)
	http.ListenAndServe(":8080", r)
}
