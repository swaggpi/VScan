// Package handlers holds HTTP handlers. It is imported by the root package by
// its local path (github.com/example/multipkg/handlers) and calls into another
// local package (config).
package handlers

import (
	"github.com/example/multipkg/config"
	"github.com/gin-gonic/gin"
)

// Import is the cross-package route handler for POST /import. It delegates
// parsing to the config package (another local package of the same module).
func Import(c *gin.Context) {
	data := []byte("name: example")
	config.Load(data)
}

// helper is unexported, so it can never be reached as handlers.helper from
// another package (it is omitted from the cross-package export index).
func helper() {}
