// Package main is a SINGLE-package web app spread across MULTIPLE files in one
// directory, used as a fixture for the Go analyzer's SOUND same-package
// cross-file resolution.
//
// In Go a package is a directory, so a top-level func declared in one file is
// callable as a BARE name (no import, no qualifier) from any other file of the
// same directory. Here the wiring is:
//
//	main.go     r.POST("/import", importHandler)   (bare handler, decl in handler.go)
//	handler.go  importHandler reads c.PostForm, calls parseConfig (bare, decl in parse.go)
//	parse.go    parseConfig parses the input with yaml.Unmarshal (external dep)
//
// So the chain  POST /import -> importHandler -> parseConfig -> yaml.Unmarshal
// crosses TWO file boundaries within the SAME package, using only bare names.
// Ground truth: gopkg.in/yaml.v2 is REACHABLE and TAINTED (see README.md).
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	// Bare same-package cross-file handler: importHandler lives in handler.go.
	r.POST("/import", importHandler)
	http.ListenAndServe(":8080", r)
}
