// handler.go is a SEPARATE file of the SAME package (main) as main.go and
// parse.go. importHandler is referenced as a bare name from main.go's route
// registration, and it calls parseConfig -- declared in yet another file
// (parse.go) -- as a bare name with no qualifier.
package main

import "github.com/gin-gonic/gin"

// importHandler is the route handler for POST /import. It reads an
// attacker-controlled request value and passes it, by a bare same-package
// cross-file call, to parseConfig.
func importHandler(c *gin.Context) {
	data := c.PostForm("data")
	parseConfig(data)
}
