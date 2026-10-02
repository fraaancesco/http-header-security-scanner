package main

import (
	"log"

	_ "http-header-security-scanner/docs"
	"http-header-security-scanner/internal/config"
	"http-header-security-scanner/internal/handler"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title           HTTP Header Security Scanner API
// @version         1.0
// @description     A tool to scan URLs and analyze HTTP security headers configuration

// @contact.name   API Support
// @contact.email  support@example.com

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8081
// @BasePath  /

// runServer and fatal are variables so tests can replace them.
var (
	runServer = func(r *gin.Engine, addr string) error { return r.Run(addr) }
	fatal     = log.Fatal
)

func main() {
	cfg := config.Load()

	gin.SetMode(cfg.Server.Mode)

	r := newRouter(cfg)

	if err := runServer(r, ":"+cfg.Server.Port); err != nil {
		fatal(err)
	}
}

func newRouter(cfg *config.Config) *gin.Engine {
	r := gin.Default()

	scanHandler := handler.NewScanHandler(cfg.Scanner.DefaultTimeout)

	r.POST("/scan", scanHandler.Scan)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return r
}
