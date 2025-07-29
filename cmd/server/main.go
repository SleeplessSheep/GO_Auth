package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/middleware"
	"auth/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	gormlogger "gorm.io/gorm/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	appLogger := logger.New(cfg.Server.Environment)
	appLogger.LogSystemEvent("server_starting", map[string]interface{}{
		"environment": cfg.Server.Environment,
		"port":        cfg.Server.Port,
	})

	// Set Gin mode based on environment
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize database
	var logLevel gormlogger.LogLevel
	if cfg.Server.Environment == "production" {
		logLevel = gormlogger.Error
	} else {
		logLevel = gormlogger.Info
	}

	db, err := database.New(&cfg.Database, logLevel)
	if err != nil {
		appLogger.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	// Run database migrations
	migrationManager, err := database.NewMigrationManager(db)
	if err != nil {
		appLogger.WithError(err).Fatal("Failed to create migration manager")
	}
	defer migrationManager.Close()

	// Get current migration status
	migrationInfo, err := migrationManager.GetMigrationInfo()
	if err != nil {
		appLogger.WithError(err).Fatal("Failed to get migration info")
	}

	appLogger.WithFields(map[string]interface{}{
		"current_version": migrationInfo.CurrentVersion,
		"is_dirty":        migrationInfo.IsDirty,
		"has_migrations":  migrationInfo.HasMigrations,
	}).Info("Database migration status")

	// Run pending migrations
	if err := migrationManager.Up(); err != nil {
		appLogger.WithError(err).Fatal("Failed to run database migrations")
	}

	appLogger.Info("Database migrations completed successfully")

	// Create Gin router
	r := gin.New()
	
	// Add middleware
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(middleware.PrometheusMiddleware())

	// Health check endpoint
	r.GET("/healthz", func(c *gin.Context) {
		if err := db.Health(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "database connection failed",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":      "healthy",
			"environment": cfg.Server.Environment,
			"version":     "1.0.0",
		})
	})

	// Metrics endpoint for Prometheus
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Temporary ping endpoint for testing
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		appLogger.WithFields(map[string]interface{}{
			"host": cfg.Server.Host,
			"port": cfg.Server.Port,
		}).Info("Starting HTTP server")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down server...")

	// Give the server 30 seconds to finish ongoing requests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		appLogger.WithError(err).Fatal("Server forced to shutdown")
	}

	appLogger.LogSystemEvent("server_stopped", map[string]interface{}{
		"reason": "graceful_shutdown",
	})
}
