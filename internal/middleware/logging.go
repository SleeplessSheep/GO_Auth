package middleware

import (
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// StructuredLogger returns a gin.LoggerWithFormatter middleware with structured logging
func StructuredLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Use structured logging for production
		logEntry := logrus.WithFields(logrus.Fields{
			"timestamp":      param.TimeStamp.Format(time.RFC3339Nano),
			"method":         param.Method,
			"path":           param.Path,
			"status_code":    param.StatusCode,
			"latency_ms":     param.Latency.Milliseconds(),
			"client_ip":      param.ClientIP,
			"user_agent":     param.Request.UserAgent(),
			"correlation_id": param.Keys["correlation_id"],
			"pod_name":       os.Getenv("POD_NAME"),
			"pod_ip":         os.Getenv("POD_IP"),
		})

		if param.ErrorMessage != "" {
			logEntry = logEntry.WithField("error", param.ErrorMessage)
		}

		// Log level based on status code
		switch {
		case param.StatusCode >= 500:
			logEntry.Error("HTTP request completed")
		case param.StatusCode >= 400:
			logEntry.Warn("HTTP request completed")
		default:
			logEntry.Info("HTTP request completed")
		}

		return "" // We've already logged, no need to return string
	})
}

// CorrelationID middleware adds correlation ID to requests for tracing
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if correlation ID exists in headers
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}
		
		// Store in context for handlers to use
		c.Set("correlation_id", correlationID)
		
		// Return in response headers
		c.Header("X-Correlation-ID", correlationID)
		
		c.Next()
	}
}

// ErrorLogger middleware for structured error logging
func ErrorLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log any errors that occurred during request processing
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				logrus.WithFields(logrus.Fields{
					"correlation_id": c.GetString("correlation_id"),
					"method":         c.Request.Method,
					"path":           c.Request.URL.Path,
					"client_ip":      c.ClientIP(),
					"error_type":     err.Type,
					"error_message":  err.Error(),
					"pod_name":       os.Getenv("POD_NAME"),
					"user_id":        c.GetString("user_id"),
				}).Error("Request processing error")
			}
		}
	}
}

// SecurityLogger middleware for security event logging
func SecurityLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		
		// Log security-relevant requests
		if isSecurityRelevant(c.Request.URL.Path) {
			logrus.WithFields(logrus.Fields{
				"event_type":     "security_request",
				"correlation_id": c.GetString("correlation_id"),
				"method":         c.Request.Method,
				"path":           c.Request.URL.Path,
				"status_code":    c.Writer.Status(),
				"client_ip":      c.ClientIP(),
				"user_agent":     c.Request.UserAgent(),
				"user_id":        c.GetString("user_id"),
				"duration_ms":    time.Since(start).Milliseconds(),
				"pod_name":       os.Getenv("POD_NAME"),
			}).Info("Security-relevant request")
		}
	}
}

// isSecurityRelevant checks if a path is security-relevant
func isSecurityRelevant(path string) bool {
	securityPaths := []string{
		"/auth/login",
		"/auth/register", 
		"/oauth/authorize",
		"/oauth/token",
		"/admin/",
	}
	
	for _, secPath := range securityPaths {
		if len(path) >= len(secPath) && path[:len(secPath)] == secPath {
			return true
		}
	}
	return false
}