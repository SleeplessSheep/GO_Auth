package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	authEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_events_total",
			Help: "Total number of authentication events",
		},
		[]string{"event_type", "success"},
	)

	activeSessionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_active_sessions",
			Help: "Number of active user sessions",
		},
	)

	databaseConnectionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_database_connections",
			Help: "Number of active database connections",
		},
	)

	redisConnectionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_redis_connections",
			Help: "Number of active Redis connections",
		},
	)
)

// PrometheusMiddleware creates a middleware for collecting HTTP metrics
func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Process request
		c.Next()

		// Record metrics
		status := strconv.Itoa(c.Writer.Status())
		duration := time.Since(start).Seconds()

		httpRequestsTotal.WithLabelValues(method, path, status).Inc()
		httpRequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}

// RecordAuthEvent records authentication events
func RecordAuthEvent(eventType string, success bool) {
	successStr := strconv.FormatBool(success)
	authEventsTotal.WithLabelValues(eventType, successStr).Inc()
}

// UpdateActiveSessions updates the active sessions gauge
func UpdateActiveSessions(count float64) {
	activeSessionsGauge.Set(count)
}

// UpdateDatabaseConnections updates the database connections gauge
func UpdateDatabaseConnections(count float64) {
	databaseConnectionsGauge.Set(count)
}

// UpdateRedisConnections updates the Redis connections gauge
func UpdateRedisConnections(count float64) {
	redisConnectionsGauge.Set(count)
}