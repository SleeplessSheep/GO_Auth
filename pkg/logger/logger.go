package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
}

// New creates a new logger instance
func New(environment string) *Logger {
	log := logrus.New()
	
	// Set output to stdout for container logging
	log.SetOutput(os.Stdout)
	
	// Add pod information to all logs
	podName := os.Getenv("POD_NAME")
	podIP := os.Getenv("POD_IP")
	
	// Configure based on environment
	if environment == "production" {
		log.SetLevel(logrus.InfoLevel)
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	} else {
		log.SetLevel(logrus.DebugLevel)
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
		})
	}
	
	// Add default fields for all logs
	if podName != "" {
		log = log.WithField("pod_name", podName).Logger
	}
	if podIP != "" {
		log = log.WithField("pod_ip", podIP).Logger
	}

	return &Logger{Logger: log}
}

// WithFields creates a new logger entry with the given fields
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

// WithError creates a new logger entry with error field
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// LogAuthEvent logs authentication events
func (l *Logger) LogAuthEvent(userID, event, ip string, success bool) {
	l.WithFields(map[string]interface{}{
		"user_id": userID,
		"event":   event,
		"ip":      ip,
		"success": success,
		"type":    "auth_event",
	}).Info("Authentication event")
}

// LogKeyOperation logs key management operations
func (l *Logger) LogKeyOperation(operation, keyID string) {
	l.WithFields(map[string]interface{}{
		"operation": operation,
		"key_id":    keyID,
		"type":      "key_operation",
	}).Info("Key operation")
}

// LogSystemEvent logs system events
func (l *Logger) LogSystemEvent(event string, details map[string]interface{}) {
	fields := map[string]interface{}{
		"event": event,
		"type":  "system_event",
	}
	for k, v := range details {
		fields[k] = v
	}
	l.WithFields(fields).Info("System event")
}