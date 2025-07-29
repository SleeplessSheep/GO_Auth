package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Security SecurityConfig `mapstructure:"security"`
	LDAP     LDAPConfig     `mapstructure:"ldap"`
	Google   GoogleConfig   `mapstructure:"google"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host" default:"0.0.0.0"`
	Port         int           `mapstructure:"port" default:"8080"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" default:"10s"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" default:"10s"`
	Environment  string        `mapstructure:"environment" default:"development"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string `mapstructure:"host" default:"localhost"`
	Port     int    `mapstructure:"port" default:"5432"`
	Name     string `mapstructure:"name" default:"auth_db"`
	User     string `mapstructure:"user" default:"postgres"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode" default:"disable"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string `mapstructure:"host" default:"localhost"`
	Port     int    `mapstructure:"port" default:"6379"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db" default:"0"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTIssuer           string        `mapstructure:"jwt_issuer" default:"auth-server"`
	JWTAudience         string        `mapstructure:"jwt_audience" default:"auth-clients"`
	AccessTokenExpiry   time.Duration `mapstructure:"access_token_expiry" default:"15m"`
	RefreshTokenExpiry  time.Duration `mapstructure:"refresh_token_expiry" default:"720h"`
	AuthCodeExpiry      time.Duration `mapstructure:"auth_code_expiry" default:"10m"`
	SessionExpiry       time.Duration `mapstructure:"session_expiry" default:"24h"`
	MasterEncryptionKey string        `mapstructure:"master_encryption_key"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	RateLimitRequests int           `mapstructure:"rate_limit_requests" default:"100"`
	RateLimitWindow   time.Duration `mapstructure:"rate_limit_window" default:"1h"`
	PasswordMinLength int           `mapstructure:"password_min_length" default:"8"`
	MaxLoginAttempts  int           `mapstructure:"max_login_attempts" default:"5"`
	LockoutDuration   time.Duration `mapstructure:"lockout_duration" default:"30m"`
}

// LDAPConfig holds LDAP configuration
type LDAPConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port" default:"389"`
	BaseDN       string `mapstructure:"base_dn"`
	BindDN       string `mapstructure:"bind_dn"`
	BindPassword string `mapstructure:"bind_password"`
	UserFilter   string `mapstructure:"user_filter" default:"(uid=%s)"`
	AdminGroup   string `mapstructure:"admin_group" default:"admin"`
}

// GoogleConfig holds Google OAuth configuration
type GoogleConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"`
}

// Load loads configuration from environment variables and config files
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	
	// Set environment variable prefix and configure replacer
	viper.SetEnvPrefix("AUTH")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	var config Config
	
	// Read config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Unmarshal into config struct
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate critical configuration
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "auth_db")
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "postgres")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("auth.jwt_issuer", "auth-server")
	viper.SetDefault("auth.jwt_audience", "auth-clients")
	viper.SetDefault("auth.access_token_expiry", "15m")
	viper.SetDefault("auth.refresh_token_expiry", "720h")
	viper.SetDefault("auth.master_encryption_key", "")
}

func validate(config *Config) error {
	if config.Database.Name == "" {
		return fmt.Errorf("database name is required")
	}
	if config.Auth.MasterEncryptionKey == "" && config.Server.Environment == "production" {
		return fmt.Errorf("master encryption key is required in production")
	}
	return nil
}