package database

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// MigrationManager handles database schema migrations
type MigrationManager struct {
	db      *DB
	migrate *migrate.Migrate
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *DB) (*MigrationManager, error) {
	// Get the underlying *sql.DB from GORM
	sqlDB, err := db.DB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB from GORM: %w", err)
	}

	// Create postgres driver instance
	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations", // Source URL
		"postgres",          // Database name
		driver,             // Database driver
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return &MigrationManager{
		db:      db,
		migrate: m,
	}, nil
}

// Up runs all pending migrations
func (mm *MigrationManager) Up() error {
	err := mm.migrate.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	return nil
}

// Down rolls back all migrations (WARNING: destructive!)
func (mm *MigrationManager) Down() error {
	err := mm.migrate.Down()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to rollback migrations: %w", err)
	}
	return nil
}

// Steps runs a specific number of migrations (positive = up, negative = down)
func (mm *MigrationManager) Steps(n int) error {
	err := mm.migrate.Steps(n)
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to run %d migration steps: %w", n, err)
	}
	return nil
}

// Version returns the current migration version
func (mm *MigrationManager) Version() (uint, bool, error) {
	version, dirty, err := mm.migrate.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, fmt.Errorf("failed to get migration version: %w", err)
	}
	return version, dirty, nil
}

// Force sets the migration version without running any migrations
// Use with caution - typically for fixing broken migration states
func (mm *MigrationManager) Force(version int) error {
	err := mm.migrate.Force(version)
	if err != nil {
		return fmt.Errorf("failed to force migration version %d: %w", version, err)
	}
	return nil
}

// Close closes the migration manager
func (mm *MigrationManager) Close() error {
	sourceErr, dbErr := mm.migrate.Close()
	if sourceErr != nil {
		return fmt.Errorf("failed to close migration source: %w", sourceErr)
	}
	if dbErr != nil {
		return fmt.Errorf("failed to close migration database: %w", dbErr)
	}
	return nil
}

// MigrationInfo holds information about migration status
type MigrationInfo struct {
	CurrentVersion uint
	IsDirty        bool
	HasMigrations  bool
}

// GetMigrationInfo returns current migration status information
func (mm *MigrationManager) GetMigrationInfo() (*MigrationInfo, error) {
	version, dirty, err := mm.Version()
	if err != nil {
		return nil, err
	}

	hasMigrations := true
	if errors.Is(err, migrate.ErrNilVersion) {
		hasMigrations = false
		version = 0
		dirty = false
	}

	return &MigrationInfo{
		CurrentVersion: version,
		IsDirty:        dirty,
		HasMigrations:  hasMigrations,
	}, nil
}