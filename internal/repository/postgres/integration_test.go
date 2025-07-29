package postgres_test

import (
	"context"
	"net"
	"testing"
	"time"

	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/models"
	"auth/internal/repository"
	"auth/internal/repository/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/logger"
)

// Note: These tests require a running PostgreSQL database
// They are integration tests, not unit tests

func setupTestDB(t *testing.T) repository.Manager {
	// Use test database configuration
	cfg := &config.DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "auth_db", // In real tests, you'd use a separate test database
		User:     "postgres",
		Password: "postgres",
		SSLMode:  "disable",
	}
	
	db, err := database.New(cfg, logger.Error)
	require.NoError(t, err)
	
	return postgres.NewManager(db)
}

func TestUserRepository_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := setupTestDB(t)
	defer manager.Close()
	
	ctx := context.Background()
	userRepo := manager.Repository().User
	
	// Test Create
	user := &models.User{
		Email:      "test@example.com",
		TFAEnabled: false,
		IsActive:   true,
	}
	
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.NotZero(t, user.CreatedAt)
	
	// Test GetByID
	retrieved, err := userRepo.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, retrieved.Email)
	assert.Equal(t, user.TFAEnabled, retrieved.TFAEnabled)
	assert.Equal(t, user.IsActive, retrieved.IsActive)
	
	// Test GetByEmail
	retrieved, err = userRepo.GetByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrieved.ID)
	
	// Test Update
	retrieved.TFAEnabled = true
	err = userRepo.Update(ctx, retrieved)
	require.NoError(t, err)
	
	// Verify update
	updated, err := userRepo.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, updated.TFAEnabled)
	
	// Test UpdateLastLogin
	loginTime := time.Now()
	err = userRepo.UpdateLastLogin(ctx, user.ID, loginTime)
	require.NoError(t, err)
	
	// Verify last login update
	updated, err = userRepo.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.NotNil(t, updated.LastLoginAt)
	assert.WithinDuration(t, loginTime, *updated.LastLoginAt, time.Second)
	
	// Test Count
	count, err := userRepo.Count(ctx)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0))
	
	// Test List
	users, err := userRepo.List(ctx, 10, 0)
	require.NoError(t, err)
	assert.Greater(t, len(users), 0)
	
	// Cleanup
	err = userRepo.Delete(ctx, user.ID)
	require.NoError(t, err)
}

func TestOAuthClientRepository_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := setupTestDB(t)
	defer manager.Close()
	
	ctx := context.Background()
	clientRepo := manager.Repository().OAuthClient
	
	// Test Create
	client := &models.OAuthClient{
		ClientID:         "test-client-" + uuid.New().String(),
		ClientSecretHash: "hashed-secret",
		ClientName:       "Test Client",
		RedirectURIs:     models.StringArray{"http://localhost:3000/callback"},
		Scopes:           models.StringArray{"openid", "profile"},
		IsActive:         true,
		IsConfidential:   true,
		RequirePKCE:      true,
	}
	
	err := clientRepo.Create(ctx, client)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, client.ID)
	
	// Test GetByClientID
	retrieved, err := clientRepo.GetByClientID(ctx, client.ClientID)
	require.NoError(t, err)
	assert.Equal(t, client.ClientName, retrieved.ClientName)
	assert.Equal(t, client.IsActive, retrieved.IsActive)
	assert.Equal(t, client.RequirePKCE, retrieved.RequirePKCE)
	
	// Test scopes array
	assert.Equal(t, len(client.Scopes), len(retrieved.Scopes))
	if len(retrieved.Scopes) >= 2 {
		assert.Contains(t, []string(retrieved.Scopes), "openid")
		assert.Contains(t, []string(retrieved.Scopes), "profile")
	}
	
	// Test SetActive
	err = clientRepo.SetActive(ctx, client.ClientID, false)
	require.NoError(t, err)
	
	// Verify deactivation
	updated, err := clientRepo.GetByClientID(ctx, client.ClientID)
	require.NoError(t, err)
	assert.False(t, updated.IsActive)
	
	// Test Count
	count, err := clientRepo.Count(ctx)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0))
	
	// Cleanup
	err = clientRepo.Delete(ctx, client.ID)
	require.NoError(t, err)
}

func TestLoginAttemptRepository_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := setupTestDB(t)
	defer manager.Close()
	
	ctx := context.Background()
	attemptRepo := manager.Repository().LoginAttempt
	
	// Test Create
	ip := net.ParseIP("192.168.1.100")
	attempt := &models.LoginAttempt{
		Email:       "test@example.com",
		IPAddress:   ip,
		Successful:  false,
		AttemptedAt: time.Now(),
	}
	
	err := attemptRepo.Create(ctx, attempt)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, attempt.ID)
	
	// Test GetByEmail
	attempts, err := attemptRepo.GetByEmail(ctx, attempt.Email, 10, 0)
	require.NoError(t, err)
	assert.Greater(t, len(attempts), 0)
	
	// Test GetByIP
	attempts, err = attemptRepo.GetByIP(ctx, ip, 10, 0)
	require.NoError(t, err)
	assert.Greater(t, len(attempts), 0)
	
	// Test CountRecentFailures
	since := time.Now().Add(-1 * time.Hour)
	count, err := attemptRepo.CountRecentFailures(ctx, attempt.Email, ip, since)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0))
	
	// Test GetRecentFailures
	failures, err := attemptRepo.GetRecentFailures(ctx, attempt.Email, ip, since)
	require.NoError(t, err)
	assert.Greater(t, len(failures), 0)
	
	// Cleanup - delete old attempts (older than now, so it should delete our test data)
	deleted, err := attemptRepo.DeleteOld(ctx, time.Now().Add(1*time.Minute))
	require.NoError(t, err)
	assert.Greater(t, deleted, int64(0))
}

func TestTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := setupTestDB(t)
	defer manager.Close()
	
	ctx := context.Background()
	
	// Test successful transaction
	tx, err := manager.Transaction(ctx)
	require.NoError(t, err)
	
	user := &models.User{
		Email:    "transaction-test@example.com",
		IsActive: true,
	}
	
	err = tx.Repository().User.Create(ctx, user)
	require.NoError(t, err)
	
	err = tx.Commit()
	require.NoError(t, err)
	
	// Verify user was created
	created, err := manager.Repository().User.GetByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.Email, created.Email)
	
	// Test rollback transaction
	tx, err = manager.Transaction(ctx)
	require.NoError(t, err)
	
	user2 := &models.User{
		Email:    "rollback-test@example.com",
		IsActive: true,
	}
	
	err = tx.Repository().User.Create(ctx, user2)
	require.NoError(t, err)
	
	err = tx.Rollback()
	require.NoError(t, err)
	
	// Verify user was not created due to rollback
	_, err = manager.Repository().User.GetByEmail(ctx, user2.Email)
	assert.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
	
	// Cleanup
	err = manager.Repository().User.Delete(ctx, created.ID)
	require.NoError(t, err)
}