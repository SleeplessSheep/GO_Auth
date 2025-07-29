package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/models"
	"auth/internal/repository/postgres"
	"github.com/google/uuid"
	"gorm.io/gorm/logger"
)

// This example demonstrates how to use the repository pattern
// Run this with: go run examples/repository_usage.go
func main() {
	// Load configuration (you could also create config manually for examples)
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.New(&cfg.Database, logger.Info)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create repository manager
	repoManager := postgres.NewManager(db)
	defer repoManager.Close()

	ctx := context.Background()

	// Example 1: User Management
	fmt.Println("=== User Management Example ===")
	
	// Create a new user
	user := &models.User{
		Email:      fmt.Sprintf("example+%d@test.com", time.Now().Unix()),
		TFAEnabled: false,
		IsActive:   true,
	}

	err = repoManager.Repository().User.Create(ctx, user)
	if err != nil {
		log.Printf("Failed to create user: %v", err)
	} else {
		fmt.Printf("Created user: %s (ID: %s)\n", user.Email, user.ID)
	}

	// Retrieve user by email
	retrievedUser, err := repoManager.Repository().User.GetByEmail(ctx, user.Email)
	if err != nil {
		log.Printf("Failed to retrieve user: %v", err)
	} else {
		fmt.Printf("Retrieved user: %s, Active: %t\n", retrievedUser.Email, retrievedUser.IsActive)
	}

	// Update last login
	err = repoManager.Repository().User.UpdateLastLogin(ctx, user.ID, time.Now())
	if err != nil {
		log.Printf("Failed to update last login: %v", err)
	} else {
		fmt.Println("Updated user last login time")
	}

	// Example 2: OAuth Client Management
	fmt.Println("\n=== OAuth Client Management Example ===")
	
	client := &models.OAuthClient{
		ClientID:         fmt.Sprintf("client-%d", time.Now().Unix()),
		ClientSecretHash: "hashed-secret-example",
		ClientName:       "Example Client Application",
		RedirectURIs:     models.StringArray{"http://localhost:3000/callback", "http://localhost:3000/auth/callback"},
		Scopes:           models.StringArray{"openid", "profile", "email"},
		IsActive:         true,
		IsConfidential:   true,
		RequirePKCE:      true,
	}

	err = repoManager.Repository().OAuthClient.Create(ctx, client)
	if err != nil {
		log.Printf("Failed to create OAuth client: %v", err)
	} else {
		fmt.Printf("Created OAuth client: %s (ID: %s)\n", client.ClientName, client.ID)
		fmt.Printf("Redirect URIs: %v\n", []string(client.RedirectURIs))
		fmt.Printf("Scopes: %v\n", []string(client.Scopes))
	}

	// Example 3: Login Attempt Tracking
	fmt.Println("\n=== Login Attempt Tracking Example ===")
	
	ip := net.ParseIP("192.168.1.100")
	attempt := &models.LoginAttempt{
		Email:         user.Email,
		IPAddress:     ip,
		Successful:    false,
		FailureReason: func() *string { s := "invalid_password"; return &s }(),
		TFARequired:   false,
		AttemptedAt:   time.Now(),
	}

	err = repoManager.Repository().LoginAttempt.Create(ctx, attempt)
	if err != nil {
		log.Printf("Failed to create login attempt: %v", err)
	} else {
		fmt.Printf("Logged failed login attempt for %s from %s\n", attempt.Email, attempt.IPAddress)
	}

	// Count recent failures for rate limiting
	since := time.Now().Add(-15 * time.Minute)
	failureCount, err := repoManager.Repository().LoginAttempt.CountRecentFailures(ctx, user.Email, ip, since)
	if err != nil {
		log.Printf("Failed to count recent failures: %v", err)
	} else {
		fmt.Printf("Recent login failures for %s from %s: %d\n", user.Email, ip, failureCount)
	}

	// Example 4: Transaction Usage
	fmt.Println("\n=== Transaction Example ===")
	
	// Start a transaction
	tx, err := repoManager.Transaction(ctx)
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
	} else {
		// Create user and client in the same transaction
		txUser := &models.User{
			Email:    fmt.Sprintf("tx-user+%d@test.com", time.Now().Unix()),
			IsActive: true,
		}

		err = tx.Repository().User.Create(ctx, txUser)
		if err != nil {
			log.Printf("Failed to create user in transaction: %v", err)
			tx.Rollback()
		} else {
			// Create an auth session for the user
			session := &models.AuthSession{
				SessionID: fmt.Sprintf("session-%s", uuid.New().String()),
				UserID:    txUser.ID,
				IPAddress: &ip,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}

			err = tx.Repository().AuthSession.Create(ctx, session)
			if err != nil {
				log.Printf("Failed to create session in transaction: %v", err)
				tx.Rollback()
			} else {
				// Commit the transaction
				err = tx.Commit()
				if err != nil {
					log.Printf("Failed to commit transaction: %v", err)
				} else {
					fmt.Printf("Successfully created user and session in transaction\n")
					fmt.Printf("User: %s, Session: %s\n", txUser.Email, session.SessionID)
				}
			}
		}
	}

	// Example 5: Repository Count and List Operations
	fmt.Println("\n=== Repository Statistics ===")
	
	userCount, err := repoManager.Repository().User.Count(ctx)
	if err != nil {
		log.Printf("Failed to count users: %v", err)
	} else {
		fmt.Printf("Total users in database: %d\n", userCount)
	}

	clientCount, err := repoManager.Repository().OAuthClient.Count(ctx)
	if err != nil {
		log.Printf("Failed to count OAuth clients: %v", err)
	} else {
		fmt.Printf("Total OAuth clients in database: %d\n", clientCount)
	}

	// List recent users
	recentUsers, err := repoManager.Repository().User.List(ctx, 5, 0)
	if err != nil {
		log.Printf("Failed to list recent users: %v", err)
	} else {
		fmt.Printf("Recent users (%d):\n", len(recentUsers))
		for _, u := range recentUsers {
			fmt.Printf("  - %s (created: %s)\n", u.Email, u.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	}

	fmt.Println("\n=== Repository Pattern Example Complete ===")
	fmt.Println("This example demonstrated:")
	fmt.Println("1. User CRUD operations")
	fmt.Println("2. OAuth client management")
	fmt.Println("3. Login attempt tracking")
	fmt.Println("4. Database transactions")
	fmt.Println("5. Count and list operations")
	fmt.Println("\nThe repository pattern provides a clean abstraction layer")
	fmt.Println("between business logic and database operations!")
}