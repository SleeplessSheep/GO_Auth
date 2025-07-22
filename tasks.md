# Implementation Tasks

This document breaks down the development work for the Golang Auth Server based on the `design.md`. The tasks are ordered to build the system from the ground up.

## Phase 1: Core Project Setup & Boilerplate

-   [ ] 1.1: Initialize Go module (`go mod init`) and create initial project structure (`/cmd`, `/internal`, `/pkg`, `/api`).
-   [ ] 1.2: Set up basic Gin web server in `cmd/server/main.go`.
-   [ ] 1.3: Create a `Dockerfile` for the Go application.
-   [ ] 1.4: Create initial Kubernetes manifests (`Deployment`, `Service`) for the auth server.
-   [ ] 1.5: Set up `docker-compose.yml` for easy local development with PostgreSQL and Redis.

## Phase 2: OIDC/OAuth 2.1 Core Implementation

-   [ ] 2.1: Implement RS256 key generation and storage.
-   [ ] 2.2: Create the `/.well-known/jwks.json` endpoint.
-   [ ] 2.3: Implement the automatic key rotation logic.
-   [ ] 2.4: Define data models for users and clients in PostgreSQL. Use `gorm` and run initial migrations.
-   [ ] 2.5: Implement the `/authorize` endpoint, including PKCE challenge storage.
-   [ ] 2.6: Implement the `/token` endpoint, including PKCE verification and issuance of ID, Access, and Refresh tokens.
-   [ ] 2.7: Implement the `/userinfo` endpoint.
-   [ ] 2.8: Implement refresh token flow (exchanging a refresh token for new tokens).

## Phase 3: User Authentication & UI

-   [ ] 3.1: Create basic HTML templates for the login, consent, and error pages.
-   [ ] 3.2: Implement local user registration (email/password).
-   [ ] 3.3: Implement local user login flow, integrating with the OIDC core.
-   [ ] 3.4: Implement password hashing with Argon2.
-   [ ] 3.5: Implement SSO session management using Redis and secure cookies.
-   [ ] 3.6: Implement Google Social Login flow.
-   [ ] 3.7: Implement LDAP authentication flow for admin users.

## Phase 4: Security & Account Management

-   [ ] 4.1: Implement TOTP 2FA registration for all user types.
-   [ ] 4.2: Enforce mandatory 2FA check for LDAP users after login.
-   [ ] 4.3: Implement optional 2FA check for local/Google users.
-   [ ] 4.4: Implement password reset flow for local users (request token generation, email sending, password update).

## Phase 5: Admin Dashboard & Deployment

-   [ ] 5.1: Create a separate Go project for the Admin Dashboard UI.
-   [ ] 5.2: Implement the login flow for the dashboard, requiring the `admin` group in the ID token.
-   [ ] 5.3: Build basic dashboard features (e.g., view users, view clients).
-   [ ] 5.4: Create Kubernetes manifests for the Admin Dashboard.
-   [ ] 5.5: Set up Nginx Ingress with `cert-manager` for TLS.
-   [ ] 5.6: Configure Nginx Ingress to enforce IP whitelisting for the Admin Dashboard.
-   [ ] 5.7: Write a deployment script/guide for setting up the full stack on Minikube.
-   [ ] 5.8: Test the public deployment and restricted admin access.
