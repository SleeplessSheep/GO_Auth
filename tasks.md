# Implementation Tasks

This document breaks down the development work for the Golang Auth Server. Tasks are grouped by epic and ordered for logical implementation.

## Epic 1: Project Foundation & Core Services

- [ ] **1.1: Project Setup:**
    - [ ] Initialize Go module (`go mod init`).
    - [ ] Create project structure (`/cmd`, `/internal`, `/pkg`, `/api`).
    - [ ] Add initial `Dockerfile`.
- [ ] **1.2: Configuration Management:**
    - [ ] Implement configuration loading from environment variables and a config file (e.g., using Viper).
- [ ] **1.3: Local Development Environment:**
    - [ ] Create `docker-compose.yml` for PostgreSQL and Redis.
- [ ] **1.4: Logging & Observability:**
    - [ ] Set up structured logging (e.g., using Logrus or Zap).
    - [ ] Create a basic `/healthz` health check endpoint.

## Epic 2: Database & Data Models

- [ ] **2.1: Schema Design & Migration:**
    - [ ] Set up a migration tool (e.g., `golang-migrate`).
    - [ ] Create the initial SQL migration for `users`, `oauth_clients`, and `signing_keys` tables.
- [ ] **2.2: Data Models:**
    - [ ] Define GORM models for all database tables.
- [ ] **2.3: Database Connectivity:**
    - [ ] Implement a database connection package in `/internal/database`.

## Epic 3: OIDC/OAuth 2.1 Core Implementation

- [ ] **3.1: JWT & Key Management:**
    - [ ] Implement RS256 key generation and storage in the `signing_keys` table.
    - [ ] Implement automatic key rotation logic (e.g., a background worker).
    - [ ] Create the `/.well-known/jwks.json` endpoint.
- [ ] **3.2: Admin Bootstrap:**
    - [ ] Implement the one-time admin client bootstrap mechanism on server startup.
- [ ] **3.3: OAuth Endpoints:**
    - [ ] Implement the `/authorize` endpoint (with PKCE challenge storage in Redis).
    - [ ] Implement the `/token` endpoint (with PKCE verification and token issuance).
    - [ ] Implement the `/userinfo` endpoint.
    - [ ] Implement the refresh token grant type.
- [ ] **3.4: Basic UI:**
    - [ ] Create basic HTML templates for login, consent, and error pages.

## Epic 4: Authentication Flows

- [ ] **4.1: Local User Authentication:**
    - [ ] Implement user registration (hashing passwords with Argon2).
    - [ ] Implement the local login flow and connect it to the OIDC endpoints.
    - [ ] Implement the password reset flow.
- [ ] **4.2: SSO & Session Management:**
    - [ ] Implement SSO session creation in Redis, managed by a secure cookie.
- [ ] **4.3: External Identity Providers:**
    - [ ] Implement the Google Social Login flow.
    - [ ] Implement the LDAP authentication flow.

## Epic 5: Security Hardening & 2FA

- [ ] **5.1: Two-Factor Authentication (2FA):**
    - [ ] Implement TOTP secret generation and registration.
    - [ ] Implement the 2FA verification step in the login flow.
    - [ ] Enforce mandatory 2FA for LDAP users.
- [ ] **5.2: Security Measures:**
    - [ ] Implement rate limiting on authentication endpoints.
    - [ ] Implement comprehensive error handling and security headers.
    - [ ] Add basic input validation to all endpoints.

## Epic 6: Admin Dashboard & Deployment

- [ ] **6.1: Admin Dashboard Application:**
    - [ ] Set up a new Go project for the Admin Dashboard UI.
    - [ ] Implement the OIDC login flow for the dashboard, requiring the `admin` group.
    - [ ] Build UI features for managing users and OAuth clients.
- [ ] **6.2: Kubernetes Deployment:**
    - [ ] Create Kubernetes manifests for the auth server and admin dashboard.
    - [ ] Set up Nginx Ingress with `cert-manager` for automatic TLS.
    - [ ] Configure Kubernetes secrets for all sensitive configuration.
- [ ] **6.3: Testing:**
    - [ ] Write unit tests for critical logic (e.g., token generation, password hashing).
    - [ ] Write integration tests for the main OIDC flows.