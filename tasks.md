# Implementation Tasks

This document breaks down the development work for the Golang Auth Server. This project serves as both a security learning exercise and DevOps showcase, with containerization and CI/CD integrated from the start.

## Epic 1: Project Foundation & DevOps Setup

- [ ] **1.1: Project Setup:**
    - [ ] Initialize Go module (`go mod init`).
    - [ ] Create project structure (`/cmd`, `/internal`, `/pkg`, `/api`).
    - [ ] Add initial `Dockerfile` with multi-stage build.
    - [ ] Create `.dockerignore` and security-focused `.gitignore`.
- [ ] **1.2: Configuration Management:**
    - [ ] Implement configuration loading from environment variables and a config file (e.g., using Viper).
    - [ ] Add configuration validation and security defaults.
- [ ] **1.3: Local Development Environment:**
    - [ ] Create `docker-compose.yml` for PostgreSQL and Redis.
    - [ ] Add development vs production environment configurations.
    - [ ] Include volume mounts for local development.
- [ ] **1.4: CI/CD Foundation:**
    - [ ] Set up GitHub Actions workflow for basic linting and testing.
    - [ ] Configure Docker image building and security scanning.
    - [ ] Add automated dependency vulnerability checks.
- [ ] **1.5: Logging & Observability:**
    - [ ] Set up structured logging (e.g., using Logrus or Zap).
    - [ ] Create comprehensive `/healthz` health check endpoint.
    - [ ] Add basic metrics endpoint (`/metrics` for Prometheus).

## Epic 2: Database & Data Models ✅ COMPLETE

- [x] **2.1: Schema Design & Migration:**
    - [x] Set up golang-migrate for professional database migrations.
    - [x] Create comprehensive initial SQL migration for all auth tables (users, oauth_clients, signing_keys, auth_codes, refresh_tokens, auth_sessions, login_attempts, password_reset_tokens, audit_log).
    - [x] Implement migration management system with version tracking.
    - [x] Docker integration with proper database lifecycle management.
- [x] **2.2: Enhanced GORM Models:**
    - [x] Define GORM models for all 9 database tables with proper relationships.
    - [x] Add custom StringArray type for PostgreSQL array handling.
    - [x] Implement proper foreign key constraints and cascading deletes.
    - [x] Add comprehensive model validation and table naming.
    - [x] Create extensive model unit tests with 100% coverage.
- [x] **2.3: Repository Pattern Implementation:**
    - [x] Create comprehensive repository interfaces for all entities.
    - [x] Implement PostgreSQL-based repository with full CRUD operations.
    - [x] Add advanced error handling with PostgreSQL-specific error mapping.
    - [x] Implement transaction support with commit/rollback capabilities.
    - [x] Create repository manager with dependency injection.
    - [x] Add integration tests for repository operations.
    - [x] Provide usage examples demonstrating all patterns.

## Epic 3: OIDC/OAuth 2.1 Core Implementation 🚧 NEXT

**Token Strategy Defined**: 
- Access tokens: OAuth 2.1 compliant with standard claims (iss, aud, scope, client_id, etc.)
- ID tokens: OIDC compliant with full profile claims (email, name, picture, auth_time, etc.)
- Admin tokens: Enhanced validation with LDAP real-time verification and short expiry
- Both user types use same token structure with different claims and validation

- [ ] **3.1: JWT Service & Key Management:**
    - [ ] Implement RS256 JWT signing and verification service
    - [ ] Create signing key management with rotation support
    - [ ] Implement access token and ID token generation with proper claims
    - [ ] Add JWT validation middleware with context propagation
    - [ ] Implement master encryption key handling for private key storage
    - [ ] Create JWKS endpoint for public key distribution
- [ ] **3.2: Authentication Services:**
    - [ ] Implement password authentication with Argon2 hashing
    - [ ] Create Google OAuth integration with proper claim mapping  
    - [ ] Implement LDAP authentication for administrators
    - [ ] Add authentication method tracking (amr) and context (acr)
- [ ] **3.3: OIDC Protocol Endpoints:**
    - [ ] Create OIDC discovery endpoint (/.well-known/openid_configuration)
    - [ ] Implement authorization endpoint (/auth) with PKCE support
    - [ ] Create token endpoint (/token) with proper grant type handling
    - [ ] Implement userinfo endpoint (/userinfo) with scope-based claims
    - [ ] Add proper error responses per OIDC specification
- [ ] **3.4: Session Management:**
    - [ ] Implement Redis-backed SSO session management
    - [ ] Create session creation, validation, and cleanup services
    - [ ] Add admin session monitoring and anomaly detection
    - [ ] Implement session revocation and logout functionality
- [ ] **3.5: Advanced Security Features:**
    - [ ] Implement admin token real-time LDAP validation
    - [ ] Add login attempt tracking and rate limiting
    - [ ] Create audit logging for all authentication events
    - [ ] Implement 2FA/TOTP support for enhanced security
- [ ] **3.6: Admin Bootstrap & UI:**
    - [ ] Implement one-time admin client bootstrap mechanism on server startup
    - [ ] Create basic HTML templates for login, consent, and error pages
    - [ ] Add admin dashboard client configuration

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

## Epic 6: Admin Dashboard & Local Minikube Deployment

- [ ] **6.1: Admin Dashboard Application:**
    - [ ] Set up a new Go project for the Admin Dashboard UI.
    - [ ] Implement the OIDC login flow for the dashboard, requiring the `admin` group.
    - [ ] Build UI features for managing users and OAuth clients.
- [ ] **6.2: Minikube Deployment (Local):**
    - [ ] Create Kubernetes manifests for the auth server and admin dashboard.
    - [ ] Set up Nginx Ingress for local routing.
    - [ ] Configure Kubernetes secrets for all sensitive configuration.
    - [ ] Document local deployment and testing procedures.
- [ ] **6.3: Security Testing:**
    - [ ] Write unit tests for critical logic (e.g., token generation, password hashing).
    - [ ] Write integration tests for the main OIDC flows.
    - [ ] Set up automated security scanning (SAST/DAST tools).
    - [ ] Document pen testing procedures with common tools (nmap, burp suite, etc.).

## Epic 7: Cloud Deployment with Domain

- [ ] **7.1: Cloud Infrastructure:**
    - [ ] Set up cloud Kubernetes cluster (GKE/EKS/AKS).
    - [ ] Configure Cloudflare DNS integration.
    - [ ] Set up cert-manager for automatic TLS with Let's Encrypt.
- [ ] **7.2: CI/CD Pipeline Enhancement:**
    - [ ] Extend GitHub Actions for cloud deployment.
    - [ ] Add staging and production environment separation.
    - [ ] Configure automated rollbacks and health checks.
- [ ] **7.3: Production Monitoring:**
    - [ ] Set up Prometheus and Grafana for monitoring.
    - [ ] Configure logging aggregation and alerting.
    - [ ] Add performance and security monitoring dashboards.

## Epic 8: AWS Migration & Advanced DevOps

- [ ] **8.1: AWS Infrastructure:**
    - [ ] Migrate to EKS with Terraform/CDK for Infrastructure as Code.
    - [ ] Set up AWS-native services (RDS, ElastiCache, Secrets Manager).
    - [ ] Configure VPC, security groups, and network policies.
- [ ] **8.2: Advanced Security & Compliance:**
    - [ ] Implement AWS security best practices (IAM roles, KMS).
    - [ ] Add compliance scanning and reporting.
    - [ ] Set up disaster recovery and backup procedures.
- [ ] **8.3: Cost Optimization & Scaling:**
    - [ ] Configure auto-scaling and resource optimization.
    - [ ] Implement cost monitoring and budgeting.
    - [ ] Document scaling strategies and cost analysis.
