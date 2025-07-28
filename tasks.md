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
    - [ ] Implement RS256 key generation and storage in the `signing_keys` table, ensuring they are encrypted at rest.
    - [ ] Implement the master encryption key retrieval from a Kubernetes Secret.
    - [ ] Create a Kubernetes CronJob manifest that calls an internal API endpoint to trigger key rotation.
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
