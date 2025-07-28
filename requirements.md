# Requirements

This document outlines the requirements for the Golang standalone Identity Provider (IdP). This project serves as both a comprehensive security learning exercise and a DevOps portfolio showcase demonstrating cloud-native deployment patterns.

## 1. High-Level Goals
- The system will act as a central, standalone OIDC-compliant Identity Provider.
- It will provide Single Sign-On (SSO) for a suite of related microservices (e.g., Admin Dashboard, Blog, Chat).
- It will enforce a strict separation between administrator and normal user roles.
- It will provide an intuitive user experience similar to Google's login flow.

## 2. User Stories

### 2.1. Normal User Authentication
*   **As a user, I want to register for an account using my email and password, so I can access services.**
*   **As a user, I want to log in with my email and password.**
*   **As a user, I want to log in using my Google account for convenience.**
*   **As a user, I want to enable Time-based One-Time Password (TOTP) 2-Factor Authentication (2FA) on my account to enhance its security.**
*   **As a user, I want to reset my password if I forget it, so I can regain access.**
*   **As a user, I want to see my active sessions on the login page and choose to continue with an existing session or login with a different account.**

### 2.2. Administrator Authentication
*   **As an administrator, I want to log in using my corporate LDAP credentials to manage the system.**
*   **As an administrator, I must use a mandatory TOTP 2FA after my LDAP login to ensure high security for my session.**

### 2.3. System & Client Application Stories
*   **As a client application (e.g., a blog), I want to redirect users to a central login page and receive an ID Token and Access Token after a successful login, so I can authenticate and authorize my users.**
*   **As the system, I want to manage a persistent SSO session for users, so they don't have to re-login for every application.**
*   **As an administrator, I want a dedicated Admin Dashboard application to manage users and OAuth clients.**

## 3. Acceptance Criteria

*   The server must implement the OIDC Authorization Code Flow with PKCE.
*   The server must support three identity providers: Local (PostgreSQL), Google (OAuth2), and LDAP.
*   **Role Separation:**
    *   Normal users are authenticated via the Local DB or Google.
    *   Administrators are authenticated *only* via LDAP.
*   **2-Factor Authentication:**
    *   2FA (TOTP) is **optional** for Normal Users.
    *   2FA (TOTP) is **mandatory** for Administrators.
*   **Tokens:**
    *   The system must issue RS256-signed ID and Access Tokens.
    *   The system must support Refresh Tokens for long-lived sessions.
    *   The system must provide a `/.well-known/jwks.json` endpoint for key rotation.
*   **Security:**
    *   Passwords must be hashed using Argon2.
    *   The system must provide a secure password reset mechanism.
*   **Administration:**
    *   An Admin Dashboard application must be provided for system management, and it must be treated as a separate OAuth client.
*   **User Experience:**
    *   The login page must display active user sessions.
    *   Users must be able to continue with an existing valid session or login with a different account.
*   **Deployment:**
    *   The system must be deployable on Minikube for local development and demonstration.
    *   The system should be designed to support cloud deployment in future iterations.
*   **Logging:**
    *   The system must log authentication events (success/failure).
    *   The system must log key operations (user registration, password reset).
    *   The system must log system events (startup, key rotation).
    *   The system must log errors and warnings with structured logging.
*   **Backup and Recovery:**
    *   The system must document PostgreSQL backup procedures.
    *   The system must document key rotation and recovery procedures.
    *   The system must document basic disaster recovery steps.
*   **DevOps & Deployment Pipeline:**
    *   The system must support three deployment stages: Local Minikube → Cloud with Domain → AWS
    *   The system must include automated CI/CD pipeline using GitHub Actions
    *   The system must include Infrastructure as Code (Terraform/Helm) for AWS deployment
    *   The system must include monitoring and observability (Prometheus/Grafana)
*   **Security Testing:**
    *   The system must include automated security scanning (SAST/DAST)
    *   The system must be designed to support penetration testing with common security tools
    *   The system must include comprehensive security documentation and threat modeling
