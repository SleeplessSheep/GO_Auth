# Requirements

This document outlines the requirements for the Golang standalone Identity Provider (IdP).

## 1. High-Level Goals
- The system will act as a central, standalone OIDC-compliant Identity Provider.
- It will provide Single Sign-On (SSO) for a suite of related microservices (e.g., Admin Dashboard, Blog, Chat).
- It will enforce a strict separation between administrator and normal user roles.

## 2. User Stories

### 2.1. Normal User Authentication
*   **As a user, I want to register for an account using my email and password, so I can access services.**
*   **As a user, I want to log in with my email and password.**
*   **As a user, I want to log in using my Google account for convenience.**
*   **As a user, I want to enable Time-based One-Time Password (TOTP) 2-Factor Authentication (2FA) on my account to enhance its security.**
*   **As a user, I want to reset my password if I forget it, so I can regain access.**

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
