# Design Document: Golang Auth Server

This document outlines the technical design for the standalone authentication server.

## 1. Overview

The system is an **Identity Provider (IdP)** that adheres to OAuth 2.1 and OpenID Connect (OIDC) best practices. It provides secure authentication, authorization, and Single Sign-On (SSO) for a suite of microservices (e.g., Admin Dashboard, Blog, E2EE Chat).

The server will support a clear separation of roles based on the identity provider:
*   **Administrators:** Authenticate exclusively via an external LDAP directory.
*   **Normal Users:** Authenticate via a local email/password store or Google Social Login.

## 2. Architecture and Components

The system will run within a Kubernetes cluster and consists of several key components:

*   **Go Auth Server:** The core IdP. It handles all authentication logic, token issuance, and user session management. It exposes OIDC/OAuth2 endpoints but serves no UI other than login/consent pages.
*   **Admin Dashboard:** A separate microservice (and OAuth 2.1 client) that provides the UI for managing the auth server (e.g., users, clients, settings). Access is restricted to users in the "admin" group.
*   **Other Microservices (Blog, Chat):** Future client applications that will rely on the Go Auth Server for user authentication.
*   **Nginx Ingress:** Manages TLS termination and routing.
*   **Redis:** High-performance cache for sessions, opaque tokens, and temporary authorization codes.
*   **PostgreSQL:** Persistent database for local user accounts and client configurations.

## 3. Admin Bootstrap Mechanism

To solve the "chicken-and-egg" problem of the first admin, the server will have a one-time bootstrap mechanism.

*   **On first startup, the server will check if any OAuth clients exist in the database.**
*   If the database is empty, it will read environment variables (e.g., `INITIAL_ADMIN_CLIENT_ID`, `INITIAL_ADMIN_CLIENT_SECRET`) to create the first client for the Admin Dashboard.
*   This allows the first administrator to log in via LDAP and use the dashboard to configure the rest of the system. This startup logic will not run again once clients are present in the database.

## 4. Database Schema

The PostgreSQL database will contain the following core tables. Migrations will be managed with a library like `golang-migrate`.

*   **`users`**: Stores local user accounts.
    *   `id` (UUID, PK)
    *   `email` (VARCHAR, UNIQUE)
    *   `password_hash` (VARCHAR) - Nullable, as Google users won't have one.
    *   `google_id` (VARCHAR, UNIQUE) - Nullable
    *   `tfa_secret` (VARCHAR) - Encrypted secret for TOTP.
    *   `created_at`, `updated_at`

*   **`oauth_clients`**: Stores information about applications that can use the auth server.
    *   `id` (UUID, PK)
    *   `client_id` (VARCHAR, UNIQUE)
    *   `client_secret_hash` (VARCHAR)
    *   `redirect_uris` (TEXT[])
    *   `scopes` (TEXT[])
    *   `client_name` (VARCHAR)

*   **`signing_keys`**: Stores the private keys for signing JWTs.
    *   `id` (`kid`) (VARCHAR, PK)
    *   `private_key` (TEXT) - Encrypted at rest.
    *   `created_at`

## 5. Token and Session Strategy

*   **Signing Algorithm:** All JWTs will be signed using **RS256**.
*   **Automatic Key Rotation:** A **Kubernetes CronJob** will run on a configurable schedule to trigger the key rotation process within the application. This job will call a dedicated, internal API endpoint to generate a new key and add it to the `signing_keys` table.
    *   **JWKS Endpoint:** The server will expose a `/.well-known/jwks.json` endpoint.
    *   **Key ID (`kid`):** Every token will have a `kid` header.
*   **Authorization Codes:** Short-lived authorization codes will be stored in **Redis**.
*   **Refresh & SSO Tokens:** Opaque refresh tokens and SSO session tokens will also be stored in **Redis**.

## 6. Security and Deployment

*   **Key Management (Hybrid Model):**
    *   The rotating RS256 private keys are stored encrypted in the `signing_keys` PostgreSQL table.
    *   The **master encryption key** used to encrypt/decrypt the signing keys is stored in a **Kubernetes Secret** and read by the application on startup. This provides a strong separation of concerns.
*   **TLS:** End-to-end encryption via Cloudflare and Let's Encrypt (`cert-manager`).
*   **Primary Admin Security:** Access to the Admin Dashboard is primarily secured by requiring authentication from an LDAP source and mandatory 2FA.
*   **PKCE:** Mandatory for all OAuth 2.1 clients.
*   **Password Hashing:** **Argon2** for local user passwords.
*   **Secrets Management:** All other credentials (database passwords, Google client secrets) will also be stored as Kubernetes Secrets.
*   **Deployment:** The entire stack will be defined in Kubernetes manifests for deployment to Minikube (local) or a public cloud provider.
