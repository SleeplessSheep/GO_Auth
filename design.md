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
*   **Nginx Ingress:** Manages TLS termination, routing, and IP-based access control.
*   **Redis:** High-performance cache for sessions and opaque tokens.
*   **PostgreSQL:** Persistent database for local user accounts and client configurations.

```
+-----------------------------------------------------------------+
| End User's Browser                                              |
+-----------------------------------------------------------------+
      | (HTTPS/TLS via Cloudflare)
      v
+-----------------------------------------------------------------+
| Kubernetes Cluster                                              |
|                                                                 |
|  +-----------------------+                                      |
|  | Nginx Ingress         | (Manages TLS/routing, IP whitelisting)|
|  +-----------------------+                                      |
|      | (Public)        | (Admin Dashboard - Whitelisted IPs)    |
|      v                 v                                        |
|  +-----------------+  +----------------------+                  |
|  | Go Auth Server  |  | Admin Dashboard UI   |                  |
|  | (IdP Core)      |  | (OAuth Client)       |                  |
|  +-----------------+  +----------------------+                  |
|      ^      |      |      ^                                     |
|      |      |      |      | (API Calls)                         |
|      v      v      v      v                                     |
|  +--------+ +--------+ +------------------+                      |
|  | Redis  | |  DB    | | External IDPs    |                      |
|  | (Cache)| |(Users) | | (Google, LDAP)   |                      |
|  +--------+ +--------+ +------------------+                      |
+-----------------------------------------------------------------+
```

## 3. User Roles and Authentication Flows

### 3.1. Normal Users (Local DB or Google)
*   **Authentication:** Users register and sign in via the Auth Server's UI using an email/password (stored in PostgreSQL) or Google's OAuth2 flow.
*   **2FA:** Users can optionally enable Time-based One-Time Password (TOTP) 2FA.
*   **Account Management:** Users can reset forgotten passwords via an email link.

### 3.2. Administrators (LDAP)
*   **Authentication:** Admins authenticate via the Auth Server's UI using their LDAP credentials.
*   **2FA:** Mandatory TOTP 2FA is required after successful LDAP authentication.
*   **Access:** Gain access to the separate Admin Dashboard service.

## 4. Token and Session Strategy

*   **Signing Algorithm:** All JWTs will be signed using **RS256**.
*   **Automatic Key Rotation:** The server will automatically generate new RS256 key pairs on a configurable schedule.
    *   **JWKS Endpoint:** The server will expose a `/.well-known/jwks.json` endpoint containing the *public keys* of all currently active and recently retired keys.
    *   **Key ID (`kid`):** Every token will have a `kid` header to identify which key signed it, allowing clients to select the correct public key for verification from the JWKS endpoint.
    *   **Graceful Retirement:** Old keys will be kept in the JWKS endpoint for a grace period beyond their token expiry time to ensure all tokens can be verified, enabling zero-downtime key rotation.
*   **ID Token:** A short-lived JWT containing user identity (`sub`, `iss`, etc.) and group affiliations via a `groups` claim (e.g., `["admin", "user"]`). Intended for the client application.
*   **Access Token:** A short-lived JWT containing `scope` claims (e.g., `blog:write`, `chat:read`) that define the permissions the client can exercise at a resource server (e.g., the Blog API).
*   **Refresh Token:** A long-lived, **opaque random string** stored in Redis. It can be revoked instantly on the server side.
*   **SSO Session:** Managed by a secure, HTTP-only cookie containing an **opaque random string** as the session ID, which is a key in Redis. This enables a seamless SSO experience.

## 5. Security and Deployment

*   **TLS:** End-to-end encryption via Cloudflare and Let's Encrypt (`cert-manager`).
*   **Admin Protection:** Admin Dashboard access is restricted by IP whitelist at the Nginx Ingress.
*   **PKCE:** Mandatory for all OAuth 2.1 clients.
*   **Password Hashing:** **Argon2** for local user passwords.
*   **Secrets Management:** Kubernetes Secrets for all credentials.
*   **Deployment:** The entire stack will be defined in Kubernetes manifests for deployment to Minikube (local) or a public cloud provider.
