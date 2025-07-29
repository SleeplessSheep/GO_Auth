-- ================================================================================================
-- INITIAL AUTH SERVER SCHEMA MIGRATION
-- ================================================================================================
-- 
-- Purpose: Create all core tables for the OIDC-compliant authentication server
-- Version: 000001
-- Created: January 2025
-- Author: Development Team
--
-- This migration creates the complete database schema for:
-- - User management (local and OAuth users)
-- - OAuth 2.1 client management 
-- - JWT signing key management with encryption
-- - Session and token management
-- - Authentication audit logging
-- ================================================================================================

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ------------------------------------------------------------------------------------------------
-- USERS TABLE
-- ------------------------------------------------------------------------------------------------
-- Stores both local users (email/password) and OAuth users (Google, etc.)
-- Supports optional 2FA with encrypted TOTP secrets

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    
    -- Password hash for local users (NULL for OAuth-only users)
    password_hash VARCHAR(255),
    
    -- OAuth integration (Google, etc.)
    google_id VARCHAR(255) UNIQUE,
    
    -- Two-Factor Authentication (TOTP)
    tfa_secret TEXT, -- Encrypted TOTP secret
    tfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- User status and metadata
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    
    -- Audit timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ -- Soft delete support
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL;
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;

-- ------------------------------------------------------------------------------------------------
-- OAUTH CLIENTS TABLE  
-- ------------------------------------------------------------------------------------------------
-- Stores OAuth 2.1 client applications that can authenticate users
-- Includes support for PKCE, multiple redirect URIs, and scopes

CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    
    -- OAuth 2.1 configuration
    redirect_uris TEXT[] NOT NULL DEFAULT '{}', -- Array of allowed redirect URIs
    scopes TEXT[] NOT NULL DEFAULT '{}', -- Array of allowed scopes
    grant_types TEXT[] NOT NULL DEFAULT '{"authorization_code", "refresh_token"}',
    response_types TEXT[] NOT NULL DEFAULT '{"code"}',
    
    -- Client metadata
    client_description TEXT,
    logo_url VARCHAR(500),
    privacy_policy_url VARCHAR(500),
    terms_of_service_url VARCHAR(500),
    
    -- Status and settings
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_confidential BOOLEAN NOT NULL DEFAULT TRUE, -- Public vs Confidential clients
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE, -- Force PKCE for security
    
    -- Audit timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes for performance
CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX idx_oauth_clients_active ON oauth_clients(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_oauth_clients_deleted_at ON oauth_clients(deleted_at) WHERE deleted_at IS NOT NULL;

-- ------------------------------------------------------------------------------------------------
-- SIGNING KEYS TABLE
-- ------------------------------------------------------------------------------------------------
-- Stores RSA private keys for JWT signing (RS256)
-- Private keys are encrypted at rest using master encryption key

CREATE TABLE signing_keys (
    id VARCHAR(255) PRIMARY KEY, -- Key ID (kid) for JWT header
    
    -- Encrypted RSA key pair
    private_key TEXT NOT NULL, -- Encrypted private key (PEM format)
    public_key TEXT NOT NULL, -- Public key (PEM format, can be public)
    
    -- Key metadata
    algorithm VARCHAR(10) NOT NULL DEFAULT 'RS256',
    key_size INTEGER NOT NULL DEFAULT 2048,
    
    -- Key lifecycle
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMPTZ, -- Optional key expiration
    
    -- Audit timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance and key management
CREATE INDEX idx_signing_keys_active ON signing_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_signing_keys_expires_at ON signing_keys(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_signing_keys_created_at ON signing_keys(created_at);

-- ------------------------------------------------------------------------------------------------
-- AUTHORIZATION CODES TABLE
-- ------------------------------------------------------------------------------------------------
-- Stores short-lived OAuth authorization codes with PKCE support
-- These are deleted after use or expiration

CREATE TABLE auth_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(255) NOT NULL UNIQUE,
    
    -- OAuth flow context
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    
    -- PKCE (Proof Key for Code Exchange) - Required for security
    pkce_challenge VARCHAR(255) NOT NULL,
    pkce_method VARCHAR(10) NOT NULL DEFAULT 'S256', -- S256 or plain
    
    -- State and nonce for additional security
    state VARCHAR(255), -- Optional state parameter
    nonce VARCHAR(255), -- Optional nonce for ID tokens
    
    -- Lifecycle
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ, -- When the code was exchanged for tokens
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_auth_codes_code ON auth_codes(code);
CREATE INDEX idx_auth_codes_user_id ON auth_codes(user_id);
CREATE INDEX idx_auth_codes_client_id ON auth_codes(client_id);
CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);
CREATE INDEX idx_auth_codes_used_at ON auth_codes(used_at) WHERE used_at IS NOT NULL;

-- ------------------------------------------------------------------------------------------------
-- REFRESH TOKENS TABLE
-- ------------------------------------------------------------------------------------------------
-- Stores long-lived refresh tokens for maintaining user sessions
-- Supports token rotation and family tracking

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL UNIQUE,
    
    -- Token context
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    
    -- Token family for rotation detection
    token_family UUID NOT NULL DEFAULT gen_random_uuid(),
    
    -- Lifecycle
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance and security
CREATE UNIQUE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(token_family);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_revoked_at ON refresh_tokens(revoked_at) WHERE revoked_at IS NOT NULL;

-- ------------------------------------------------------------------------------------------------
-- AUTH SESSIONS TABLE  
-- ------------------------------------------------------------------------------------------------
-- Stores SSO sessions for seamless authentication across multiple clients
-- Managed via secure HTTP cookies

CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) NOT NULL UNIQUE,
    
    -- Session context
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Client information
    ip_address INET, -- IP address for security tracking
    user_agent TEXT, -- Browser/client information
    
    -- Session lifecycle
    expires_at TIMESTAMPTZ NOT NULL,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance and session management
CREATE UNIQUE INDEX idx_auth_sessions_session_id ON auth_sessions(session_id);
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);
CREATE INDEX idx_auth_sessions_ip_address ON auth_sessions(ip_address);

-- ------------------------------------------------------------------------------------------------
-- LOGIN ATTEMPTS TABLE
-- ------------------------------------------------------------------------------------------------
-- Tracks authentication attempts for rate limiting and security monitoring
-- Supports both successful and failed attempts

CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Attempt details
    email VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    
    -- Attempt result
    successful BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason VARCHAR(100), -- 'invalid_password', 'account_locked', etc.
    
    -- 2FA details (if applicable)
    tfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    tfa_successful BOOLEAN,
    
    -- Audit
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for rate limiting and monitoring
CREATE INDEX idx_login_attempts_email ON login_attempts(email);
CREATE INDEX idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX idx_login_attempts_attempted_at ON login_attempts(attempted_at);
CREATE INDEX idx_login_attempts_email_ip ON login_attempts(email, ip_address);
CREATE INDEX idx_login_attempts_successful ON login_attempts(successful, attempted_at);

-- ------------------------------------------------------------------------------------------------
-- PASSWORD RESET TOKENS TABLE
-- ------------------------------------------------------------------------------------------------
-- Manages secure password reset functionality with expiring tokens

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL UNIQUE,
    
    -- Reset context
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL, -- Store email for verification
    
    -- Token lifecycle
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for token management
CREATE UNIQUE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_password_reset_tokens_used_at ON password_reset_tokens(used_at) WHERE used_at IS NOT NULL;

-- ------------------------------------------------------------------------------------------------
-- AUDIT LOG TABLE
-- ------------------------------------------------------------------------------------------------  
-- Comprehensive audit trail for security and compliance
-- Tracks all significant authentication and authorization events

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Event details
    event_type VARCHAR(50) NOT NULL, -- 'user_login', 'token_issued', 'key_rotated', etc.
    event_category VARCHAR(20) NOT NULL, -- 'authentication', 'authorization', 'administration'
    
    -- Context
    actor_type VARCHAR(20) NOT NULL, -- 'user', 'client', 'system'
    actor_id VARCHAR(255), -- User ID, Client ID, or system identifier
    
    -- Target (what was acted upon)
    target_type VARCHAR(20), -- 'user', 'client', 'token', 'key'
    target_id VARCHAR(255),
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    client_id VARCHAR(255),
    
    -- Event outcome
    success BOOLEAN NOT NULL,
    error_code VARCHAR(50),
    error_message TEXT,
    
    -- Additional metadata
    metadata JSONB, -- Flexible additional data
    
    -- Audit
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for audit querying and monitoring
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_event_category ON audit_log(event_category);
CREATE INDEX idx_audit_log_actor ON audit_log(actor_type, actor_id);
CREATE INDEX idx_audit_log_target ON audit_log(target_type, target_id);
CREATE INDEX idx_audit_log_occurred_at ON audit_log(occurred_at);
CREATE INDEX idx_audit_log_success ON audit_log(success, occurred_at);
CREATE INDEX idx_audit_log_ip_address ON audit_log(ip_address);

-- ------------------------------------------------------------------------------------------------
-- TRIGGERS FOR AUTOMATIC TIMESTAMP UPDATES
-- ------------------------------------------------------------------------------------------------

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_clients_updated_at BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_signing_keys_updated_at BEFORE UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_refresh_tokens_updated_at BEFORE UPDATE ON refresh_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_auth_sessions_updated_at BEFORE UPDATE ON auth_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ================================================================================================
-- INITIAL DATA SETUP
-- ================================================================================================

-- Create schema_migrations table for golang-migrate tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT NOT NULL PRIMARY KEY,
    dirty BOOLEAN NOT NULL
);

-- ================================================================================================
-- COMMENTS FOR DOCUMENTATION
-- ================================================================================================

COMMENT ON TABLE users IS 'Stores user accounts for both local and OAuth authentication';
COMMENT ON TABLE oauth_clients IS 'OAuth 2.1 client applications that can authenticate users';
COMMENT ON TABLE signing_keys IS 'RSA key pairs for JWT signing with encrypted private keys';
COMMENT ON TABLE auth_codes IS 'Short-lived authorization codes with PKCE support';
COMMENT ON TABLE refresh_tokens IS 'Long-lived tokens for maintaining user sessions';
COMMENT ON TABLE auth_sessions IS 'SSO sessions managed via secure cookies';
COMMENT ON TABLE login_attempts IS 'Authentication attempt tracking for rate limiting';
COMMENT ON TABLE password_reset_tokens IS 'Secure password reset token management';
COMMENT ON TABLE audit_log IS 'Comprehensive audit trail for security and compliance';

-- ================================================================================================
-- MIGRATION COMPLETE
-- ================================================================================================