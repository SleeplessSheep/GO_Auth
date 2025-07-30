-- ================================================================================================
-- ADD USER TYPE AND AUTH PROVIDER FIELDS
-- ================================================================================================
-- 
-- Purpose: Add user classification fields to support admin/user types and authentication providers
-- Version: 000002
-- Created: January 2025
-- Author: Development Team
--
-- This migration adds:
-- - user_type: Distinguish between 'user' and 'admin' users
-- - auth_provider: Track authentication method ('local', 'google', 'ldap')
-- - ldap_dn: Store LDAP Distinguished Name for admin users
-- ================================================================================================

-- Add user_type column
ALTER TABLE users ADD COLUMN user_type VARCHAR(20) NOT NULL DEFAULT 'user';

-- Add auth_provider column  
ALTER TABLE users ADD COLUMN auth_provider VARCHAR(20) NOT NULL DEFAULT 'local';

-- Add ldap_dn column for admin users
ALTER TABLE users ADD COLUMN ldap_dn TEXT;

-- Add check constraints for valid values
ALTER TABLE users ADD CONSTRAINT check_user_type CHECK (user_type IN ('user', 'admin'));
ALTER TABLE users ADD CONSTRAINT check_auth_provider CHECK (auth_provider IN ('local', 'google', 'ldap'));

-- Create indexes for performance
CREATE INDEX idx_users_user_type ON users(user_type);
CREATE INDEX idx_users_auth_provider ON users(auth_provider);
CREATE INDEX idx_users_ldap_dn ON users(ldap_dn) WHERE ldap_dn IS NOT NULL;

-- Add comments
COMMENT ON COLUMN users.user_type IS 'User classification: user or admin';
COMMENT ON COLUMN users.auth_provider IS 'Authentication provider: local, google, or ldap';
COMMENT ON COLUMN users.ldap_dn IS 'LDAP Distinguished Name for admin users';

-- ================================================================================================
-- MIGRATION COMPLETE
-- ================================================================================================