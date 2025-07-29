-- ================================================================================================
-- ROLLBACK MIGRATION: INITIAL AUTH SERVER SCHEMA
-- ================================================================================================
-- 
-- Purpose: Drop all tables and extensions created in the initial schema migration
-- Version: 000001 (DOWN)
-- 
-- WARNING: This will permanently delete all data in the authentication system!
-- Only run this migration if you need to completely reset the database schema.
-- ================================================================================================

-- Drop all triggers first
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_oauth_clients_updated_at ON oauth_clients;
DROP TRIGGER IF EXISTS update_signing_keys_updated_at ON signing_keys;
DROP TRIGGER IF EXISTS update_refresh_tokens_updated_at ON refresh_tokens;
DROP TRIGGER IF EXISTS update_auth_sessions_updated_at ON auth_sessions;

-- Drop the trigger function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop all tables in reverse dependency order
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS auth_codes;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS users;

-- Drop migration tracking table
DROP TABLE IF EXISTS schema_migrations;

-- Note: We don't drop extensions (pgcrypto, uuid-ossp) as they might be used by other applications
-- If you need to drop them completely, uncomment the following lines:
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "uuid-ossp";

-- ================================================================================================
-- ROLLBACK COMPLETE
-- ================================================================================================