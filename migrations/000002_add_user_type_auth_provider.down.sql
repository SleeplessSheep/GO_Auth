-- ================================================================================================
-- ROLLBACK USER TYPE AND AUTH PROVIDER FIELDS
-- ================================================================================================
-- 
-- Purpose: Remove user classification fields
-- Version: 000002
-- Created: January 2025
-- Author: Development Team
--
-- This rollback removes:
-- - user_type column
-- - auth_provider column
-- - ldap_dn column
-- - Related indexes and constraints
-- ================================================================================================

-- Drop indexes
DROP INDEX IF EXISTS idx_users_ldap_dn;
DROP INDEX IF EXISTS idx_users_auth_provider;
DROP INDEX IF EXISTS idx_users_user_type;

-- Drop check constraints
ALTER TABLE users DROP CONSTRAINT IF EXISTS check_auth_provider;
ALTER TABLE users DROP CONSTRAINT IF EXISTS check_user_type;

-- Drop columns
ALTER TABLE users DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE users DROP COLUMN IF EXISTS auth_provider;
ALTER TABLE users DROP COLUMN IF EXISTS user_type;

-- ================================================================================================
-- ROLLBACK COMPLETE
-- ================================================================================================