# Security Test Suite

This directory contains comprehensive security tests for the OAuth 2.1 authentication server implementation.

## Test Categories

### 1. PKCE Security Tests
- **PKCE Code Challenge Validation**: Tests S256 and plain methods
- **PKCE Tampering Protection**: Validates rejection of mismatched code verifiers
- **Invalid Method Handling**: Ensures unsupported PKCE methods are rejected

### 2. State Parameter Security Tests
- **CSRF Protection**: Validates mandatory state parameter enforcement
- **State Preservation**: Ensures state is correctly returned in responses
- **Missing State Detection**: Confirms requests without state are rejected

### 3. OAuth 2.1 Compliance Tests
- **Service Configuration**: Validates mandatory PKCE and state enforcement
- **Error Response Security**: Ensures error messages don't leak sensitive information
- **Scope Validation**: Tests proper scope parsing and validation

### 4. Session Security Tests
- **Session Binding**: Validates tokens are properly bound to sessions
- **Session Validation**: Tests session-user relationships
- **Session Cleanup**: Ensures proper session invalidation

## Running Security Tests

```bash
# Run all security tests
go test ./internal/security_test -v

# Run with timeout
go test ./internal/security_test -v -timeout=30s

# Run specific test
go test ./internal/security_test -v -run TestPKCEValidationDirect
```

## CI/CD Integration

These tests are automatically run in the CI/CD pipeline as part of the security validation step:

```yaml
- name: Run security tests
  run: |
    echo "Running OAuth 2.1 security validation tests..."
    go test -v ./internal/security_test -timeout=30s
  continue-on-error: false
```

## Test Philosophy

### What We Test
✅ **PKCE Attack Resistance**: Code challenge tampering, verifier manipulation
✅ **State Parameter Security**: CSRF protection, parameter preservation  
✅ **OAuth 2.1 Compliance**: Mandatory security features enforcement
✅ **Error Handling**: Secure error responses without information leakage
✅ **Session Security**: Session binding, validation, and cleanup

### What We Don't Test Here
❌ **Database Integration**: Covered in integration tests
❌ **HTTP Endpoints**: Will be covered when endpoints are implemented
❌ **End-to-End Flows**: Covered in full integration test suite

## Security Test Results

All tests validate that the OAuth 2.1 implementation:
- ✅ Mandates PKCE with proper validation
- ✅ Requires state parameters for CSRF protection
- ✅ Rejects invalid/malformed requests securely
- ✅ Provides appropriate error responses
- ✅ Maintains session security and integrity

## Adding New Security Tests

When adding new security tests:

1. **Name tests descriptively**: `TestPKCECodeChallengeManipulation`
2. **Include attack scenarios**: Test both valid and invalid cases
3. **Validate error handling**: Ensure proper rejection of attacks
4. **Document the security concern**: Explain what attack you're testing
5. **Use proper assertions**: Fail tests on security vulnerabilities

Example:
```go
func TestNewSecurityFeature(t *testing.T) {
    // Test valid case
    // Test attack scenario  
    // Validate proper rejection
    // Check error messages don't leak info
}
```