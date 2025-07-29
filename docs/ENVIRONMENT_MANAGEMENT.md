# Environment & Secret Management Strategy

## 📋 Overview

This document outlines the comprehensive environment variable and secret management strategy for the Auth Server project. This approach follows industry best practices and ensures security across all deployment environments.

## 🏗️ Architecture Philosophy

### **Separation of Concerns**
- **Template Files**: Document structure and provide development guidance
- **Local Development**: Safe, documented defaults for Docker development  
- **GitHub Secrets**: Secure CI/CD pipeline integration
- **Production Secrets**: External secret management (K8s Secrets, AWS Secrets Manager)

### **Security Principles**
1. **Never commit real secrets** to version control
2. **Different secrets per environment** (dev/staging/prod)
3. **Least privilege access** to secret systems
4. **Regular secret rotation** with documented procedures
5. **Audit trails** for all secret access and modifications

## 📁 File Structure & Purpose

```
.
├── .env.template              # 📝 TEMPLATE: Complete variable documentation
├── .env.docker               # 🐳 SAFE: Development values for Docker Compose  
├── .github/workflows/ci.yml  # 🔄 EXAMPLE: GitHub Secrets integration
└── deployments/k8s/
    └── secrets.template.yaml # ☸️ TEMPLATE: Kubernetes secrets structure
```

### **File Classification**

| File | Status | Purpose | Commit Safe |
|------|--------|---------|-------------|
| `.env.template` | Template | Document all required variables | ✅ Yes |
| `.env.docker` | Development | Docker Compose integration | ✅ Yes |
| `.env` | Runtime | Local development secrets | ❌ **Never** |
| `secrets.yaml` | Runtime | Kubernetes secrets | ❌ **Never** |

## 🔄 Environment Flow

### **Local Development**
```
.env.template → .env (user creates) → Application
```
- Developer copies template to `.env`
- Fills in actual values for local development
- Application reads from environment variables

### **Docker Development**  
```
.env.docker → docker-compose.yml → Container Environment
```
- Safe development values included in repository
- Works out-of-the-box with `docker-compose up`
- No secret setup required for basic development

### **GitHub Actions CI/CD**
```
GitHub Secrets → Workflow Environment → Application/Deployment
```
- Real secrets stored in GitHub repository settings
- Accessed via `${{ secrets.SECRET_NAME }}` syntax
- Injected as environment variables in runners

### **Kubernetes Production**
```
External Secret Manager → K8s Secret → Pod Environment Variables
```
- Secrets stored in external systems (AWS Secrets Manager, etc.)
- External Secrets Operator syncs to Kubernetes
- Mounted as environment variables in pods

## 🔐 Secret Categories

### **Critical Secrets** (Never in plain text)
- `AUTH_AUTH_MASTER_ENCRYPTION_KEY`: JWT signing key encryption
- `AUTH_DATABASE_PASSWORD`: Database authentication
- `AUTH_REDIS_PASSWORD`: Redis authentication  
- `AUTH_GOOGLE_CLIENT_SECRET`: OAuth integration
- `AUTH_LDAP_BIND_PASSWORD`: LDAP service account

### **Sensitive Configuration** (Environment-specific)
- Database hosts and connection strings
- External service URLs
- Security policy settings
- Feature flags and operational parameters

### **Public Configuration** (Safe to document)
- Default ports and timeouts
- Non-sensitive service discovery
- Public OAuth client IDs
- Documentation and help URLs

## 🛠️ Implementation Guide

### **For Developers**

1. **Local Setup**
   ```bash
   # Copy template and customize
   cp .env.template .env
   # Edit .env with your local values
   nano .env
   ```

2. **Docker Development**
   ```bash
   # Uses safe defaults from .env.docker
   docker-compose up
   ```

3. **Testing Configuration**
   ```bash
   # Validate configuration loading
   go run cmd/server/main.go --config-check
   ```

### **For DevOps Engineers**

1. **GitHub Secrets Setup**
   - Repository Settings → Secrets and variables → Actions
   - Add secrets for CI/CD pipeline: `TEST_MASTER_ENCRYPTION_KEY`, etc.

2. **Kubernetes Deployment**
   ```bash
   # Create namespace
   kubectl create namespace auth-system
   
   # Create secrets from file
   kubectl create secret generic auth-server-secrets \
     --from-env-file=.env.production \
     --namespace=auth-system
   ```

3. **External Secrets (Recommended)**
   ```bash
   # Install External Secrets Operator
   helm repo add external-secrets https://charts.external-secrets.io
   helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace
   
   # Apply ExternalSecret resources
   kubectl apply -f deployments/k8s/secrets.template.yaml
   ```

### **For Security Teams**

1. **Secret Rotation Procedures**
   - Quarterly rotation of master encryption keys
   - Monthly rotation of service account passwords
   - Automated rotation using cloud provider tools

2. **Access Auditing**
   - Monitor secret access in Kubernetes audit logs
   - Track GitHub Actions secret usage
   - Review cloud provider secret manager access logs

3. **Compliance Verification**
   - No secrets in git history: `git log --all --full-history -- .env`
   - Verify secret encryption at rest in cloud providers
   - Validate least-privilege IAM policies

## 🚨 Security Warnings & Best Practices

### **DO**
- ✅ Use different secrets for each environment
- ✅ Rotate secrets regularly (quarterly minimum)
- ✅ Use external secret management in production
- ✅ Monitor and audit secret access
- ✅ Document secret ownership and rotation procedures

### **DON'T**
- ❌ Commit any `.env` files with real secrets
- ❌ Share secrets via chat/email/unencrypted storage
- ❌ Use the same secrets across environments
- ❌ Hardcode secrets in Docker images
- ❌ Log secret values (even in debug mode)

### **Emergency Procedures**

1. **Secret Compromise**
   - Immediately rotate affected secrets
   - Review access logs for unauthorized usage
   - Update all affected environments
   - Document incident and remediation steps

2. **Lost Access**
   - Use break-glass procedures documented in runbooks
   - Verify identity through multiple channels
   - Update access controls and rotate secrets

## 📊 Monitoring & Alerting

### **Key Metrics**
- Secret rotation age (alert if > 90 days)
- Failed authentication attempts with service accounts
- Unauthorized secret access patterns
- Configuration validation failures

### **Alerting Rules**
```yaml
# Example Prometheus alerting rules
groups:
- name: auth-server-secrets
  rules:
  - alert: SecretRotationOverdue
    expr: (time() - auth_secret_last_rotated_timestamp) > (90 * 24 * 3600)
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: "Auth server secret rotation overdue"
      
  - alert: AuthenticationFailures
    expr: rate(auth_events_total{success="false"}[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High authentication failure rate detected"
```

## 🔄 Migration & Upgrade Procedures

### **Environment Migration**
1. Create new environment secrets
2. Deploy application with new configuration
3. Validate functionality with new secrets
4. Update DNS/routing to new environment
5. Decommission old environment and rotate secrets

### **Secret Format Changes**
1. Update templates with new format documentation
2. Create migration scripts for existing secrets
3. Deploy backward-compatible configuration readers
4. Migrate secrets in rolling fashion
5. Remove legacy format support after migration

---

**Document Version**: 1.0  
**Last Updated**: January 2025  
**Owner**: DevOps Team  
**Review Schedule**: Quarterly  
**Classification**: Internal Use Only