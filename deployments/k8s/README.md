# Kubernetes Deployment for Auth Server

This directory contains production-ready Kubernetes manifests for deploying the OAuth 2.1/OIDC Auth Server.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Nginx Ingress │────│   Auth Server    │────│   PostgreSQL    │
│   (TLS/HTTPS)   │    │   (2+ replicas)  │    │   (Persistent)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                │
                       ┌─────────────────┐
                       │      Redis      │
                       │   (Sessions)    │
                       └─────────────────┘
```

## Quick Start

### 1. Prerequisites

```bash
# Ensure you have a Kubernetes cluster running
kubectl cluster-info

# Install nginx-ingress controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/cloud/deploy.yaml

# Optional: Install cert-manager for TLS
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.2/cert-manager.yaml
```

### 2. Deploy to Development

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Deploy development environment
kubectl apply -k overlays/dev/

# Check deployment status
kubectl get pods -n auth-system-dev
kubectl get services -n auth-system-dev

# Access the service
minikube service auth-service-dev -n auth-system-dev
```

### 3. Deploy to Production

```bash
# Update secrets with real values
kubectl apply -f secrets.yaml

# Update ingress with your domain
sed -i 's/auth.your-domain.com/auth.yourdomain.com/g' ingress.yaml

# Deploy production environment
kubectl apply -k .

# Verify deployment
kubectl get all -n auth-system
```

## Configuration

### Environment Variables

All configuration is managed through ConfigMaps and Secrets:

- **ConfigMap `auth-config`**: Non-sensitive configuration
- **Secret `auth-secrets`**: Database passwords, JWT keys, OAuth secrets
- **Secret `postgres-secret`**: Database credentials

### Secrets Management

⚠️ **Important**: The provided secrets are examples only!

For production, use proper secret management:

```bash
# Generate secure database password
kubectl create secret generic auth-secrets \\
  --from-literal=DB_PASSWORD="$(openssl rand -base64 32)" \\
  --from-literal=MASTER_ENCRYPTION_KEY="$(openssl rand -base64 32)" \\
  -n auth-system

# Or use external secret management
# - HashiCorp Vault
# - AWS Secrets Manager  
# - Azure Key Vault
# - Google Secret Manager
```

### TLS/SSL Configuration

For production HTTPS:

1. **With cert-manager (recommended)**:
   ```bash
   # Install cert-manager first
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.2/cert-manager.yaml
   
   # Update ingress.yaml with your domain
   # Certificate will be automatically provisioned
   ```

2. **With existing certificates**:
   ```bash
   kubectl create secret tls auth-tls-secret \\
     --cert=path/to/tls.crt \\
     --key=path/to/tls.key \\
     -n auth-system
   ```

## Scaling and High Availability

### Horizontal Pod Autoscaler

```bash
# Check HPA status
kubectl get hpa -n auth-system

# Manual scaling
kubectl scale deployment auth-server --replicas=5 -n auth-system
```

### Database High Availability

For production, consider:
- **PostgreSQL with replication** (primary/standby)
- **Managed database services** (AWS RDS, Google Cloud SQL)
- **PostgreSQL operators** (Crunchy Data, Zalando)

## Monitoring and Observability

### Prometheus Metrics

The auth server exposes metrics at `/metrics`:

```bash
# Check metrics
kubectl port-forward svc/auth-service 8080:80 -n auth-system
curl http://localhost:8080/metrics
```

### Logs

```bash
# View application logs
kubectl logs -f deployment/auth-server -n auth-system

# View all pod logs
kubectl logs -f -l app.kubernetes.io/name=auth-server -n auth-system
```

### Health Checks

```bash
# Check health endpoint
kubectl port-forward svc/auth-service 8080:80 -n auth-system
curl http://localhost:8080/healthz
```

## Security

### Network Policies

Network policies restrict pod-to-pod communication:

```bash
# View network policies
kubectl get networkpolicy -n auth-system

# Test connectivity
kubectl run debug --rm -it --image=busybox -n auth-system -- sh
```

### Pod Security

- **Non-root user**: Containers run as user 1000
- **Read-only filesystem**: Root filesystem is read-only
- **Dropped capabilities**: All Linux capabilities dropped
- **Security context**: Comprehensive security settings

### RBAC

Minimal RBAC permissions for service accounts:

```bash
# Check service account permissions
kubectl auth can-i --list --as=system:serviceaccount:auth-system:auth-server-sa -n auth-system
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**:
   ```bash
   # Check PostgreSQL status
   kubectl get pods -l app.kubernetes.io/name=postgres -n auth-system
   kubectl logs -l app.kubernetes.io/name=postgres -n auth-system
   
   # Test connection
   kubectl exec -it deployment/postgres -n auth-system -- psql -U auth_user -d auth_db -c "SELECT 1"
   ```

2. **Migration Failed**:
   ```bash
   # Check init container logs
   kubectl logs deployment/auth-server -c db-migrate -n auth-system
   
   # Run migration manually
   kubectl exec -it deployment/auth-server -n auth-system -- /app/auth migrate up
   ```

3. **Ingress Not Working**:
   ```bash
   # Check ingress controller
   kubectl get pods -n ingress-nginx
   
   # Check ingress rules
   kubectl describe ingress auth-ingress -n auth-system
   
   # Test service directly
   kubectl port-forward svc/auth-service 8080:80 -n auth-system
   ```

### Debug Commands

```bash
# Get all resources
kubectl get all -n auth-system

# Describe problematic pods
kubectl describe pod <pod-name> -n auth-system

# Check events
kubectl get events -n auth-system --sort-by='.firstTimestamp'

# Execute into container
kubectl exec -it deployment/auth-server -n auth-system -- sh
```

## Development

### Local Development with Minikube

```bash
# Start minikube
minikube start

# Enable addons
minikube addons enable ingress
minikube addons enable metrics-server

# Deploy development environment
kubectl apply -k overlays/dev/

# Access via minikube
minikube service auth-service-dev -n auth-system-dev

# Add to /etc/hosts
echo "$(minikube ip) auth.local" | sudo tee -a /etc/hosts
```

### Building and Testing

```bash
# Build Docker image
docker build -t auth-server:dev .

# Load into minikube
minikube image load auth-server:dev

# Update kustomization
kustomize edit set image IMAGE_TAG_PLACEHOLDER=auth-server:dev

# Deploy
kubectl apply -k overlays/dev/
```

## Production Checklist

- [ ] Update all secrets with secure random values
- [ ] Configure proper domain names in ingress
- [ ] Set up TLS certificates (cert-manager or manual)
- [ ] Configure monitoring (Prometheus/Grafana)
- [ ] Set up log aggregation (ELK/Loki)
- [ ] Configure backup for PostgreSQL
- [ ] Set up alerting for critical components
- [ ] Review and adjust resource limits
- [ ] Configure network policies
- [ ] Set up external secret management
- [ ] Configure load balancer/ingress for your cloud provider
- [ ] Set up CI/CD pipeline for automated deployments

## Files Overview

| File | Purpose |
|------|---------|
| `namespace.yaml` | Kubernetes namespaces (prod/dev) |  
| `configmap.yaml` | Non-sensitive configuration |
| `secrets.yaml` | Sensitive configuration (passwords, keys) |
| `postgres.yaml` | PostgreSQL database deployment |
| `redis.yaml` | Redis cache deployment |
| `auth-server.yaml` | Main application deployment |
| `ingress.yaml` | HTTP/HTTPS routing and TLS |
| `monitoring.yaml` | Prometheus, NetworkPolicy, RBAC |
| `kustomization.yaml` | Kustomize configuration |
| `dev-patches.yaml` | Development environment overrides |