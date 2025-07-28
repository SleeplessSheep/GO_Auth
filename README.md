# OIDC Identity Provider - Security & DevOps Showcase

A production-ready OpenID Connect Identity Provider built in Go, demonstrating enterprise-grade security patterns and modern DevOps practices. This project showcases both deep security knowledge and comprehensive cloud-native deployment capabilities.

## 🎯 Project Goals

**Security Learning**: Hands-on implementation of OAuth 2.1/OIDC standards, cryptographic key management, multi-factor authentication, and security testing with penetration testing tools.

**DevOps Showcase**: Complete CI/CD pipeline with multi-environment deployments, Infrastructure as Code, monitoring, and cloud-native architecture patterns.

## 🏗️ Architecture Overview

- **Go-based Auth Server**: OIDC-compliant with RS256 JWT signing and automatic key rotation
- **Multi-Provider Authentication**: Local credentials, Google OAuth, and LDAP with role-based separation
- **Security-First Design**: Argon2 password hashing, mandatory PKCE, encrypted key storage, and comprehensive 2FA
- **Cloud-Native**: Kubernetes-native with Redis sessions, PostgreSQL persistence, and Prometheus monitoring

## 🚀 Three-Stage Deployment Pipeline

### Stage 1: Local Development (Minikube)
- Complete Kubernetes stack running locally
- Docker Compose for rapid development
- Local DNS and self-signed certificates
- Integrated security testing tools

### Stage 2: Cloud Production (Cloudflare Domain)
- Managed Kubernetes cluster (GKE/EKS/AKS)
- Automatic TLS with Let's Encrypt
- Cloudflare DNS integration
- Production monitoring and alerting

### Stage 3: AWS Enterprise
- Full AWS-native deployment with EKS
- Infrastructure as Code with Terraform
- AWS services integration (RDS, ElastiCache, KMS)
- Advanced security and compliance features

## 🔐 Security Features

- **Multi-Factor Authentication**: TOTP-based with different enforcement levels
- **Role-Based Access**: Clear separation between users and administrators
- **Key Management**: Hybrid encryption model with automatic rotation
- **Security Testing**: Automated SAST/DAST scanning and penetration testing procedures
- **Compliance**: Security headers, rate limiting, and comprehensive audit logging

## 🛠️ Technology Stack

**Backend**: Go, Gin, GORM, golang-migrate  
**Security**: Argon2, RS256 JWT, TOTP, OAuth 2.1/OIDC  
**Infrastructure**: Kubernetes, Docker, Redis, PostgreSQL  
**DevOps**: GitHub Actions, Terraform, Helm, Prometheus, Grafana  
**Cloud**: GCP/AWS/Azure, Cloudflare, Let's Encrypt  

## 📚 Documentation

- [`requirements.md`](requirements.md) - Functional requirements and user stories
- [`design.md`](design.md) - Technical architecture and security design
- [`tasks.md`](tasks.md) - Implementation roadmap with DevOps integration
- [`CLAUDE.md`](CLAUDE.md) - Development guide for AI assistance

## 🎓 Learning Outcomes

This project demonstrates proficiency in:
- **Security Engineering**: Authentication protocols, cryptography, threat modeling
- **DevOps Practices**: CI/CD, Infrastructure as Code, monitoring, incident response  
- **Cloud Architecture**: Kubernetes, microservices, scalability patterns
- **Software Engineering**: Go development, testing, documentation, maintainability

## 🚦 Getting Started

1. **Prerequisites**: Go 1.24+, Docker, kubectl, minikube
2. **Local Setup**: `docker-compose up -d` for dependencies
3. **Development**: `go run cmd/server/main.go`
4. **Testing**: `go test ./...`

See [`tasks.md`](tasks.md) for detailed implementation steps.

---

*This project serves as a comprehensive portfolio piece demonstrating both security expertise and DevOps capabilities for graduate-level positions in cybersecurity and platform engineering.*