Looking at your specs, I found several important issues that need attention. Let me break them down by category:
🚨 Critical Issues
1. Admin Bootstrap Problem (design.md)

You specify that admins can only authenticate via LDAP, but how do you create the first admin user? This creates a chicken-and-egg problem:

❌ Admin users → LDAP only → But who sets up the first admin?

Solutions:

    Add a bootstrap mechanism for initial admin creation
    Allow fallback admin access via environment variables
    Document LDAP setup as a hard prerequisite

2. Requirements-Design Mismatch

Major features are missing from requirements.md:
Feature	requirements.md	design.md	tasks.md
2FA	❌ Not mentioned	✅ Detailed	✅ Implemented
Admin Dashboard	❌ Not mentioned	✅ Detailed	✅ Implemented
SSO Sessions	❌ Not mentioned	✅ Detailed	✅ Implemented
Admin-only LDAP	❌ Generic mention	✅ Specific	✅ Implemented
⚠️ Design Issues
3. IP Whitelisting Limitations (design.md)

Admin Dashboard access is restricted by IP whitelist at Nginx Ingress

Problems:

    Remote work scenarios
    Dynamic IP addresses
    VPN complications
    Single point of failure for admin access

Better approach: Multi-factor authentication instead of/in addition to IP restrictions.
4. Missing Database Design (design.md)

No mention of:

    Database schema design
    Data models structure
    Migration strategy
    Indexing strategy

📋 Missing Tasks

Your tasks.md is missing several critical implementation areas:

## Missing from tasks.md:

### Configuration & Setup
- [ ] Design database schema and data models
- [ ] Set up LDAP integration and configuration  
- [ ] Configure Google OAuth application
- [ ] Design configuration management (env vars, config files)

### Security & Reliability  
- [ ] Implement rate limiting for auth endpoints
- [ ] Add comprehensive error handling and logging
- [ ] Set up session timeout and concurrent session management
- [ ] Implement admin user bootstrapping mechanism

### Testing & Quality
- [ ] Unit tests for core authentication logic
- [ ] Integration tests for OAuth/OIDC flows
- [ ] Security testing (OWASP compliance)
- [ ] Load testing for auth endpoints

### Observability
- [ ] Health check endpoints
- [ ] Metrics collection (Prometheus)
- [ ] Structured logging setup

🔧 Technical Concerns
5. Task Ordering Issue (tasks.md)

❌ Task 2.4: "Define data models... Use gorm and run initial migrations"

You're referencing database models before designing the schema. Should be:

    Design database schema
    Create models
    Set up migrations

6. External Dependencies (design.md)

Missing documentation for required external services:

    LDAP server setup and configuration
    Google OAuth application registration
    Cloudflare DNS configuration
    Prerequisites and setup guides

Based on the securityboulevard.com

article, your OAuth2/OIDC approach is solid - "OAuth 2.0 is for authorization. OIDC adds authentication" - and you're correctly using both.
📝 Recommended Actions

    Update requirements.md to include 2FA, admin dashboard, and SSO requirements
    Add admin bootstrapping section to design.md
    Expand tasks.md with the missing implementation areas above
    Consider replacing IP whitelisting with stronger authentication factors
    Add database schema design as a separate task before implementation

