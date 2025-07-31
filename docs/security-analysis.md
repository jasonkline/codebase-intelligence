# Security Analysis Guide

Comprehensive guide to the security analysis capabilities of Codebase Intelligence.

## Overview

The security analysis system provides multi-layered vulnerability detection, authentication pattern analysis, and compliance checking. It combines static analysis, pattern recognition, and OWASP-compliant scanning to identify security issues in your codebase.

## Security Analysis Features

### 🛡️ OWASP Top 10 Detection
- **Injection Flaws**: SQL, NoSQL, OS command injection
- **Broken Authentication**: Session management, credential issues
- **Sensitive Data Exposure**: Hardcoded secrets, logging sensitive data
- **XML External Entities (XXE)**: XML processing vulnerabilities
- **Broken Access Control**: Authorization bypass, privilege escalation
- **Security Misconfiguration**: Default configs, verbose errors
- **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based XSS
- **Insecure Deserialization**: Object injection, remote code execution
- **Components with Known Vulnerabilities**: Outdated dependencies
- **Insufficient Logging**: Missing security event logging

### 🔐 Authentication & Authorization Analysis
- **Authentication Flow Mapping**: Complete auth flow visualization
- **Role-Based Access Control (RBAC)**: Permission system validation
- **Multi-tenant Security**: Tenant isolation verification
- **Session Management**: Token handling and validation
- **Password Security**: Strength requirements and storage

### 🚨 Real-time Security Monitoring
- **Live Vulnerability Detection**: Instant scanning as you code
- **Security Pattern Enforcement**: Governance rule compliance
- **Critical Issue Blocking**: Prevent deployment of critical vulnerabilities
- **Security Score Tracking**: Continuous security posture monitoring

## Security Tools Reference

### Core Security Analysis

#### `analyze_security`
Comprehensive security scanning of files or directories.

**Usage:**
```typescript
// Claude Code
"Analyze this API directory for security vulnerabilities"

// Direct MCP call
{
  "name": "analyze_security",
  "arguments": {
    "path": "/path/to/api",
    "options": {
      "minSeverity": "medium",
      "includeCategories": ["injection", "authentication", "authorization"]
    }
  }
}
```

**Security Categories:**
- `injection` - SQL, NoSQL, command injection
- `authentication` - Auth bypass, weak credentials
- `authorization` - Access control issues
- `crypto` - Cryptographic vulnerabilities
- `secrets` - Hardcoded credentials, API keys
- `xss` - Cross-site scripting
- `csrf` - Cross-site request forgery
- `deserialization` - Unsafe object handling
- `logging` - Information disclosure

#### `check_auth_pattern`
Analyze authentication and authorization implementation.

**Usage:**
```typescript
"How is authentication implemented in this codebase?"
```

**Analysis Output:**
- Authentication flow mapping
- Entry point identification
- Auth check coverage
- Role-based access patterns
- Security gaps and recommendations

#### `find_vulnerabilities`
Target specific vulnerability types with detailed analysis.

**Usage:**
```typescript
"Find all SQL injection vulnerabilities in this project"
```

## Security Rules Engine

### Built-in Security Rules

#### Authentication Rules
```json
{
  "id": "missing-auth-check",
  "name": "Missing Authentication Check",
  "severity": "critical",
  "category": "authentication",
  "description": "API endpoint lacks authentication middleware",
  "pattern": "export\\s+async\\s+function\\s+(GET|POST|PUT|DELETE)\\s*\\([^)]*\\)\\s*{(?!.*requireAuth)",
  "message": "Add authentication middleware to API route",
  "remediation": "Add requireAuthWithTenant() at the beginning of the function"
}
```

#### Authorization Rules
```json
{
  "id": "rbac-bypass",
  "name": "RBAC Bypass",
  "severity": "high", 
  "category": "authorization",
  "description": "Direct database access bypassing role checks",
  "pattern": "getOrgDatabase\\(\\)(?!.*hasPermission)",
  "message": "Use role-checked database access",
  "remediation": "Call hasPermission() before database operations"
}
```

#### Injection Rules
```json
{
  "id": "sql-injection-risk",
  "name": "SQL Injection Risk",
  "severity": "critical",
  "category": "injection",
  "description": "Potential SQL injection through string concatenation",
  "pattern": "SELECT.*\\+.*\\$|INSERT.*\\+.*\\$|UPDATE.*\\+.*\\$",
  "message": "Use parameterized queries to prevent SQL injection",
  "remediation": "Replace string concatenation with prepared statements"
}
```

### Custom Security Rules

Define project-specific security rules:

```json
{
  "security": {
    "customRules": [
      {
        "id": "tenant-isolation-required",
        "name": "Tenant Isolation Required",
        "severity": "critical",
        "category": "authorization",
        "description": "All database queries must include tenant isolation",
        "pattern": "supabase\\.from\\([^)]+\\)(?!.*\\.eq\\(['\"]org_id['\"])",
        "message": "Add tenant isolation to database query",
        "remediation": "Add .eq('org_id', orgId) to filter by organization",
        "autoFix": {
          "enabled": true,
          "replacement": "$&.eq('org_id', orgId)"
        }
      },
      {
        "id": "api-key-exposure",
        "name": "API Key Exposure",
        "severity": "high",
        "category": "secrets",
        "description": "Detect exposed API keys in code",
        "patterns": [
          "api[_-]?key[\\s]*=[\\s]*['\"][a-zA-Z0-9]{20,}['\"]",
          "secret[_-]?key[\\s]*=[\\s]*['\"][a-zA-Z0-9]{20,}['\"]"
        ],
        "message": "API key exposed in source code",
        "remediation": "Move API key to environment variables"
      }
    ]
  }
}
```

## Security Analysis Configuration

### Project Security Settings

```json
{
  "security": {
    "enabled": true,
    "scanOnSave": true,
    "blockCritical": true,
    "realTimeScanning": true,
    "categories": {
      "owasp": true,
      "authentication": true,
      "authorization": true,
      "injection": true,
      "crypto": true,
      "secrets": true,
      "xss": true,
      "csrf": true,
      "deserialization": true,
      "logging": true
    },
    "severity": {
      "minLevel": "low",
      "blockLevel": "critical",
      "alertLevel": "high"
    },
    "reporting": {
      "format": "detailed",
      "includeRemediation": true,
      "includeExamples": true,
      "exportFormats": ["json", "html", "pdf"]
    },
    "whitelist": {
      "files": ["test/**/*.ts", "scripts/**/*.ts"],
      "rules": ["missing-auth-check"],
      "patterns": ["console\\.log\\("]
    }
  }
}
```

### Environment Configuration

```bash
# Security scanning
export CI_ENABLE_SECURITY_SCAN="true"
export CI_SECURITY_STRICT_MODE="true"
export CI_BLOCK_CRITICAL_ISSUES="true"
export CI_SECURITY_TIMEOUT="60000"

# Rule configuration
export CI_SECURITY_MIN_SEVERITY="medium"
export CI_SECURITY_MAX_FINDINGS="100"
export CI_SECURITY_INCLUDE_CATEGORIES="owasp,auth,injection"

# Reporting
export CI_SECURITY_REPORT_FORMAT="detailed"
export CI_SECURITY_EXPORT_PATH="./security-reports"
```

## Authentication Pattern Analysis

### Supported Authentication Patterns

#### JWT Token Validation
```typescript
// Detected pattern
export async function requireAuthWithTenant() {
  const token = await getToken();
  const payload = jwt.verify(token, secret);
  return { user: payload.user, orgSlug: payload.orgSlug };
}

// Analysis output
{
  "pattern": "jwt-validation",
  "strength": "strong",
  "coverage": 85,
  "issues": []
}
```

#### Session-Based Authentication
```typescript
// Detected pattern
export async function validateSession(sessionId: string) {
  const session = await getSession(sessionId);
  if (!session || session.expired) {
    throw new Error('Invalid session');
  }
  return session.user;
}

// Analysis output
{
  "pattern": "session-based",
  "strength": "medium",
  "coverage": 78,
  "issues": ["Session timeout not enforced"]
}
```

#### OAuth/OIDC Integration
```typescript
// Detected pattern
export async function handleOAuthCallback(code: string) {
  const tokens = await exchangeCodeForTokens(code);
  const userInfo = await fetchUserInfo(tokens.access_token);
  return createSession(userInfo);
}

// Analysis output
{
  "pattern": "oauth-integration",
  "strength": "strong",
  "coverage": 92,
  "issues": []
}
```

### RBAC Analysis

#### Role Definition Detection
```typescript
// Detected roles
enum UserRole {
  ADMIN = 'admin',
  USER = 'user', 
  MODERATOR = 'moderator'
}

// Analysis output
{
  "roles": ["admin", "user", "moderator"],
  "permissions": ["read", "write", "delete", "manage"],
  "coverage": 89,
  "issues": ["Missing permission checks in 3 endpoints"]
}
```

#### Permission Validation
```typescript
// Detected pattern
export function hasPermission(userRole: UserRole, action: string): boolean {
  const permissions = rolePermissions[userRole];
  return permissions.includes(action);
}

// Analysis output
{
  "permissionSystem": "explicit",
  "coverage": 94,
  "enforced": true,
  "gaps": []
}
```

## Multi-tenant Security Analysis

### Tenant Isolation Patterns

#### Row Level Security (RLS)
```sql
-- Detected RLS policy
CREATE POLICY tenant_isolation ON public.users
FOR ALL USING (org_id = current_setting('app.current_org_id'));

-- Analysis output
{
  "isolation": "row-level-security", 
  "coverage": 96,
  "tables": ["users", "projects", "tasks"],
  "issues": ["Missing RLS on 'logs' table"]
}
```

#### Application-Level Filtering
```typescript
// Detected pattern
export async function getOrgDatabaseWithAuth() {
  const { orgId } = await requireAuthWithTenant();
  return supabase.from('table').eq('org_id', orgId);
}

// Analysis output
{
  "isolation": "application-level",
  "coverage": 87,
  "enforcement": "middleware",
  "issues": ["2 queries bypass org filtering"]
}
```

## Vulnerability Detection Examples

### SQL Injection Detection

**Vulnerable Code:**
```typescript
const query = `SELECT * FROM users WHERE id = ${userId}`;
const result = await db.query(query);
```

**Detection Result:**
```json
{
  "id": "sql-injection-001",
  "severity": "critical",
  "category": "injection",
  "file": "src/api/users.ts",
  "line": 15,
  "message": "SQL injection vulnerability through string concatenation",
  "remediation": "Use parameterized queries",
  "fix": "const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);"
}
```

### Hardcoded Secrets Detection

**Vulnerable Code:**
```typescript
const apiKey = "sk-1234567890abcdef";
const config = {
  secret: "hardcoded-secret-key"
};
```

**Detection Result:**
```json
{
  "id": "hardcoded-secret-001",
  "severity": "high",
  "category": "secrets",
  "file": "src/config.ts",
  "line": 12,
  "message": "Hardcoded API key detected",
  "remediation": "Move to environment variables",
  "fix": "const apiKey = process.env.API_KEY;"
}
```

### Authentication Bypass Detection

**Vulnerable Code:**
```typescript
export async function GET() {
  const data = await getOrgDatabase().from('sensitive_data').select('*');
  return Response.json(data);
}
```

**Detection Result:**
```json
{
  "id": "auth-bypass-001",
  "severity": "critical",
  "category": "authentication",
  "file": "src/app/api/data/route.ts",
  "line": 8,
  "message": "API endpoint missing authentication check",
  "remediation": "Add authentication middleware",
  "fix": "const { user, orgSlug } = await requireAuthWithTenant();"
}
```

## Security Reporting

### Detailed Security Report

```json
{
  "timestamp": "2024-03-15T10:30:00.000Z",
  "project": "/path/to/project",
  "summary": {
    "totalFindings": 12,
    "criticalIssues": 2,
    "highIssues": 4,
    "mediumIssues": 5,
    "lowIssues": 1,
    "securityScore": 78
  },
  "categories": {
    "authentication": 3,
    "authorization": 2,
    "injection": 2,
    "secrets": 1,
    "crypto": 1,
    "xss": 1,
    "logging": 2
  },
  "trends": {
    "previousScore": 65,
    "improvement": 13,
    "newIssues": 2,
    "resolvedIssues": 5
  },
  "findings": [
    {
      "id": "AUTH-001",
      "severity": "critical",
      "category": "authentication",
      "title": "Missing Authentication in API Route",
      "file": "src/app/api/users/route.ts",
      "line": 12,
      "description": "API endpoint allows unauthenticated access to user data",
      "impact": "Unauthorized access to sensitive user information",
      "remediation": {
        "description": "Add authentication middleware",
        "code": "const { user, orgSlug } = await requireAuthWithTenant();",
        "effort": "low",
        "priority": "immediate"
      },
      "references": [
        "OWASP A01:2021 – Broken Access Control",
        "CWE-862: Missing Authorization"
      ]
    }
  ],
  "recommendations": [
    "Implement authentication for all API endpoints",
    "Add comprehensive input validation",
    "Enable security logging for audit trails",
    "Regular security dependency updates"
  ]
}
```

### Security Dashboard Metrics

```json
{
  "security": {
    "score": 78,
    "trend": "improving",
    "coverage": {
      "authentication": 89,
      "authorization": 94,
      "inputValidation": 67,
      "logging": 45
    },
    "compliance": {
      "owasp": 85,
      "internal": 92,
      "industry": 78
    }
  }
}
```

## Integration with CI/CD

### GitHub Actions Integration

```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install Codebase Intelligence
        run: npm install -g @codebase-intelligence/server
      
      - name: Run Security Analysis
        run: |
          codebase-intelligence analyze-security \
            --project . \
            --min-severity medium \
            --block-critical \
            --output security-report.json
      
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
      
      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('security-report.json'));
            
            const comment = `## Security Analysis Results
            
            - **Security Score**: ${report.summary.securityScore}/100
            - **Critical Issues**: ${report.summary.criticalIssues}
            - **High Issues**: ${report.summary.highIssues}
            
            ${report.summary.criticalIssues > 0 ? '❌ Critical security issues found!' : '✅ No critical issues found'}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### Pre-commit Hooks

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Running security analysis..."
codebase-intelligence analyze-security \
  --staged-only \
  --min-severity high \
  --block-critical

if [ $? -ne 0 ]; then
  echo "❌ Security issues found. Commit blocked."
  echo "Run 'codebase-intelligence security --fix' to address issues."
  exit 1
fi

echo "✅ Security analysis passed."
```

## Best Practices

### Security Configuration
1. **Enable Real-time Scanning**: Catch issues as you code
2. **Block Critical Issues**: Prevent deployment of critical vulnerabilities
3. **Regular Security Updates**: Keep rules and patterns current
4. **Custom Rules**: Define project-specific security requirements

### Development Workflow
1. **Security-First Design**: Consider security from the start
2. **Regular Security Reviews**: Schedule periodic security analysis
3. **Team Training**: Ensure team understands security patterns
4. **Continuous Monitoring**: Track security metrics over time

### Remediation Strategy
1. **Priority-Based**: Address critical issues first
2. **Automated Fixes**: Use auto-fix for simple issues
3. **Pattern Enforcement**: Prevent similar issues in future
4. **Documentation**: Document security decisions and patterns

---

*For more advanced security features, see our [Enterprise Security Guide](./enterprise/security.md) and [Custom Rules Development](./development/custom-rules.md).*