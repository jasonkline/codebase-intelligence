# MCP Tools Reference

The Codebase Intelligence MCP Server provides 33 powerful tools for comprehensive code analysis, security scanning, pattern recognition, and knowledge extraction. This reference covers all available tools with detailed examples.

## Tool Categories

### 🔍 Core Analysis Tools
- [`ping`](#ping) - Test server connectivity
- [`analyze_project`](#analyze_project) - Comprehensive project analysis
- [`analyze_security`](#analyze_security) - Security vulnerability scanning

### 🛡️ Security Tools
- [`check_auth_pattern`](#check_auth_pattern) - Authentication pattern analysis
- [`find_vulnerabilities`](#find_vulnerabilities) - Specific vulnerability detection
- [`explain_security`](#explain_security) - Security model explanation

### 🛡️ OWASP Security Tools
- [`analyze_cheatsheet_compliance`](#analyze_cheatsheet_compliance) - OWASP Cheat Sheet compliance analysis
- [`assess_asvs_compliance`](#assess_asvs_compliance) - ASVS compliance assessment
- [`scan_api_security`](#scan_api_security) - OWASP API Security Top 10 scan
- [`scan_mobile_security`](#scan_mobile_security) - OWASP Mobile Top 10 scan
- [`scan_ai_security`](#scan_ai_security) - OWASP AI Security scan
- [`generate_compliance_report`](#generate_compliance_report) - Comprehensive OWASP compliance report
- [`get_cheatsheet_guidance`](#get_cheatsheet_guidance) - Context-aware OWASP guidance

### 🧠 Pattern Recognition Tools
- [`learn_patterns`](#learn_patterns) - Extract patterns from codebase
- [`check_pattern_compliance`](#check_pattern_compliance) - Validate against patterns
- [`get_approved_pattern`](#get_approved_pattern) - Retrieve approved patterns
- [`suggest_pattern`](#suggest_pattern) - Get pattern suggestions

### 💡 Knowledge System Tools
- [`explain_system`](#explain_system) - Natural language system queries
- [`analyze_impact`](#analyze_impact) - Change impact analysis
- [`get_system_docs`](#get_system_docs) - Generate system documentation
- [`trace_data_flow`](#trace_data_flow) - Data flow visualization

### ⚡ Real-time Intelligence Tools
- [`validate_as_typed`](#validate_as_typed) - Real-time code validation
- [`suggest_next`](#suggest_next) - Predictive code suggestions
- [`prevent_error`](#prevent_error) - Proactive error detection
- [`quick_fix`](#quick_fix) - Instant fix suggestions
- [`explain_warning`](#explain_warning) - Warning explanations
- [`start_watching`](#start_watching) - Enable file watching
- [`stop_watching`](#stop_watching) - Disable file watching

## Tool Reference

### Core Analysis Tools

#### `ping`
Test server connectivity and basic functionality.

**Parameters:**
- `message` (optional, string): Message to echo back

**Example:**
```typescript
// Claude Code usage
"Test the codebase intelligence server connectivity"

// Direct MCP call
{
  "name": "ping",
  "arguments": {
    "message": "test connection"
  }
}
```

**Response:**
```json
{
  "message": "pong: test connection",
  "timestamp": "2024-03-15T10:30:00.000Z",
  "version": "1.0.0"
}
```

#### `analyze_project`
Perform comprehensive analysis of an entire project.

**Parameters:**
- `projectPath` (required, string): Absolute path to project directory
- `include` (optional, array): File patterns to include
- `exclude` (optional, array): File patterns to exclude
- `parallel` (optional, boolean): Enable parallel processing
- `maxConcurrency` (optional, number): Maximum concurrent operations
- `watchMode` (optional, boolean): Enable real-time watching

**Example:**
```typescript
// Claude Code usage
"Analyze this project for security issues and patterns"

// Direct MCP call
{
  "name": "analyze_project",
  "arguments": {
    "projectPath": "/path/to/project",
    "include": ["src/**/*.ts", "src/**/*.tsx"],
    "exclude": ["node_modules/**", "**/*.test.ts"],
    "parallel": true,
    "maxConcurrency": 4
  }
}
```

**Response:**
```json
{
  "success": true,
  "projectPath": "/path/to/project",
  "summary": {
    "filesProcessed": 247,
    "filesSkipped": 12,
    "errors": 0,
    "duration": 15420,
    "totalSymbols": 1834,
    "totalPatterns": 45,
    "securityIssues": 7,
    "languages": {"typescript": 235, "javascript": 12},
    "systems": ["authentication", "api", "database"],
    "coverage": {
      "authCovered": 85,
      "rbacImplemented": 92,
      "dataAccessSecure": 78
    }
  },
  "findings": {
    "criticalSecurityIssues": [
      "Direct database access without authentication in 3 files",
      "Hardcoded secrets found in configuration"
    ],
    "authPatterns": ["JWT validation", "Role-based access control"],
    "rbacPatterns": ["Admin role", "User role", "Moderator role"],
    "dataAccessPatterns": ["RLS enabled", "Tenant isolation"],
    "apiPatterns": ["RESTful endpoints", "Error handling"]
  },
  "recommendations": [
    "Implement authentication for all API endpoints",
    "Replace hardcoded secrets with environment variables",
    "Add input validation to user-facing endpoints"
  ]
}
```

### Security Tools

#### `analyze_security`
Perform deep security analysis on files or directories.

**Parameters:**
- `path` (required, string): Path to analyze
- `options` (optional, object): Security scan options
  - `includeCategories` (array): Vulnerability categories to include
  - `excludeCategories` (array): Vulnerability categories to exclude
  - `minSeverity` (string): Minimum severity level
  - `maxFindings` (number): Maximum findings to return

**Example:**
```typescript
// Claude Code usage  
"Check this API directory for security vulnerabilities"

// Direct MCP call
{
  "name": "analyze_security",
  "arguments": {
    "path": "/path/to/api",
    "options": {
      "minSeverity": "medium",
      "maxFindings": 20,
      "includeCategories": ["injection", "authentication", "authorization"]
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "path": "/path/to/api",
  "timestamp": "2024-03-15T10:30:00.000Z",
  "summary": {
    "totalFindings": 12,
    "criticalIssues": 2,
    "bySeverity": {
      "critical": 2,
      "high": 4,
      "medium": 6,
      "low": 0
    },
    "byCategory": {
      "authentication": 3,
      "injection": 2,
      "authorization": 7
    }
  },
  "findings": {
    "security": [
      {
        "id": "auth_001",
        "severity": "critical",
        "category": "authentication",
        "title": "Missing authentication check",
        "file": "api/users/route.ts",
        "line": 15,
        "description": "API endpoint allows unauthenticated access",
        "remediation": "Add requireAuthWithTenant() call"
      }
    ]
  },
  "criticalFindings": [
    "Direct database access bypassing RLS",
    "API endpoint without authentication"
  ],
  "recommendations": [
    "Implement authentication middleware for all routes",
    "Use authenticated database connections",
    "Add input validation and sanitization"
  ]
}
```

#### `check_auth_pattern`
Analyze authentication and authorization patterns.

**Parameters:**
- `path` (required, string): Path to analyze

**Example:**
```typescript
// Claude Code usage
"How is authentication implemented in this codebase?"

// Direct MCP call
{
  "name": "check_auth_pattern",
  "arguments": {
    "path": "/path/to/project"
  }
}
```

**Response:**
```json
{
  "success": true,
  "path": "/path/to/project",
  "authFlow": {
    "entryPoints": 15,
    "authChecks": 12,
    "roleChecks": 8,
    "permissionChecks": 5,
    "gaps": 3
  },
  "rbac": {
    "roles": ["admin", "user", "moderator"],
    "permissions": ["read", "write", "delete", "manage"],
    "issues": 2
  },
  "patterns": {
    "authPatterns": [
      {
        "name": "requireAuthWithTenant",
        "type": "function_call",
        "line": 23,
        "confidence": 0.95
      }
    ]
  },
  "securityGaps": [
    {
      "title": "Missing authentication in DELETE endpoint",
      "severity": "high",
      "line": 45,
      "remediation": "Add authentication middleware"
    }
  ]
}
```

### OWASP Security Tools

#### `analyze_cheatsheet_compliance`
Analyze code compliance against OWASP Cheat Sheet patterns and provide context-aware security guidance.

**Parameters:**
- `filePath` (required, string): Absolute path to the file to analyze
- `categories` (optional, array): Specific cheat sheet categories to check (authentication, session_management, etc.)
- `severity` (optional, string): Minimum severity level to report (critical/high/medium/low)

**Example:**
```typescript
// Claude Code usage
"Check this authentication code against OWASP cheat sheets"

// Direct MCP call
{
  "name": "analyze_cheatsheet_compliance",
  "arguments": {
    "filePath": "/path/to/auth.ts",
    "categories": ["authentication", "session_management"],
    "severity": "medium"
  }
}
```

**Response:**
```json
{
  "success": true,
  "filePath": "/path/to/auth.ts",
  "compliance": {
    "overallScore": 78,
    "issues": 3,
    "recommendations": 5
  },
  "findings": [
    {
      "category": "authentication",
      "severity": "high",
      "title": "Weak password policy",
      "line": 45,
      "cheatSheet": "Authentication Cheat Sheet",
      "guidance": "Implement strong password requirements with minimum 12 characters",
      "remediation": "Update password validation to require complex passwords"
    }
  ]
}
```

#### `assess_asvs_compliance`
Perform comprehensive ASVS (Application Security Verification Standard) compliance assessment against levels 1-3.

**Parameters:**
- `projectPath` (required, string): Absolute path to the project directory
- `level` (optional, number): ASVS compliance level to assess against (1/2/3, default: 1)
- `includeManualReview` (optional, boolean): Include controls that require manual review

**Example:**
```typescript
// Claude Code usage
"Assess this project's ASVS Level 2 compliance"

// Direct MCP call
{
  "name": "assess_asvs_compliance",
  "arguments": {
    "projectPath": "/path/to/project",
    "level": 2,
    "includeManualReview": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "projectPath": "/path/to/project",
  "level": 2,
  "compliance": {
    "overallScore": 72,
    "totalControls": 286,
    "implementedControls": 206,
    "partialControls": 45,
    "missingControls": 35
  },
  "categories": {
    "V1_Architecture": { "score": 85, "implemented": 12, "total": 14 },
    "V2_Authentication": { "score": 68, "implemented": 25, "total": 37 },
    "V3_Session": { "score": 90, "implemented": 18, "total": 20 }
  },
  "criticalFindings": [
    "V2.1.1: Missing multi-factor authentication",
    "V3.2.3: Session tokens not properly invalidated"
  ]
}
```

#### `scan_api_security`
Comprehensive API security scan based on OWASP API Security Top 10, identifying API-specific vulnerabilities.

**Parameters:**
- `path` (required, string): Absolute path to API files or directory
- `includeEndpoints` (optional, boolean): Include detailed endpoint analysis
- `riskThreshold` (optional, number): Risk score threshold (1-10) for reporting

**Example:**
```typescript
// Claude Code usage
"Scan this API directory for OWASP API Security Top 10 issues"

// Direct MCP call
{
  "name": "scan_api_security",
  "arguments": {
    "path": "/path/to/api",
    "includeEndpoints": true,
    "riskThreshold": 3
  }
}
```

**Response:**
```json
{
  "success": true,
  "path": "/path/to/api",
  "summary": {
    "totalEndpoints": 45,
    "vulnerableEndpoints": 12,
    "riskScore": 7.2,
    "top10Coverage": {
      "API1_BrokenObjectLevelAuth": 8,
      "API2_BrokenUserAuth": 3,
      "API3_ExcessiveDataExposure": 5
    }
  },
  "findings": [
    {
      "endpoint": "GET /api/users/{id}",
      "vulnerability": "API1_BrokenObjectLevelAuth",
      "severity": "high",
      "description": "Missing object-level authorization check",
      "remediation": "Implement proper authorization validation"
    }
  ]
}
```

#### `scan_mobile_security`
Mobile application security scan based on OWASP Mobile Top 10, analyzing mobile-specific vulnerabilities.

**Parameters:**
- `path` (required, string): Absolute path to mobile app files or directory
- `platform` (optional, string): Target mobile platform (iOS/Android/Cross-Platform)
- `includeFrameworkAnalysis` (optional, boolean): Include mobile framework-specific analysis

**Example:**
```typescript
// Claude Code usage
"Scan this React Native app for mobile security issues"

// Direct MCP call
{
  "name": "scan_mobile_security",
  "arguments": {
    "path": "/path/to/mobile-app",
    "platform": "Cross-Platform",
    "includeFrameworkAnalysis": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "path": "/path/to/mobile-app",
  "platform": "Cross-Platform",
  "summary": {
    "riskScore": 6.8,
    "totalIssues": 15,
    "top10Coverage": {
      "M1_ImproperPlatformUsage": 2,
      "M2_InsecureDataStorage": 4,
      "M3_InsecureCommunication": 3
    }
  },
  "findings": [
    {
      "vulnerability": "M2_InsecureDataStorage",
      "severity": "high",
      "file": "src/storage/SecureStorage.js",
      "description": "Sensitive data stored without encryption",
      "remediation": "Use platform keychain/keystore for sensitive data"
    }
  ]
}
```

#### `scan_ai_security`
AI/ML security scan based on OWASP AI Testing Guide, identifying AI-specific vulnerabilities including prompt injection and model security.

**Parameters:**
- `path` (required, string): Absolute path to AI/ML code files or directory
- `includeModelAnalysis` (optional, boolean): Include detailed ML model security analysis
- `riskLevel` (optional, string): Minimum risk level to report (high/medium/low)

**Example:**
```typescript
// Claude Code usage
"Scan this AI application for security vulnerabilities"

// Direct MCP call
{
  "name": "scan_ai_security",
  "arguments": {
    "path": "/path/to/ai-app",
    "includeModelAnalysis": true,
    "riskLevel": "medium"
  }
}
```

**Response:**
```json
{
  "success": true,
  "path": "/path/to/ai-app",
  "summary": {
    "riskScore": 8.1,
    "totalVulnerabilities": 9,
    "categories": {
      "promptInjection": 3,
      "modelSecurity": 2,
      "dataPoisoning": 4
    }
  },
  "findings": [
    {
      "vulnerability": "Prompt Injection",
      "severity": "critical",
      "file": "src/llm/ChatHandler.ts",
      "description": "User input directly concatenated to prompt without sanitization",
      "remediation": "Implement input sanitization and prompt templating"
    }
  ]
}
```

#### `generate_compliance_report`
Generate comprehensive OWASP compliance report covering multiple standards with detailed metrics and remediation guidance.

**Parameters:**
- `projectPath` (required, string): Absolute path to the project directory
- `standards` (optional, array): OWASP standards to include (top10/api-security/asvs/mobile/ai-guide/cheat-sheets)
- `includeRemediation` (optional, boolean): Include detailed remediation guidance
- `outputFormat` (optional, string): Report output format (json/summary)

**Example:**
```typescript
// Claude Code usage
"Generate a comprehensive OWASP compliance report for this project"

// Direct MCP call
{
  "name": "generate_compliance_report",
  "arguments": {
    "projectPath": "/path/to/project",
    "standards": ["top10", "api-security", "asvs"],
    "includeRemediation": true,
    "outputFormat": "summary"
  }
}
```

**Response:**
```json
{
  "success": true,
  "projectPath": "/path/to/project",
  "generatedAt": "2024-03-15T10:30:00.000Z",
  "overallCompliance": {
    "score": 74,
    "grade": "B",
    "criticalIssues": 5,
    "highIssues": 12,
    "mediumIssues": 28
  },
  "standardsAssessment": {
    "owaspTop10": { "score": 78, "issues": 15 },
    "apiSecurity": { "score": 72, "issues": 8 },
    "asvs": { "score": 71, "issues": 22 }
  },
  "recommendations": [
    {
      "priority": "critical",
      "title": "Implement proper authentication",
      "description": "Multiple endpoints lack authentication",
      "effort": "high",
      "impact": "critical"
    }
  ]
}
```

#### `get_cheatsheet_guidance`
Get context-aware security guidance from OWASP Cheat Sheets based on code context and security patterns.

**Parameters:**
- `query` (required, string): Security topic or vulnerability type to get guidance for
- `context` (optional, string): Code context (file type, framework, etc.) for targeted guidance
- `limit` (optional, number): Maximum number of guidance items to return

**Example:**
```typescript
// Claude Code usage
"How should I implement secure authentication in a Node.js API?"

// Direct MCP call
{
  "name": "get_cheatsheet_guidance",
  "arguments": {
    "query": "authentication",
    "context": "Node.js Express API",
    "limit": 5
  }
}
```

**Response:**
```json
{
  "success": true,
  "query": "authentication",
  "context": "Node.js Express API",
  "guidance": [
    {
      "title": "Implement Strong Password Policies",
      "cheatSheet": "Authentication Cheat Sheet",
      "category": "password_management",
      "description": "Enforce minimum 12 characters with complexity requirements",
      "implementation": "Use libraries like joi or express-validator",
      "example": "const passwordSchema = joi.string().min(12).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])/)"
    }
  ]
}
```

### Pattern Recognition Tools

#### `learn_patterns`
Extract and learn patterns from existing codebase.

**Parameters:**
- `projectPath` (required, string): Project directory path
- `categories` (optional, array): Pattern categories to learn
- `minConfidence` (optional, number): Minimum confidence threshold

**Example:**
```typescript
// Claude Code usage
"Learn the coding patterns from this project"

// Direct MCP call
{
  "name": "learn_patterns",
  "arguments": {
    "projectPath": "/path/to/project",
    "categories": ["auth", "api", "data_access"],
    "minConfidence": 0.8
  }
}
```

**Response:**
```json
{
  "success": true,
  "projectPath": "/path/to/project",
  "summary": {
    "filesAnalyzed": 156,
    "totalPatternsLearned": 23,
    "patternsByCategory": {
      "auth": 8,
      "api": 9,
      "data_access": 6
    },
    "duration": 8450
  },
  "recommendations": [
    "Successfully learned 23 patterns",
    "Patterns are now available for compliance checking",
    "Use check_pattern_compliance to validate code"
  ]
}
```

#### `check_pattern_compliance`
Validate code against learned patterns and governance rules.

**Parameters:**
- `filePath` (required, string): File to check
- `patternCategory` (optional, string): Specific category to check
- `explainViolations` (optional, boolean): Include detailed explanations

**Example:**
```typescript
// Claude Code usage
"Check if this file follows our coding patterns"

// Direct MCP call
{
  "name": "check_pattern_compliance",
  "arguments": {
    "filePath": "/path/to/file.ts",
    "patternCategory": "api",
    "explainViolations": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "filePath": "/path/to/file.ts",
  "compliance": {
    "overallScore": 75,
    "violations": 3,
    "issues": 2,
    "recommendations": 4
  },
  "violations": [
    {
      "ruleId": "api_auth_required",
      "ruleName": "API Authentication Required",
      "severity": "high",
      "line": 15,
      "message": "API endpoint missing authentication check",
      "suggestion": "Add requireAuthWithTenant() at the beginning",
      "explanation": "This violates the API governance rule requiring authentication"
    }
  ],
  "patterns": {
    "auth": 2,
    "api": 4,
    "dataAccess": 1
  }
}
```

### Knowledge System Tools

#### `explain_system`
Answer natural language questions about the codebase.

**Parameters:**
- `query` (required, string): Question about the system
- `context` (optional, string): Additional context
- `detailLevel` (optional, string): Level of detail (summary/detailed/technical)

**Example:**
```typescript
// Claude Code usage
"How does authentication work in this application?"

// Direct MCP call
{
  "name": "explain_system",
  "arguments": {
    "query": "How does authentication work in this application?",
    "detailLevel": "detailed"
  }
}
```

**Response:**
```json
{
  "success": true,
  "query": "How does authentication work in this application?",
  "confidence": 0.92,
  "answer": "Authentication in this application follows a JWT-based approach with multi-tenant support:\n\n1. **Login Process**: Users authenticate via Supabase Auth using OAuth or email/password\n2. **Token Validation**: Every API route calls requireAuthWithTenant() to validate JWT tokens\n3. **Context Extraction**: The middleware extracts user, organization slug, and role from the token\n4. **Database Access**: All database operations use getOrgDatabaseWithAuth() for automatic tenant isolation\n5. **Authorization**: Role-based permissions are checked using hasPermission() function\n\nThe system supports three roles: admin (full access), member (limited access), and approver (can approve timecards). All data is isolated by organization using Row Level Security (RLS).",
  "sources": [
    "src/lib/supabase-auth.ts",
    "src/lib/database.ts",
    "src/lib/roles.ts"
  ],
  "codeExamples": [
    {
      "file": "src/lib/supabase-auth.ts",
      "function": "requireAuthWithTenant",
      "description": "Main authentication middleware"
    }
  ],
  "relatedTopics": ["RBAC", "Multi-tenancy", "Database Security"],
  "followUpQuestions": [
    "What roles are available in the system?",
    "How is data isolated between organizations?",
    "What happens when authentication fails?"
  ]
}
```

#### `analyze_impact`
Analyze the impact of proposed changes.

**Parameters:**
- `targetComponent` (required, string): Component to change
- `changeType` (required, string): Type of change (modify/delete/add/refactor)
- `changeDescription` (optional, string): Description of the change

**Example:**
```typescript
// Claude Code usage
"What would happen if I modify the authentication middleware?"

// Direct MCP call
{
  "name": "analyze_impact",
  "arguments": {
    "targetComponent": "src/lib/supabase-auth.ts",
    "changeType": "modify",
    "changeDescription": "Update JWT validation logic"
  }
}
```

**Response:**
```json
{
  "success": true,
  "targetComponent": "src/lib/supabase-auth.ts",
  "changeType": "modify",
  "changeId": "change_abc123",
  "summary": {
    "overallRisk": "high",
    "impactScore": 85,
    "affectedComponents": 23,
    "testingEffort": "extensive",
    "totalDuration": "2-3 days"
  },
  "riskAssessment": {
    "overallRisk": "high",
    "businessImpact": "critical",
    "technicalRisk": "high",
    "riskFactors": [
      "Core authentication component",
      "Used by all API endpoints",
      "Security-critical functionality",
      "Multi-tenant isolation dependency"
    ]
  },
  "recommendations": [
    {
      "type": "testing",
      "recommendation": "Create comprehensive test suite before changes",
      "priority": "critical",
      "effort": "high"
    },
    {
      "type": "deployment",
      "recommendation": "Deploy to staging environment first",
      "priority": "high",
      "effort": "medium"
    }
  ],
  "testingPlan": {
    "estimatedEffort": "extensive",
    "requiredTests": 15,
    "criticalPaths": [
      "User login flow",
      "API authentication",
      "Multi-tenant isolation",
      "Role-based access"
    ]
  }
}
```

### Real-time Intelligence Tools

#### `validate_as_typed`
Provide real-time validation as code is being written.

**Parameters:**
- `filePath` (required, string): File being edited
- `content` (required, string): Current file content
- `line` (optional, number): Current line number
- `column` (optional, number): Current column number
- `triggerCharacter` (optional, string): Character that triggered validation

**Example:**
```typescript
// Claude Code usage
"Check this code as I'm writing it"

// Direct MCP call
{
  "name": "validate_as_typed",
  "arguments": {
    "filePath": "/path/to/file.ts",
    "content": "export async function GET() {\n  const db = getOrgDatabase()\n  return Response.json(data)\n}",
    "line": 2,
    "column": 25
  }
}
```

**Response:**
```json
{
  "success": true,
  "filePath": "/path/to/file.ts",
  "timestamp": "2024-03-15T10:30:00.000Z",
  "issues": [
    {
      "id": "direct-db-access",
      "severity": "critical",
      "message": "Direct database access detected - use getOrgDatabaseWithAuth() instead",
      "line": 2,
      "column": 15,
      "quickFix": {
        "title": "Use authenticated database connection",
        "oldText": "getOrgDatabase()",
        "newText": "await getOrgDatabaseWithAuth()"
      }
    },
    {
      "id": "missing-auth",
      "severity": "high", 
      "message": "API route missing authentication check",
      "line": 1,
      "column": 1,
      "quickFix": {
        "title": "Add authentication",
        "oldText": "export async function GET() {",
        "newText": "export async function GET() {\n  const { user, orgSlug } = await requireAuthWithTenant()"
      }
    }
  ],
  "suggestions": [
    {
      "type": "security",
      "message": "Consider adding input validation",
      "priority": "medium"
    }
  ]
}
```

#### `suggest_next`
Predict and suggest what code should come next.

**Parameters:**
- `filePath` (required, string): File being edited
- `content` (required, string): Current file content
- `line` (required, number): Current line number
- `column` (required, number): Current column number
- `context` (optional, string): Additional context
- `maxSuggestions` (optional, number): Maximum suggestions to return

**Example:**
```typescript
// Direct MCP call
{
  "name": "suggest_next",
  "arguments": {
    "filePath": "/path/to/api/route.ts",
    "content": "export async function POST() {\n  const { user, orgSlug } = await requireAuthWithTenant()\n  ",
    "line": 3,
    "column": 2,
    "context": "Creating a new API endpoint with database access",
    "maxSuggestions": 3
  }
}
```

**Response:**
```json
{
  "success": true,
  "filePath": "/path/to/api/route.ts",
  "suggestions": [
    {
      "text": "const db = await getOrgDatabaseWithAuth()",
      "category": "database-access",
      "confidence": 0.95,
      "description": "Add authenticated database connection",
      "reasoning": "Pattern detected: after auth check, typically need database access"
    },
    {
      "text": "if (!hasPermission(user.role, 'write:resource')) {\n    return new Response('Forbidden', { status: 403 })\n  }",
      "category": "authorization",
      "confidence": 0.87,
      "description": "Add permission check",
      "reasoning": "POST endpoints typically require write permissions"
    },
    {
      "text": "const body = await request.json()",
      "category": "input-handling", 
      "confidence": 0.82,
      "description": "Parse request body",
      "reasoning": "POST requests usually need to parse body data"
    }
  ]
}
```

## Usage Patterns

### Common Workflows

#### 1. Initial Project Analysis
```typescript
// Step 1: Analyze the entire project
"Analyze this project for security issues and coding patterns"

// Step 2: Learn patterns from the codebase  
"Learn the coding patterns from this project"

// Step 3: Check specific areas of concern
"Check the authentication implementation in this codebase"
```

#### 2. Security Assessment Workflow
```typescript
// Comprehensive OWASP compliance assessment
"Generate a comprehensive OWASP compliance report for this project"

// API-specific security scan
"Scan this API directory for OWASP API Security Top 10 issues"

// ASVS compliance check
"Assess this project's ASVS Level 2 compliance"

// Context-aware security guidance
"How should I implement secure authentication in a Node.js API?"
```

#### 3. Code Review Workflow
```typescript
// Check pattern compliance
"Check if this file follows our coding patterns"

// OWASP cheat sheet compliance
"Check this authentication code against OWASP cheat sheets"

// Security analysis
"Analyze this API directory for security vulnerabilities" 

// Impact analysis for changes
"What would be the impact of modifying this authentication function?"
```

#### 4. Real-time Development
```typescript
// Enable file watching
{
  "name": "start_watching",
  "arguments": { "projectPath": "/path/to/project" }
}

// Get real-time validation and suggestions as you type
// (These would be called automatically by Claude Code)
```

### Error Handling

All tools follow consistent error handling patterns:

```json
{
  "success": false,
  "error": "Error message describing what went wrong",
  "code": "ERROR_CODE",
  "details": {
    "additionalContext": "More information about the error"
  }
}
```

### Performance Considerations

- **Large projects**: Use `parallel: true` and appropriate `maxConcurrency`
- **Real-time tools**: Have sub-100ms response times
- **Analysis tools**: May take several seconds for large codebases
- **Caching**: Results are cached when possible to improve performance

## Next Steps

- **[Security Analysis Guide](./security-tools.md)** - Deep dive into security features
- **[OWASP Integration Guide](./owasp-tools.md)** - OWASP compliance and security standards
- **[Pattern Recognition Guide](./pattern-tools.md)** - Learn about pattern system
- **[Knowledge System Guide](./knowledge-tools.md)** - Explore AI-powered insights
- **[Real-time Features](./intelligence-tools.md)** - Set up live code assistance

---

*For more examples and advanced usage, see our [API Reference](../api-reference.md) and [Configuration Guide](../configuration.md).*