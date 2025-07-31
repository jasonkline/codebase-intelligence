# Pattern Recognition System

Comprehensive guide to the pattern recognition and governance capabilities of Codebase Intelligence.

## Overview

The pattern recognition system automatically learns coding patterns from your codebase, enforces governance rules, and ensures consistency across your team's development practices. It combines machine learning, AST analysis, and rule-based validation to maintain code quality and architectural compliance.

## Core Concepts

### What are Patterns?

Patterns are recurring code structures, practices, or architectural decisions that define how your team writes code. Examples include:

- **Authentication Patterns**: How users are authenticated and authorized
- **API Patterns**: Standard structure for API endpoints
- **Data Access Patterns**: How data is queried and modified
- **Error Handling Patterns**: Consistent error handling approaches
- **Validation Patterns**: Input validation and sanitization methods

### Pattern Categories

```json
{
  "categories": [
    "auth",           // Authentication and authorization
    "rbac",           // Role-based access control
    "api",            // API endpoint structures
    "data_access",    // Database and data operations
    "validation",     // Input validation
    "error_handling", // Error handling approaches
    "logging",        // Logging and monitoring
    "testing",        // Test patterns
    "performance",    // Performance optimizations
    "security"        // Security implementations
  ]
}
```

## Pattern Learning

### Automatic Pattern Learning

The system automatically discovers patterns by analyzing your codebase:

```typescript
// Example: Authentication pattern automatically detected
export async function requireAuthWithTenant() {
  const token = await getToken();
  const payload = jwt.verify(token, secret);
  return { user: payload.user, orgSlug: payload.orgSlug };
}

// Pattern learned:
{
  "name": "requireAuthWithTenant",
  "category": "auth",
  "confidence": 0.95,
  "occurrences": 23,
  "signature": "requireAuthWithTenant()",
  "variations": ["requireAuth", "authenticateUser"]
}
```

### Learning Configuration

```json
{
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.8,
    "minOccurrences": 3,
    "maxPatterns": 1000,
    "categories": ["auth", "api", "data_access"],
    "excludePatterns": ["console.log", "debugger"],
    "similarity": {
      "threshold": 0.85,
      "algorithm": "ast-fuzzy"
    }
  }
}
```

### Learning Modes

#### Automatic Learning (`auto`)
```json
{
  "patterns": {
    "learningMode": "auto",
    "schedule": "on_change",
    "background": true
  }
}
```

#### Manual Learning (`manual`)
```json
{
  "patterns": {
    "learningMode": "manual",
    "approvalRequired": true,
    "reviewProcess": "pull_request"
  }
}
```

#### Disabled Learning (`disabled`)
```json
{
  "patterns": {
    "learningMode": "disabled",
    "useCustomOnly": true
  }
}
```

## Pattern Recognition Tools

### `learn_patterns`
Extract and learn patterns from existing codebase.

**Usage:**
```typescript
// Claude Code
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
  "summary": {
    "filesAnalyzed": 156,
    "totalPatternsLearned": 23,
    "patternsByCategory": {
      "auth": 8,
      "api": 9,
      "data_access": 6
    }
  },
  "patterns": [
    {
      "id": "auth_001",
      "name": "requireAuthWithTenant",
      "category": "auth",
      "confidence": 0.95,
      "occurrences": 12,
      "description": "Standard authentication middleware",
      "signature": "requireAuthWithTenant()",
      "examples": [
        "src/lib/auth.ts:15",
        "src/api/users/route.ts:8"
      ]
    }
  ]
}
```

### `check_pattern_compliance`
Validate code against learned patterns and governance rules.

**Usage:**
```typescript
// Claude Code
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
  "compliance": {
    "overallScore": 75,
    "violations": 3,
    "recommendations": 4
  },
  "violations": [
    {
      "ruleId": "api_auth_required",
      "severity": "high",
      "line": 15,
      "message": "API endpoint missing authentication check",
      "suggestion": "Add requireAuthWithTenant() at the beginning",
      "autoFix": {
        "available": true,
        "code": "const { user, orgSlug } = await requireAuthWithTenant();"
      }
    }
  ]
}
```

### `get_approved_pattern`
Retrieve approved patterns for a specific category.

**Usage:**
```typescript
// Claude Code
"Show me the approved authentication patterns"

// Direct MCP call
{
  "name": "get_approved_pattern",
  "arguments": {
    "category": "auth",
    "includeExamples": true
  }
}
```

### `suggest_pattern`
Get pattern suggestions for current code context.

**Usage:**
```typescript
// Claude Code
"What pattern should I use for this API endpoint?"

// Direct MCP call
{
  "name": "suggest_pattern",
  "arguments": {
    "filePath": "/path/to/api/route.ts",
    "context": "Creating new API endpoint",
    "category": "api"
  }
}
```

## Pattern Types

### Function Patterns

**Authentication Pattern:**
```typescript
// Learned pattern
export async function requireAuthWithTenant(): Promise<AuthContext> {
  const token = await getToken();
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  return {
    user: payload.user,
    orgSlug: payload.orgSlug,
    permissions: payload.permissions
  };
}

// Pattern signature
{
  "type": "function",
  "name": "requireAuthWithTenant",
  "parameters": [],
  "returnType": "Promise<AuthContext>",
  "complexity": "medium"
}
```

**Database Access Pattern:**
```typescript
// Learned pattern
export async function getOrgDatabaseWithAuth(): Promise<Database> {
  const { orgSlug } = await requireAuthWithTenant();
  return supabase.schema(orgSlug);
}

// Pattern signature
{
  "type": "function",
  "name": "getOrgDatabaseWithAuth",
  "dependencies": ["requireAuthWithTenant"],
  "category": "data_access"
}
```

### Structural Patterns

**API Route Pattern:**
```typescript
// Learned pattern structure
export async function POST(request: Request) {
  // 1. Authentication
  const { user, orgSlug } = await requireAuthWithTenant();
  
  // 2. Permission check
  if (!hasPermission(user.role, 'write:resource')) {
    return new Response('Forbidden', { status: 403 });
  }
  
  // 3. Input validation
  const body = await request.json();
  const validatedData = validateInput(body);
  
  // 4. Database operation
  const db = await getOrgDatabaseWithAuth();
  const result = await db.from('table').insert(validatedData);
  
  // 5. Response
  return Response.json(result);
}

// Pattern structure
{
  "type": "structure",
  "name": "authenticated-api-route",
  "sequence": [
    "authentication",
    "authorization", 
    "validation",
    "database_operation",
    "response"
  ],
  "required": ["authentication", "database_operation"],
  "optional": ["authorization", "validation"]
}
```

### Import Patterns

**Standard Import Pattern:**
```typescript
// Learned import pattern
import { requireAuthWithTenant } from '@/lib/auth';
import { getOrgDatabaseWithAuth } from '@/lib/database';
import { hasPermission } from '@/lib/rbac';

// Pattern structure
{
  "type": "imports",
  "name": "api-route-imports",
  "required": ["@/lib/auth", "@/lib/database"],
  "common": ["@/lib/rbac", "@/lib/validation"]
}
```

## Governance Rules

### Rule Definition

```json
{
  "governance": {
    "rules": [
      {
        "id": "api_auth_required",
        "name": "API Authentication Required",
        "description": "All API routes must implement authentication",
        "category": "security",
        "severity": "critical",
        "scope": "api/**/*.ts",
        "conditions": {
          "fileType": "api_route",
          "hasExport": ["GET", "POST", "PUT", "DELETE"]
        },
        "requirements": {
          "mustInclude": ["requireAuthWithTenant"],
          "mustNotInclude": ["getOrgDatabase()"],
          "structure": "authenticated-api-route"
        },
        "exceptions": [
          "api/auth/**",
          "api/public/**"
        ],
        "autoFix": {
          "enabled": true,
          "insertion": {
            "position": "function_start",
            "code": "const { user, orgSlug } = await requireAuthWithTenant();"
          }
        }
      }
    ]
  }
}
```

### Rule Enforcement

#### Blocking Rules
```json
{
  "governance": {
    "enforcement": {
      "mode": "strict",
      "blockOnViolation": true,
      "allowOverride": false
    }
  }
}
```

#### Warning Rules
```json
{
  "governance": {
    "enforcement": {
      "mode": "advisory",
      "blockOnViolation": false,
      "warnOnViolation": true
    }
  }
}
```

#### Auto-fix Rules
```json
{
  "governance": {
    "autoFix": {
      "enabled": true,
      "requireApproval": false,
      "categories": ["formatting", "imports", "simple_security"]
    }
  }
}
```

## Pattern Matching Algorithms

### AST-Based Matching

The system uses Abstract Syntax Tree analysis for precise pattern matching:

```typescript
// Source code
function authenticateUser(token: string) {
  return jwt.verify(token, secret);
}

// AST pattern (simplified)
{
  "type": "FunctionDeclaration",
  "name": "authenticateUser",
  "parameters": [
    {
      "name": "token",
      "type": "string"
    }
  ],
  "body": {
    "type": "ReturnStatement",
    "expression": {
      "type": "CallExpression",
      "callee": "jwt.verify"
    }
  }
}
```

### Fuzzy Matching

Handles variations in implementation:

```typescript
// Pattern variations automatically detected
function requireAuth() { /* ... */ }           // 95% match
function authenticateUser() { /* ... */ }      // 87% match  
function checkUserAuth() { /* ... */ }         // 82% match
function validateToken() { /* ... */ }         // 78% match
```

### Semantic Similarity

Uses semantic analysis to group related patterns:

```typescript
// Semantically similar patterns
const getUser = () => getCurrentUser();        // Data access
const fetchUser = () => loadUserData();        // Data access  
const retrieveUser = () => getUserInfo();      // Data access

// Grouped as "user-data-access" pattern category
```

## Pattern Evolution

### Version Control Integration

```json
{
  "patterns": {
    "versioning": {
      "enabled": true,
      "trackChanges": true,
      "approvalRequired": true,
      "gitIntegration": true
    }
  }
}
```

### Pattern Migration

```json
{
  "migrations": [
    {
      "from": "getOrgDatabase()",
      "to": "getOrgDatabaseWithAuth()",
      "reason": "Security enhancement",
      "automatic": true,
      "version": "1.1.0"
    }
  ]
}
```

### Deprecation Warnings

```json
{
  "patterns": {
    "deprecated": [
      {
        "pattern": "getUser",
        "replacement": "getCurrentUserWithAuth",
        "warning": "This pattern is deprecated for security reasons",
        "removeIn": "2.0.0"
      }
    ]
  }
}
```

## Advanced Pattern Features

### Conditional Patterns

```json
{
  "patterns": {
    "conditional": [
      {
        "name": "admin-only-endpoint",
        "condition": "hasRole('admin')",
        "requirements": ["requireAuthWithTenant", "checkAdminRole"],
        "applies": "api/admin/**"
      }
    ]
  }
}
```

### Composite Patterns

```json
{
  "patterns": {
    "composite": [
      {
        "name": "secure-crud-api",
        "components": [
          "authentication",
          "authorization", 
          "validation",
          "audit-logging"
        ],
        "sequence": true,
        "required": ["authentication", "authorization"]
      }
    ]
  }
}
```

### Context-Aware Patterns

```json
{
  "patterns": {
    "contextual": [
      {
        "name": "database-access",
        "context": {
          "framework": "nextjs",
          "database": "supabase",
          "auth": "jwt"
        },
        "implementation": "getOrgDatabaseWithAuth",
        "alternatives": {
          "prisma": "getPrismaClient",
          "mongoose": "getMongoConnection"
        }
      }
    ]
  }
}
```

## Pattern Analytics

### Usage Statistics

```json
{
  "analytics": {
    "patterns": {
      "requireAuthWithTenant": {
        "usage": 87,
        "compliance": 94,
        "violations": 3,
        "trend": "increasing"
      },
      "getOrgDatabaseWithAuth": {
        "usage": 76,
        "compliance": 89,
        "violations": 8,
        "trend": "stable"
      }
    },
    "categories": {
      "auth": {
        "coverage": 94,
        "compliance": 91,
        "health": "excellent"
      },
      "api": {
        "coverage": 87,
        "compliance": 83,
        "health": "good"
      }
    }
  }
}
```

### Compliance Metrics

```json
{
  "compliance": {
    "overall": 86,
    "byCategory": {
      "auth": 94,
      "api": 87,
      "data_access": 82,
      "validation": 76
    },
    "trends": {
      "improving": ["auth", "api"],
      "declining": ["validation"],
      "stable": ["data_access"]
    },
    "recommendations": [
      "Focus on improving validation patterns",
      "Consider mandatory validation rules",
      "Add more validation pattern examples"
    ]
  }
}
```

## Integration Examples

### CI/CD Integration

```yaml
# .github/workflows/pattern-compliance.yml
name: Pattern Compliance Check
on: [push, pull_request]

jobs:
  patterns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Check Pattern Compliance
        run: |
          codebase-intelligence check-patterns \
            --min-score 80 \
            --block-critical \
            --output pattern-report.json
      
      - name: Comment PR
        if: github.event_name == 'pull_request'
        run: |
          # Post compliance results to PR
          gh pr comment ${{ github.event.number }} \
            --body-file pattern-report.md
```

### Pre-commit Hooks

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Checking pattern compliance..."
codebase-intelligence check-patterns --staged-only --min-score 75

if [ $? -ne 0 ]; then
  echo "❌ Pattern compliance check failed"
  echo "Run 'codebase-intelligence patterns --fix' to address issues"
  exit 1
fi

echo "✅ Pattern compliance check passed"
```

### IDE Integration

```json
{
  "patterns": {
    "ide": {
      "realTimeValidation": true,
      "suggestions": true,
      "autoComplete": true,
      "quickFixes": true
    }
  }
}
```

## Best Practices

### Pattern Definition
1. **Clear Names**: Use descriptive pattern names
2. **Consistent Categories**: Organize patterns logically
3. **Good Examples**: Provide clear usage examples
4. **Documentation**: Document pattern purpose and usage

### Governance Strategy
1. **Gradual Introduction**: Start with warnings, then enforce
2. **Team Buy-in**: Get team agreement on patterns
3. **Regular Review**: Periodically review and update patterns
4. **Exception Handling**: Allow exceptions when needed

### Maintenance
1. **Pattern Evolution**: Update patterns as code evolves
2. **Performance Monitoring**: Track pattern matching performance
3. **Usage Analytics**: Monitor pattern adoption
4. **Continuous Improvement**: Refine patterns based on usage

---

*For advanced pattern customization, see our [Pattern Development Guide](./development/custom-patterns.md) and [Governance Configuration](./configuration.md#governance).*