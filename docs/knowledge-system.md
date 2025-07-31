# Knowledge System Guide

Comprehensive guide to the AI-powered knowledge system that understands and explains your codebase.

## Overview

The Knowledge System transforms your codebase into an intelligent, queryable knowledge base. Using advanced natural language processing and code analysis, it can answer questions about your system's architecture, explain complex workflows, and provide insights about code relationships and dependencies.

## Core Capabilities

### 🧠 Natural Language Queries
Ask questions about your codebase in plain English and get detailed, contextual answers with code examples and explanations.

### 📚 Automatic Documentation
Generate comprehensive system documentation, API references, and architectural diagrams automatically from your code.

### 🔍 System Understanding
Deep analysis of system components, data flows, and architectural patterns to provide intelligent insights.

### 📊 Impact Analysis
Understand the implications of proposed changes before implementing them.

## Knowledge System Tools

### `explain_system`
Answer natural language questions about your codebase.

**Usage:**
```typescript
// Claude Code examples
"How does authentication work in this application?"
"What happens when a user creates a new project?"
"Explain the data flow from API to database"
"What are all the ways to access user data?"
```

**Direct MCP call:**
```json
{
  "name": "explain_system",
  "arguments": {
    "query": "How does authentication work in this application?",
    "context": "Looking at the API routes",
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

### `analyze_impact`
Analyze the impact of proposed changes.

**Usage:**
```typescript
// Claude Code examples
"What would happen if I modify the authentication middleware?"
"What components would be affected if I change the User model?"
"Impact analysis for removing the legacy API endpoints"
```

**Direct MCP call:**
```json
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
  "summary": {
    "overallRisk": "high",
    "impactScore": 85,
    "affectedComponents": 23,
    "testingEffort": "extensive"
  },
  "affectedComponents": [
    {
      "name": "API Routes",
      "path": "src/app/api/**/*.ts",
      "impactLevel": "critical",
      "reason": "All API routes depend on authentication middleware",
      "filesAffected": 15
    },
    {
      "name": "Database Access",
      "path": "src/lib/database.ts", 
      "impactLevel": "high",
      "reason": "Database connections require auth context",
      "filesAffected": 1
    }
  ],
  "riskAssessment": {
    "businessImpact": "critical",
    "technicalRisk": "high",
    "riskFactors": [
      "Core authentication component",
      "Used by all API endpoints",
      "Security-critical functionality"
    ]
  },
  "recommendations": [
    {
      "type": "testing",
      "recommendation": "Create comprehensive test suite before changes",
      "priority": "critical"
    },
    {
      "type": "deployment",
      "recommendation": "Deploy to staging environment first",
      "priority": "high"
    }
  ]
}
```

### `get_system_docs`
Generate system documentation automatically.

**Usage:**
```typescript
// Claude Code examples
"Generate API documentation for this project"
"Create architecture documentation"
"Generate database schema documentation"
```

### `trace_data_flow`
Visualize and explain data flows through your system.

**Usage:**
```typescript
// Claude Code examples
"Trace data flow for user creation"
"How does data flow from the API to the database?"
"Show me the complete flow for processing a payment"
```

## Knowledge Sources

### Code Analysis
The system extracts knowledge from multiple sources in your codebase:

#### Function Signatures and Documentation
```typescript
/**
 * Authenticates a user and validates tenant access
 * @param request - HTTP request containing authorization header
 * @returns User context with organization information
 * @throws AuthenticationError if token is invalid
 * @throws AuthorizationError if user lacks tenant access
 */
export async function requireAuthWithTenant(
  request?: Request
): Promise<AuthContext> {
  // Implementation extracted and analyzed
}

// Knowledge extracted:
{
  "function": "requireAuthWithTenant",
  "purpose": "Authentication and tenant validation",
  "parameters": ["request: Request (optional)"],
  "returns": "Promise<AuthContext>",
  "throws": ["AuthenticationError", "AuthorizationError"],
  "category": "authentication"
}
```

#### Type Definitions
```typescript
interface User {
  id: string;
  email: string;
  role: UserRole;
  orgId: string;
  permissions: Permission[];
}

enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  MODERATOR = 'moderator'
}

// Knowledge extracted:
{
  "entity": "User",
  "type": "interface",
  "properties": {
    "id": "unique identifier",
    "email": "user email address",
    "role": "user role (admin/user/moderator)",
    "orgId": "organization identifier for multi-tenancy",
    "permissions": "array of user permissions"
  },
  "relationships": ["UserRole", "Permission", "Organization"]
}
```

#### Import/Export Relationships
```typescript
// src/lib/auth.ts
export { requireAuthWithTenant, validateToken };

// src/api/users/route.ts
import { requireAuthWithTenant } from '@/lib/auth';

// Knowledge extracted:
{
  "module": "src/lib/auth.ts",
  "exports": ["requireAuthWithTenant", "validateToken"],
  "usedBy": [
    "src/api/users/route.ts",
    "src/api/projects/route.ts",
    // ... other files
  ],
  "centralityScore": 0.89,
  "criticality": "high"
}
```

#### Database Schema Information
```sql
-- Extracted from Prisma schema or SQL files
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  org_id UUID REFERENCES organizations(id),
  role user_role NOT NULL DEFAULT 'user',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Knowledge extracted:
{
  "table": "users",
  "primaryKey": "id",
  "foreignKeys": ["org_id -> organizations.id"],
  "indexes": ["email (unique)"],
  "constraints": ["email NOT NULL", "role NOT NULL"],
  "relationships": ["belongs_to: Organization"]
}
```

### Comment Analysis

#### Documentation Comments
```typescript
/**
 * Handles user registration workflow
 * 
 * This function orchestrates the complete user registration process:
 * 1. Validates input data
 * 2. Checks for existing users
 * 3. Creates user account
 * 4. Sends welcome email
 * 5. Sets up default organization
 * 
 * @example
 * const user = await registerUser({
 *   email: 'user@example.com',
 *   password: 'secure-password',
 *   organizationName: 'My Company'
 * });
 */
```

#### Inline Comments
```typescript
// SECURITY: This endpoint requires admin privileges
// TODO: Add rate limiting to prevent abuse
// PERFORMANCE: Consider caching user permissions
```

### Test Files Analysis
```typescript
describe('Authentication System', () => {
  it('should authenticate valid users', async () => {
    // Test reveals expected behavior
  });
  
  it('should reject invalid tokens', async () => {
    // Test reveals error conditions
  });
});

// Knowledge extracted:
{
  "component": "Authentication System",
  "behaviors": [
    "authenticates valid users",
    "rejects invalid tokens"
  ],
  "testCoverage": "85%"
}
```

## Query Types and Examples

### Architectural Questions

**"How is the system structured?"**
```
Response: The system follows a layered architecture:

1. **Presentation Layer**: Next.js API routes in app/api/
2. **Business Logic**: Utility functions in lib/
3. **Data Layer**: Supabase PostgreSQL with Row Level Security
4. **Authentication**: JWT-based auth with Supabase Auth

Key architectural patterns:
- Multi-tenant with organization-based data isolation
- Role-based access control (RBAC)
- RESTful API design
- Server-side rendering with Next.js
```

**"What are the main system boundaries?"**
```
Response: The system has these main boundaries:

1. **External APIs**: Supabase, OAuth providers
2. **Database Boundary**: PostgreSQL with RLS policies
3. **Organization Boundary**: Tenant isolation via org_id
4. **Authentication Boundary**: JWT token validation
5. **Permission Boundary**: Role-based access control
```

### Workflow Questions

**"What happens when a user logs in?"**
```
Response: User login follows this workflow:

1. **Client Authentication**: User submits credentials to Supabase Auth
2. **Token Generation**: Supabase generates JWT with user claims
3. **Token Validation**: requireAuthWithTenant() validates the token
4. **Context Extraction**: Middleware extracts user ID, org slug, role
5. **Session Setup**: User context is available for subsequent requests
6. **Database Access**: All queries automatically filtered by org_id

Code flow:
- Entry: Supabase Auth
- Validation: requireAuthWithTenant() in lib/auth.ts
- Context: AuthContext interface
- Database: getOrgDatabaseWithAuth() in lib/database.ts
```

### Data Flow Questions

**"How does data flow from API to database?"**
```
Response: Data flows through these layers:

1. **API Request**: Client sends request to Next.js API route
2. **Authentication**: requireAuthWithTenant() validates user
3. **Authorization**: hasPermission() checks user permissions  
4. **Validation**: Input validation using Zod schemas
5. **Database Access**: getOrgDatabaseWithAuth() creates filtered connection
6. **RLS Enforcement**: PostgreSQL RLS policies enforce org isolation
7. **Response**: Filtered data returned to client

Security boundaries:
- Authentication at API layer
- Authorization before database access
- RLS policies at database layer
- Multi-tenant isolation throughout
```

### Technical Questions

**"What libraries and frameworks are used?"**
```
Response: The system uses these key technologies:

**Frontend/Backend:**
- Next.js 13+ (App Router)
- TypeScript for type safety
- Tailwind CSS for styling

**Authentication & Database:**
- Supabase (PostgreSQL + Auth)
- JWT tokens for session management
- Row Level Security for data isolation

**Validation & Utilities:**
- Zod for schema validation
- date-fns for date manipulation
- Lucide React for icons

**Development:**
- ESLint + Prettier for code quality
- Prisma for database schema management
```

### Security Questions

**"How is data protected?"**
```
Response: Data protection uses multiple layers:

1. **Authentication**: JWT token validation on all API routes
2. **Authorization**: Role-based permissions (admin/user/moderator)
3. **Multi-tenant Isolation**: org_id filtering on all data access
4. **Row Level Security**: Database-level access policies
5. **Input Validation**: Zod schemas prevent injection attacks
6. **HTTPS Enforcement**: All traffic encrypted in transit

Security controls:
- requireAuthWithTenant() - mandatory auth check
- hasPermission() - role-based access control
- getOrgDatabaseWithAuth() - automatic tenant filtering
- RLS policies - database-level isolation
```

## Documentation Generation

### API Documentation
The system can automatically generate comprehensive API documentation:

```markdown
# API Documentation

## Authentication Endpoints

### POST /api/auth/login
Authenticates a user and returns a JWT token.

**Parameters:**
- `email` (string, required): User email address
- `password` (string, required): User password

**Response:**
```json
{
  "token": "jwt-token-string",
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "role": "user",
    "orgSlug": "organization-slug"
  }
}
```

**Errors:**
- 401: Invalid credentials
- 429: Rate limit exceeded
```

### Architecture Documentation
Automatically generated system architecture documentation:

```markdown
# System Architecture

## Component Overview
The system consists of 5 main components:

1. **Web Application** (Next.js)
   - Location: `app/` directory
   - Purpose: User interface and API routes
   - Dependencies: React, TypeScript, Tailwind

2. **Authentication System** (Supabase Auth)
   - Location: `lib/auth.ts`
   - Purpose: User authentication and session management
   - Key Functions: requireAuthWithTenant(), validateToken()

3. **Database Layer** (PostgreSQL)
   - Location: Supabase PostgreSQL
   - Purpose: Data storage with multi-tenant isolation
   - Key Features: Row Level Security, automatic backups

4. **Authorization System** (RBAC)
   - Location: `lib/rbac.ts`
   - Purpose: Role-based access control
   - Roles: admin, user, moderator

5. **API Layer** (Next.js API Routes)
   - Location: `app/api/` directory
   - Purpose: RESTful API endpoints
   - Security: JWT authentication, input validation
```

## Configuration

### Knowledge System Settings

```json
{
  "knowledge": {
    "enabled": true,
    "sources": {
      "comments": {
        "enabled": true,
        "weight": 0.8,
        "includeInline": true,
        "includeJSDoc": true
      },
      "typeDefinitions": {
        "enabled": true,
        "weight": 0.9,
        "includeInterfaces": true,
        "includeEnums": true
      },
      "tests": {
        "enabled": true,
        "weight": 0.6,
        "includeDescriptions": true,
        "includeAssertions": false
      },
      "imports": {
        "enabled": true,
        "weight": 0.7,
        "trackDependencies": true
      }
    },
    "processing": {
      "nlp": {
        "enabled": true,
        "confidenceThreshold": 0.7,
        "maxResponseLength": 2000
      },
      "caching": {
        "enabled": true,
        "ttl": 3600,
        "maxSize": "256MB"
      }
    },
    "documentation": {
      "autoGenerate": true,
      "formats": ["markdown", "html"],
      "includeDiagrams": true,
      "updateOnChange": true,
      "outputPath": "docs/generated/"
    }
  }
}
```

### Environment Variables

```bash
# Knowledge system configuration
export CI_KNOWLEDGE_ENABLED="true"
export CI_KNOWLEDGE_CONFIDENCE_THRESHOLD="0.7"
export CI_KNOWLEDGE_MAX_RESPONSE_LENGTH="2000"
export CI_KNOWLEDGE_CACHE_SIZE="256MB"

# Documentation generation
export CI_DOCS_AUTO_GENERATE="true"
export CI_DOCS_OUTPUT_PATH="docs/generated/"
export CI_DOCS_INCLUDE_DIAGRAMS="true"
```

## Advanced Features

### Context-Aware Responses
The system provides responses tailored to your specific context:

```typescript
// When asking about authentication in an API route file
"How should I authenticate this endpoint?"

// Response is context-aware:
"Based on the file location (app/api/users/route.ts), you should add authentication using the requireAuthWithTenant() pattern used throughout this codebase:

```typescript
export async function GET() {
  const { user, orgSlug } = await requireAuthWithTenant();
  // Your endpoint logic here
}
```

This follows the established pattern used in 23 other API routes in your codebase."
```

### Cross-Reference Analysis
Understanding relationships between different parts of your system:

```typescript
"What components depend on the User model?"

// Response includes complete dependency analysis:
"The User model is referenced by 15 components:

**Direct Dependencies:**
- Authentication system (lib/auth.ts)
- RBAC system (lib/rbac.ts) 
- User API routes (app/api/users/*.ts)

**Indirect Dependencies:**
- All API routes (through authentication)
- Database access layer (through org filtering)
- Frontend components (through API calls)

**Database Relationships:**
- Projects (user_id foreign key)
- Timecards (created_by foreign key)
- Organizations (through org_id)
```

### Change Impact Prediction
Predictive analysis of how changes might affect your system:

```typescript
"What would happen if I change the User role enum?"

// Response predicts comprehensive impact:
"Changing the User role enum would have significant impact:

**High Impact Areas:**
- Authentication middleware (role validation)
- Permission checking system
- Database RLS policies
- Frontend role-based rendering

**Required Changes:**
- Update role validation in hasPermission()
- Modify database enum type
- Update frontend role checks
- Revise documentation

**Testing Requirements:**
- Authentication flow tests
- Permission system tests
- Database constraint tests
- End-to-end user flows

**Deployment Considerations:**
- Database migration required
- Potential breaking changes for existing users
- Staging environment testing recommended
```

## Best Practices

### Effective Querying
1. **Be Specific**: Ask about particular components or workflows
2. **Provide Context**: Mention the file or area you're working on
3. **Ask Follow-ups**: Use suggested follow-up questions
4. **Request Examples**: Ask for code examples when helpful

### Documentation Maintenance
1. **Keep Comments Current**: Update documentation comments regularly
2. **Use Descriptive Names**: Function and variable names aid understanding
3. **Document Decisions**: Explain architectural choices in comments
4. **Update Examples**: Keep code examples current with implementation

### Knowledge Quality
1. **Regular Updates**: Regenerate knowledge base after major changes
2. **Validate Responses**: Cross-check generated documentation
3. **Feedback Loop**: Report inaccurate responses to improve the system
4. **Complement with Human Knowledge**: Use AI insights alongside human expertise

---

*For more advanced knowledge system features, see our [AI Integration Guide](./ai-integration.md) and [Custom Knowledge Sources](./development/custom-knowledge.md).*