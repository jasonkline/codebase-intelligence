# Intelligent Codebase Assistant: Pattern Recognition, Security Analysis & Knowledge System

## Overview
Build a comprehensive codebase intelligence system that acts as a "second brain" for Claude Code and developers. This system will:
- Learn and enforce patterns across all critical systems (auth, RBAC, data access, API design)
- Proactively identify security vulnerabilities and architectural issues
- Maintain a queryable knowledge base about how the application works
- Provide real-time guidance to prevent mistakes before they happen
- Document and explain critical systems in plain language

## Goals & Requirements

### Primary Goals
1. **System Understanding** - Deep comprehension of how critical systems work
2. **Pattern Recognition** - Learn and catalog all patterns (auth, RBAC, API, data access, UI components)
3. **Security Analysis** - Proactive detection of vulnerabilities at all severity levels
4. **Knowledge Queries** - Answer questions about the application architecture
5. **Mistake Prevention** - Stop errors before they happen with real-time guidance
6. **Style Enforcement** - Maintain consistent code style and structure
7. **Documentation Generation** - Auto-generate explanations of complex systems
8. **Cross-Reference Intelligence** - Understand impact of changes across the codebase

### Non-Goals (v1)
- Multi-language support (focus on TypeScript/JavaScript first)
- Distributed indexing across teams
- Advanced refactoring capabilities
- Git history analysis

## Architecture Overview

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│   Your Code     │────▶│    Parser    │────▶│   Index DB  │
│  (TS/JS files)  │     │ (TypeScript  │     │  (SQLite)   │
└─────────────────┘     │  Compiler)   │     └─────────────┘
         │              └──────────────┘              │
         │                      │                     │
         │                      ▼                     │
         │              ┌──────────────┐              │
         │              │   Pattern    │              │
         │              │   Analyzer   │              │
         │              └──────────────┘              │
         │                      │                     │
         ▼                      ▼                     ▼
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│  File Watcher   │     │  Governance  │     │ Search API  │
│   (chokidar)    │     │    Engine    │     │ (Full-text) │
└─────────────────┘     └──────────────┘     └─────────────┘
                                │                     │
                                └──────┬──────────────┘
                                       ▼
                                ┌─────────────┐
                                │ MCP Server  │
                                │   (stdio)   │
                                └─────────────┘
                                       │
                                       ▼
                                ┌─────────────┐
                                │Claude Code  │
                                └─────────────┘
```

## Technical Stack

### Core Technologies
- **Language**: TypeScript (matches your codebase)
- **Parser**: TypeScript Compiler API
- **Pattern Recognition**: AST-based pattern matching with custom rules
- **Database**: SQLite with FTS5 (full-text search)
- **File Watching**: Chokidar
- **MCP Protocol**: stdio-based server
- **Process Management**: Node.js child processes

### Why These Choices?
- **TypeScript Compiler API**: Native understanding of TS/JS, handles all edge cases
- **AST Pattern Matching**: Deep structural analysis beyond regex
- **SQLite**: Zero-config, portable, fast enough for local use
- **Chokidar**: Battle-tested file watcher, handles all platforms
- **stdio MCP**: Simplest integration with Claude Code

## Data Model

### Index Schema (SQLite)

```sql
-- Symbols table (functions, classes, variables, etc.)
CREATE TABLE symbols (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL, -- 'function', 'class', 'interface', 'variable', etc.
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    column_start INTEGER NOT NULL,
    column_end INTEGER NOT NULL,
    parent_symbol_id INTEGER,
    signature TEXT, -- For functions: parameter types and return type
    doc_comment TEXT,
    visibility TEXT, -- 'public', 'private', 'protected'
    is_exported BOOLEAN,
    FOREIGN KEY (parent_symbol_id) REFERENCES symbols(id)
);

-- References table (where symbols are used)
CREATE TABLE references (
    id INTEGER PRIMARY KEY,
    symbol_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    reference_kind TEXT, -- 'call', 'import', 'type', 'extend', etc.
    FOREIGN KEY (symbol_id) REFERENCES symbols(id)
);

-- Files table (track file metadata)
CREATE TABLE files (
    id INTEGER PRIMARY KEY,
    path TEXT UNIQUE NOT NULL,
    last_indexed TIMESTAMP,
    hash TEXT NOT NULL, -- To detect changes
    size INTEGER,
    language TEXT
);

-- Full-text search virtual table
CREATE VIRTUAL TABLE symbols_fts USING fts5(
    name, 
    doc_comment,
    file_path,
    content=symbols
);

-- Patterns table (identified code patterns)
CREATE TABLE patterns (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL, -- 'auth_check', 'api_route', 'db_access', etc.
    category TEXT NOT NULL, -- 'security', 'data_access', 'api', etc.
    description TEXT,
    ast_signature TEXT, -- Serialized AST pattern for matching
    example_file TEXT,
    example_line INTEGER,
    confidence_threshold REAL DEFAULT 0.8,
    is_approved BOOLEAN DEFAULT TRUE
);

-- Pattern instances (where patterns are found)
CREATE TABLE pattern_instances (
    id INTEGER PRIMARY KEY,
    pattern_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    confidence REAL NOT NULL, -- 0.0 to 1.0
    metadata JSON, -- Additional context
    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
);

-- Governance rules
CREATE TABLE governance_rules (
    id INTEGER PRIMARY KEY,
    pattern_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL, -- 'required', 'forbidden', 'preferred'
    scope_pattern TEXT, -- File path pattern where rule applies
    message TEXT NOT NULL, -- Guidance message for violations
    severity TEXT DEFAULT 'warning', -- 'error', 'warning', 'info'
    auto_fix_available BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
);

-- Pattern violations
CREATE TABLE pattern_violations (
    id INTEGER PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (rule_id) REFERENCES governance_rules(id)
);

-- System knowledge base
CREATE TABLE system_knowledge (
    id INTEGER PRIMARY KEY,
    system_name TEXT NOT NULL, -- 'auth', 'rbac', 'data_access', etc.
    component TEXT NOT NULL,
    description TEXT NOT NULL,
    implementation_details TEXT,
    security_considerations TEXT,
    related_files JSON,
    related_patterns JSON,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security vulnerabilities
CREATE TABLE security_issues (
    id INTEGER PRIMARY KEY,
    severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
    category TEXT NOT NULL, -- 'auth', 'injection', 'xss', 'csrf', etc.
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    cwe_id TEXT, -- Common Weakness Enumeration ID
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE
);

-- Code style patterns
CREATE TABLE style_patterns (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL, -- 'component_structure', 'import_order', etc.
    category TEXT NOT NULL, -- 'react', 'typescript', 'imports', etc.
    ast_pattern TEXT,
    example_code TEXT,
    anti_pattern_example TEXT,
    auto_fixable BOOLEAN DEFAULT FALSE
);

-- RBAC patterns
CREATE TABLE rbac_patterns (
    id INTEGER PRIMARY KEY,
    role TEXT NOT NULL,
    permission TEXT NOT NULL,
    resource_pattern TEXT,
    implementation_pattern TEXT,
    file_references JSON
);

-- System dependencies
CREATE TABLE system_dependencies (
    id INTEGER PRIMARY KEY,
    from_system TEXT NOT NULL,
    to_system TEXT NOT NULL,
    dependency_type TEXT NOT NULL, -- 'imports', 'calls', 'extends', etc.
    strength INTEGER, -- 1-10 coupling strength
    description TEXT
);
```

## Implementation Phases

### Phase 1: System Analysis & Knowledge Extraction (Week 1)
- [ ] Parse and understand the complete codebase structure
- [ ] Extract and document all authentication flows
- [ ] Map RBAC implementation and permission patterns
- [ ] Identify all data access patterns and RLS usage
- [ ] Build initial system knowledge base
- [ ] Document critical security checkpoints

### Phase 2: Security Analysis Engine (Week 2)
- [ ] Implement OWASP vulnerability scanning
- [ ] Build authentication bypass detection
- [ ] Create SQL injection pattern detection
- [ ] Add XSS vulnerability scanning
- [ ] Implement CSRF protection verification
- [ ] Build security issue prioritization system

### Phase 3: Pattern Learning & Recognition (Week 3)
- [ ] Build comprehensive AST pattern matching
- [ ] Learn authorization patterns from codebase
- [ ] Extract component structure patterns
- [ ] Identify API design patterns
- [ ] Learn error handling patterns
- [ ] Create style and import patterns

### Phase 4: Knowledge Query System (Week 4)
- [ ] Build natural language query interface
- [ ] Implement system explanation generator
- [ ] Create architecture documentation engine
- [ ] Add "how does X work?" answering
- [ ] Build dependency impact analyzer
- [ ] Generate security assessment reports

### Phase 5: Real-time Intelligence (Week 5)
- [ ] Implement continuous pattern monitoring
- [ ] Build real-time security scanning
- [ ] Create instant violation detection
- [ ] Add predictive error prevention
- [ ] Implement smart code suggestions
- [ ] Build performance impact predictions

### Phase 6: MCP Integration & UI (Week 6)
- [ ] Build comprehensive MCP tool suite
- [ ] Create security alert interface
- [ ] Implement pattern guidance tools
- [ ] Add knowledge query tools
- [ ] Build explanation request interface
- [ ] Create visual dependency explorer

### Phase 7: Advanced Intelligence (Week 7-8)
- [ ] Implement change impact analysis
- [ ] Build automated documentation updates
- [ ] Create security threat modeling
- [ ] Add performance pattern analysis
- [ ] Build test coverage intelligence
- [ ] Implement refactoring safety analysis

## MCP Tool Interface Design

### Proposed Tools for Claude Code

```typescript
// Ask questions about the system
{
  "name": "explain_system",
  "parameters": {
    "query": "string", // e.g., "How does authentication work?", "What is the RBAC model?"
    "detail_level": "summary|detailed|technical"
  }
}

// Get security analysis for code
{
  "name": "analyze_security",
  "parameters": {
    "file": "string",
    "line_start": "number",
    "line_end": "number",
    "check_type": "all|auth|injection|xss|csrf|rbac"
  }
}

// Check pattern compliance with explanation
{
  "name": "check_pattern_compliance",
  "parameters": {
    "file": "string",
    "line_start": "number",
    "line_end": "number",
    "pattern_category": "auth|rbac|api|data_access|style|all",
    "explain_violations": "boolean"
  }
}

// Get the correct way to implement something
{
  "name": "how_to_implement",
  "parameters": {
    "feature": "string", // e.g., "api endpoint with auth", "database query with RLS"
    "context": "string", // Additional context
    "include_examples": "boolean"
  }
}

// Analyze impact of changes
{
  "name": "analyze_impact",
  "parameters": {
    "file": "string",
    "change_description": "string",
    "check_security": "boolean",
    "check_dependencies": "boolean"
  }
}

// Get security warnings for current context
{
  "name": "get_security_warnings",
  "parameters": {
    "file": "string",
    "severity": "critical|high|medium|low|all",
    "include_remediation": "boolean"
  }
}

// Query system knowledge
{
  "name": "query_knowledge",
  "parameters": {
    "topic": "string", // e.g., "authentication", "rbac roles", "database architecture"
    "include_code_examples": "boolean",
    "include_security_notes": "boolean"
  }
}

// Validate RBAC implementation
{
  "name": "check_rbac",
  "parameters": {
    "file": "string",
    "role": "string",
    "permission": "string",
    "resource": "string"
  }
}

// Get style guide for context
{
  "name": "get_style_guide",
  "parameters": {
    "file_type": "component|api|service|hook|utility",
    "framework": "react|nextjs|node"
  }
}

// Explain critical system flow
{
  "name": "explain_flow",
  "parameters": {
    "flow_name": "string", // e.g., "user login", "api request", "data fetch"
    "include_diagram": "boolean"
  }
}
```

## Configuration

### .codeintelligence.json
```json
{
  "include": ["src/**/*.ts", "src/**/*.tsx", "app/**/*.ts", "app/**/*.tsx", "lib/**/*.ts"],
  "exclude": ["node_modules", "dist", "*.test.ts", ".next"],
  "database": {
    "path": ".codeintel/index.db",
    "maxSize": "1GB"
  },
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.85,
    "categories": ["auth", "rbac", "api", "data_access", "validation", "error_handling", "ui_components", "styles"]
  },
  "security": {
    "enabled": true,
    "scanOnSave": true,
    "blockCritical": true,
    "warnOnHigh": true,
    "owasp": true,
    "customRules": ".security-rules.json"
  },
  "knowledge": {
    "autoDocument": true,
    "updateFrequency": "on_change",
    "includeArchitectureDocs": true,
    "generateFlowDiagrams": true
  },
  "governance": {
    "enabled": true,
    "strictMode": false,
    "autoSuggest": true,
    "enforceStyles": true,
    "requireApprovedPatterns": ["auth", "rbac", "data_access"]
  },
  "intelligence": {
    "explainComplexity": true,
    "suggestRefactoring": true,
    "trackTechnicalDebt": true
  },
  "server": {
    "port": 7345,
    "logLevel": "info",
    "enableUI": true,
    "uiPort": 7346
  }
}
```

## Performance Considerations

### Indexing Performance
- Process files in parallel (worker threads)
- Batch database writes
- Use prepared statements
- Index only changed files

### Search Performance
- Use SQLite's FTS5 for text search
- Create appropriate indexes
- Implement result pagination
- Cache frequent queries

### Memory Usage
- Stream large files instead of loading entirely
- Limit AST depth for complex files
- Implement garbage collection triggers
- Monitor and limit cache sizes

## Development Approach

### Testing Strategy
- Unit tests for parser logic
- Integration tests for database operations
- End-to-end tests for MCP communication
- Performance benchmarks for large codebases

### Monitoring & Debugging
- Structured logging with levels
- Performance metrics collection
- Index health checks
- Debug mode with verbose output

## Open Questions

1. **Symbol Resolution**: How deep should we go with type inference?
2. **Storage Location**: Should index be project-local or user-global?
3. **Privacy**: Should we index all files or respect .gitignore?
4. **Updates**: Real-time vs. batch indexing trade-offs?
5. **Scalability**: How to handle very large codebases (100k+ files)?

## Next Steps

1. Review and refine this plan
2. Set up the TypeScript project
3. Build a minimal proof-of-concept
4. Test with the narwol PSA codebase
5. Iterate based on performance and usability

## System Intelligence Examples

### Authentication & RBAC Understanding
```typescript
// User: "How does authentication work in this app?"
// System responds with:
"""
Authentication Flow:
1. User logs in via Supabase Auth (OAuth or email/password)
2. JWT token includes organization membership and role
3. Every API route must call requireAuthWithTenant()
4. This validates the JWT and extracts user, orgSlug, and role
5. Database access uses RLS with organization context

RBAC Model:
- Roles: admin, member, approver
- Permissions are checked at API level
- Admin: Full access to organization
- Member: Limited to own data + read access
- Approver: Can approve timecards

Security: All data is isolated by organization using RLS
"""

// Claude Code gets this context automatically when working on auth
```

### Security Analysis & Warnings
```typescript
// CRITICAL: Direct database access without auth
const db = drizzle(connectionString) // ❌ 
// System: "CRITICAL SECURITY: Bypassing RLS. Use getOrgDatabaseWithAuth()"

// HIGH: Hardcoded organization
const data = await getOrgData('acme-corp') // ❌
// System: "HIGH: Hardcoded org breaks multi-tenancy. Use orgSlug from auth"

// MEDIUM: Missing permission check
export async function DELETE() {
  const { user } = await requireAuthWithTenant() // ❌
  // System: "MEDIUM: Add role check - only admins should delete"
}

// LOW: Inconsistent error handling
catch (e) { console.log(e) } // ❌
// System: "LOW: Use consistent error handling pattern - see lib/errors.ts"
```

### Pattern Guidance for Common Tasks
```typescript
// Developer: "How do I create a new API endpoint?"
// System provides complete template:
"""
For API endpoint with database access:

import { requireAuthWithTenant } from '@/lib/supabase-auth'
import { getOrgDatabaseWithAuth } from '@/lib/database'
import { hasPermission } from '@/lib/roles'

export async function GET() {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant()
    
    // Check permissions if needed
    if (!hasPermission(role, 'read:resource')) {
      return new Response('Forbidden', { status: 403 })
    }
    
    const db = await getOrgDatabaseWithAuth()
    const data = await db.select().from(table)
    
    return Response.json({ data })
  } catch (error) {
    return new Response('Internal Error', { status: 500 })
  }
}
"""
```

### Style & Structure Enforcement
```typescript
// Component Structure Pattern
// ✅ Correct pattern learned from codebase:
export function ClientCard({ client }: { client: Client }) {
  const { organization } = useOrganization()
  // hooks first
  // then derived state
  // then handlers
  // then render
}

// ❌ System flags incorrect structure:
export function ClientCard({ client }: { client: Client }) {
  return <div>...</div> // Missing organization context
  const { organization } = useOrganization() // Hooks after return
}
```

### Impact Analysis
```typescript
// Developer: "What happens if I change getOrgDatabase?"
// System analyzes and reports:
"""
Impact Analysis for getOrgDatabase():
- Used in 47 files
- Critical for: All API routes, data access layer
- Security Impact: HIGH - affects RLS implementation
- Breaking changes would affect:
  - 23 API endpoints
  - 15 server actions
  - All database queries
  
Recommendation: Create new function instead of modifying
"""
```

### Knowledge Queries
```typescript
// User: "Explain the database architecture"
// System responds:
"""
Multi-Tenant Database Architecture:

1. Structure:
   - One Supabase project per organization
   - Complete data isolation between tenants
   - Each org has identical schema

2. Access Patterns:
   - getSupabaseRLS(): For simple CRUD with automatic RLS
   - getOrgDatabaseWithAuth(): For complex queries with Drizzle
   
3. Security:
   - Row Level Security on all tables
   - Organization ID injected via JWT claims
   - No cross-tenant data access possible

4. Connection Management:
   - Connections cached per organization
   - Automatic cleanup on inactivity

See: lib/database.ts for implementation
"""
```

## Real-time Claude Code Assistance

```typescript
// As Claude Code writes:
const db = getOrgDatabase()

// System immediately suggests:
"⚠️ Missing auth context. Change to: const db = await getOrgDatabaseWithAuth()"

// Claude Code asks: "How should I handle errors here?"
// System responds with exact pattern from codebase:
"Use the error handling pattern from lib/api-utils.ts:
try {
  // ... your code
} catch (error) {
  console.error('API Error:', error)
  return new Response('Internal Server Error', { status: 500 })
}"
```

## Success Metrics

- Pattern detection accuracy: > 90%
- Security issue detection: 100% for critical, > 95% for high
- Knowledge query response time: < 2 seconds
- Real-time analysis: < 100ms per file change
- False positive rate: < 5%
- System learning time: < 10 minutes initial scan
- Memory usage: < 1GB for typical project
- Claude Code error reduction: > 80%
- Developer satisfaction: Reduced code review iterations by 70%

## Unique Value Proposition

This system goes beyond simple indexing to create a **comprehensive intelligence layer** that:

1. **Understands** your application's architecture and patterns
2. **Prevents** mistakes before they happen
3. **Teaches** Claude Code and developers the right way
4. **Secures** your codebase with proactive threat detection
5. **Maintains** consistency across all code
6. **Explains** complex systems in plain language
7. **Evolves** with your codebase automatically

The result: Claude Code becomes an expert on YOUR specific codebase, making fewer mistakes and writing more secure, consistent code that follows your established patterns.

## Implementation Guide for Code Agents

This section provides expert prompts for implementing each phase. Each prompt is designed to be used with a fresh Claude Code session for optimal results.

### Project Setup Prompt

```
Create a new TypeScript project called "codebase-intelligence" for building an MCP server that provides intelligent code analysis, pattern recognition, and security scanning capabilities.

Requirements:
1. Initialize a TypeScript project with strict mode enabled
2. Set up the following project structure:
   - src/
     - index.ts (MCP server entry point)
     - parser/ (AST parsing logic)
     - patterns/ (pattern recognition engine)
     - security/ (security analysis)
     - knowledge/ (knowledge base system)
     - database/ (SQLite integration)
     - mcp/ (MCP protocol implementation)
   - tests/
   - docs/

3. Install these dependencies:
   - @modelcontextprotocol/sdk
   - typescript (with @types/node)
   - @typescript-eslint/parser
   - @typescript-eslint/typescript-estree
   - better-sqlite3 (with @types/better-sqlite3)
   - chokidar
   - fast-glob
   - micromatch
   - chalk
   - winston (for logging)

4. Create a basic MCP stdio server in src/index.ts that:
   - Implements the MCP protocol
   - Exposes a test tool called "ping" that returns "pong"
   - Sets up logging to a file

5. Create package.json scripts:
   - "build": TypeScript compilation
   - "start": Run the built server
   - "dev": Run with ts-node in watch mode
   - "test": Jest test runner

6. Create an .mcp.json configuration file for testing

7. Add a comprehensive README.md explaining the project

Ensure all code uses the latest stables versions and follows best practices and includes proper error handling.
```

### Phase 1: System Analysis & Knowledge Extraction

```
Implement the core system analysis engine for the codebase-intelligence project. This phase focuses on parsing TypeScript/JavaScript code and extracting system knowledge.

Requirements:

1. Create src/parser/ASTParser.ts that:
   - Uses @typescript-eslint/parser to parse TypeScript files
   - Extracts all function declarations, classes, interfaces, and type definitions
   - Identifies imports and exports
   - Captures JSDoc comments and inline comments
   - Handles React components (both function and class components)
   - Returns a structured AST representation

2. Create src/database/schema.ts with SQLite schema from the plan document:
   - symbols table (functions, classes, variables)
   - references table (usage tracking)
   - files table (file metadata)
   - system_knowledge table
   - Create database initialization logic

3. Create src/parser/SystemAnalyzer.ts that:
   - Identifies authentication patterns (look for requireAuthWithTenant, auth checks)
   - Extracts RBAC patterns (roles, permissions, hasPermission calls)
   - Finds data access patterns (database queries, RLS usage)
   - Detects API route patterns
   - Maps system dependencies

4. Create src/knowledge/KnowledgeExtractor.ts that:
   - Analyzes parsed AST to understand system flows
   - Builds a knowledge graph of how systems connect
   - Generates human-readable explanations
   - Identifies critical security checkpoints

5. Implement src/scanner/FileScanner.ts that:
   - Recursively scans project directories
   - Respects .gitignore patterns
   - Processes files in parallel for performance
   - Stores results in SQLite database

6. Add MCP tool: "analyze_project" that:
   - Accepts a project path
   - Runs the complete analysis pipeline
   - Returns a summary of findings

Test with a sample TypeScript project to ensure proper extraction of all elements.
```

### Phase 2: Security Analysis Engine

```
Build a comprehensive security analysis engine for the codebase-intelligence project that can detect vulnerabilities and security anti-patterns.

Requirements:

1. Create src/security/SecurityScanner.ts that detects:
   - Direct database access without authentication
   - Hardcoded credentials or secrets
   - SQL injection vulnerabilities
   - Missing authorization checks
   - Unvalidated user input
   - Insecure direct object references
   - Cross-site scripting (XSS) vulnerabilities

2. Create src/security/AuthPatternAnalyzer.ts that:
   - Identifies all authentication check patterns
   - Detects API routes missing auth checks
   - Finds authorization bypass vulnerabilities
   - Maps the complete auth flow
   - Identifies RBAC implementation issues

3. Create src/security/RLSAnalyzer.ts for Row Level Security:
   - Detects direct database client creation
   - Identifies queries bypassing RLS
   - Finds hardcoded organization IDs
   - Validates proper tenant isolation

4. Create src/security/VulnerabilityDatabase.ts that:
   - Maps findings to CWE IDs
   - Assigns severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
   - Provides remediation guidance
   - Tracks false positives

5. Implement src/security/OWASPScanner.ts covering:
   - OWASP Top 10 vulnerability patterns
   - Security misconfiguration detection
   - Sensitive data exposure
   - Broken authentication patterns
   - Security logging and monitoring gaps

6. Add MCP tools:
   - "analyze_security": Full security scan of a file/directory
   - "check_auth_pattern": Verify authentication implementation
   - "find_vulnerabilities": Get all security issues by severity

7. Create severity-based reporting that:
   - Returns CRITICAL issues immediately
   - Groups issues by category
   - Provides code examples of proper implementation
   - Suggests specific fixes

Include comprehensive tests with vulnerable code examples.
```

### Phase 3: Pattern Learning & Recognition

```
Implement an intelligent pattern recognition system that learns from existing code and enforces consistency.

Requirements:

1. Create src/patterns/PatternLearner.ts that:
   - Analyzes existing code to extract common patterns
   - Uses AST similarity matching to group similar code
   - Calculates pattern confidence scores
   - Identifies pattern variations and determines the "canonical" version
   - Learns from manually approved patterns

2. Create src/patterns/PatternMatcher.ts that:
   - Compares new code against learned patterns
   - Uses fuzzy AST matching (ignore variable names, focus on structure)
   - Returns similarity scores and differences
   - Handles partial matches and pattern composition

3. Create src/patterns/categories/ with specialized analyzers:
   - AuthPatterns.ts: Authentication and authorization patterns
   - APIPatterns.ts: API route structure and error handling
   - DataAccessPatterns.ts: Database query patterns and RLS usage
   - ComponentPatterns.ts: React component structure and hooks usage
   - StylePatterns.ts: Import organization, naming conventions

4. Create src/patterns/PatternRegistry.ts that:
   - Stores approved patterns with metadata
   - Manages pattern categories and relationships
   - Handles pattern versioning and evolution
   - Provides pattern search and retrieval

5. Implement src/governance/RuleEngine.ts that:
   - Defines rules for when patterns are required/forbidden
   - Checks code against governance rules
   - Generates context-aware violation messages
   - Suggests automatic fixes where possible

6. Add MCP tools:
   - "learn_patterns": Extract patterns from existing code
   - "check_pattern_compliance": Validate code against patterns
   - "get_approved_pattern": Retrieve the correct pattern for a use case
   - "suggest_pattern": Get pattern suggestions for new code

7. Create pattern visualization:
   - Export patterns as code examples
   - Generate pattern documentation
   - Show pattern usage statistics

Build a pattern library from common authentication, API, and component patterns.
```

### Phase 4: Knowledge Query System

```
Build a natural language query system that can answer questions about the codebase and explain complex systems.

Requirements:

1. Create src/knowledge/QueryEngine.ts that:
   - Parses natural language questions about the codebase
   - Maps questions to knowledge base queries
   - Generates human-readable responses
   - Supports questions like "How does authentication work?", "What is the RBAC model?", "Explain the database architecture"

2. Create src/knowledge/SystemExplainer.ts that:
   - Generates explanations for complex systems
   - Creates flow diagrams in text format
   - Explains architectural decisions
   - Documents security considerations
   - Provides code examples

3. Create src/knowledge/DependencyAnalyzer.ts that:
   - Maps dependencies between systems
   - Calculates impact of changes
   - Identifies circular dependencies
   - Measures coupling between modules
   - Generates dependency graphs

4. Create src/knowledge/DocumentationGenerator.ts that:
   - Auto-generates system documentation
   - Creates API documentation from code
   - Generates architecture diagrams
   - Produces security documentation
   - Updates docs as code changes

5. Implement src/knowledge/ImpactAnalyzer.ts that:
   - Predicts impact of code changes
   - Identifies affected systems
   - Calculates risk scores
   - Suggests testing requirements
   - Warns about breaking changes

6. Add MCP tools:
   - "explain_system": Answer questions about the codebase
   - "analyze_impact": Assess impact of proposed changes
   - "get_system_docs": Retrieve documentation for a system
   - "trace_data_flow": Show how data flows through the system
   - "explain_security": Explain security measures for a component

7. Create knowledge templates for common queries:
   - Authentication flow explanation
   - RBAC model documentation
   - Database architecture overview
   - API design patterns
   - Security best practices

Ensure responses are clear, concise, and include relevant code examples.
```

### Phase 5: Real-time Intelligence

```
Implement real-time monitoring and intelligent code assistance that provides immediate feedback during development.

Requirements:

1. Create src/realtime/FileWatcher.ts that:
   - Uses chokidar to monitor file changes
   - Implements intelligent debouncing
   - Tracks file creation, modification, and deletion
   - Maintains file history for rollback
   - Handles bulk changes efficiently

2. Create src/realtime/IncrementalAnalyzer.ts that:
   - Performs incremental AST updates
   - Updates only affected patterns and dependencies
   - Maintains analysis cache
   - Provides sub-100ms response times
   - Handles partial/invalid code gracefully

3. Create src/realtime/InstantValidator.ts that:
   - Validates code as it's written
   - Checks patterns in real-time
   - Identifies security issues immediately
   - Suggests corrections inline
   - Provides context-aware hints

4. Create src/intelligence/SmartSuggestions.ts that:
   - Predicts what the developer is trying to do
   - Suggests appropriate patterns
   - Recommends security best practices
   - Provides code completion templates
   - Learns from developer choices

5. Implement src/intelligence/ErrorPrevention.ts that:
   - Detects potential errors before they happen
   - Warns about common mistakes
   - Suggests safer alternatives
   - Validates business logic
   - Checks for edge cases

6. Add real-time MCP tools:
   - "validate_as_typed": Check code in real-time
   - "suggest_next": Predict next code pattern
   - "prevent_error": Warn about potential issues
   - "quick_fix": Provide instant corrections
   - "explain_warning": Explain why something is flagged

7. Create performance optimizations:
   - Implement caching strategies
   - Use worker threads for heavy analysis
   - Prioritize critical validations
   - Batch non-critical updates
   - Maintain responsive UI

Ensure the system remains responsive even with large codebases.
```

### Phase 6: MCP Integration & UI

```
Create a comprehensive MCP server implementation with all tools and optional web UI for visualization.

Requirements:

1. Update src/mcp/MCPServer.ts to:
   - Implement all planned MCP tools from previous phases
   - Handle concurrent requests efficiently
   - Provide detailed error messages
   - Support streaming responses for large results
   - Include request validation and sanitization

2. Create src/mcp/tools/ directory with:
   - SecurityTools.ts: All security analysis tools
   - PatternTools.ts: Pattern recognition and compliance tools
   - KnowledgeTools.ts: Query and explanation tools
   - NavigationTools.ts: Code navigation and search tools
   - GovernanceTools.ts: Rule checking and enforcement tools

3. Create src/ui/WebServer.ts (optional) that:
   - Provides a web interface on port 7346
   - Shows real-time analysis status
   - Displays pattern library
   - Visualizes security issues
   - Presents knowledge graph

4. Implement src/mcp/ResponseFormatter.ts that:
   - Formats responses for optimal Claude Code consumption
   - Includes relevant context and examples
   - Prioritizes actionable information
   - Supports markdown formatting
   - Handles large results with pagination

5. Create configuration system:
   - Load .codeintelligence.json configuration
   - Support environment variables
   - Allow runtime configuration changes
   - Validate configuration schema
   - Provide sensible defaults

6. Add monitoring and debugging:
   - Request/response logging
   - Performance metrics
   - Error tracking
   - Debug mode with verbose output
   - Health check endpoint

7. Create integration tests:
   - Test all MCP tools
   - Verify concurrent request handling
   - Test error scenarios
   - Validate response formats
   - Measure performance

Build example .mcp.json configurations for common scenarios.
```

### Phase 7: Advanced Intelligence

```
Implement advanced AI-powered features for comprehensive code intelligence and automated assistance.

Requirements:

1. Create src/intelligence/ChangePredictor.ts that:
   - Analyzes code change patterns
   - Predicts likely next changes
   - Identifies refactoring opportunities
   - Suggests code improvements
   - Learns from historical changes

2. Create src/intelligence/TechnicalDebtTracker.ts that:
   - Identifies code smells
   - Measures complexity metrics
   - Tracks debt accumulation
   - Prioritizes refactoring targets
   - Generates debt reports

3. Create src/intelligence/TestIntelligence.ts that:
   - Analyzes test coverage gaps
   - Suggests test cases
   - Identifies untested edge cases
   - Generates test templates
   - Maps tests to requirements

4. Create src/intelligence/PerformanceAnalyzer.ts that:
   - Detects performance anti-patterns
   - Identifies optimization opportunities
   - Suggests caching strategies
   - Finds unnecessary computations
   - Recommends async patterns

5. Implement src/intelligence/RefactoringAssistant.ts that:
   - Suggests safe refactoring operations
   - Validates refactoring safety
   - Generates refactoring plans
   - Tracks refactoring impact
   - Provides rollback strategies

6. Add advanced MCP tools:
   - "suggest_refactoring": Get refactoring recommendations
   - "analyze_debt": Technical debt assessment
   - "optimize_performance": Performance improvement suggestions
   - "generate_tests": Create test cases for code
   - "predict_bugs": Identify potential bug locations

7. Create machine learning integration:
   - Pattern discovery from code history
   - Anomaly detection in code patterns
   - Developer behavior learning
   - Code quality prediction
   - Bug prediction models

Include evaluation metrics and benchmarks for all intelligence features.
```

### Final Integration Prompt

```
Complete the codebase-intelligence project by integrating all components and preparing for production use.

Requirements:

1. Create comprehensive integration tests that:
   - Test the complete analysis pipeline
   - Verify all MCP tools work together
   - Measure end-to-end performance
   - Test with real-world codebases
   - Validate security scanning accuracy

2. Build example integrations:
   - Create .mcp.json for narwol-psa project
   - Document Claude Code configuration
   - Provide setup scripts
   - Include troubleshooting guide

3. Optimize for production:
   - Implement connection pooling
   - Add graceful shutdown
   - Handle memory efficiently
   - Support large codebases (100k+ files)
   - Add monitoring hooks

4. Create deployment package:
   - Build distributable binaries
   - Create Docker container
   - Support multiple platforms
   - Include auto-update mechanism

5. Write comprehensive documentation:
   - Installation guide
   - Configuration reference
   - MCP tool documentation
   - Pattern writing guide
   - Security rule creation

6. Add telemetry and analytics:
   - Usage statistics (privacy-preserving)
   - Performance metrics
   - Error reporting
   - Feature adoption tracking

Test the complete system with the narwol-psa codebase and verify it catches authentication issues, suggests proper patterns, and can explain the system architecture.
```

## Success Criteria

Each phase should be tested against these criteria:
1. The code compiles without errors
2. All tests pass
3. The feature works as specified
4. Performance meets targets (< 100ms for real-time operations)
5. Memory usage stays under 1GB
6. The MCP tools return helpful, actionable information