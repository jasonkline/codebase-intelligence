# System Architecture

This document provides a comprehensive overview of the Codebase Intelligence system architecture, design principles, and technical implementation details.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude Code                              │
│                 (User Interface)                            │
└─────────────────────┬───────────────────────────────────────┘
                      │ MCP Protocol (stdio)
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                MCP Server                                   │
│            (Main Entry Point)                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Security  │ │   Pattern   │ │  Knowledge  │           │
│  │    Tools    │ │    Tools    │ │    Tools    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Navigation  │ │ Intelligence│ │ Governance  │           │
│  │    Tools    │ │    Tools    │ │    Tools    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Core Analysis Engine                         │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│ │ AST Parser  │ │File Scanner │ │System       │            │
│ │(TypeScript) │ │(Parallel)   │ │Analyzer     │            │  
│ └─────────────┘ └─────────────┘ └─────────────┘            │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│ │  Pattern    │ │  Security   │ │ Knowledge   │            │
│ │  Registry   │ │  Scanner    │ │ Extractor   │            │
│ └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Data & Storage Layer                           │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│ │   SQLite    │ │    FTS5     │ │   Memory    │            │
│ │  Database   │ │Full-text    │ │   Cache     │            │
│ │             │ │   Search    │ │             │            │
│ └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. MCP Server Layer

The MCP (Model Context Protocol) server is the main entry point that communicates with Claude Code via stdio. It orchestrates all analysis operations and manages the tool ecosystem.

**Key Responsibilities:**
- Protocol handling and message routing
- Tool registration and management
- Request validation and error handling
- Response formatting and streaming
- Connection lifecycle management

**Technology Stack:**
- Node.js with TypeScript
- @modelcontextprotocol/sdk
- stdio transport for communication
- JSON-RPC 2.0 protocol

### 2. Tool Modules

The system is organized into specialized tool modules, each handling specific aspects of code analysis:

#### Security Tools
- **Purpose**: Vulnerability detection and security analysis
- **Components**: SecurityScanner, AuthPatternAnalyzer, RLSAnalyzer, OWASPScanner
- **Features**: OWASP Top 10 detection, authentication flow analysis, authorization validation

#### Pattern Tools  
- **Purpose**: Code pattern recognition and enforcement
- **Components**: PatternRegistry, PatternMatcher, PatternLearner
- **Features**: AST-based pattern matching, fuzzy similarity detection, governance rules

#### Knowledge Tools
- **Purpose**: System understanding and documentation
- **Components**: QueryEngine, SystemExplainer, DocumentationGenerator
- **Features**: Natural language processing, architecture documentation, impact analysis

#### Intelligence Tools
- **Purpose**: AI-powered code assistance
- **Components**: SmartSuggestions, ErrorPrevention, TechnicalDebtTracker
- **Features**: Predictive coding, refactoring suggestions, complexity analysis

#### Navigation Tools
- **Purpose**: Code exploration and dependency analysis
- **Components**: DependencyAnalyzer, SymbolResolver, ReferenceTracker
- **Features**: Cross-reference navigation, dependency graphs, symbol search

#### Governance Tools
- **Purpose**: Code quality and compliance enforcement
- **Components**: RuleEngine, ComplianceChecker, StyleGuideValidator
- **Features**: Custom rules, policy enforcement, automated compliance reporting

### 3. Analysis Engine

The core analysis engine provides the fundamental parsing and analysis capabilities that all tools build upon.

#### AST Parser
```typescript
interface ASTParser {
  parseFile(filePath: string): Promise<ParsedFile>
  parseString(content: string, filePath?: string): ParsedSymbol[]
  extractSymbols(ast: Program): Symbol[]
  extractImports(ast: Program): Import[]
  extractExports(ast: Program): Export[]
}
```

**Features:**
- TypeScript Compiler API integration
- Full AST parsing with type information
- Symbol extraction and classification
- Import/export dependency tracking
- Comment and documentation extraction

#### File Scanner
```typescript
interface FileScanner {
  scanProject(path: string, options: ScanOptions): Promise<ScanResult>
  scanFile(filePath: string): Promise<ParsedFile>
  watchProject(path: string, callback: FileChangeCallback): Watcher
}
```

**Features:**
- Parallel file processing with configurable concurrency
- Intelligent file filtering with glob patterns
- Real-time file watching with change detection
- Progress tracking and error reporting
- Memory-efficient streaming for large projects

#### Pattern Registry
```typescript
interface PatternRegistry {
  learnPatterns(files: ParsedFile[], categories: string[]): Promise<Pattern[]>
  matchPatterns(ast: Program, category?: string): PatternMatch[]
  getApprovedPatterns(category: string): Pattern[]
  validateCompliance(file: ParsedFile): ComplianceResult
}
```

**Features:**
- Machine learning-based pattern extraction
- Fuzzy AST matching with confidence scoring
- Pattern categorization and tagging
- Governance rule integration
- Version control and pattern evolution

### 4. Data Layer

The data layer provides persistent storage, caching, and search capabilities.

#### Database Schema

**Core Tables:**
```sql
-- Symbols and references
symbols (id, name, kind, file_path, line_start, line_end, signature, doc_comment)
references (id, symbol_id, file_path, line, reference_kind)
files (id, path, last_indexed, hash, size, language)

-- Pattern system
patterns (id, name, category, description, ast_signature, confidence_threshold)
pattern_instances (id, pattern_id, file_path, line_start, line_end, confidence)
governance_rules (id, pattern_id, rule_type, scope_pattern, message, severity)

-- Knowledge base
system_knowledge (id, system_name, component, description, implementation_details)
security_issues (id, severity, category, file_path, description, remediation)
system_dependencies (id, from_system, to_system, dependency_type, strength)
```

**Full-Text Search:**
```sql
-- FTS5 virtual table for fast text search
CREATE VIRTUAL TABLE symbols_fts USING fts5(
    name, doc_comment, file_path,
    content=symbols
);
```

#### Caching Strategy

**Multi-Level Caching:**
1. **Memory Cache**: Hot data and frequently accessed symbols
2. **Database Cache**: Parsed ASTs and analysis results
3. **File System Cache**: Temporary analysis artifacts

**Cache Invalidation:**
- File modification time tracking
- Hash-based change detection
- Dependency-aware invalidation
- LRU eviction policies

### 5. Real-time Intelligence

The real-time intelligence system provides instant feedback and analysis as code is being written.

#### File Watcher
```typescript
interface FileWatcher {
  watch(path: string, options: WatchOptions): Promise<void>
  onFileChange(callback: (change: FileChange) => void): void  
  onFileCreate(callback: (file: string) => void): void
  onFileDelete(callback: (file: string) => void): void
}
```

**Features:**
- Cross-platform file system monitoring
- Intelligent debouncing to prevent analysis storms
- Batch processing of multiple changes
- Selective watching based on file patterns

#### Incremental Analyzer  
```typescript
interface IncrementalAnalyzer {
  updateFile(filePath: string, content: string): Promise<AnalysisResult>
  invalidateFile(filePath: string): void
  getDependentFiles(filePath: string): string[]
  updateDependencies(filePath: string): Promise<void>
}
```

**Features:**
- Differential analysis to minimize processing
- Dependency graph maintenance
- Smart cache invalidation
- Sub-100ms response times for small changes

## Security Architecture

### Authentication & Authorization

**MCP Security Model:**
- stdio transport provides process-level isolation
- No network ports exposed by default
- File system access limited to configured project paths
- Environment variable-based configuration

**Data Security:**
- All processing happens locally
- No source code transmitted externally
- Optional telemetry with anonymization
- Configurable data retention policies

### Vulnerability Detection Pipeline

```
Input File → AST Parser → Security Rules → Pattern Matching → Vulnerability DB → Risk Scoring → Report Generation
```

**Security Scanners:**
1. **Static Analysis**: AST-based vulnerability detection
2. **Pattern Analysis**: Authentication/authorization flow validation
3. **Dependency Analysis**: Third-party vulnerability scanning
4. **Configuration Analysis**: Security misconfigurations
5. **OWASP Compliance**: Top 10 vulnerability classes

## Performance Architecture

### Scalability Design

**Horizontal Scaling:**
- Stateless server design enables multiple instances
- Shared-nothing architecture with local databases
- Load balancing via file system partitioning
- Container-friendly with Docker support

**Vertical Scaling:**
- Multi-threaded analysis with worker pools
- Memory-mapped database files for large datasets
- Streaming analysis for memory efficiency
- Configurable resource limits and throttling

### Performance Optimizations

**Analysis Pipeline:**
```
File Discovery → Parallel Parsing → Batch Processing → Result Aggregation → Response Streaming
```

**Database Optimizations:**
- SQLite WAL mode for concurrent access
- Prepared statements and connection pooling
- Strategic indexing for common queries
- VACUUM operations for maintenance

**Memory Management:**
- Configurable heap limits and monitoring
- Automatic garbage collection tuning
- Cache size limits with LRU eviction
- Memory leak detection and reporting

## Production Architecture

### Deployment Options

**Standalone Binary:**
- Single executable with embedded dependencies
- Cross-platform support (Linux, macOS, Windows)
- No external runtime requirements
- Automatic update capability

**Container Deployment:**
```dockerfile
# Multi-stage build for minimal image size
FROM node:18-alpine AS builder
# ... build steps
FROM node:18-alpine AS production  
# ... production image
```

**Kubernetes Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: codebase-intelligence
spec:
  replicas: 3
  selector:
    matchLabels:
      app: codebase-intelligence
  template:
    # ... pod specification
```

### Monitoring & Observability

**Health Checks:**
- HTTP endpoints for health status
- Deep health checks for all components
- Dependency health validation
- Performance metrics collection

**Logging:**
- Structured logging with Winston
- Multiple output formats (JSON, text)
- Log rotation and retention policies
- Error tracking and alerting

**Metrics:**
- Performance counters and timings
- Memory usage and GC statistics
- Analysis throughput and error rates
- Custom business metrics

**Telemetry:**
- Privacy-focused usage analytics
- Performance benchmarking data
- Error reporting and diagnostics
- Feature adoption tracking

## Extension Architecture

### Plugin System

**Custom Analyzers:**
```typescript
interface CustomAnalyzer {
  name: string
  version: string
  supportedLanguages: string[]
  analyze(file: ParsedFile): Promise<AnalysisResult>
}
```

**Custom Patterns:**
```typescript
interface CustomPattern {
  id: string
  category: string
  matcher: (ast: Program) => PatternMatch[]
  validator: (match: PatternMatch) => boolean
}
```

**Custom Rules:**
```typescript
interface CustomRule {
  id: string
  name: string
  severity: Severity
  check: (file: ParsedFile) => RuleViolation[]
  autoFix?: (violation: RuleViolation) => CodeFix
}
```

### Integration Points

**MCP Tool Registration:**
- Dynamic tool discovery and registration
- Version compatibility checking
- Permission-based access control
- Tool lifecycle management

**Database Extensions:**
- Custom table schemas for plugin data
- Migration system for schema updates
- Backup and restore capabilities
- Data export/import utilities

## Design Principles

### 1. Performance First
- Sub-second response times for interactive features
- Efficient memory usage for large codebases
- Parallel processing wherever possible
- Intelligent caching at all levels

### 2. Security by Design
- Local processing with no external dependencies
- Principle of least privilege for file access
- Secure defaults in all configurations
- Comprehensive audit logging

### 3. Extensibility
- Plugin architecture for custom analyzers
- Configuration-driven behavior
- API-first design for integration
- Clear separation of concerns

### 4. Reliability
- Graceful degradation under resource constraints
- Comprehensive error handling and recovery
- Data consistency and integrity guarantees
- Automated testing at all levels

### 5. Developer Experience
- Clear and comprehensive documentation
- Intuitive configuration and setup
- Rich debugging and diagnostic capabilities
- Responsive community support

## Future Architecture Considerations

### Planned Enhancements

**Multi-Language Support:**
- Python, Java, C#, Go analyzer plugins
- Language-specific pattern libraries
- Cross-language dependency analysis
- Polyglot project support

**Distributed Analysis:**
- Microservice architecture for enterprise deployments
- Distributed caching and state management
- Horizontal auto-scaling
- Multi-region deployment support

**Advanced AI Integration:**
- Large language model integration for code understanding
- Automated refactoring suggestions
- Intelligent documentation generation
- Predictive vulnerability detection

**Enterprise Features:**
- Role-based access control
- Audit trails and compliance reporting
- Integration with enterprise tools (LDAP, SSO)
- Custom branding and white-labeling

---

*This architecture is designed to evolve with the needs of modern development teams while maintaining performance, security, and reliability at scale.*