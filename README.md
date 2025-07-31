# Codebase Intelligence

An intelligent codebase analysis system that provides comprehensive code intelligence, pattern recognition, and security scanning capabilities through the Model Context Protocol (MCP).

## Overview

Codebase Intelligence acts as a "second brain" for Claude Code and developers, offering:

- **Deep System Understanding**: Comprehends critical systems (auth, RBAC, data access, API design)
- **Pattern Recognition**: Learns and enforces patterns across your codebase
- **Security Analysis**: Proactive vulnerability detection at all severity levels
- **Knowledge Queries**: Answer questions about application architecture
- **Real-time Guidance**: Prevents mistakes before they happen
- **Style Enforcement**: Maintains consistent code structure
- **Documentation Generation**: Auto-generates explanations of complex systems

## Features

### 🔍 **Intelligent Code Analysis**
- TypeScript/JavaScript AST parsing and analysis
- Symbol extraction and relationship mapping
- Dependency tracking and impact analysis

### 🛡️ **Security Scanning**
- OWASP Top 10 vulnerability detection
- Authentication and authorization pattern analysis
- SQL injection and XSS vulnerability scanning
- Row Level Security (RLS) compliance checking

### 🧠 **Pattern Recognition**
- Learn patterns from existing codebase
- Enforce architectural consistency
- Detect anti-patterns and code smells
- Suggest best practices

### 📚 **Knowledge Base**
- Natural language queries about your codebase
- System architecture explanations
- Flow diagrams and documentation generation
- Technical debt tracking

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build
```

### Development

```bash
# Run in development mode with hot reload
npm run dev

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint
```

### MCP Integration

1. **Add to Claude Code MCP Configuration**:
   ```json
   {
     "mcpServers": {
       "codebase-intelligence": {
         "command": "node",
         "args": ["/path/to/codebase-intelligence/dist/index.js"],
         "env": {
           "NODE_ENV": "production"
         }
       }
     }
   }
   ```

2. **Test the connection**:
   The server exposes a `ping` tool for connectivity testing.

## Architecture

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

## Technology Stack

- **Language**: TypeScript
- **Parser**: TypeScript Compiler API
- **Database**: SQLite with FTS5 (full-text search)
- **File Watching**: Chokidar
- **Protocol**: MCP (Model Context Protocol)
- **Testing**: Jest
- **Logging**: Winston

## MCP Tools

Currently available tools:

### `ping`
Test connectivity with the server.

**Parameters:**
- `message` (optional): Custom message to echo back

**Example:**
```typescript
{
  "name": "ping",
  "arguments": {
    "message": "Hello World"
  }
}
```

## Project Structure

```
codebase-intelligence/
├── src/
│   ├── index.ts              # MCP server entry point
│   ├── mcp/                  # MCP protocol implementation
│   │   └── server.ts
│   ├── parser/               # AST parsing logic
│   ├── patterns/             # Pattern recognition engine
│   ├── security/             # Security analysis
│   ├── knowledge/            # Knowledge base system
│   ├── database/             # SQLite integration
│   └── utils/                # Shared utilities
│       └── logger.ts
├── tests/                    # Test files
├── docs/                     # Documentation
├── package.json
├── tsconfig.json
├── jest.config.js
└── README.md
```

## Development Roadmap

The project is being developed in phases:

1. **Phase 1**: System Analysis & Knowledge Extraction
2. **Phase 2**: Security Analysis Engine
3. **Phase 3**: Pattern Learning & Recognition
4. **Phase 4**: Knowledge Query System
5. **Phase 5**: Real-time Intelligence
6. **Phase 6**: MCP Integration & UI
7. **Phase 7**: Advanced Intelligence

## Configuration

Configuration will be managed through `.codeintelligence.json`:

```json
{
  "include": ["src/**/*.ts", "src/**/*.tsx"],
  "exclude": ["node_modules", "dist", "*.test.ts"],
  "database": {
    "path": ".codeintel/index.db"
  },
  "security": {
    "enabled": true,
    "scanOnSave": true
  },
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.85
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

## Logging

Logs are written to:
- `logs/combined.log` - All log levels
- `logs/error.log` - Error messages only
- Console (development mode only)

Log levels: `error`, `warn`, `info`, `debug`

## License

ISC License - see LICENSE file for details

## Support

For issues and feature requests, please use the GitHub issue tracker.

---

**Note**: This project is under active development. APIs and interfaces may change as we implement the full feature set outlined in the development roadmap.