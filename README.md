# Codebase Intelligence

An intelligent codebase analysis system that provides comprehensive code intelligence, pattern recognition, and security scanning capabilities through the Model Context Protocol (MCP) for Claude Code.

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

## Installation

### Prerequisites

- Node.js 16+ installed
- A TypeScript/JavaScript project to analyze
- Claude Code installed and configured

### Quick Install

```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build
```

### Configure Claude Code MCP

Add to your Claude Code MCP configuration (`.mcp.json` in your project or `~/.claude.json`):

```json
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "node",
      "args": ["/path/to/codebase-intelligence/dist/index.js"],
      "env": {
        "CI_PROJECT_PATH": "/path/to/your/project",
        "NODE_ENV": "production",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

**Important**: Replace `/path/to/codebase-intelligence` with the actual path where you cloned this repository, and `/path/to/your/project` with your project's path.

### Test the Installation

1. Restart Claude Code to pick up the new MCP configuration
2. Test connectivity: `"Test the codebase intelligence connection"`
3. Run analysis: `"Analyze this project for security issues"`

## Usage

### Security Analysis
```
"Check this code for security vulnerabilities"
"Are there any authentication issues in my API?"
"Scan for SQL injection risks"
```

### Pattern Recognition
```
"What coding patterns does this project use?"
"Learn the architecture from this codebase"
"How is data access handled here?"
```

### Knowledge Queries
```
"Explain how authentication works in this application"
"What would break if I change this file?"
"How are these components connected?"
```

### Real-time Intelligence
```
"Help me write code that follows this project's patterns"
"Suggest improvements for this function"
"What's the best way to add a new API endpoint?"
```

## MCP Tools Available

The server exposes 21 MCP tools:

- `ping` - Test connectivity
- `analyze_project` - Full project analysis
- `analyze_security` - Security vulnerability scanning
- `check_auth_pattern` - Authentication pattern analysis
- `find_vulnerabilities` - OWASP vulnerability detection
- `learn_patterns` - Pattern recognition and learning
- `explain_system` - System architecture explanation
- `analyze_impact` - Change impact analysis
- `get_system_docs` - Documentation generation
- `trace_data_flow` - Data flow analysis
- And 11 more specialized tools for governance, real-time assistance, and pattern compliance

## Development

```bash
# Run in development mode with hot reload
npm run dev

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Clean build artifacts
npm run clean
```

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

## Configuration

The system can be configured through a `.codeintelligence.json` file in your project root:

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

## Logging

Logs are written to:
- `logs/combined.log` - All log levels
- `logs/error.log` - Error messages only
- Console (development mode only)

Log levels: `error`, `warn`, `info`, `debug`

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

## Support

- **Issues**: [GitHub Issues](https://github.com/jasonkline/codebase-intelligence/issues)
- **Author**: Jason Kline <jason.kline@narwol.ai>

## License

ISC License - see LICENSE file for details

---

**Note**: This is a working MCP server ready for production use with Claude Code. All documented features are implemented and tested.