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

## Compatibility

### ✅ **Supported Languages & Frameworks**
- **Languages**: TypeScript, JavaScript (ES6+), JSON, Markdown
- **Frontend**: Next.js, React, Vue.js, Angular, Svelte, Nuxt.js
- **Backend**: Express.js, NestJS, Fastify, Koa.js, Node.js native
- **Databases**: PostgreSQL, MySQL, SQLite, MongoDB, Supabase
- **Auth Systems**: Supabase Auth, Auth0, NextAuth.js, JWT, custom
- **Project Types**: Monorepos, microservices, serverless, JAMstack

### 🎯 **Universal Features**
- **Framework Detection**: Automatically detects your stack
- **Pattern Learning**: Adapts to any coding conventions
- **Security Scanning**: OWASP compliance for any JavaScript project
- **Architecture Analysis**: Works with any folder structure

**See [Compatibility Guide](docs/compatibility.md) for complete details.**

## Installation

### Prerequisites

- Node.js 16+ installed
- A TypeScript/JavaScript project to analyze
- Claude Code installed and configured

### Installation

```bash
# Clone and build from source
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence
npm install
npm run build
```

#### Alternative: Docker Deployment
```bash
# Run with Docker (optional)
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence
docker-compose up -d
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

## System Requirements

### Minimum Requirements
- **Node.js**: 16.x or higher
- **Memory**: 512MB RAM
- **Storage**: 100MB available space
- **OS**: macOS, Linux, Windows (WSL2 recommended)

### Recommended for Production
- **Node.js**: 18.x LTS or 20.x
- **Memory**: 2GB+ RAM for large codebases
- **Storage**: 1GB+ available space
- **CPU**: Multi-core for parallel processing

## Configuration

The system can be configured through:

### Environment Variables
```bash
# Required
CI_PROJECT_PATH=/path/to/your/project

# Optional
LOG_LEVEL=info                    # debug, info, warn, error
NODE_ENV=production              # development, production
DB_PATH=.codeintel/index.db      # Custom database path
MAX_FILE_SIZE=1048576           # Max file size in bytes (1MB)
```

### Project Configuration File (`.codeintelligence.json`)
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

## Production Deployment

### Running the Server
```bash
# After building, run the MCP server
node dist/index.js

# Or with environment variables
CI_PROJECT_PATH=/path/to/your/project node dist/index.js
```

### Docker (Alternative)
```bash
# Using Docker Compose
docker-compose up -d

# Or custom container
docker build -t codebase-intelligence .
docker run -d \
  -e CI_PROJECT_PATH=/projects \
  -v /path/to/your/project:/projects:ro \
  codebase-intelligence
```

### Health Check
```bash
# Test MCP connectivity
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node dist/index.js
```

### Logging
Logs are written to:
- `logs/combined.log` - All log levels
- `logs/error.log` - Error messages only
- Console (development mode only)

## Technology Stack

- **Language**: TypeScript
- **Parser**: TypeScript Compiler API
- **Database**: SQLite with FTS5 (full-text search)
- **File Watching**: Chokidar
- **Protocol**: MCP (Model Context Protocol)
- **Testing**: Jest
- **Logging**: Winston

## Security Considerations

- **File Access**: Limited to configured project paths only
- **No Network Access**: Runs locally, no external connections
- **Data Privacy**: All analysis stays on your machine
- **Sandboxed Execution**: No arbitrary code execution
- **Read-Only Analysis**: Never modifies your source code

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

## Troubleshooting

### Common Issues

**"Failed to reconnect to codebase-intelligence"**
- Verify paths in MCP configuration are correct and absolute
- Ensure project was built: `npm run build`
- Check `CI_PROJECT_PATH` environment variable
- Restart Claude Code after configuration changes

**"CI_PROJECT_PATH environment variable not set"**
- Add `CI_PROJECT_PATH` to your MCP server environment configuration

**Performance Issues**
- Increase memory allocation for large codebases
- Use `exclude` patterns to skip unnecessary files
- Enable parallel processing in configuration

## Documentation

- **[Quick Start Guide](docs/quickstart.md)** - Get up and running in 5 minutes
- **[Compatibility Guide](docs/compatibility.md)** - Supported frameworks and languages
- **[Installation Guide](docs/installation.md)** - Detailed installation instructions
- **[Configuration Guide](docs/configuration.md)** - Advanced configuration options
- **[Security Analysis](docs/security-analysis.md)** - Security scanning capabilities
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

## Support

- **Issues**: [GitHub Issues](https://github.com/jasonkline/codebase-intelligence/issues)
- **Author**: Jason Kline <jason.kline@narwol.ai>

## License

Apache 2.0 + Commons Clause - see [LICENSE](https://github.com/jasonkline/codebase-intelligence?tab=License-1-ov-file) file for details

---

**Note**: This is a working MCP server ready for production use with Claude Code. All documented features are implemented and tested.
