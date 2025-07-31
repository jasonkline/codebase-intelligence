# Quick Start Guide

Get up and running with Codebase Intelligence in 5 minutes.

## Prerequisites

- Node.js 16+ installed
- A TypeScript/JavaScript project to analyze
- Claude Code installed and configured

## 1. Install Codebase Intelligence

### Option A: Automated Installation (Recommended)
```bash
curl -fsSL https://install.codebase-intelligence.com | bash
```

### Option B: npm Installation
```bash
npm install -g @codebase-intelligence/server
```

### Option C: Download Binary
```bash
# Linux/macOS
curl -L https://github.com/your-org/codebase-intelligence/releases/latest/download/codebase-intelligence-$(uname -s)-$(uname -m).tar.gz | tar -xz
sudo mv codebase-intelligence /usr/local/bin/
```

## 2. Initialize Your Project

Navigate to your project directory and initialize:

```bash
cd /path/to/your/project
codebase-intelligence init
```

This creates a `.codeintelligence.json` configuration file:

```json
{
  "version": "1.0",
  "analysis": {
    "include": ["src/**/*.ts", "src/**/*.tsx"],
    "exclude": ["node_modules/**", "**/*.test.ts"]
  },
  "patterns": {
    "learningMode": "auto",
    "categories": ["auth", "api", "data_access"]
  },
  "security": {
    "enabled": true,
    "scanOnSave": true
  }
}
```

## 3. Configure Claude Code Integration

Add Codebase Intelligence to your Claude Code MCP configuration:

```bash
mkdir -p ~/.config/claude-code

cat > ~/.config/claude-code/mcp.json << 'EOF'
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "codebase-intelligence",
      "args": ["--stdio"],
      "env": {
        "CI_PROJECT_PATH": "/path/to/your/project",
        "CI_LOG_LEVEL": "info"
      },
      "description": "Intelligent codebase analysis and security scanning"
    }
  }
}
EOF
```

**Important**: Replace `/path/to/your/project` with your actual project path.

## 4. Run Your First Analysis

Test the installation:

```bash
# Test connectivity
codebase-intelligence ping

# Run initial analysis
codebase-intelligence analyze
```

You should see output like:
```
✓ Project analyzed successfully
✓ Found 234 files, 1,456 symbols
✓ Learned 23 patterns
✓ Identified 3 security issues
✓ Analysis completed in 12.3s
```

## 5. Start Using with Claude Code

Open Claude Code and try these commands:

### Basic Analysis
```
"Analyze this project for security issues and coding patterns"
```

### Security Check
```
"Check this API directory for authentication vulnerabilities"
```

### Pattern Learning
```
"Learn the coding patterns from this codebase"
```

### Real-time Help
```
"Explain how authentication works in this application"
```

## Quick Commands Reference

### Analysis Commands
```bash
# Full project analysis
codebase-intelligence analyze

# Security-only scan
codebase-intelligence security

# Pattern learning
codebase-intelligence patterns learn

# Real-time watching
codebase-intelligence watch
```

### Utility Commands
```bash
# Check system health
codebase-intelligence health

# View configuration
codebase-intelligence config show

# Check version
codebase-intelligence --version

# Get help
codebase-intelligence --help
```

## Example: Analyzing a Next.js Project

Let's walk through analyzing a typical Next.js project:

### 1. Project Structure
```
my-nextjs-app/
├── app/
│   ├── api/
│   │   ├── auth/
│   │   └── users/
│   └── components/
├── lib/
│   ├── auth.ts
│   └── database.ts
└── package.json
```

### 2. Configuration
```json
{
  "version": "1.0",
  "project": {
    "name": "My Next.js App",
    "framework": "nextjs"
  },
  "analysis": {
    "include": [
      "app/**/*.ts",
      "app/**/*.tsx", 
      "lib/**/*.ts",
      "components/**/*.ts"
    ],
    "exclude": [
      "node_modules/**",
      ".next/**",
      "**/*.test.ts"
    ]
  },
  "patterns": {
    "categories": ["auth", "api", "data_access", "components"]
  },
  "security": {
    "enabled": true,
    "categories": {
      "authentication": true,
      "authorization": true,
      "injection": true
    }
  }
}
```

### 3. Run Analysis
```bash
codebase-intelligence analyze --verbose
```

### 4. Example Claude Code Interactions

**Security Analysis:**
```
User: "Check my API routes for security issues"

Response: I found 3 security issues in your API routes:
1. Missing authentication in app/api/users/route.ts:15
2. Direct database access without RLS in app/api/auth/route.ts:23  
3. Potential SQL injection in lib/database.ts:45

Recommendations:
- Add requireAuthWithTenant() to all API routes
- Use getOrgDatabaseWithAuth() for database access
- Implement parameterized queries
```

**Pattern Recognition:**
```
User: "What coding patterns does this project follow?"

Response: I've identified these patterns in your codebase:
- Authentication: Uses Supabase Auth with custom middleware
- API Routes: Standard Next.js 13+ app directory structure
- Database: PostgreSQL with Row Level Security (RLS)
- Authorization: Role-based access control (admin/user/moderator)

Your code follows these patterns consistently across 89% of files.
```

## Common First-Time Issues

### Issue: "Command not found"
```bash
# Check if binary is in PATH
which codebase-intelligence

# If not found, add to PATH
export PATH=$PATH:/usr/local/bin
```

### Issue: "Project path not set"
```bash
# Set the project path environment variable
export CI_PROJECT_PATH="/path/to/your/project"

# Or use the --project flag
codebase-intelligence analyze --project /path/to/your/project
```

### Issue: "Permission denied"
```bash
# Fix binary permissions
chmod +x /usr/local/bin/codebase-intelligence

# Fix config file permissions
chmod 644 .codeintelligence.json
```

### Issue: "Claude Code not connecting"
```bash
# Test MCP connectivity directly
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | codebase-intelligence --stdio

# Check MCP configuration
cat ~/.config/claude-code/mcp.json
```

## Next Steps

Now that you have Codebase Intelligence running:

1. **[Configure for your needs](./configuration.md)** - Customize settings for your project
2. **[Explore security features](./security-analysis.md)** - Deep dive into vulnerability detection
3. **[Learn pattern recognition](./pattern-recognition.md)** - Understand the pattern system
4. **[Set up real-time features](./realtime-intelligence.md)** - Enable live code assistance
5. **[Optimize performance](./performance.md)** - Tune for large codebases

## Getting Help

- **Documentation**: Browse this documentation site
- **Issues**: [GitHub Issues](https://github.com/your-org/codebase-intelligence/issues)
- **Discord**: [Community Discord](https://discord.gg/codebase-intelligence)
- **Email**: support@codebase-intelligence.com

## Success! 🎉

You now have Codebase Intelligence analyzing your code and providing intelligent insights through Claude Code. The system will:

- ✅ Learn your coding patterns automatically
- ✅ Detect security vulnerabilities in real-time  
- ✅ Answer questions about your codebase
- ✅ Provide smart code suggestions
- ✅ Enforce governance rules

Happy coding!

---

*Completed the quick start? Check out our [advanced features guide](./architecture.md) to unlock the full power of Codebase Intelligence.*