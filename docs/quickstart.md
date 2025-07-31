# Quick Start Guide

Get up and running with Codebase Intelligence in 5 minutes.

## Prerequisites

- Node.js 16+ installed
- A TypeScript/JavaScript project to analyze
- Claude Code installed and configured

## 1. Install Codebase Intelligence

```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build
```

## 2. Configure Claude Code Integration

Add Codebase Intelligence to your Claude Code MCP configuration.

### Option A: Project-specific Configuration

Create `.mcp.json` in your project root:

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

### Option B: Global Configuration

Add to your `~/.claude.json`:

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

**Important**: Replace paths with your actual directories:
- `/path/to/codebase-intelligence` → where you cloned this repository
- `/path/to/your/project` → your project to analyze

## 3. Test the Installation

1. **Restart Claude Code** to pick up the configuration changes

2. **Test connectivity**:
   ```
   "Test the codebase intelligence connection"
   ```

3. **Run initial analysis**:
   ```
   "Analyze this project for security issues and patterns"
   ```

You should see detailed analysis results with security findings, patterns, and recommendations.

## 4. Example Usage

### Security Analysis
```
"Check this API directory for authentication vulnerabilities"
"Scan for SQL injection risks in the database layer"
"Are there any hardcoded secrets in this codebase?"
```

### Pattern Learning
```
"Learn the coding patterns from this codebase"
"What authentication patterns does this project use?"
"How is error handling implemented across the codebase?"
```

### Real-time Help
```
"Explain how authentication works in this application"
"What would break if I modify this database schema?"
"Help me write a new API endpoint following project conventions"
```

## 5. Example: Analyzing a Next.js Project

Let's walk through analyzing a typical Next.js project:

### Project Structure
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

### Configuration
Create `.mcp.json` in your Next.js project:

```json
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "node",
      "args": ["/Users/yourname/codebase-intelligence/dist/index.js"],
      "env": {
        "CI_PROJECT_PATH": "/Users/yourname/my-nextjs-app",
        "NODE_ENV": "production",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Run Analysis
```
"Analyze this Next.js project for security patterns and vulnerabilities"
```

### Example Results
Claude Code will return detailed analysis like:

**Security Analysis:**
```
Found 3 security issues in your API routes:
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
Identified these patterns in your codebase:
- Authentication: Uses Supabase Auth with custom middleware
- API Routes: Standard Next.js 13+ app directory structure
- Database: PostgreSQL with Row Level Security (RLS)
- Authorization: Role-based access control (admin/user/moderator)

Your code follows these patterns consistently across 89% of files.
```

## Troubleshooting

### Issue: "Failed to reconnect to codebase-intelligence"

**Solution:**
1. Check that the paths in your MCP config are correct and absolute
2. Ensure the project was built: `npm run build`
3. Verify the `CI_PROJECT_PATH` points to your actual project
4. Restart Claude Code after configuration changes

### Issue: "CI_PROJECT_PATH environment variable not set"

**Solution:**
Make sure your MCP configuration includes the `CI_PROJECT_PATH` environment variable pointing to your project directory.

### Issue: "Permission denied"

**Solution:**
```bash
# Fix file permissions
chmod +x /path/to/codebase-intelligence/dist/index.js
```

## Next Steps

Now that you have Codebase Intelligence running:

1. **Explore security features** - Try different security analysis commands
2. **Learn project patterns** - Let it analyze your coding conventions
3. **Get real-time help** - Ask questions about your architecture
4. **Use for code reviews** - Get intelligent suggestions for improvements

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/jasonkline/codebase-intelligence/issues)
- **Author**: Jason Kline <jason.kline@narwol.ai>

## Success! 🎉

You now have Codebase Intelligence analyzing your code and providing intelligent insights through Claude Code. The system will:

- ✅ Learn your coding patterns automatically
- ✅ Detect security vulnerabilities in real-time  
- ✅ Answer questions about your codebase
- ✅ Provide smart code suggestions
- ✅ Enforce governance rules

Happy coding!