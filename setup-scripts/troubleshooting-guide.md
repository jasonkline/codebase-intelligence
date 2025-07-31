# Codebase Intelligence Troubleshooting Guide

This guide helps resolve common issues with the Codebase Intelligence MCP server.

## Quick Diagnostics

### 1. Test Server Connectivity
```bash
# Test if the server starts correctly
./setup-scripts/install.sh --test

# Check server status manually
node dist/index.js
```

### 2. Check Logs
```bash
# View recent logs
tail -f ~/.codebase-intelligence/logs/combined.log

# Check error logs
tail -f ~/.codebase-intelligence/logs/error.log

# View logs with timestamp filtering
grep "$(date +%Y-%m-%d)" ~/.codebase-intelligence/logs/combined.log
```

### 3. Validate Configuration
```bash
# Check MCP configuration
cat ~/.config/claude-code/mcp.json | jq .

# Validate project configuration
cat ~/.codebase-intelligence/config/your-project.json | jq .
```

## Common Issues and Solutions

### Server Won't Start

**Symptoms:**
- "Failed to start MCP server" in Claude Code
- Server process exits immediately
- No response to ping requests

**Diagnosis:**
```bash
# Check Node.js version (requires 16+)
node --version

# Test server directly
cd ~/.codebase-intelligence
node index.js

# Check for missing dependencies
npm ls --depth=0
```

**Solutions:**

1. **Update Node.js**
   ```bash
   # Install/update Node.js to version 16+
   # Visit https://nodejs.org or use nvm
   nvm install node
   nvm use node
   ```

2. **Reinstall Dependencies**
   ```bash
   cd ~/.codebase-intelligence
   rm -rf node_modules
   npm install
   ```

3. **Check Permissions**
   ```bash
   # Ensure executable permissions
   chmod +x ~/.codebase-intelligence/index.js
   
   # Check directory permissions
   ls -la ~/.codebase-intelligence/
   ```

### Database Issues

**Symptoms:**
- "Database initialization failed"
- SQLite errors in logs
- Analysis results not persisting

**Diagnosis:**
```bash
# Check database file
ls -la ~/.codebase-intelligence/data/

# Test database connectivity
sqlite3 ~/.codebase-intelligence/data/your-project.db ".tables"

# Check disk space
df -h ~/.codebase-intelligence/
```

**Solutions:**

1. **Reset Database** (⚠️ Loses all analysis data)
   ```bash
   rm ~/.codebase-intelligence/data/*.db
   # Restart server to recreate
   ```

2. **Fix Permissions**
   ```bash
   chmod 644 ~/.codebase-intelligence/data/*.db
   chmod 755 ~/.codebase-intelligence/data/
   ```

3. **Check Disk Space**
   ```bash
   # Free up space if needed
   docker system prune  # If using Docker
   npm cache clean --force
   ```

### Analysis Performance Issues

**Symptoms:**
- Analysis takes very long (>5 minutes)
- High memory usage
- Claude Code becomes unresponsive

**Diagnosis:**
```bash
# Check system resources
top -p $(pgrep -f codebase-intelligence)

# Monitor memory usage
ps aux | grep codebase-intelligence

# Check project size
find /path/to/project -name "*.ts" -o -name "*.tsx" | wc -l
```

**Solutions:**

1. **Optimize File Patterns**
   ```json
   {
     "include": ["src/**/*.ts", "src/**/*.tsx"],
     "exclude": [
       "node_modules/**",
       "dist/**", 
       "build/**",
       ".next/**",
       "**/*.test.*",
       "**/*.spec.*",
       "**/*.d.ts"
     ]
   }
   ```

2. **Reduce Concurrency**
   ```json
   {
     "analysis": {
       "maxConcurrency": 2,
       "parallel": false
     }
   }
   ```

3. **Enable Incremental Analysis**
   ```json
   {
     "realtime": {
       "enabled": true,
       "debounceMs": 500
     }
   }
   ```

### Security Scanning Issues

**Symptoms:**
- No security issues detected
- False positives
- Missing vulnerability categories

**Diagnosis:**
```bash
# Test security scanner on known vulnerable file
node -e "
const scanner = require('./dist/security/SecurityScanner');
scanner.scanFile('./test-project/src/api/insecure/route.ts').then(console.log);
"

# Check security rules configuration
cat ~/.codebase-intelligence/config/your-project.json | jq .security
```

**Solutions:**

1. **Update Security Rules**
   ```json
   {
     "security": {
       "enabled": true,
       "scanOnSave": true,
       "minSeverity": "medium",
       "owasp": true,
       "customRules": "./security-rules.json"
     }
   }
   ```

2. **Verify File Types**
   - Ensure files have proper extensions (.ts, .tsx, .js, .jsx)
   - Check that files are in included patterns
   - Verify files are not in exclude patterns

3. **Manual Test**
   ```bash
   # Test specific vulnerability detection
   node dist/test-security.js /path/to/suspicious/file.ts
   ```

### Pattern Recognition Problems

**Symptoms:**
- No patterns learned from codebase
- Pattern matching fails
- Inconsistent suggestions

**Diagnosis:**
```bash
# Check pattern registry
sqlite3 ~/.codebase-intelligence/data/your-project.db "SELECT * FROM patterns LIMIT 10;"

# View pattern analysis logs
grep "pattern" ~/.codebase-intelligence/logs/combined.log | tail -20
```

**Solutions:**

1. **Retrain Patterns**
   ```bash
   # Clear existing patterns and relearn
   sqlite3 ~/.codebase-intelligence/data/your-project.db "DELETE FROM patterns; DELETE FROM pattern_instances;"
   
   # Restart server to trigger relearning
   ```

2. **Adjust Confidence Threshold**
   ```json
   {
     "patterns": {
       "minConfidence": 0.6,
       "learningMode": "auto"
     }
   }
   ```

3. **Add Manual Patterns**
   ```json
   {
     "patterns": {
       "manual": {
         "auth": [
           "requireAuthWithTenant",
           "getOrgDatabaseWithAuth"
         ]
       }
     }
   }
   ```

### Claude Code Integration Issues

**Symptoms:**
- Server not showing up in Claude Code
- Tools not available
- Responses not formatted correctly

**Diagnosis:**
```bash
# Check MCP server registration
claude-code --list-servers

# Validate MCP configuration
cat ~/.config/claude-code/mcp.json | jq .mcpServers

# Test MCP protocol directly
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node ~/.codebase-intelligence/index.js
```

**Solutions:**

1. **Restart Claude Code**
   ```bash
   # Completely restart Claude Code
   pkill -f claude-code
   claude-code
   ```

2. **Fix MCP Configuration**
   ```json
   {
     "mcpServers": {
       "codebase-intelligence": {
         "command": "node",
         "args": ["/absolute/path/to/codebase-intelligence/dist/index.js"],
         "env": {
           "CI_PROJECT_PATH": "/absolute/path/to/your/project"
         }
       }
     }
   }
   ```

3. **Check Paths**
   - Use absolute paths in MCP configuration
   - Verify all files exist at specified paths
   - Check environment variables

## Environment-Specific Issues

### macOS

**Common Issues:**
- Permission denied errors
- Gatekeeper blocking execution

**Solutions:**
```bash
# Fix permissions
sudo chown -R $(whoami) ~/.codebase-intelligence

# Allow execution (if needed)
xattr -d com.apple.quarantine ~/.codebase-intelligence/index.js
```

### Linux

**Common Issues:**
- SQLite library missing
- File descriptor limits

**Solutions:**
```bash
# Install SQLite development libraries
sudo apt-get install sqlite3 libsqlite3-dev  # Ubuntu/Debian
sudo yum install sqlite-devel               # CentOS/RHEL

# Increase file descriptor limit
ulimit -n 4096
```

### Windows

**Common Issues:**
- Path separators
- PowerShell execution policy

**Solutions:**
```powershell
# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Use PowerShell instead of cmd for setup
```

## Performance Optimization

### Large Codebases (>10k files)

```json
{
  "analysis": {
    "maxConcurrency": 1,
    "parallel": false,
    "batchSize": 50,
    "maxFileSize": "1MB"
  },
  "patterns": {
    "maxPatterns": 1000,
    "cacheSize": "100MB"
  },
  "database": {
    "maxSize": "2GB",
    "vacuumInterval": "1h"
  }
}
```

### Memory-Constrained Environments

```json
{
  "realtime": {
    "enabled": false
  },
  "analysis": {
    "streaming": true,
    "maxMemory": "512MB"
  }
}
```

## Getting Help

### Log Analysis

When reporting issues, include relevant logs:

```bash
# Collect logs for the last hour
grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" ~/.codebase-intelligence/logs/combined.log > debug-logs.txt

# Include system information
echo "Node version: $(node --version)" >> debug-logs.txt
echo "OS: $(uname -a)" >> debug-logs.txt
echo "Claude Code version: $(claude-code --version)" >> debug-logs.txt
```

### Debug Mode

Enable detailed logging:

```json
{
  "server": {
    "logLevel": "debug",
    "enableTelemetry": true,
    "debugMode": true
  }
}
```

### Community Support

- GitHub Issues: [Create an issue](https://github.com/jasonkline/codebase-intelligence/issues)
- Documentation: Check the README.md and examples/
- Project Repository: [GitHub](https://github.com/jasonkline/codebase-intelligence)

## Maintenance

### Regular Maintenance Tasks

```bash
# Weekly: Clean up old logs
find ~/.codebase-intelligence/logs -name "*.log" -mtime +7 -delete

# Monthly: Vacuum database
sqlite3 ~/.codebase-intelligence/data/your-project.db "VACUUM;"

# Update to latest version
cd /path/to/codebase-intelligence
git pull
npm run build
./setup-scripts/install.sh
```

### Backup Important Data

```bash
# Backup learned patterns and knowledge
cp -r ~/.codebase-intelligence/data/ ~/backups/codebase-intelligence-$(date +%Y%m%d)/

# Backup configuration
cp -r ~/.codebase-intelligence/config/ ~/backups/codebase-intelligence-config-$(date +%Y%m%d)/
```

Remember: Always backup your data before major updates or configuration changes!