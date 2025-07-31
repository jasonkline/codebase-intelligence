# Troubleshooting Guide

Common issues and solutions for Codebase Intelligence MCP Server.

## Quick Diagnostics

### Health Check Command
```bash
# Run comprehensive system health check
codebase-intelligence health

# Run specific diagnostics
codebase-intelligence diagnose --category connection
codebase-intelligence diagnose --category performance
codebase-intelligence diagnose --category security
```

### System Information
```bash
# Check version and system info
codebase-intelligence --version
codebase-intelligence config system

# View current configuration
codebase-intelligence config show

# Test MCP connectivity
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | codebase-intelligence --stdio
```

## Installation Issues

### Issue: Command Not Found

**Symptoms:**
```bash
$ codebase-intelligence
bash: codebase-intelligence: command not found
```

**Solutions:**

1. **Check if installed:**
   ```bash
   which codebase-intelligence
   npm list -g @codebase-intelligence/server
   ```

2. **Fix PATH issues:**
   ```bash
   # Add to ~/.bashrc or ~/.zshrc
   export PATH=$PATH:/usr/local/bin
   export PATH=$PATH:~/.npm-global/bin
   
   # Reload shell
   source ~/.bashrc
   ```

3. **Reinstall:**
   ```bash
   # From source
   git clone https://github.com/jasonkline/codebase-intelligence.git
   cd codebase-intelligence
   npm install
   npm run build
   ./setup-scripts/install.sh
   ```

### Issue: Permission Denied

**Symptoms:**
```bash
$ codebase-intelligence
bash: /usr/local/bin/codebase-intelligence: Permission denied
```

**Solutions:**

1. **Fix binary permissions:**
   ```bash
   sudo chmod +x /usr/local/bin/codebase-intelligence
   ```

2. **Fix ownership:**
   ```bash
   sudo chown $(whoami) /usr/local/bin/codebase-intelligence
   ```

3. **Install in user directory:**
   ```bash
   # Clone to user directory
   git clone https://github.com/jasonkline/codebase-intelligence.git ~/.codebase-intelligence-source
   cd ~/.codebase-intelligence-source
   npm install
   npm run build
   ./setup-scripts/install.sh --install-dir ~/.codebase-intelligence
   ```

### Issue: Node.js Version Too Old

**Symptoms:**
```
Error: Node.js version 14.x is not supported. Minimum required: 16.x
```

**Solutions:**

1. **Update Node.js (using nvm):**
   ```bash
   # Install nvm if not present
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
   
   # Install and use Node.js 18
   nvm install 18
   nvm use 18
   nvm alias default 18
   ```

2. **System package update:**
   ```bash
   # Ubuntu/Debian
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   
   # macOS
   brew install node@18
   brew link node@18
   ```

## Configuration Issues

### Issue: Project Path Not Set

**Symptoms:**
```
Error: CI_PROJECT_PATH environment variable not set
```

**Solutions:**

1. **Set environment variable:**
   ```bash
   export CI_PROJECT_PATH="/path/to/your/project"
   
   # Make permanent
   echo 'export CI_PROJECT_PATH="/path/to/your/project"' >> ~/.bashrc
   ```

2. **Use command line flag:**
   ```bash
   codebase-intelligence analyze --project /path/to/your/project
   ```

3. **Update MCP configuration:**
   ```json
   {
     "mcpServers": {
       "codebase-intelligence": {
         "env": {
           "CI_PROJECT_PATH": "/path/to/your/project"
         }
       }
     }
   }
   ```

### Issue: Invalid Configuration File

**Symptoms:**
```
Error: Invalid configuration in .codeintelligence.json
SyntaxError: Unexpected token } in JSON
```

**Solutions:**

1. **Validate JSON syntax:**
   ```bash
   # Check JSON syntax
   cat .codeintelligence.json | jq .
   
   # If jq not installed
   node -e "console.log(JSON.parse(require('fs').readFileSync('.codeintelligence.json')))"
   ```

2. **Common JSON fixes:**
   ```json
   // ❌ Trailing comma
   {
     "analysis": {
       "include": ["src/**/*.ts"],
     }
   }
   
   // ✅ No trailing comma
   {
     "analysis": {
       "include": ["src/**/*.ts"]
     }
   }
   ```

3. **Reset to default:**
   ```bash
   # Backup current config
   mv .codeintelligence.json .codeintelligence.json.backup
   
   # Generate new config
   codebase-intelligence init
   ```

### Issue: Permission Errors on Config Files

**Symptoms:**
```
Error: EACCES: permission denied, open '.codeintelligence.json'
```

**Solutions:**

1. **Fix file permissions:**
   ```bash
   chmod 644 .codeintelligence.json
   chmod 755 .codeintel/
   ```

2. **Fix directory ownership:**
   ```bash
   sudo chown -R $(whoami):$(whoami) .codeintel/
   ```

## MCP Integration Issues

### Issue: Claude Code Not Connecting

**Symptoms:**
- Claude Code doesn't recognize codebase-intelligence tools
- "No MCP servers found" message

**Solutions:**

1. **Check MCP configuration location:**
   ```bash
   # Default locations
   ls -la ~/.config/claude-code/mcp.json
   ls -la ~/.claude-code/mcp.json
   
   # Create directory if missing
   mkdir -p ~/.config/claude-code
   ```

2. **Validate MCP configuration:**
   ```bash
   # Check JSON syntax
   cat ~/.config/claude-code/mcp.json | jq .
   
   # Test server directly
   echo '{"jsonrpc":"2.0","id":1,"method":"ping"}' | codebase-intelligence --stdio
   ```

3. **Common MCP config issues:**
   ```json
   // ❌ Wrong command path
   {
     "mcpServers": {
       "codebase-intelligence": {
         "command": "codebase-intelligence-server"
       }
     }
   }
   
   // ✅ Correct command
   {
     "mcpServers": {
       "codebase-intelligence": {
         "command": "codebase-intelligence",
         "args": ["--stdio"]
       }
     }
   }
   ```

4. **Restart Claude Code:**
   ```bash
   # Kill Claude Code process
   pkill -f "claude-code"
   
   # Restart Claude Code
   claude-code
   ```

### Issue: MCP Server Timeout

**Symptoms:**
```
Error: MCP server timeout after 30s
```

**Solutions:**

1. **Increase timeout in MCP config:**
   ```json
   {
     "mcpServers": {
       "codebase-intelligence": {
         "timeout": 120000,
         "heartbeat": 60000
       }
     }
   }
   ```

2. **Check server startup time:**
   ```bash
   time codebase-intelligence ping
   ```

3. **Optimize for faster startup:**
   ```json
   {
     "analysis": {
       "parallel": true,
       "maxConcurrency": 2
     },
     "database": {
       "cacheSize": "128MB"
     }
   }
   ```

### Issue: Tools Not Available

**Symptoms:**
- Some MCP tools missing from Claude Code
- "Tool not found" errors

**Solutions:**

1. **Check tool registration:**
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | codebase-intelligence --stdio
   ```

2. **Clear cache and restart:**
   ```bash
   rm -rf .codeintel/cache/
   pkill -f "codebase-intelligence"
   ```

3. **Update to latest version:**
   ```bash
   cd /path/to/codebase-intelligence
   git pull origin main
   npm install
   npm run build
   ./setup-scripts/install.sh
   ```

## Performance Issues

### Issue: Analysis Taking Too Long

**Symptoms:**
- Analysis never completes
- High CPU/memory usage
- Timeout errors

**Solutions:**

1. **Check project size:**
   ```bash
   find . -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" | wc -l
   du -sh .
   ```

2. **Optimize configuration:**
   ```json
   {
     "analysis": {
       "exclude": [
         "node_modules/**",
         "dist/**",
         "build/**",
         ".next/**",
         "**/*.test.ts",
         "**/*.spec.ts",
         "**/*.d.ts"
       ],
       "maxFileSize": "1MB",
       "timeout": 120000,
       "parallel": true,
       "maxConcurrency": 4
     }
   }
   ```

3. **Increase system resources:**
   ```bash
   export CI_MEMORY_LIMIT="8GB"
   export CI_MAX_CONCURRENCY="8"
   export CI_ANALYSIS_TIMEOUT="600000"  # 10 minutes
   ```

4. **Enable progress tracking:**
   ```bash
   codebase-intelligence analyze --verbose --progress
   ```

### Issue: High Memory Usage

**Symptoms:**
- System becomes unresponsive
- Out of memory errors
- Swap usage spikes

**Solutions:**

1. **Limit memory usage:**
   ```bash
   export CI_MEMORY_LIMIT="2GB"
   export CI_DATABASE_CACHE_SIZE="128MB"
   ```

2. **Reduce concurrency:**
   ```json
   {
     "analysis": {
       "parallel": true,
       "maxConcurrency": 2
     }
   }
   ```

3. **Process in batches:**
   ```bash
   # Analyze specific directories
   codebase-intelligence analyze --path src/components
   codebase-intelligence analyze --path src/api
   ```

4. **Monitor memory usage:**
   ```bash
   # While analysis is running
   watch -n 1 'ps aux | grep codebase-intelligence'
   ```

### Issue: Database Lock Errors

**Symptoms:**
```
Error: database is locked
SQLITE_BUSY: database is locked
```

**Solutions:**

1. **Check for running processes:**
   ```bash
   ps aux | grep codebase-intelligence
   pkill -f codebase-intelligence
   ```

2. **Clear database locks:**
   ```bash
   rm -f .codeintel/analysis.db-wal
   rm -f .codeintel/analysis.db-shm
   ```

3. **Recreate database:**
   ```bash
   rm -f .codeintel/analysis.db
   codebase-intelligence analyze
   ```

4. **Enable WAL mode:**
   ```json
   {
     "database": {
       "walMode": true,
       "busyTimeout": 30000
     }
   }
   ```

## Security Analysis Issues

### Issue: Too Many False Positives

**Symptoms:**
- Security scanner flags legitimate code
- Overwhelming number of low-severity issues

**Solutions:**

1. **Adjust severity threshold:**
   ```json
   {
     "security": {
       "minSeverity": "medium",
       "maxFindings": 50
     }
   }
   ```

2. **Add whitelisting:**
   ```json
   {
     "security": {
       "whitelist": {
         "files": ["test/**/*.ts", "scripts/**/*.ts"],
         "rules": ["console-log-usage"],
         "patterns": ["console\\.log\\("]
       }
     }
   }
   ```

3. **Disable specific categories:**
   ```json
   {
     "security": {
       "categories": {
         "logging": false,
         "crypto": true,
         "injection": true
       }
     }
   }
   ```

### Issue: Missing Security Issues

**Symptoms:**
- Known vulnerabilities not detected
- Security scanner seems incomplete

**Solutions:**

1. **Enable all categories:**
   ```json
   {
     "security": {
       "categories": {
         "owasp": true,
         "authentication": true,
         "authorization": true,
         "injection": true,
         "crypto": true,
         "secrets": true
       }
     }
   }
   ```

2. **Lower confidence threshold:**
   ```json
   {
     "security": {
       "minConfidence": 0.6,
       "includeExperimental": true
     }
   }
   ```

3. **Add custom rules:**
   ```json
   {
     "security": {
       "customRules": [
         {
           "id": "project-specific-issue",
           "pattern": "specificVulnerablePattern",
           "severity": "high"
         }
       ]
     }
   }
   ```

## Pattern Recognition Issues

### Issue: Patterns Not Learning

**Symptoms:**
- No patterns detected after analysis
- Pattern compliance always shows 0%

**Solutions:**

1. **Check learning mode:**
   ```json
   {
     "patterns": {
       "learningMode": "auto",
       "minConfidence": 0.7,
       "categories": ["auth", "api", "data_access"]
     }
   }
   ```

2. **Verify code has patterns:**
   ```bash
   # Check for repeated code structures
   grep -r "requireAuth" src/
   grep -r "getOrgDatabase" src/
   ```

3. **Lower confidence threshold:**
   ```json
   {
     "patterns": {
       "minConfidence": 0.5,
       "minOccurrences": 2
     }
   }
   ```

4. **Manual pattern definition:**
   ```json
   {
     "patterns": {
       "customPatterns": [
         {
           "name": "auth-middleware",
           "pattern": "requireAuthWithTenant\\(\\)",
           "category": "auth"
         }
       ]
     }
   }
   ```

## Logging and Debugging

### Enable Debug Logging

```bash
# Enable debug logging
export CI_LOG_LEVEL="debug"
export CI_DEBUG_AST="true"
export CI_DEBUG_PATTERNS="true"
export CI_DEBUG_SECURITY="true"

# Run with verbose output
codebase-intelligence analyze --verbose --debug
```

### Log Locations

```bash
# Default log locations
~/.codebase-intelligence/logs/error.log
~/.codebase-intelligence/logs/debug.log
.codeintel/logs/analysis.log

# View logs
tail -f ~/.codebase-intelligence/logs/error.log
```

### Profiling Performance

```bash
# Enable profiler
export CI_PROFILER_ENABLED="true"

# Run analysis with profiling
codebase-intelligence analyze --profile

# View profile results
ls -la .codeintel/profiles/
```

## Getting Help

### Collect Diagnostic Information

```bash
#!/bin/bash
# Create diagnostic report
echo "=== System Information ===" > diagnostic-report.txt
codebase-intelligence --version >> diagnostic-report.txt
node --version >> diagnostic-report.txt
npm --version >> diagnostic-report.txt
uname -a >> diagnostic-report.txt

echo "=== Configuration ===" >> diagnostic-report.txt
cat .codeintelligence.json >> diagnostic-report.txt

echo "=== Environment Variables ===" >> diagnostic-report.txt
env | grep CI_ >> diagnostic-report.txt

echo "=== MCP Configuration ===" >> diagnostic-report.txt
cat ~/.config/claude-code/mcp.json >> diagnostic-report.txt

echo "=== Health Check ===" >> diagnostic-report.txt
codebase-intelligence health >> diagnostic-report.txt

echo "=== Recent Logs ===" >> diagnostic-report.txt
tail -n 50 ~/.codebase-intelligence/logs/error.log >> diagnostic-report.txt
```

### Support Channels

1. **Documentation**: Browse this documentation site
2. **GitHub Issues**: [Report bugs and issues](https://github.com/jasonkline/codebase-intelligence/issues)
3. **Project Repository**: [GitHub](https://github.com/jasonkline/codebase-intelligence)

### Issue Templates

**Bug Report Template:**
```
**Environment:**
- OS: [macOS/Linux/Windows]
- Node.js version: [version]
- Codebase Intelligence version: [version]
- Project size: [number of files]

**Issue Description:**
[Clear description of the problem]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Configuration:**
```json
[Your .codeintelligence.json file]
```

**Logs:**
```
[Relevant log entries]
```
```

## Common Fixes Summary

| Issue | Quick Fix |
|-------|-----------|
| Command not found | `export PATH=$PATH:/usr/local/bin` |
| Permission denied | `chmod +x /usr/local/bin/codebase-intelligence` |
| Project path not set | `export CI_PROJECT_PATH="/path/to/project"` |
| MCP not connecting | Check `~/.config/claude-code/mcp.json` |
| Analysis timeout | Increase `CI_ANALYSIS_TIMEOUT` |
| High memory usage | Reduce `CI_MAX_CONCURRENCY` |
| Database locked | `pkill -f codebase-intelligence` |
| No patterns learned | Set `"learningMode": "auto"` |
| Too many security alerts | Increase `"minSeverity": "medium"` |
| JSON config error | Validate with `cat file.json \| jq .` |

---

*Still need help? [Create an issue](https://github.com/jasonkline/codebase-intelligence/issues/new) on GitHub.*