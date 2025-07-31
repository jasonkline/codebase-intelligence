# Codebase Intelligence Configuration Examples

This directory contains example configurations for different use cases and environments.

## MCP Server Configurations

### Basic Configuration (`mcp-config-basic.json`)
A minimal MCP configuration for getting started with Codebase Intelligence.

```bash
# Copy to your Claude Code configuration directory
cp examples/mcp-config-basic.json ~/.config/claude-code/.mcp.json
```

### Development Configuration (`mcp-config-development.json`) 
Development-optimized configuration with debugging enabled and TypeScript source execution.

Features:
- Debug logging enabled
- TypeScript source execution with ts-node
- Development database path
- Shorter timeouts for faster iteration

### Production Configuration (`mcp-config-production.json`)
Production-ready configuration with optimized settings.

Features:
- Warning-level logging only
- Compiled JavaScript execution
- System database paths
- Retry mechanisms and longer timeouts

### Team Configuration (`mcp-config-team.json`)
Shared configuration for team environments with centralized database.

Features:
- Shared database location
- Team-optimized settings
- Production stability with development visibility

## Codebase Intelligence Configurations

### Basic Configuration (`.codeintelligence-basic.json`)
Standard configuration suitable for most TypeScript/React projects.

Features:
- Automatic pattern learning
- Security scanning enabled
- Basic governance rules
- Standard performance settings

### Strict Configuration (`.codeintelligence-strict.json`)
Enterprise-grade configuration with maximum security and governance.

Features:
- Manual pattern approval required
- Strict governance mode
- Maximum security scanning
- Performance profiling enabled
- Integration support (VSCode, GitHub, Slack)
- Higher confidence thresholds
- Custom rule sets support

### Development Configuration (`.codeintelligence-development.json`)
Developer-friendly configuration optimized for fast iteration.

Features:
- Relaxed governance rules
- Debug logging
- Web UI enabled
- Reduced pattern confidence thresholds
- Minimal toolset for faster startup
- Performance profiling for optimization

## Usage Instructions

### For Individual Developers

1. **Choose a configuration** that matches your needs:
   - New to the tool: Use `basic` configurations
   - Active development: Use `development` configurations
   - Production deployment: Use `production` configurations

2. **Copy the MCP configuration**:
   ```bash
   # Replace with your actual Claude Code config directory
   cp examples/mcp-config-basic.json ~/.config/claude-code/.mcp.json
   ```

3. **Copy the Codebase Intelligence configuration**:
   ```bash
   # To your project root
   cp examples/.codeintelligence-basic.json .codeintelligence.json
   ```

4. **Update paths** in both files to match your system:
   - Update `cwd` in MCP configuration
   - Update `database.path` in CI configuration

### For Teams

1. **Set up shared infrastructure**:
   ```bash
   # Create shared directory
   sudo mkdir -p /shared/codebase-intelligence
   sudo mkdir -p /shared/codeintel
   
   # Set permissions
   sudo chown -R team:team /shared/codebase-intelligence
   sudo chown -R team:team /shared/codeintel
   ```

2. **Deploy the server**:
   ```bash
   # Clone and build in shared location
   cd /shared/codebase-intelligence
   git clone <repository-url> .
   npm install
   npm run build
   ```

3. **Use team configuration**:
   ```bash
   cp examples/mcp-config-team.json ~/.config/claude-code/.mcp.json
   cp examples/.codeintelligence-strict.json /shared/codebase-intelligence/.codeintelligence.json
   ```

### For Enterprise

1. **Review security settings** in `.codeintelligence-strict.json`
2. **Customize rule sets** by creating custom pattern and rule files
3. **Set up monitoring** and alerting for the web UI endpoints
4. **Configure integrations** for your development tools
5. **Implement backup strategies** for the knowledge database

## Configuration Customization

### Environment Variables

All configurations support environment variable overrides:

```bash
# Override log level
export CODEINTEL_LOGLEVEL=debug

# Override database path  
export CODEINTEL_DATABASE_PATH=/custom/path/index.db

# Override server port
export CODEINTEL_PORT=8080
```

### Custom Pattern Files

For strict/enterprise configurations, create custom pattern files:

```json
// enterprise-auth-patterns.json
{
  "patterns": [
    {
      "name": "enterprise_auth_check",
      "category": "auth",
      "description": "Enterprise authentication pattern",
      "confidence": 0.95,
      "required": true
    }
  ]
}
```

### Custom Security Rules

```json
// security-rules.json
{
  "rules": [
    {
      "id": "no-hardcoded-secrets",
      "severity": "critical",
      "pattern": "/(password|secret|key)\\s*=\\s*['\"][^'\"]+['\"]/i",
      "message": "Hardcoded secrets are not allowed"
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **Server won't start**:
   - Check file paths in MCP configuration
   - Verify Node.js version compatibility
   - Check database directory permissions

2. **Tools not appearing**:
   - Verify MCP configuration is in correct location
   - Check Claude Code logs for connection errors
   - Ensure server process is running

3. **Performance issues**:
   - Reduce `maxConcurrentRequests`
   - Increase `cacheSize` and `maxMemoryUsage`
   - Enable profiling to identify bottlenecks

4. **Database errors**:
   - Check database directory exists and is writable
   - Verify database file isn't corrupted
   - Try deleting database to force recreation

### Debug Mode

Enable debug mode for troubleshooting:

```json
{
  "server": {
    "logLevel": "debug"
  },
  "performance": {
    "enableProfiling": true
  }
}
```

Then check logs at `.codeintel/logs/` for detailed information.

## Configuration Reference

For complete configuration options, see the main documentation or use the JSON schema validation in your IDE with the `$schema` property included in the example files.