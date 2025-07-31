# Configuration Reference

This document provides a complete reference for configuring the Codebase Intelligence MCP Server.

## Configuration Files

### Project Configuration (`.codeintelligence.json`)

Place this file in your project root to configure project-specific settings:

```json
{
  "version": "1.0",
  "project": {
    "name": "My Project",
    "description": "Project description for documentation",
    "language": "typescript",
    "framework": "nextjs"
  },
  "analysis": {
    "include": [
      "src/**/*.ts",
      "src/**/*.tsx",
      "app/**/*.ts",
      "app/**/*.tsx",
      "lib/**/*.ts"
    ],
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
    "timeout": 30000,
    "parallel": true,
    "maxConcurrency": 4
  },
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.8,
    "maxPatterns": 1000,
    "categories": [
      "auth",
      "rbac", 
      "api",
      "data_access",
      "validation",
      "error_handling"
    ],
    "customPatterns": [
      {
        "name": "requireAuthWithTenant",
        "category": "auth",
        "description": "Authentication middleware pattern",
        "pattern": "requireAuthWithTenant()",
        "required": true
      }
    ]
  },
  "security": {
    "enabled": true,
    "scanOnSave": true,
    "blockCritical": true,
    "categories": {
      "owasp": true,
      "authentication": true,
      "authorization": true,
      "injection": true,
      "crypto": true,
      "secrets": true
    },
    "customRules": [
      {
        "id": "no-direct-db-access",
        "name": "No Direct Database Access",
        "severity": "critical",
        "description": "Database access must go through authenticated connections",
        "pattern": "getOrgDatabase\\(\\)",
        "message": "Use getOrgDatabaseWithAuth() instead of getOrgDatabase()",
        "replacement": "getOrgDatabaseWithAuth()"
      }
    ],
    "whitelist": [
      "test/**/*.ts",
      "scripts/**/*.ts"
    ]
  },
  "knowledge": {
    "autoDocument": true,
    "updateFrequency": "on_change",
    "includeComments": true,
    "includeTypes": true,
    "generateFlowCharts": true,
    "maxDocumentationSize": "10MB"
  },
  "realtime": {
    "enabled": true,
    "watchMode": true,
    "debounceMs": 300,
    "validationDelay": 100,
    "suggestionDelay": 500,
    "features": {
      "validation": true,
      "suggestions": true,
      "errorPrevention": true,
      "quickFix": true
    }
  },
  "database": {
    "path": ".codeintel/analysis.db",
    "memoryLimit": "1GB",
    "cacheSize": "256MB",
    "backup": {
      "enabled": true,
      "frequency": "daily",
      "retention": 7
    }
  },
  "telemetry": {
    "enabled": true,
    "anonymizeData": true,
    "includePerformance": true,
    "includeErrors": true,
    "includeUsage": false,
    "endpoint": "https://telemetry.codebase-intelligence.com/v1/events"
  }
}
```

### MCP Server Configuration

Add to your Claude Code MCP configuration (`~/.config/claude-code/mcp.json`):

```json
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "codebase-intelligence",
      "args": ["--stdio"],
      "env": {
        "CI_PROJECT_PATH": "/path/to/your/project",
        "CI_CONFIG_PATH": ".codeintelligence.json",
        "CI_LOG_LEVEL": "info",
        "CI_ENABLE_TELEMETRY": "true",
        "CI_DATABASE_PATH": ".codeintel/analysis.db",
        "CI_TEMP_DIR": "/tmp/codebase-intelligence",
        "CI_MAX_CONCURRENCY": "4",
        "CI_MEMORY_LIMIT": "4GB",
        "CI_ANALYSIS_TIMEOUT": "300000"
      },
      "description": "Intelligent codebase analysis and security scanning",
      "disabled": false,
      "timeout": 60000,
      "heartbeat": 30000
    }
  }
}
```

## Environment Variables

### Required Variables

```bash
# Project path (required)
export CI_PROJECT_PATH="/path/to/your/project"
```

### Core Configuration

```bash
# Configuration file location
export CI_CONFIG_PATH=".codeintelligence.json"

# Database configuration
export CI_DATABASE_PATH=".codeintel/analysis.db"
export CI_DATABASE_MEMORY_LIMIT="1GB"
export CI_DATABASE_CACHE_SIZE="256MB"

# Logging configuration
export CI_LOG_LEVEL="info"  # debug, info, warn, error
export CI_LOG_FILE="logs/codebase-intelligence.log"
export CI_LOG_MAX_SIZE="100MB"
export CI_LOG_MAX_FILES="5"

# Temporary directory
export CI_TEMP_DIR="/tmp/codebase-intelligence"
```

### Performance Configuration

```bash
# Analysis performance
export CI_MAX_CONCURRENCY="4"
export CI_MEMORY_LIMIT="4GB"
export CI_ANALYSIS_TIMEOUT="300000"  # 5 minutes in ms
export CI_FILE_SIZE_LIMIT="10MB"

# Real-time features
export CI_WATCH_DEBOUNCE="300"  # ms
export CI_VALIDATION_DELAY="100"  # ms
export CI_SUGGESTION_DELAY="500"  # ms

# Caching
export CI_CACHE_ENABLED="true"
export CI_CACHE_SIZE="256MB"
export CI_CACHE_TTL="3600"  # 1 hour in seconds
```

### Security Configuration

```bash
# Security scanning
export CI_ENABLE_SECURITY_SCAN="true"
export CI_SECURITY_STRICT_MODE="false"
export CI_BLOCK_CRITICAL_ISSUES="true"
export CI_SECURITY_TIMEOUT="60000"  # 1 minute

# Pattern enforcement
export CI_PATTERN_LEARNING="auto"  # auto, manual, disabled
export CI_PATTERN_MIN_CONFIDENCE="0.8"
export CI_GOVERNANCE_STRICT="false"
```

### Telemetry Configuration

```bash
# Telemetry settings
export CI_ENABLE_TELEMETRY="true"
export CI_TELEMETRY_ANONYMIZE="true"
export CI_TELEMETRY_ENDPOINT="https://telemetry.codebase-intelligence.com/v1/events"
export CI_TELEMETRY_BATCH_SIZE="100"
export CI_TELEMETRY_FLUSH_INTERVAL="30000"  # 30 seconds
```

### Development Configuration

```bash
# Development mode
export CI_DEV_MODE="false"
export CI_DEBUG_AST="false"
export CI_DEBUG_PATTERNS="false"
export CI_DEBUG_SECURITY="false"
export CI_PROFILER_ENABLED="false"
```

## Advanced Configuration

### Custom Analyzers

```json
{
  "analyzers": [
    {
      "name": "custom-auth-analyzer",
      "path": "./analyzers/auth-analyzer.js",
      "enabled": true,
      "priority": 10,
      "config": {
        "strictMode": true,
        "requiredMethods": ["requireAuthWithTenant"]
      }
    }
  ]
}
```

### Custom Security Rules

```json
{
  "security": {
    "customRules": [
      {
        "id": "no-hardcoded-secrets",
        "name": "No Hardcoded Secrets",
        "severity": "critical",
        "description": "Detect hardcoded API keys and secrets",
        "patterns": [
          "api[_-]?key[\\s]*=[\\s]*['\"][a-zA-Z0-9]{20,}['\"]",
          "secret[_-]?key[\\s]*=[\\s]*['\"][a-zA-Z0-9]{20,}['\"]",
          "password[\\s]*=[\\s]*['\"][^'\"]{8,}['\"]"
        ],
        "message": "Hardcoded secrets detected. Use environment variables instead.",
        "remediation": "Move secrets to environment variables or secure key management."
      }
    ]
  }
}
```

### Pattern Definitions

```json
{
  "patterns": {
    "definitions": [
      {
        "name": "authenticated-api-route",
        "category": "api",
        "description": "Standard authenticated API route pattern",
        "structure": {
          "requires": [
            "requireAuthWithTenant",
            "getOrgDatabaseWithAuth"
          ],
          "sequence": [
            "auth_middleware",
            "permission_check",
            "database_access",
            "response"
          ]
        },
        "governance": {
          "required": true,
          "exceptions": ["test/**/*"],
          "autoFix": true
        }
      }
    ]
  }
}
```

### Knowledge System Configuration

```json
{
  "knowledge": {
    "sources": [
      {
        "type": "comments",
        "weight": 0.8
      },
      {
        "type": "type_definitions",
        "weight": 0.9
      },
      {
        "type": "function_signatures",
        "weight": 0.7
      },
      {
        "type": "test_descriptions",
        "weight": 0.6
      }
    ],
    "nlp": {
      "enabled": true,
      "confidence_threshold": 0.7,
      "max_response_length": 1000
    },
    "documentation": {
      "auto_generate": true,
      "formats": ["markdown", "html"],
      "include_diagrams": true,
      "update_on_change": true
    }
  }
}
```

## Configuration Validation

### Validation Schema

The system validates your configuration against a JSON schema. Common validation errors:

1. **Invalid file patterns**: Ensure glob patterns are valid
2. **Performance limits**: Memory and concurrency limits must be reasonable
3. **Pattern syntax**: Custom patterns must use valid regex
4. **Security rules**: Security rule patterns must compile

### Configuration Testing

Test your configuration:

```bash
# Validate configuration file
codebase-intelligence config validate

# Test with dry run
codebase-intelligence analyze --dry-run --config .codeintelligence.json

# Check environment variables
codebase-intelligence config env

# Verify MCP integration
codebase-intelligence config mcp
```

## Configuration Examples

### Small Project Configuration

```json
{
  "version": "1.0",
  "analysis": {
    "include": ["src/**/*.ts"],
    "exclude": ["node_modules/**", "**/*.test.ts"],
    "parallel": false,
    "maxConcurrency": 2
  },
  "patterns": {
    "learningMode": "manual",
    "minConfidence": 0.9,
    "categories": ["auth", "api"]
  },
  "security": {
    "enabled": true,
    "scanOnSave": false,
    "blockCritical": false
  },
  "realtime": {
    "enabled": false
  }
}
```

### Large Enterprise Configuration

```json
{
  "version": "1.0",
  "analysis": {
    "include": [
      "apps/**/*.ts",
      "libs/**/*.ts", 
      "services/**/*.ts"
    ],
    "exclude": [
      "node_modules/**",
      "dist/**",
      "**/*.test.ts",
      "**/*.spec.ts"
    ],
    "parallel": true,
    "maxConcurrency": 8,
    "timeout": 600000
  },
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.85,
    "maxPatterns": 5000,
    "categories": [
      "auth", "rbac", "api", "data_access",
      "validation", "error_handling", "logging",
      "monitoring", "performance"
    ]
  },
  "security": {
    "enabled": true,
    "scanOnSave": true,
    "blockCritical": true,
    "categories": {
      "owasp": true,
      "authentication": true,
      "authorization": true,
      "injection": true,
      "crypto": true,
      "secrets": true,
      "dependencies": true
    }
  },
  "knowledge": {
    "autoDocument": true,
    "updateFrequency": "on_change",
    "generateFlowCharts": true,
    "includeMetrics": true
  },
  "realtime": {
    "enabled": true,
    "watchMode": true,
    "debounceMs": 200,
    "features": {
      "validation": true,
      "suggestions": true,
      "errorPrevention": true,
      "quickFix": true,
      "performanceHints": true
    }
  },
  "database": {
    "memoryLimit": "4GB",
    "cacheSize": "1GB",
    "backup": {
      "enabled": true,
      "frequency": "hourly",
      "retention": 24
    }
  },
  "telemetry": {
    "enabled": true,
    "anonymizeData": true,
    "includePerformance": true,
    "includeErrors": true,
    "includeUsage": true
  }
}
```

## Configuration Migration

### Version Updates

When updating configuration versions:

```bash
# Check current version
codebase-intelligence config version

# Migrate configuration
codebase-intelligence config migrate --from 0.9 --to 1.0

# Backup before migration
codebase-intelligence config backup
```

### Breaking Changes

#### v0.9 to v1.0
- `patterns.rules` renamed to `patterns.customPatterns`
- `security.owasp` moved to `security.categories.owasp`
- `analysis.watchMode` moved to `realtime.watchMode`

## Troubleshooting Configuration

### Common Issues

1. **Configuration not found**:
   ```bash
   # Check file exists and is readable
   ls -la .codeintelligence.json
   ```

2. **Invalid JSON syntax**:
   ```bash
   # Validate JSON syntax
   cat .codeintelligence.json | jq .
   ```

3. **Environment variables not set**:
   ```bash
   # Check required variables
   echo $CI_PROJECT_PATH
   ```

4. **Permission issues**:
   ```bash
   # Fix file permissions
   chmod 644 .codeintelligence.json
   ```

### Debug Configuration

Enable configuration debugging:

```bash
export CI_DEBUG_CONFIG="true"
export CI_LOG_LEVEL="debug"
codebase-intelligence analyze
```

---

*For more configuration examples, see our [GitHub repository](https://github.com/your-org/codebase-intelligence/tree/main/examples/configurations).*