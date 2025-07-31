# Codebase Intelligence MCP Server - Production Deployment Guide

## Overview

The Codebase Intelligence MCP Server is a comprehensive system that provides intelligent code analysis, pattern recognition, and security scanning capabilities for Claude Code. This production deployment guide covers everything needed to deploy, configure, and maintain the system at scale.

## Quick Start

### Option 1: Source Installation
```bash
# Clone the repository and run installation script
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence
./setup-scripts/install.sh
```

### Option 2: Docker Deployment
```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Start with Docker Compose
docker-compose up -d
```

### Option 3: Manual Build
```bash
# Clone and build from source
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence
npm install
npm run build

# Run directly
node dist/index.js
```

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│   Your Code     │────▶│    Parser    │────▶│   Index DB  │
│  (TS/JS files)  │     │ (TypeScript  │     │  (SQLite)   │
└─────────────────┘     │  Compiler)   │     └─────────────┘
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
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 10GB free space
- **Node.js**: 16.x or later
- **OS**: Linux, macOS, or Windows

### Recommended Requirements
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 50GB+ SSD
- **Node.js**: 18.x LTS
- **OS**: Linux (Ubuntu 20.04+) or macOS

### Large Codebase Requirements (100k+ files)
- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Storage**: 100GB+ NVMe SSD
- **Database**: SQLite with dedicated storage

## Installation Methods

### 1. Installation Script

The installation script handles all dependencies and configuration automatically:

```bash
# Clone repository first
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Basic installation
./setup-scripts/install.sh

# Custom installation directory
./setup-scripts/install.sh --install-dir /opt/codebase-intelligence

# With custom project path
./setup-scripts/install.sh --project-path /path/to/your/project
```

### 2. Docker Deployment

#### Using Docker Compose (Recommended)

```yaml
# docker-compose.yml
version: '3.8'
services:
  codebase-intelligence:
    image: codebase-intelligence:latest
    environment:
      - CI_PROJECT_PATH=/projects
      - CI_LOG_LEVEL=info
    volumes:
      - ./your-project:/projects:ro
      - codebase-data:/app/data
      - codebase-logs:/app/logs
    restart: unless-stopped

volumes:
  codebase-data:
  codebase-logs:
```

#### Building from Source
```bash
# Build the Docker image
docker build -t codebase-intelligence:latest .

# Run the container
docker run -d \
  --name codebase-intelligence \
  -e CI_PROJECT_PATH=/projects \
  -v $(pwd):/projects:ro \
  -v codebase-data:/app/data \
  codebase-intelligence:latest
```

### 3. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: codebase-intelligence
spec:
  replicas: 1
  selector:
    matchLabels:
      app: codebase-intelligence
  template:
    metadata:
      labels:
        app: codebase-intelligence
    spec:
      containers:
      - name: codebase-intelligence
        image: codebase-intelligence:latest
        env:
        - name: CI_PROJECT_PATH
          value: "/projects"
        - name: CI_DATABASE_PATH
          value: "/app/data/analysis.db"
        volumeMounts:
        - name: project-source
          mountPath: /projects
          readOnly: true
        - name: data-storage
          mountPath: /app/data
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: project-source
        hostPath:
          path: /path/to/your/project
      - name: data-storage
        persistentVolumeClaim:
          claimName: codebase-intelligence-data
```

### 4. Manual Installation

For development or custom deployments:

```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build

# Start the server
npm start
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CI_PROJECT_PATH` | - | **Required**: Path to your project |
| `CI_CONFIG_PATH` | `.codeintelligence.json` | Configuration file path |
| `CI_DATABASE_PATH` | `.codeintel/index.db` | SQLite database path |
| `CI_LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |
| `CI_ENABLE_TELEMETRY` | `true` | Enable usage analytics |
| `CI_TEMP_DIR` | `/tmp/codebase-intelligence` | Temporary files directory |
| `NODE_ENV` | `production` | Node.js environment |

### Configuration File

Create `.codeintelligence.json` in your project root:

```json
{
  "include": ["src/**/*.ts", "src/**/*.tsx", "app/**/*.ts"],
  "exclude": ["node_modules", "dist", "*.test.ts", ".next"],
  "database": {
    "path": ".codeintel/index.db",
    "maxSize": "1GB"
  },
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.85,
    "categories": ["auth", "rbac", "api", "data_access", "validation"]
  },
  "security": {
    "enabled": true,
    "scanOnSave": true,
    "blockCritical": true,
    "warnOnHigh": true,
    "owasp": true
  },
  "knowledge": {
    "autoDocument": true,
    "updateFrequency": "on_change",
    "includeArchitectureDocs": true
  },
  "governance": {
    "enabled": true,
    "strictMode": false,
    "autoSuggest": true,
    "requireApprovedPatterns": ["auth", "rbac", "data_access"]
  },
  "server": {
    "port": 7345,
    "logLevel": "info",
    "enableUI": true,
    "uiPort": 7346
  }
}
```

### Claude Code MCP Configuration

Add to your `~/.config/claude-code/mcp.json`:

```json
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "node",
      "args": ["/path/to/codebase-intelligence/dist/index.js"],
      "env": {
        "CI_PROJECT_PATH": "/path/to/your/project",
        "CI_LOG_LEVEL": "info",
        "CI_ENABLE_TELEMETRY": "true"
      },
      "description": "Intelligent codebase analysis and security scanning",
      "disabled": false
    }
  }
}
```

## Production Optimizations

### Database Optimization

```json
{
  "database": {
    "path": "/var/lib/codebase-intelligence/analysis.db",
    "maxSize": "5GB",
    "connectionPool": {
      "maxConnections": 10,
      "minConnections": 2,
      "acquireTimeout": 10000,
      "idleTimeout": 300000
    },
    "performance": {
      "walMode": true,
      "cacheSize": "100MB",
      "mmapSize": "1GB"
    }
  }
}
```

### Memory Management

```json
{
  "memory": {
    "warningThreshold": 75,
    "criticalThreshold": 85,
    "maxHeapSize": "4GB",
    "gcInterval": 300000
  },
  "cache": {
    "maxSize": "500MB",
    "ttl": 3600000,
    "cleanupInterval": 300000
  }
}
```

### Performance Tuning

```json
{
  "performance": {
    "maxConcurrency": 4,
    "batchSize": 100,
    "analysisTimeout": 300000,
    "enableStreaming": true,
    "compressionLevel": 6
  }
}
```

## Monitoring and Observability

### Health Checks

The server exposes health check endpoints:

```bash
# Basic health check
curl http://localhost:7346/health

# Detailed health status
curl http://localhost:7346/health/detailed

# Metrics endpoint
curl http://localhost:7346/metrics
```

### Logging

Logs are written to both console and files:

```bash
# View live logs
tail -f ~/.codebase-intelligence/logs/combined.log

# View error logs only
tail -f ~/.codebase-intelligence/logs/error.log

# Search logs
grep "ERROR" ~/.codebase-intelligence/logs/combined.log
```

### Telemetry and Analytics

The system can collect anonymous usage data (disabled by default):

```json
{
  "telemetry": {
    "enabled": false,
    "anonymize": true,
    "includeSystemMetrics": false,
    "excludePatterns": ["password", "secret", "token"]
  }
}
```

To disable telemetry:
```bash
export CI_ENABLE_TELEMETRY=false
```

## Security Considerations

### Network Security
- The MCP server uses stdio communication (no network ports exposed by default)
- Optional web UI runs on localhost only
- All data processing happens locally

### Data Privacy
- No source code is transmitted outside your environment
- Telemetry data is anonymized and aggregated
- All analysis data stored locally in SQLite

### File System Security
```bash
# Recommended permissions
chmod 750 ~/.codebase-intelligence/
chmod 640 ~/.codebase-intelligence/data/*.db
chmod 644 ~/.codebase-intelligence/logs/*.log
```

### Access Control
```json
{
  "security": {
    "allowedPaths": ["/path/to/your/projects"],
    "blockedPaths": ["/etc", "/usr", "/var"],
    "maxFileSize": "10MB",
    "allowedExtensions": [".ts", ".tsx", ".js", ".jsx", ".json"]
  }
}
```

## Scaling and High Availability

### Horizontal Scaling
- Run multiple instances for different projects
- Use load balancers for web UI (if enabled)
- Shared read-only project volumes

### Database Scaling
- SQLite handles up to 100k files efficiently
- For larger codebases, consider partitioning by project
- Regular database maintenance with VACUUM

### Resource Management
```json
{
  "resources": {
    "cpu": {
      "maxCores": 4,
      "analysisTimeout": 300000
    },
    "memory": {
      "maxHeap": "4GB",
      "cacheLimit": "1GB"
    },
    "disk": {
      "maxDatabaseSize": "10GB",
      "maxLogSize": "1GB"
    }
  }
}
```

## Backup and Recovery

### Database Backup
```bash
# Create backup
sqlite3 ~/.codebase-intelligence/data/analysis.db ".backup /backup/analysis-$(date +%Y%m%d).db"

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backup/codebase-intelligence"
mkdir -p "$BACKUP_DIR"
sqlite3 ~/.codebase-intelligence/data/analysis.db ".backup $BACKUP_DIR/analysis-$(date +%Y%m%d-%H%M%S).db"
find "$BACKUP_DIR" -name "analysis-*.db" -mtime +7 -delete
```

### Configuration Backup
```bash
# Backup configuration
cp ~/.codebase-intelligence/config/* /backup/config/
cp ~/.config/claude-code/mcp.json /backup/config/
```

### Restore Process
```bash
# Stop the server
pkill -f codebase-intelligence

# Restore database
cp /backup/analysis-20240315.db ~/.codebase-intelligence/data/analysis.db

# Restore configuration
cp /backup/config/* ~/.codebase-intelligence/config/

# Restart server
systemctl start codebase-intelligence
```

## Troubleshooting

### Common Issues

**Server won't start**
```bash
# Check Node.js version
node --version  # Should be 16+

# Check permissions
ls -la ~/.codebase-intelligence/

# Test server directly
node ~/.codebase-intelligence/dist/index.js
```

**High memory usage**
```bash
# Check memory usage
ps aux | grep codebase-intelligence

# Enable memory monitoring
export CI_LOG_LEVEL=debug

# Reduce concurrency
CI_MAX_CONCURRENCY=1 node ~/.codebase-intelligence/dist/index.js
```

**Database issues**
```bash
# Check database integrity
sqlite3 ~/.codebase-intelligence/data/analysis.db "PRAGMA integrity_check;"

# Rebuild database
rm ~/.codebase-intelligence/data/analysis.db
# Restart server to rebuild
```

### Performance Debugging

Enable detailed performance logging:
```bash
export CI_LOG_LEVEL=debug
export CI_ENABLE_PROFILING=true
node --inspect ~/.codebase-intelligence/dist/index.js
```

### Support

- **Documentation**: [docs/](./docs/)
- **Issues**: [GitHub Issues](https://github.com/jasonkline/codebase-intelligence/issues)
- **Project Repository**: [GitHub](https://github.com/jasonkline/codebase-intelligence)

## Upgrading

### Version Compatibility
- v1.x.x: Compatible with Claude Code 1.x
- Database schema migrations handled automatically
- Configuration files backward compatible

### Upgrade Process
```bash
# Backup current installation
cp -r ~/.codebase-intelligence ~/.codebase-intelligence.backup

# Pull latest changes and rebuild
git pull origin main
npm install
npm run build
./setup-scripts/install.sh

# Verify upgrade
~/.codebase-intelligence/dist/index.js --version
```

### Rollback Process
```bash
# Stop current server
pkill -f codebase-intelligence

# Restore backup
rm -rf ~/.codebase-intelligence
mv ~/.codebase-intelligence.backup ~/.codebase-intelligence

# Restart server
```

## License and Support

This software is licensed under the MIT License. See [LICENSE](./LICENSE) for details.

For questions, issues, or contributions, please visit the [project repository](https://github.com/jasonkline/codebase-intelligence).

---

*Last updated: $(date +%Y-%m-%d)*
*Version: 1.0.0*