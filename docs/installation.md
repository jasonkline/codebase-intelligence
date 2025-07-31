# Installation Guide

This guide covers all available methods to install and set up the Codebase Intelligence MCP Server.

## System Requirements

### Minimum Requirements
- **Operating System**: Linux, macOS, or Windows
- **Node.js**: Version 16.x or later
- **Memory**: 4GB RAM
- **Storage**: 10GB free space
- **CPU**: 2 cores

### Recommended Requirements
- **Operating System**: Linux (Ubuntu 20.04+) or macOS
- **Node.js**: Version 18.x LTS
- **Memory**: 8GB+ RAM
- **Storage**: 50GB+ SSD storage
- **CPU**: 4+ cores

### Large Codebase Requirements (100k+ files)
- **Memory**: 16GB+ RAM
- **Storage**: 100GB+ NVMe SSD
- **CPU**: 8+ cores
- **Database**: Dedicated storage for SQLite

## Installation Methods

### Method 1: Source Installation (Recommended)

The recommended way to install Codebase Intelligence:

```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build

# Run the installation script
./setup-scripts/install.sh
```

**Custom installation options:**
```bash
# Install to custom directory
./setup-scripts/install.sh --install-dir /opt/codebase-intelligence

# Specify project path during installation
./setup-scripts/install.sh --project-path /path/to/your/project

# Custom MCP configuration location
./setup-scripts/install.sh --mcp-config ~/.config/custom-mcp.json
```

### Method 2: Manual Build from Source

For custom builds or development:

#### All Platforms
```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build

# Set up environment and run
export CI_PROJECT_PATH=/path/to/your/project
node dist/index.js
```

#### Create a Standalone Installation
```bash
# After building, copy to installation directory
sudo mkdir -p /opt/codebase-intelligence
sudo cp -r dist/* /opt/codebase-intelligence/
sudo cp package.json /opt/codebase-intelligence/
sudo cp -r node_modules /opt/codebase-intelligence/

# Create startup script
sudo cat > /opt/codebase-intelligence/start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
node index.js "$@"
EOF
sudo chmod +x /opt/codebase-intelligence/start.sh

# Link to system path
sudo ln -sf /opt/codebase-intelligence/start.sh /usr/local/bin/codebase-intelligence
```

### Method 3: Docker Installation

#### Using Docker Compose (Recommended)
```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Configure your project path
echo "CI_PROJECT_PATH=/path/to/your/project" > .env

# Start the services
docker-compose up -d

# View logs
docker-compose logs -f
```

#### Using Docker directly
```bash
# Pull the latest image
docker pull codebase-intelligence:latest

# Run the container
docker run -d \
  --name codebase-intelligence \
  -e CI_PROJECT_PATH=/projects \
  -v /path/to/your/project:/projects:ro \
  -v codebase-data:/app/data \
  codebase-intelligence:latest

# Check status
docker ps
docker logs codebase-intelligence
```

### Method 4: Development Setup

For development or contributing:

```bash
# Clone the repository
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence

# Install dependencies
npm install

# Build the project
npm run build

# Start in development mode
npm run dev

# Or start the built server
npm start
```

### Method 5: Alternative Installation

#### Direct Node.js Execution
```bash
# Clone and run directly
git clone https://github.com/jasonkline/codebase-intelligence.git
cd codebase-intelligence
npm install
npm run build

# Run directly with Node.js
node dist/index.js --project /path/to/your/project
```

#### Create a Global Command
```bash
# After building the project
echo '#!/bin/bash' > codebase-intelligence
echo "cd $(pwd) && node dist/index.js \"\$@\"" >> codebase-intelligence
chmod +x codebase-intelligence
sudo mv codebase-intelligence /usr/local/bin/

# Now you can run from anywhere
codebase-intelligence --project /path/to/your/project
```

## Post-Installation Setup

### 1. Configure Claude Code Integration

Add Codebase Intelligence to your Claude Code MCP configuration:

```bash
# Edit MCP configuration
mkdir -p ~/.config/claude-code
cat > ~/.config/claude-code/mcp.json << 'EOF'
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "codebase-intelligence",
      "args": ["--stdio"],
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
EOF
```

### 2. Project Configuration

Create a configuration file in your project:

```bash
cd /path/to/your/project
cat > .codeintelligence.json << 'EOF'
{
  "include": ["src/**/*.ts", "src/**/*.tsx", "app/**/*.ts"],
  "exclude": ["node_modules", "dist", "*.test.ts", ".next"],
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.8,
    "categories": ["auth", "rbac", "api", "data_access"]
  },
  "security": {
    "enabled": true,
    "scanOnSave": true,
    "blockCritical": true,
    "owasp": true
  },
  "knowledge": {
    "autoDocument": true,
    "updateFrequency": "on_change"
  }
}
EOF
```

### 3. Initial Analysis

Run your first analysis:

```bash
# Set project path
export CI_PROJECT_PATH=/path/to/your/project

# Run initial analysis
codebase-intelligence analyze

# Or test connectivity
codebase-intelligence ping
```

### 4. Verification

Verify the installation is working:

```bash
# Check version
codebase-intelligence --version

# Test MCP connectivity
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | codebase-intelligence --stdio

# Check system health
codebase-intelligence health
```

## Environment Variables

Configure the system using environment variables:

```bash
# Required
export CI_PROJECT_PATH="/path/to/your/project"

# Optional
export CI_CONFIG_PATH=".codeintelligence.json"
export CI_DATABASE_PATH=".codeintel/analysis.db"
export CI_LOG_LEVEL="info"  # debug, info, warn, error
export CI_ENABLE_TELEMETRY="true"
export CI_TEMP_DIR="/tmp/codebase-intelligence"

# Performance
export CI_MAX_CONCURRENCY="4"
export CI_MEMORY_LIMIT="4GB"
export CI_ANALYSIS_TIMEOUT="300000"  # 5 minutes

# Security
export CI_ENABLE_SECURITY_SCAN="true"
export CI_SECURITY_STRICT_MODE="false"
export CI_BLOCK_CRITICAL_ISSUES="true"
```

## Service Setup

### systemd (Linux)

Create a system service:

```bash
sudo cat > /etc/systemd/system/codebase-intelligence.service << 'EOF'
[Unit]
Description=Codebase Intelligence MCP Server
After=network.target

[Service]
Type=simple
User=codebase-intelligence
Group=codebase-intelligence
Environment=CI_PROJECT_PATH=/var/projects/main
Environment=CI_LOG_LEVEL=info
ExecStart=/usr/local/bin/codebase-intelligence --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable codebase-intelligence
sudo systemctl start codebase-intelligence
```

### launchd (macOS)

Create a launch daemon:

```bash
cat > ~/Library/LaunchAgents/com.codebase-intelligence.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.codebase-intelligence</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/codebase-intelligence</string>
        <string>--daemon</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CI_PROJECT_PATH</key>
        <string>/Users/username/projects/main</string>
        <key>CI_LOG_LEVEL</key>
        <string>info</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load the service
launchctl load ~/Library/LaunchAgents/com.codebase-intelligence.plist
```

## Troubleshooting Installation

### Common Issues

**Node.js version too old**
```bash
# Check version
node --version

# Update Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Permission errors**
```bash
# Fix ownership
sudo chown -R $(whoami) ~/.codebase-intelligence

# Fix permissions
chmod +x ~/.codebase-intelligence/bin/codebase-intelligence
```

**Missing dependencies**
```bash
# Linux
sudo apt-get install sqlite3 build-essential python3

# macOS
brew install sqlite3
xcode-select --install
```

**Port conflicts**
```bash
# Check what's using the port
sudo lsof -i :7345

# Use different port
export CI_SERVER_PORT=7347
```

### Verification Steps

1. **Check installation**:
   ```bash
   which codebase-intelligence
   codebase-intelligence --version
   ```

2. **Test basic functionality**:
   ```bash
   codebase-intelligence ping
   ```

3. **Check MCP integration**:
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | codebase-intelligence --stdio
   ```

4. **Verify project analysis**:
   ```bash
   codebase-intelligence analyze --dry-run
   ```

### Getting Help

If you encounter issues:

1. **Check logs**:
   ```bash
   tail -f ~/.codebase-intelligence/logs/error.log
   ```

2. **Run diagnostics**:
   ```bash
   codebase-intelligence diagnose
   ```

3. **Community support**:
   - [GitHub Issues](https://github.com/jasonkline/codebase-intelligence/issues)
   - [Project Repository](https://github.com/jasonkline/codebase-intelligence)

## Next Steps

After successful installation:

1. **[Configure your project](./configuration.md)** - Set up project-specific settings
2. **[Run your first analysis](./quickstart.md)** - Analyze your codebase
3. **[Explore MCP tools](./mcp-tools/README.md)** - Learn about available features
4. **[Set up monitoring](./deployment/monitoring.md)** - Monitor system health

---

*Need help? Check our [troubleshooting guide](./troubleshooting.md) or [create an issue](https://github.com/jasonkline/codebase-intelligence/issues).*