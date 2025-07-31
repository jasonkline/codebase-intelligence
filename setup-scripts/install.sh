#!/bin/bash

# Codebase Intelligence MCP Server Installation Script
# This script installs and configures the Codebase Intelligence system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_INSTALL_DIR="$HOME/.codebase-intelligence"
DEFAULT_PROJECT_PATH="$(pwd)"
DEFAULT_MCP_CONFIG="$HOME/.config/claude-code/mcp.json"

print_header() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "   Codebase Intelligence MCP Server Setup"
    echo "=================================================="
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_step "Checking dependencies..."
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 16+ and try again."
        exit 1
    fi
    
    NODE_VERSION=$(node --version | sed 's/v//')
    NODE_MAJOR=$(echo $NODE_VERSION | cut -d. -f1)
    
    if [ "$NODE_MAJOR" -lt 16 ]; then
        print_error "Node.js version $NODE_VERSION is too old. Please install Node.js 16+ and try again."
        exit 1
    fi
    
    print_info "Node.js version $NODE_VERSION ✓"
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed. Please install npm and try again."
        exit 1
    fi
    
    print_info "npm $(npm --version) ✓"
    
    # Check Claude Code
    if ! command -v claude-code &> /dev/null; then
        print_warning "Claude Code CLI not found. Please ensure it's installed and in your PATH."
        print_info "You can install it from: https://docs.anthropic.com/claude-code"
    else
        print_info "Claude Code CLI ✓"
    fi
}

create_directories() {
    print_step "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/data"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "$INSTALL_DIR/projects"
    
    print_info "Created installation directory: $INSTALL_DIR"
}

install_server() {
    print_step "Installing Codebase Intelligence server..."
    
    # Navigate to the source directory
    if [ ! -f "package.json" ] || [ ! -f "src/index.ts" ]; then
        print_error "Please run this script from the codebase-intelligence project root directory."
        exit 1
    fi
    
    # Install dependencies
    print_info "Installing npm dependencies..."
    npm install
    
    # Build the project
    print_info "Building the project..."
    npm run build
    
    # Copy built files to installation directory
    print_info "Copying files to $INSTALL_DIR..."
    cp -r dist/* "$INSTALL_DIR/"
    cp package.json "$INSTALL_DIR/"
    cp -r node_modules "$INSTALL_DIR/"
    
    # Make the binary executable
    chmod +x "$INSTALL_DIR/index.js"
    
    print_info "Server installed successfully"
}

create_config() {
    print_step "Creating configuration..."
    
    # Create project-specific config
    PROJECT_CONFIG="$INSTALL_DIR/config/$(basename "$PROJECT_PATH").json"
    
    cat > "$PROJECT_CONFIG" << EOF
{
  "projectPath": "$PROJECT_PATH",
  "database": {
    "path": "$INSTALL_DIR/data/$(basename "$PROJECT_PATH").db",
    "maxSize": "1GB"
  },
  "patterns": {
    "learningMode": "auto",
    "minConfidence": 0.8,
    "categories": ["auth", "rbac", "api", "data_access", "validation", "error_handling", "ui_components"]
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
    "includeArchitectureDocs": true,
    "generateFlowDiagrams": true
  },
  "governance": {
    "enabled": true,
    "strictMode": false,
    "autoSuggest": true,
    "enforceStyles": true,
    "requireApprovedPatterns": ["auth", "rbac", "data_access"]
  },
  "intelligence": {
    "explainComplexity": true,
    "suggestRefactoring": true,
    "trackTechnicalDebt": true
  },
  "server": {
    "logLevel": "info",
    "enableTelemetry": true
  }
}
EOF
    
    print_info "Created project config: $PROJECT_CONFIG"
    
    # Create MCP configuration
    MCP_CONFIG_DIR="$(dirname "$MCP_CONFIG")"
    mkdir -p "$MCP_CONFIG_DIR"
    
    # Check if MCP config exists
    if [ -f "$MCP_CONFIG" ]; then
        print_warning "MCP config already exists at $MCP_CONFIG"
        print_warning "Backing up existing config..."
        cp "$MCP_CONFIG" "$MCP_CONFIG.backup.$(date +%s)"
    fi
    
    # Create or update MCP config
    cat > "$MCP_CONFIG" << EOF
{
  "mcpServers": {
    "codebase-intelligence": {
      "command": "node",
      "args": [
        "$INSTALL_DIR/index.js"
      ],
      "env": {
        "CI_PROJECT_PATH": "$PROJECT_PATH",
        "CI_CONFIG_PATH": "$PROJECT_CONFIG",
        "CI_LOG_LEVEL": "info",
        "CI_ENABLE_TELEMETRY": "true"
      },
      "description": "Codebase Intelligence for $(basename "$PROJECT_PATH")",
      "disabled": false
    }
  }
}
EOF
    
    print_info "Created MCP config: $MCP_CONFIG"
}

run_initial_analysis() {
    print_step "Running initial project analysis..."
    
    export CI_PROJECT_PATH="$PROJECT_PATH"
    export CI_CONFIG_PATH="$INSTALL_DIR/config/$(basename "$PROJECT_PATH").json"
    export CI_LOG_LEVEL="info"
    
    print_info "Starting server for initial analysis..."
    
    # Run a quick test to ensure everything works
    timeout 30s node "$INSTALL_DIR/index.js" &
    SERVER_PID=$!
    
    sleep 3
    
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_info "Server started successfully"
        kill $SERVER_PID
        wait $SERVER_PID 2>/dev/null || true
    else
        print_error "Server failed to start. Check logs at $INSTALL_DIR/logs/"
        exit 1
    fi
    
    print_info "Initial analysis completed"
}

print_completion() {
    print_step "Installation completed successfully!"
    echo
    print_info "Codebase Intelligence has been installed to: $INSTALL_DIR"
    print_info "Project configuration: $INSTALL_DIR/config/$(basename "$PROJECT_PATH").json"
    print_info "MCP configuration: $MCP_CONFIG"
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Restart Claude Code to load the MCP server"
    echo "2. Try these commands in Claude Code:"
    echo "   - 'Analyze this project for security issues'"
    echo "   - 'How does authentication work in this codebase?'"
    echo "   - 'Check this file for pattern compliance'"
    echo
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo "- Logs are available at: $INSTALL_DIR/logs/"
    echo "- Configuration: $INSTALL_DIR/config/"
    echo "- Run '$0 --test' to test the installation"
    echo
    echo -e "${YELLOW}Documentation:${NC}"
    echo "- Project README: $(pwd)/README.md"
    echo "- Examples: $(pwd)/examples/"
}

run_test() {
    print_step "Testing installation..."
    
    if [ ! -f "$INSTALL_DIR/index.js" ]; then
        print_error "Server not found. Please run the installation first."
        exit 1
    fi
    
    export CI_PROJECT_PATH="$PROJECT_PATH"
    export CI_CONFIG_PATH="$INSTALL_DIR/config/$(basename "$PROJECT_PATH").json"
    export CI_LOG_LEVEL="debug"
    
    print_info "Starting test server..."
    
    # Create a simple test script
    cat > /tmp/ci-test.js << 'EOF'
const { spawn } = require('child_process');

const server = spawn('node', [process.env.INSTALL_DIR + '/index.js'], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: process.env
});

let output = '';
server.stdout.on('data', (data) => {
  output += data.toString();
});

server.stderr.on('data', (data) => {
  console.error('Server error:', data.toString());
});

// Send a ping request
setTimeout(() => {
  const request = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'ping',
      arguments: { message: 'test' }
    }
  };
  
  server.stdin.write(JSON.stringify(request) + '\n');
  
  setTimeout(() => {
    server.kill();
    
    if (output.includes('pong')) {
      console.log('✅ Test passed: Server responded to ping');
      process.exit(0);
    } else {
      console.log('❌ Test failed: No pong response');
      console.log('Output:', output);
      process.exit(1);
    }
  }, 2000);
}, 1000);
EOF
    
    INSTALL_DIR="$INSTALL_DIR" node /tmp/ci-test.js
    rm /tmp/ci-test.js
    
    print_info "Test completed successfully"
}

# Parse command line arguments
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
PROJECT_PATH="$DEFAULT_PROJECT_PATH"
MCP_CONFIG="$DEFAULT_MCP_CONFIG"
RUN_TEST=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --project-path)
            PROJECT_PATH="$2"
            shift 2
            ;;
        --mcp-config)
            MCP_CONFIG="$2"
            shift 2
            ;;
        --test)
            RUN_TEST=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo
            echo "Options:"
            echo "  --install-dir DIR     Installation directory (default: $DEFAULT_INSTALL_DIR)"
            echo "  --project-path DIR    Project to analyze (default: current directory)"
            echo "  --mcp-config FILE     MCP configuration file (default: $DEFAULT_MCP_CONFIG)"
            echo "  --test                Test the installation"
            echo "  --help                Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Convert to absolute paths
INSTALL_DIR="$(realpath "$INSTALL_DIR")"
PROJECT_PATH="$(realpath "$PROJECT_PATH")"
MCP_CONFIG="$(realpath "$MCP_CONFIG")"

# Main execution
print_header

if [ "$RUN_TEST" = true ]; then
    run_test
    exit 0
fi

print_info "Installation directory: $INSTALL_DIR"
print_info "Project path: $PROJECT_PATH"
print_info "MCP config: $MCP_CONFIG"
echo

check_dependencies
create_directories
install_server
create_config
run_initial_analysis
print_completion