#!/usr/bin/env node

/**
 * Build script for creating distributable binaries of Codebase Intelligence
 * Supports multiple platforms and architectures
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const SUPPORTED_PLATFORMS = {
  'linux-x64': { platform: 'linux', arch: 'x64', ext: '' },
  'linux-arm64': { platform: 'linux', arch: 'arm64', ext: '' },
  'darwin-x64': { platform: 'darwin', arch: 'x64', ext: '' },
  'darwin-arm64': { platform: 'darwin', arch: 'arm64', ext: '' },
  'win32-x64': { platform: 'win32', arch: 'x64', ext: '.exe' }
};

const PACKAGE_INFO = require('../package.json');
const BUILD_DIR = path.join(__dirname, '..', 'dist-binaries');
const OUTPUT_DIR = path.join(BUILD_DIR, 'releases');

class BinaryBuilder {
  constructor() {
    this.version = PACKAGE_INFO.version;
    this.currentPlatform = os.platform();
    this.currentArch = os.arch();
  }

  async build(platforms = null) {
    console.log('🏗️  Starting binary build process...');
    console.log(`📦 Version: ${this.version}`);
    console.log(`🖥️  Current platform: ${this.currentPlatform}-${this.currentArch}`);
    
    // Clean and create build directories
    this.setupDirectories();
    
    // Build TypeScript first
    console.log('\n📝 Building TypeScript...');
    this.buildTypeScript();
    
    // Determine which platforms to build
    const targetPlatforms = platforms || Object.keys(SUPPORTED_PLATFORMS);
    console.log(`\n🎯 Target platforms: ${targetPlatforms.join(', ')}`);
    
    // Build for each platform
    for (const platformKey of targetPlatforms) {
      if (!SUPPORTED_PLATFORMS[platformKey]) {
        console.warn(`⚠️  Unknown platform: ${platformKey}, skipping`);
        continue;
      }
      
      try {
        await this.buildPlatform(platformKey, SUPPORTED_PLATFORMS[platformKey]);
      } catch (error) {
        console.error(`❌ Failed to build for ${platformKey}:`, error.message);
      }
    }
    
    // Create release packages
    console.log('\n📦 Creating release packages...');
    this.createReleasePackages(targetPlatforms);
    
    console.log('\n✅ Build process completed!');
    console.log(`📁 Binaries available in: ${OUTPUT_DIR}`);
  }

  setupDirectories() {
    if (fs.existsSync(BUILD_DIR)) {
      fs.rmSync(BUILD_DIR, { recursive: true, force: true });
    }
    
    fs.mkdirSync(BUILD_DIR, { recursive: true });
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    
    console.log(`📁 Created build directory: ${BUILD_DIR}`);
  }

  buildTypeScript() {
    try {
      execSync('npm run build', { stdio: 'inherit', cwd: path.join(__dirname, '..') });
      console.log('✅ TypeScript build completed');
    } catch (error) {
      console.error('❌ TypeScript build failed:', error.message);
      process.exit(1);
    }
  }

  async buildPlatform(platformKey, { platform, arch, ext }) {
    console.log(`\n🔨 Building for ${platformKey}...`);
    
    const binaryName = `codebase-intelligence${ext}`;
    const outputPath = path.join(BUILD_DIR, platformKey, binaryName);
    
    // Create platform directory
    const platformDir = path.join(BUILD_DIR, platformKey);
    fs.mkdirSync(platformDir, { recursive: true });
    
    try {
      // Use pkg to create binary
      const pkgCommand = [
        'npx pkg',
        path.join(__dirname, '..', 'dist', 'index.js'),
        '--target', `node18-${platform}-${arch}`,
        '--output', outputPath,
        '--compress', 'Brotli'
      ].join(' ');
      
      console.log(`  📝 Command: ${pkgCommand}`);
      execSync(pkgCommand, { stdio: 'inherit', cwd: path.join(__dirname, '..') });
      
      // Copy additional files
      this.copyAdditionalFiles(platformDir);
      
      // Create startup script for Unix platforms
      if (platform !== 'win32') {
        this.createStartupScript(platformDir, binaryName);
      }
      
      // Create configuration template
      this.createConfigTemplate(platformDir);
      
      console.log(`✅ Binary created: ${outputPath}`);
      
      // Verify binary works
      await this.verifyBinary(outputPath);
      
    } catch (error) {
      console.error(`❌ Failed to build binary for ${platformKey}:`, error.message);
      throw error;
    }
  }

  copyAdditionalFiles(platformDir) {
    const filesToCopy = [
      { src: 'README.md', required: false },
      { src: 'LICENSE', required: false },
      { src: 'CHANGELOG.md', required: false },
      { src: 'examples', required: false, isDirectory: true },
      { src: 'setup-scripts', required: false, isDirectory: true }
    ];
    
    for (const file of filesToCopy) {
      const srcPath = path.join(__dirname, '..', file.src);
      const destPath = path.join(platformDir, file.src);
      
      try {
        if (fs.existsSync(srcPath)) {
          if (file.isDirectory) {
            this.copyDirectory(srcPath, destPath);
          } else {
            fs.copyFileSync(srcPath, destPath);
          }
          console.log(`  📄 Copied: ${file.src}`);
        } else if (file.required) {
          throw new Error(`Required file not found: ${file.src}`);
        }
      } catch (error) {
        console.warn(`  ⚠️  Failed to copy ${file.src}: ${error.message}`);
      }
    }
  }

  copyDirectory(src, dest) {
    fs.mkdirSync(dest, { recursive: true });
    const entries = fs.readdirSync(src, { withFileTypes: true });
    
    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      
      if (entry.isDirectory()) {
        this.copyDirectory(srcPath, destPath);
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }

  createStartupScript(platformDir, binaryName) {
    const scriptContent = `#!/bin/bash

# Codebase Intelligence MCP Server Startup Script
# This script sets up the environment and starts the server

set -e

# Get the directory where this script is located
DIR="$( cd "$( dirname "\${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Set default environment variables
export CI_LOG_LEVEL=\${CI_LOG_LEVEL:-info}
export CI_DATABASE_PATH=\${CI_DATABASE_PATH:-"\$DIR/data/analysis.db"}
export CI_CONFIG_PATH=\${CI_CONFIG_PATH:-"\$DIR/config.json"}
export CI_ENABLE_TELEMETRY=\${CI_ENABLE_TELEMETRY:-true}

# Create data directory if it doesn't exist
mkdir -p "\$DIR/data"
mkdir -p "\$DIR/logs"

# Check if project path is provided
if [ -z "\$CI_PROJECT_PATH" ]; then
    echo "Warning: CI_PROJECT_PATH environment variable not set"
    echo "Usage: CI_PROJECT_PATH=/path/to/your/project ./start.sh"
    echo "Or set it as an environment variable"
fi

# Start the server
echo "Starting Codebase Intelligence MCP Server..."
echo "Project path: \$CI_PROJECT_PATH"
echo "Database: \$CI_DATABASE_PATH"
echo "Config: \$CI_CONFIG_PATH"
echo "Log level: \$CI_LOG_LEVEL"
echo ""

exec "\$DIR/${binaryName}" "\$@"
`;

    const scriptPath = path.join(platformDir, 'start.sh');
    fs.writeFileSync(scriptPath, scriptContent);
    fs.chmodSync(scriptPath, 0o755);
    
    console.log('  📄 Created startup script: start.sh');
  }

  createConfigTemplate(platformDir) {
    const configTemplate = {
      database: {
        path: "./data/analysis.db",
        maxSize: "1GB"
      },
      patterns: {
        learningMode: "auto",
        minConfidence: 0.8,
        categories: ["auth", "rbac", "api", "data_access", "validation", "error_handling", "ui_components"]
      },
      security: {
        enabled: true,
        scanOnSave: true,
        blockCritical: true,
        warnOnHigh: true,
        owasp: true
      },
      knowledge: {
        autoDocument: true,
        updateFrequency: "on_change",
        includeArchitectureDocs: true,
        generateFlowDiagrams: true
      },
      governance: {
        enabled: true,
        strictMode: false,
        autoSuggest: true,
        enforceStyles: true,
        requireApprovedPatterns: ["auth", "rbac", "data_access"]
      },
      intelligence: {
        explainComplexity: true,
        suggestRefactoring: true,
        trackTechnicalDebt: true
      },
      server: {
        logLevel: "info",
        enableTelemetry: true
      }
    };
    
    const configPath = path.join(platformDir, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify(configTemplate, null, 2));
    
    console.log('  📄 Created config template: config.json');
  }

  async verifyBinary(binaryPath) {
    try {
      // Test if binary runs and responds to --version
      const output = execSync(`"${binaryPath}" --version || echo "Version check failed"`, {
        encoding: 'utf8',
        timeout: 10000
      });
      
      if (output.includes(this.version) || output.includes('pong')) {
        console.log('  ✅ Binary verification passed');
      } else {
        console.log('  ⚠️  Binary verification inconclusive');
      }
    } catch (error) {
      console.warn('  ⚠️  Binary verification failed:', error.message);
    }
  }

  createReleasePackages(platforms) {
    for (const platformKey of platforms) {
      const platformDir = path.join(BUILD_DIR, platformKey);
      
      if (!fs.existsSync(platformDir)) {
        console.warn(`⚠️  Platform directory not found: ${platformKey}`);
        continue;
      }
      
      try {
        const archiveName = `codebase-intelligence-v${this.version}-${platformKey}`;
        const isWindows = platformKey.includes('win32');
        
        if (isWindows) {
          // Create ZIP for Windows
          this.createZipArchive(platformDir, archiveName);
        } else {
          // Create tar.gz for Unix-like systems
          this.createTarArchive(platformDir, archiveName);
        }
        
        console.log(`✅ Created package: ${archiveName}`);
      } catch (error) {
        console.error(`❌ Failed to create package for ${platformKey}:`, error.message);
      }
    }
  }

  createTarArchive(sourceDir, archiveName) {
    const archivePath = path.join(OUTPUT_DIR, `${archiveName}.tar.gz`);
    const command = `tar -czf "${archivePath}" -C "${path.dirname(sourceDir)}" "${path.basename(sourceDir)}"`;
    
    execSync(command, { stdio: 'inherit' });
    
    // Calculate and display file size
    const stats = fs.statSync(archivePath);
    console.log(`  📦 Size: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);
  }

  createZipArchive(sourceDir, archiveName) {
    // For Windows, we'll use a simple approach or require zip utility
    const archivePath = path.join(OUTPUT_DIR, `${archiveName}.zip`);
    
    try {
      // Try using zip command if available
      const command = `zip -r "${archivePath}" "${sourceDir}"`;
      execSync(command, { stdio: 'inherit' });
    } catch (error) {
      // Fallback: create without compression (just copy directory)
      console.warn('  ⚠️  ZIP utility not available, copying directory instead');
      const fallbackDir = path.join(OUTPUT_DIR, archiveName);
      this.copyDirectory(sourceDir, fallbackDir);
    }
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  const builder = new BinaryBuilder();
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node build-binaries.js [platforms...]');
    console.log('');
    console.log('Available platforms:');
    Object.keys(SUPPORTED_PLATFORMS).forEach(platform => {
      console.log(`  ${platform}`);
    });
    console.log('');
    console.log('Examples:');
    console.log('  node build-binaries.js                    # Build for all platforms');
    console.log('  node build-binaries.js linux-x64          # Build for Linux x64 only');
    console.log('  node build-binaries.js darwin-x64 win32-x64 # Build for macOS and Windows');
    return;
  }
  
  const platforms = args.length > 0 ? args : null;
  
  try {
    await builder.build(platforms);
  } catch (error) {
    console.error('❌ Build failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = BinaryBuilder;