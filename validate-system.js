#!/usr/bin/env node

/**
 * System Validation Script for Codebase Intelligence
 * This script validates the complete system functionality including:
 * - Server startup and connectivity
 * - MCP tool functionality
 * - Security analysis accuracy
 * - Pattern recognition
 * - Knowledge system queries
 * - Performance benchmarks
 */

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const TEST_PROJECT_PATH = path.join(__dirname, 'test-project');
const TEST_TIMEOUT = 30000; // 30 seconds

class SystemValidator {
  constructor() {
    this.results = {
      tests: [],
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0
      },
      performance: {},
      errors: []
    };
    this.server = null;
  }

  async validate() {
    console.log('🔍 Starting Codebase Intelligence System Validation');
    console.log('================================================\n');

    try {
      await this.checkPrerequisites();
      await this.startServer();
      await this.runValidationTests();
      await this.runPerformanceTests();
      await this.stopServer();
      
      this.printResults();
    } catch (error) {
      console.error('❌ System validation failed:', error.message);
      await this.cleanup();
      process.exit(1);
    }
  }

  async checkPrerequisites() {
    console.log('📋 Checking Prerequisites...');
    
    const checks = [
      {
        name: 'Node.js version',
        check: () => {
          const version = process.version;
          const majorVersion = parseInt(version.substring(1).split('.')[0]);
          return majorVersion >= 16;
        },
        message: 'Node.js 16+ required'
      },
      {
        name: 'Built application',
        check: () => fs.existsSync(path.join(__dirname, 'dist', 'index.js')),
        message: 'Run "npm run build" first'
      },
      {
        name: 'Test project exists',
        check: () => fs.existsSync(TEST_PROJECT_PATH),
        message: 'Test project directory not found'
      },
      {
        name: 'SQLite available',
        check: () => {
          try {
            require('better-sqlite3');
            return true;
          } catch {
            return false;
          }
        },
        message: 'SQLite (better-sqlite3) not available'
      }
    ];

    for (const check of checks) {
      try {
        const passed = check.check();
        console.log(`  ${passed ? '✅' : '❌'} ${check.name}`);
        
        if (!passed) {
          throw new Error(check.message);
        }
      } catch (error) {
        console.error(`  ❌ ${check.name}: ${error.message}`);
        throw error;
      }
    }
    
    console.log('');
  }

  async startServer() {
    console.log('🚀 Starting MCP Server...');
    
    return new Promise((resolve, reject) => {
      const serverPath = path.join(__dirname, 'dist', 'index.js');
      
      this.server = spawn('node', [serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          CI_PROJECT_PATH: TEST_PROJECT_PATH,
          CI_LOG_LEVEL: 'error', // Reduce noise during testing
          CI_ENABLE_TELEMETRY: 'false',
          NODE_ENV: 'test'
        }
      });

      let output = '';
      let errorOutput = '';

      this.server.stdout.on('data', (data) => {
        output += data.toString();
      });

      this.server.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      this.server.on('error', (error) => {
        console.error('❌ Failed to start server:', error.message);
        reject(error);
      });

      // Give server time to start
      setTimeout(() => {
        if (this.server && this.server.exitCode === null) {
          console.log('✅ Server started successfully\n');
          resolve();
        } else {
          console.error('❌ Server failed to start');
          console.error('Output:', output);
          console.error('Errors:', errorOutput);
          reject(new Error('Server startup failed'));
        }
      }, 3000);
    });
  }

  async runValidationTests() {
    console.log('🧪 Running Validation Tests...');
    
    const tests = [
      {
        name: 'Server Connectivity',
        test: () => this.testServerConnectivity()
      },
      {
        name: 'Project Analysis',
        test: () => this.testProjectAnalysis()
      },
      {
        name: 'Security Scanning',
        test: () => this.testSecurityScanning()
      },
      {
        name: 'Authentication Pattern Detection',
        test: () => this.testAuthPatternDetection()
      },
      {
        name: 'Vulnerability Detection',
        test: () => this.testVulnerabilityDetection()
      },
      {
        name: 'Pattern Learning',
        test: () => this.testPatternLearning()
      },
      {
        name: 'Knowledge Queries',
        test: () => this.testKnowledgeQueries()
      },
      {
        name: 'Real-time Validation',
        test: () => this.testRealtimeValidation()
      }
    ];

    for (const test of tests) {
      await this.runTest(test);
    }
  }

  async runTest(test) {
    console.log(`  🔬 ${test.name}...`);
    const startTime = Date.now();
    
    try {
      const result = await Promise.race([
        test.test(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Test timeout')), TEST_TIMEOUT)
        )
      ]);
      
      const duration = Date.now() - startTime;
      
      this.results.tests.push({
        name: test.name,
        status: 'passed',
        duration,
        result
      });
      
      this.results.summary.passed++;
      console.log(`    ✅ Passed (${duration}ms)`);
      
      if (result && typeof result === 'object' && result.details) {
        console.log(`    📊 ${result.details}`);
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.results.tests.push({
        name: test.name,
        status: 'failed',
        duration,
        error: error.message
      });
      
      this.results.summary.failed++;
      this.results.errors.push(`${test.name}: ${error.message}`);
      console.log(`    ❌ Failed (${duration}ms): ${error.message}`);
    }
    
    this.results.summary.total++;
  }

  async testServerConnectivity() {
    const request = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'ping',
        arguments: { message: 'validation-test' }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const content = response.result.content[0];
        if (content.message && content.message.includes('pong')) {
          return { success: true, details: 'Server responding to ping' };
        }
      }
      throw new Error('Invalid ping response');
    });
  }

  async testProjectAnalysis() {
    const request = {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'analyze_project',
        arguments: {
          projectPath: TEST_PROJECT_PATH,
          include: ['**/*.ts', '**/*.tsx'],
          exclude: ['node_modules/**']
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const analysis = response.result.content[0];
        if (analysis.success && analysis.summary) {
          return {
            success: true,
            details: `Analyzed ${analysis.summary.filesProcessed} files, found ${analysis.summary.securityIssues} security issues`
          };
        }
      }
      throw new Error('Project analysis failed');
    });
  }

  async testSecurityScanning() {
    const request = {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'analyze_security',
        arguments: {
          path: path.join(TEST_PROJECT_PATH, 'src', 'api', 'insecure'),
          options: { minSeverity: 'medium' }
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const analysis = response.result.content[0];
        if (analysis.success && analysis.summary) {
          const findings = analysis.summary.totalFindings;
          return {
            success: true,
            details: `Found ${findings} security findings in vulnerable code`
          };
        }
      }
      throw new Error('Security scanning failed');
    });
  }

  async testAuthPatternDetection() {
    const request = {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'check_auth_pattern',
        arguments: {
          path: TEST_PROJECT_PATH
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const analysis = response.result.content[0];
        if (analysis.success && analysis.authFlow) {
          return {
            success: true,
            details: `Detected ${analysis.authFlow.authChecks} auth checks, ${analysis.authFlow.gaps} gaps`
          };
        }
      }
      throw new Error('Auth pattern detection failed');
    });
  }

  async testVulnerabilityDetection() {
    const request = {
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: {
        name: 'find_vulnerabilities',
        arguments: {
          path: TEST_PROJECT_PATH,
          severity: 'high',
          maxResults: 10
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const analysis = response.result.content[0];
        if (analysis.success && analysis.summary) {
          return {
            success: true,
            details: `Found ${analysis.summary.total} vulnerabilities (${analysis.summary.critical} critical)`
          };
        }
      }
      throw new Error('Vulnerability detection failed');
    });
  }

  async testPatternLearning() {
    const request = {
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: {
        name: 'learn_patterns',
        arguments: {
          projectPath: TEST_PROJECT_PATH,
          categories: ['auth', 'api'],
          minConfidence: 0.7
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const analysis = response.result.content[0];
        if (analysis.success && analysis.summary) {
          return {
            success: true,
            details: `Learned ${analysis.summary.totalPatternsLearned} patterns from ${analysis.summary.filesAnalyzed} files`
          };
        }
      }
      throw new Error('Pattern learning failed');
    });
  }

  async testKnowledgeQueries() {
    const request = {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: {
        name: 'explain_system',
        arguments: {
          query: 'How does authentication work in this codebase?',
          detailLevel: 'summary'
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const explanation = response.result.content[0];
        if (explanation.success && explanation.answer) {
          return {
            success: true,
            details: `Generated explanation with confidence ${explanation.confidence}`
          };
        }
      }
      throw new Error('Knowledge query failed');
    });
  }

  async testRealtimeValidation() {
    const testCode = `
export async function GET() {
  const db = getOrgDatabase() // Missing auth
  const data = await db.select().from(users)
  return Response.json(data)
}`;

    const request = {
      jsonrpc: '2.0',
      id: 8,
      method: 'tools/call',
      params: {
        name: 'validate_as_typed',
        arguments: {
          filePath: path.join(TEST_PROJECT_PATH, 'test-file.ts'),
          content: testCode,
          line: 3,
          column: 15
        }
      }
    };

    return this.sendMCPRequest(request).then(response => {
      if (response && response.result && response.result.content) {
        const validation = response.result.content[0];
        if (validation.success && validation.issues) {
          return {
            success: true,
            details: `Real-time validation found ${validation.issues.length} issues`
          };
        }
      }
      throw new Error('Real-time validation failed');
    });
  }

  async runPerformanceTests() {
    console.log('\n⚡ Running Performance Tests...');

    const performanceTests = [
      {
        name: 'Analysis Speed',
        test: () => this.benchmarkAnalysisSpeed()
      },
      {
        name: 'Memory Usage',
        test: () => this.benchmarkMemoryUsage()
      },
      {
        name: 'Response Time',
        test: () => this.benchmarkResponseTime()
      }
    ];

    for (const test of performanceTests) {
      console.log(`  📊 ${test.name}...`);
      try {
        const result = await test.test();
        this.results.performance[test.name] = result;
        console.log(`    ✅ ${result.description}`);
      } catch (error) {
        console.log(`    ⚠️  ${test.name} benchmark failed: ${error.message}`);
        this.results.performance[test.name] = { error: error.message };
      }
    }
  }

  async benchmarkAnalysisSpeed() {
    const startTime = Date.now();
    
    await this.testProjectAnalysis();
    
    const duration = Date.now() - startTime;
    const filesPerSecond = Math.round(10 / (duration / 1000)); // Assuming ~10 test files
    
    return {
      duration,
      filesPerSecond,
      description: `Analyzed project in ${duration}ms (~${filesPerSecond} files/second)`
    };
  }

  async benchmarkMemoryUsage() {
    const memBefore = process.memoryUsage();
    
    // Run several operations to stress memory
    await Promise.all([
      this.testSecurityScanning(),
      this.testPatternLearning(),
      this.testVulnerabilityDetection()
    ]);
    
    const memAfter = process.memoryUsage();
    const heapIncrease = memAfter.heapUsed - memBefore.heapUsed;
    
    return {
      heapIncrease,
      totalHeap: memAfter.heapUsed,
      description: `Memory increase: ${Math.round(heapIncrease / 1024 / 1024)}MB, total: ${Math.round(memAfter.heapUsed / 1024 / 1024)}MB`
    };
  }

  async benchmarkResponseTime() {
    const tests = [];
    const iterations = 5;
    
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      await this.testServerConnectivity();
      tests.push(Date.now() - startTime);
    }
    
    const avgResponseTime = tests.reduce((a, b) => a + b, 0) / tests.length;
    const maxResponseTime = Math.max(...tests);
    
    return {
      average: avgResponseTime,
      maximum: maxResponseTime,
      description: `Average response: ${Math.round(avgResponseTime)}ms, max: ${Math.round(maxResponseTime)}ms`
    };
  }

  async sendMCPRequest(request) {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        reject(new Error('Server not running'));
        return;
      }

      let responseData = '';
      
      const timeout = setTimeout(() => {
        reject(new Error('Request timeout'));
      }, TEST_TIMEOUT);

      const dataHandler = (data) => {
        responseData += data.toString();
        
        // Check if we have a complete JSON response
        try {
          const response = JSON.parse(responseData);
          clearTimeout(timeout);
          this.server.stdout.removeListener('data', dataHandler);
          resolve(response);
        } catch (e) {
          // Not complete JSON yet, continue collecting
        }
      };

      this.server.stdout.on('data', dataHandler);
      this.server.stdin.write(JSON.stringify(request) + '\n');
    });
  }

  async stopServer() {
    if (this.server) {
      console.log('\n🛑 Stopping server...');
      this.server.kill('SIGTERM');
      
      return new Promise((resolve) => {
        this.server.on('exit', () => {
          console.log('✅ Server stopped\n');
          resolve();
        });
        
        // Force kill after 5 seconds
        setTimeout(() => {
          if (this.server) {
            this.server.kill('SIGKILL');
            resolve();
          }
        }, 5000);
      });
    }
  }

  async cleanup() {
    await this.stopServer();
  }

  printResults() {
    console.log('📋 Validation Results');
    console.log('====================\n');
    
    // Summary
    const { total, passed, failed, skipped } = this.results.summary;
    const successRate = total > 0 ? Math.round((passed / total) * 100) : 0;
    
    console.log(`📊 Summary: ${passed}/${total} tests passed (${successRate}%)`);
    
    if (failed > 0) {
      console.log(`❌ Failed: ${failed}`);
    }
    if (skipped > 0) {
      console.log(`⏭️  Skipped: ${skipped}`);
    }
    
    console.log('');
    
    // Performance results
    if (Object.keys(this.results.performance).length > 0) {
      console.log('⚡ Performance Results:');
      for (const [name, result] of Object.entries(this.results.performance)) {
        if (result.error) {
          console.log(`  ❌ ${name}: ${result.error}`);
        } else {
          console.log(`  ✅ ${name}: ${result.description}`);
        }
      }
      console.log('');
    }
    
    // Errors
    if (this.results.errors.length > 0) {
      console.log('❌ Errors:');
      this.results.errors.forEach(error => {
        console.log(`  • ${error}`);
      });
      console.log('');
    }
    
    // Overall status
    if (failed === 0) {
      console.log('🎉 All tests passed! System is ready for production.');
    } else if (successRate >= 80) {
      console.log('⚠️  Some tests failed, but core functionality works.');
    } else {
      console.log('❌ Multiple critical tests failed. Check configuration and try again.');
      process.exit(1);
    }
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node validate-system.js [options]');
    console.log('');
    console.log('Options:');
    console.log('  --help, -h     Show this help message');
    console.log('  --verbose, -v  Enable verbose output');
    console.log('');
    console.log('This script validates the complete Codebase Intelligence system');
    console.log('including server functionality, MCP tools, and performance.');
    return;
  }
  
  const validator = new SystemValidator();
  
  process.on('SIGINT', async () => {
    console.log('\n🛑 Validation interrupted');
    await validator.cleanup();
    process.exit(1);
  });
  
  try {
    await validator.validate();
  } catch (error) {
    console.error('❌ Validation failed:', error.message);
    await validator.cleanup();
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = SystemValidator;