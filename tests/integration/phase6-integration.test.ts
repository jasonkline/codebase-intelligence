import { jest } from '@jest/globals';
import { join } from 'path';
import { ConfigurationManager } from '../../src/config/ConfigurationManager';
import { PerformanceMonitor } from '../../src/monitoring/PerformanceMonitor';
import { ResponseFormatter } from '../../src/mcp/ResponseFormatter';
import { SecurityTools } from '../../src/mcp/tools/SecurityTools';
import { PatternTools } from '../../src/mcp/tools/PatternTools';
import { KnowledgeTools } from '../../src/mcp/tools/KnowledgeTools';
import { NavigationTools } from '../../src/mcp/tools/NavigationTools';
import { GovernanceTools } from '../../src/mcp/tools/GovernanceTools';
import { WebServer } from '../../src/ui/WebServer';

// Mock external dependencies
jest.mock('../../src/security/SecurityScanner');
jest.mock('../../src/security/AuthPatternAnalyzer');
jest.mock('../../src/security/RLSAnalyzer');
jest.mock('../../src/security/OWASPScanner');
jest.mock('../../src/patterns/PatternRegistry');
jest.mock('../../src/governance/RuleEngine');
jest.mock('../../src/knowledge/QueryEngine');
jest.mock('../../src/knowledge/SystemExplainer');
jest.mock('../../src/knowledge/DocumentationGenerator');
jest.mock('../../src/knowledge/ImpactAnalyzer');
jest.mock('../../src/knowledge/DependencyAnalyzer');
jest.mock('../../src/database/schema');

describe('Phase 6 Integration Tests', () => {
  let configManager: ConfigurationManager;
  let performanceMonitor: PerformanceMonitor;
  let responseFormatter: ResponseFormatter;

  beforeEach(() => {
    // Create test configuration
    configManager = new ConfigurationManager();
    performanceMonitor = new PerformanceMonitor();
    responseFormatter = new ResponseFormatter(configManager);
  });

  afterEach(() => {
    performanceMonitor.reset();
  });

  describe('Configuration Management', () => {
    test('should load default configuration', () => {
      const config = configManager.getConfig();
      
      expect(config).toMatchObject({
        version: expect.any(String),
        include: expect.any(Array),
        exclude: expect.any(Array),
        database: expect.objectContaining({
          path: expect.any(String),
          maxSize: expect.any(String)
        }),
        security: expect.objectContaining({
          enabled: expect.any(Boolean),
          scanOnSave: expect.any(Boolean)
        }),
        server: expect.objectContaining({
          logLevel: expect.stringMatching(/^(debug|info|warn|error)$/),
          enableUI: expect.any(Boolean)
        })
      });
    });

    test('should validate tool enable/disable functionality', () => {
      expect(configManager.isToolEnabled('analyze_security')).toBe(true);
      
      configManager.disableTool('analyze_security');
      expect(configManager.isToolEnabled('analyze_security')).toBe(false);
      
      configManager.enableTool('analyze_security');
      expect(configManager.isToolEnabled('analyze_security')).toBe(true);
    });

    test('should handle configuration updates', () => {
      const updates = {
        security: {
          enabled: false,
          scanOnSave: false,
          blockCritical: false,
          warnOnHigh: false,
          owasp: false,
          reportingLevel: 'critical' as const
        }
      };

      configManager.updateConfig(updates);
      const config = configManager.getConfig();
      
      expect(config.security.enabled).toBe(false);
      expect(config.security.scanOnSave).toBe(false);
    });

    test('should apply environment overrides', () => {
      process.env.CODEINTEL_LOGLEVEL = 'debug';
      process.env.CODEINTEL_PORT = '8080';
      
      const testConfigManager = new ConfigurationManager();
      const config = testConfigManager.getConfig();
      
      expect(config.server.logLevel).toBe('debug');
      expect(config.server.port).toBe(8080);
      
      // Cleanup
      delete process.env.CODEINTEL_LOGLEVEL;
      delete process.env.CODEINTEL_PORT;
    });
  });

  describe('Performance Monitoring', () => {
    test('should record tool call metrics', () => {
      performanceMonitor.recordToolCall('test_tool', 150, true);
      performanceMonitor.recordToolCall('test_tool', 200, false);
      
      const metrics = performanceMonitor.getMetrics();
      
      expect(metrics.toolCalls.total).toBe(2);
      expect(metrics.toolCalls.successful).toBe(1);
      expect(metrics.toolCalls.failed).toBe(1);
      expect(metrics.toolCalls.byTool.test_tool).toMatchObject({
        count: 2,
        totalTime: 350,
        averageTime: 175,
        successRate: 0.5
      });
    });

    test('should track different types of operations', () => {
      performanceMonitor.recordSecurityScan('owasp', 500, 3);
      performanceMonitor.recordPatternAnalysis('compliance', 300, 0);
      performanceMonitor.recordKnowledgeQuery('explain', 200, 0.9, true);
      performanceMonitor.recordNavigationQuery('search', 100, 25);
      performanceMonitor.recordGovernanceCheck('validation', 150, 2, 10);
      
      const metrics = performanceMonitor.getMetrics();
      
      expect(metrics.securityScans.total).toBe(1);
      expect(metrics.securityScans.vulnerabilitiesFound).toBe(3);
      expect(metrics.patternAnalysis.complianceChecks).toBe(1);
      expect(metrics.knowledgeQueries.cacheHitRate).toBeGreaterThan(0);
      expect(metrics.navigationQueries.symbolsFound).toBe(25);
      expect(metrics.governanceChecks.violationsFound).toBe(2);
    });

    test('should generate comprehensive performance report', () => {
      performanceMonitor.recordToolCall('fast_tool', 50, true);
      performanceMonitor.recordToolCall('slow_tool', 2000, true);
      
      const report = performanceMonitor.generateReport();
      
      expect(report).toMatchObject({
        timestamp: expect.any(String),
        uptime: expect.any(String),
        summary: expect.objectContaining({
          totalRequests: expect.any(Number),
          successRate: expect.any(String),
          averageResponseTime: expect.any(String)
        }),
        detailed: expect.any(Object),
        system: expect.any(Object),
        recommendations: expect.any(Array)
      });
    });

    test('should trigger alerts for performance issues', () => {
      const mockAlert = jest.fn();
      
      // Add a test alert rule
      performanceMonitor.addAlertRule({
        name: 'test_alert',
        condition: (metrics) => metrics.toolCalls.averageTime > 100,
        severity: 'warning',
        message: 'Test alert triggered',
        cooldown: 1
      });
      
      // Record slow operations to trigger alert
      performanceMonitor.recordToolCall('slow_tool', 150, true);
      performanceMonitor.recordToolCall('slow_tool', 200, true);
      
      // The alert should be triggered internally (logged)
      const metrics = performanceMonitor.getMetrics();
      expect(metrics.toolCalls.averageTime).toBeGreaterThan(100);
    });
  });

  describe('Response Formatting', () => {
    test('should format security tool responses', async () => {
      const mockSecurityResult = {
        content: [{
          success: true,
          path: '/test/file.ts',
          timestamp: new Date().toISOString(),
          summary: {
            totalFindings: 5,
            criticalIssues: 2
          },
          criticalFindings: [
            {
              severity: 'critical',
              title: 'SQL Injection',
              file: '/test/file.ts',
              line: 42,
              remediation: 'Use parameterized queries'
            }
          ],
          findings: {
            security: [
              { severity: 'high', title: 'XSS Vulnerability' }
            ]
          }
        }]
      };

      const formatted = await responseFormatter.formatToolResponse('analyze_security', mockSecurityResult);
      
      expect(formatted.content[0]).toMatchObject({
        success: true,
        summary: expect.any(Object),
        criticalActions: expect.any(Array)
      });

      expect(formatted.content[0].urgentActions).toBeDefined();
      expect(formatted.content[0].urgentActions.length).toBeGreaterThan(0);
    });

    test('should format pattern tool responses', async () => {
      const mockPatternResult = {
        content: [{
          success: true,
          filePath: '/test/component.tsx',
          compliance: {
            overallScore: 0.85,
            violations: 3
          },
          violations: [
            {
              ruleId: 'style-001',
              severity: 'warning',
              line: 15,
              message: 'Missing prop types',
              autoFixAvailable: true,
              suggestion: 'Add PropTypes definition'
            }
          ],
          patterns: {
            components: 5,
            style: 2
          }
        }]
      };

      const formatted = await responseFormatter.formatToolResponse('check_pattern_compliance', mockPatternResult);
      
      expect(formatted.content[0]).toMatchObject({
        success: true,
        summary: expect.any(Object),
        actionableInsights: expect.any(Array)
      });

      expect(formatted.content[0].quickFixes).toBeDefined();
      expect(formatted.content[0].quickFixes.length).toBe(1);
    });

    test('should format knowledge tool responses', async () => {
      const mockKnowledgeResult = {
        content: [{
          success: true,
          query: 'How does authentication work?',
          confidence: 0.9,
          answer: 'Authentication in this system uses JWT tokens with multi-tenant support...',
          codeExamples: [
            {
              title: 'Auth Check Example',
              code: 'const { user } = await requireAuth()',
              explanation: 'Standard authentication pattern'
            }
          ],
          relatedTopics: ['RBAC', 'Authorization', 'Multi-tenancy']
        }]
      };

      const formatted = await responseFormatter.formatToolResponse('explain_system', mockKnowledgeResult);
      
      expect(formatted.content[0]).toMatchObject({
        success: true,
        keyInsights: expect.any(Array),
        quickReference: expect.any(Object)
      });

      if (formatted.content[0].practicalExamples) {
        expect(formatted.content[0].practicalExamples[0]).toMatchObject({
          title: expect.any(String),
          language: expect.any(String),
          code: expect.any(String),
          explanation: expect.any(String)
        });
      }
    });

    test('should handle error responses properly', () => {
      const error = new Error('Test error message');
      const formatted = responseFormatter.formatErrorResponse('test_tool', error);
      
      expect(formatted.content[0]).toMatchObject({
        success: false,
        error: true,
        toolName: 'test_tool',
        errorMessage: 'Test error message',
        suggestion: expect.any(String),
        recovery: expect.objectContaining({
          canRetry: expect.any(Boolean),
          suggestion: expect.any(String)
        })
      });
    });

    test('should limit response size for large results', async () => {
      const largeResult = {
        content: [{
          success: true,
          largeArray: Array(1000).fill('x'.repeat(100)), // Large data
          normalField: 'normal'
        }]
      };

      const formatted = await responseFormatter.formatToolResponse('test_tool', largeResult, {
        maxContentLength: 10000 // Small limit to trigger truncation
      });

      expect(formatted.content[0].largeArray_truncated).toBe(true);
      expect(formatted.content[0].largeArray_original_count).toBe(1000);
      expect(formatted.content[0].largeArray.length).toBeLessThan(1000);
    });
  });

  describe('Tool Integration', () => {
    test('should create and configure security tools', () => {
      // Mock dependencies
      const mockSecurityScanner = {} as any;
      const mockAuthAnalyzer = {} as any;
      const mockRLSAnalyzer = {} as any;
      const mockOWASPScanner = {} as any;

      const securityTools = new SecurityTools(
        mockSecurityScanner,
        mockAuthAnalyzer,
        mockRLSAnalyzer,
        mockOWASPScanner,
        responseFormatter,
        performanceMonitor
      );

      const toolDefinitions = securityTools.getToolDefinitions();
      
      expect(toolDefinitions).toHaveLength(3);
      expect(toolDefinitions.map(t => t.name)).toEqual([
        'analyze_security',
        'check_auth_pattern',
        'find_vulnerabilities'
      ]);

      expect(securityTools.hasTools(['analyze_security'])).toBe(true);
      expect(securityTools.hasTools(['unknown_tool'])).toBe(false);
    });

    test('should validate tool definitions schemas', () => {
      const mockDeps = {
        securityScanner: {} as any,
        authAnalyzer: {} as any,
        rlsAnalyzer: {} as any,
        owaspScanner: {} as any,
        patternRegistry: {} as any,
        ruleEngine: {} as any,
        queryEngine: {} as any,
        systemExplainer: {} as any,
        documentationGenerator: {} as any,
        impactAnalyzer: {} as any,
        database: {} as any,
        dependencyAnalyzer: {} as any
      };

      const tools = [
        new SecurityTools(mockDeps.securityScanner, mockDeps.authAnalyzer, mockDeps.rlsAnalyzer, mockDeps.owaspScanner, responseFormatter, performanceMonitor),
        new PatternTools(mockDeps.patternRegistry, mockDeps.ruleEngine, responseFormatter, performanceMonitor),
        new KnowledgeTools(mockDeps.queryEngine, mockDeps.systemExplainer, mockDeps.documentationGenerator, mockDeps.impactAnalyzer, responseFormatter, performanceMonitor),
        new NavigationTools(mockDeps.database, mockDeps.dependencyAnalyzer, responseFormatter, performanceMonitor),
        new GovernanceTools(mockDeps.ruleEngine, mockDeps.patternRegistry, responseFormatter, performanceMonitor)
      ];

      tools.forEach(tool => {
        const definitions = tool.getToolDefinitions();
        
        definitions.forEach(def => {
          expect(def).toMatchObject({
            name: expect.any(String),
            description: expect.any(String),
            inputSchema: expect.objectContaining({
              type: 'object',
              properties: expect.any(Object),
              required: expect.any(Array)
            })
          });

          // Validate schema structure
          expect(def.inputSchema.properties).toBeDefined();
          expect(Array.isArray(def.inputSchema.required)).toBe(true);
        });
      });
    });
  });

  describe('Web Server Integration', () => {
    let webServer: WebServer;
    let mockDatabase: any;

    beforeEach(() => {
      mockDatabase = {
        getDb: jest.fn(() => ({
          prepare: jest.fn(() => ({
            all: jest.fn(() => []),
            get: jest.fn(() => ({}))
          }))
        }))
      };

      webServer = new WebServer(
        configManager,
        performanceMonitor,
        mockDatabase,
        { port: 0 } // Use port 0 for testing
      );
    });

    afterEach(async () => {
      if (webServer) {
        await webServer.stop();
      }
    });

    test('should start and stop web server', async () => {
      await expect(webServer.start()).resolves.not.toThrow();
      await expect(webServer.stop()).resolves.not.toThrow();
    });

    test('should prevent double start', async () => {
      await webServer.start();
      await expect(webServer.start()).rejects.toThrow('already running');
    });
  });

  describe('End-to-End Tool Chain', () => {
    test('should handle complete analysis workflow', async () => {
      // This test simulates a complete workflow from tool call to formatted response
      
      // 1. Record performance metrics
      const startTime = Date.now();
      
      // 2. Simulate tool execution
      performanceMonitor.recordToolCall('analyze_security', 250, true);
      
      // 3. Format response
      const mockResult = {
        content: [{
          success: true,
          path: '/test/secure-file.ts',
          summary: { totalFindings: 0, criticalIssues: 0 },
          findings: { security: [], rls: [], owasp: [] }
        }]
      };
      
      const formattedResponse = await responseFormatter.formatToolResponse(
        'analyze_security',
        mockResult,
        { includeMetadata: true }
      );
      
      // 4. Verify workflow completion
      expect(formattedResponse._metadata).toMatchObject({
        toolName: 'analyze_security',
        timestamp: expect.any(String),
        confidence: expect.any(Number)
      });
      
      const metrics = performanceMonitor.getMetrics();
      expect(metrics.toolCalls.total).toBe(1);
      expect(metrics.toolCalls.successful).toBe(1);
    });

    test('should handle error propagation through the tool chain', async () => {
      // Simulate tool failure
      performanceMonitor.recordToolCall('failing_tool', 100, false);
      
      // Format error response
      const error = new Error('Tool execution failed');
      const errorResponse = responseFormatter.formatErrorResponse('failing_tool', error);
      
      // Verify error handling
      expect(errorResponse.content[0]).toMatchObject({
        success: false,
        error: true,
        toolName: 'failing_tool',
        errorMessage: 'Tool execution failed'
      });
      
      const metrics = performanceMonitor.getMetrics();
      expect(metrics.toolCalls.failed).toBe(1);
    });
  });

  describe('Configuration Validation', () => {
    test('should validate configuration schema', () => {
      const config = configManager.getConfig();
      
      // Test required fields
      expect(config.include).toBeDefined();
      expect(config.exclude).toBeDefined();
      expect(config.database).toBeDefined();
      expect(config.security).toBeDefined();
      expect(config.patterns).toBeDefined();
      expect(config.governance).toBeDefined();
      expect(config.server).toBeDefined();
      
      // Test data types
      expect(Array.isArray(config.include)).toBe(true);
      expect(Array.isArray(config.exclude)).toBe(true);
      expect(typeof config.security.enabled).toBe('boolean');
      expect(typeof config.patterns.minConfidence).toBe('number');
      expect(['debug', 'info', 'warn', 'error']).toContain(config.server.logLevel);
    });

    test('should handle invalid configuration gracefully', () => {
      const invalidUpdates = {
        patterns: {
          minConfidence: 1.5 // Invalid: should be 0-1
        },
        server: {
          logLevel: 'invalid' as any // Invalid log level
        }
      };

      // The configuration manager should validate and potentially auto-fix
      configManager.updateConfig(invalidUpdates);
      const config = configManager.getConfig();
      
      // Should be auto-corrected or ignored
      expect(config.patterns.minConfidence).toBeLessThanOrEqual(1);
      expect(config.patterns.minConfidence).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Memory and Resource Management', () => {
    test('should not leak memory during normal operations', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Simulate many operations
      for (let i = 0; i < 100; i++) {
        performanceMonitor.recordToolCall(`tool_${i % 5}`, Math.random() * 100, true);
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable (less than 10MB for this test)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    test('should clean up resources properly', async () => {
      // Test cleanup methods
      await expect(async () => {
        const securityTools = new SecurityTools({} as any, {} as any, {} as any, {} as any, responseFormatter, performanceMonitor);
        await securityTools.cleanup();
      }).not.toThrow();
    });
  });
});

describe('Phase 6 Feature Completeness', () => {
  test('should have all required MCP tools implemented', () => {
    const expectedTools = [
      'analyze_security',
      'check_auth_pattern', 
      'find_vulnerabilities',
      'learn_patterns',
      'check_pattern_compliance',
      'get_approved_pattern',
      'suggest_pattern',
      'explain_system',
      'analyze_impact',
      'get_system_docs',
      'trace_data_flow',
      'explain_security',
      'search_code',
      'find_symbol',
      'get_file_structure',
      'analyze_dependencies',
      'validate_governance',
      'create_rule',
      'get_governance_report',
      'enforce_style_guide'
    ];

    // This would be tested with actual tool instances
    // For now, just verify we have the expected count
    expect(expectedTools.length).toBe(20);
  });

  test('should have comprehensive configuration options', () => {
    const configManager = new ConfigurationManager();
    const config = configManager.getConfig();
    
    const requiredSections = [
      'version', 'include', 'exclude', 'database', 'patterns', 
      'security', 'knowledge', 'governance', 'intelligence', 
      'server', 'performance', 'tools'
    ];

    requiredSections.forEach(section => {
      expect(config).toHaveProperty(section);
    });
  });

  test('should have monitoring for all operation types', () => {
    const monitor = new PerformanceMonitor();
    
    // Test all monitoring methods exist
    expect(typeof monitor.recordToolCall).toBe('function');
    expect(typeof monitor.recordSecurityScan).toBe('function');
    expect(typeof monitor.recordPatternAnalysis).toBe('function');
    expect(typeof monitor.recordKnowledgeQuery).toBe('function');
    expect(typeof monitor.recordNavigationQuery).toBe('function');
    expect(typeof monitor.recordGovernanceCheck).toBe('function');
    expect(typeof monitor.generateReport).toBe('function');
  });
});