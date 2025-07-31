import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/testing-library/jest-dom';
import path from 'path';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import CodebaseIntelligenceMCPServer from '../../src/mcp/server';
import DatabaseManager from '../../src/database/schema';
import { ConfigurationManager } from '../../src/config/ConfigurationManager';
import { PerformanceMonitor } from '../../src/monitoring/PerformanceMonitor';

// Test configuration
const TEST_PROJECT_PATH = path.join(__dirname, '../../test-project');
const TEST_CONFIG_PATH = path.join(__dirname, './test-config.json');
const TEST_DB_PATH = path.join(__dirname, './test-analysis.db');

interface TestContext {
  server: CodebaseIntelligenceMCPServer;
  database: DatabaseManager;
  config: ConfigurationManager;
  performanceMonitor: PerformanceMonitor;
}

describe('Final Integration Tests - Complete Analysis Pipeline', () => {
  let testContext: TestContext;

  beforeAll(async () => {
    // Clean up any existing test files
    if (existsSync(TEST_DB_PATH)) {
      await fs.unlink(TEST_DB_PATH);
    }

    // Create test configuration
    const testConfig = {
      database: {
        path: TEST_DB_PATH,
        maxSize: '100MB'
      },
      patterns: {
        learningMode: 'auto',
        minConfidence: 0.8,
        categories: ['auth', 'rbac', 'api', 'data_access', 'validation', 'error_handling']
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
        updateFrequency: 'on_change',
        includeArchitectureDocs: true
      },
      governance: {
        enabled: true,
        strictMode: false,
        autoSuggest: true,
        enforceStyles: true
      }
    };

    await fs.writeFile(TEST_CONFIG_PATH, JSON.stringify(testConfig, null, 2));

    // Initialize test context
    const config = new ConfigurationManager(TEST_CONFIG_PATH);
    const database = new DatabaseManager(TEST_DB_PATH);
    const performanceMonitor = new PerformanceMonitor();
    const server = new CodebaseIntelligenceMCPServer();

    testContext = {
      server,
      database,
      config,
      performanceMonitor
    };

    // Initialize database schema
    await database.initialize();
  });

  afterAll(async () => {
    // Cleanup
    if (testContext.database) {
      await testContext.database.close();
    }
    
    // Clean up test files
    if (existsSync(TEST_DB_PATH)) {
      await fs.unlink(TEST_DB_PATH);
    }
    if (existsSync(TEST_CONFIG_PATH)) {
      await fs.unlink(TEST_CONFIG_PATH);
    }
  });

  beforeEach(async () => {
    // Reset performance monitor for each test
    testContext.performanceMonitor.reset();
  });

  describe('End-to-End Analysis Pipeline', () => {
    test('should complete full project analysis within performance targets', async () => {
      const startTime = Date.now();

      // Test the analyze_project tool
      const result = await testContext.server.handleAnalyzeProject({
        projectPath: TEST_PROJECT_PATH,
        include: ['**/*.ts', '**/*.tsx'],
        exclude: ['node_modules/**'],
        parallel: true,
        maxConcurrency: 4
      });

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(result.content).toHaveLength(1);
      const analysis = result.content[0];
      
      // Verify analysis structure
      expect(analysis.success).toBe(true);
      expect(analysis.projectPath).toBe(TEST_PROJECT_PATH);
      expect(analysis.summary).toBeDefined();
      expect(analysis.findings).toBeDefined();
      expect(analysis.recommendations).toBeDefined();

      // Performance targets
      expect(duration).toBeLessThan(60000); // Complete within 60 seconds
      expect(analysis.summary.filesProcessed).toBeGreaterThan(0);
      expect(analysis.summary.duration).toBeLessThan(60000);

      // Security analysis should identify issues
      expect(analysis.summary.securityIssues).toBeGreaterThan(0);
      expect(analysis.findings.criticalSecurityIssues.length).toBeGreaterThan(0);

      console.log(`✅ Analysis completed in ${duration}ms`);
      console.log(`📁 Processed ${analysis.summary.filesProcessed} files`);
      console.log(`🔍 Found ${analysis.summary.securityIssues} security issues`);
    }, 90000); // 90 second timeout

    test('should detect authentication patterns and gaps', async () => {
      // Test auth pattern analysis
      const result = await testContext.server.handleCheckAuthPattern({
        path: path.join(TEST_PROJECT_PATH, 'src/api')
      });

      expect(result.content).toHaveLength(1);
      const authAnalysis = result.content[0];

      expect(authAnalysis.success).toBe(true);
      expect(authAnalysis.authFlow).toBeDefined();
      expect(authAnalysis.rbac).toBeDefined();
      expect(authAnalysis.patterns).toBeDefined();
      expect(authAnalysis.securityGaps).toBeDefined();

      // Should detect our test vulnerabilities
      expect(authAnalysis.securityGaps.length).toBeGreaterThan(0);
      
      // Should find both secure and insecure patterns
      expect(authAnalysis.authFlow.entryPoints).toBeGreaterThan(0);

      console.log(`🔐 Found ${authAnalysis.authFlow.authChecks} auth checks`);
      console.log(`⚠️ Identified ${authAnalysis.securityGaps.length} security gaps`);
    });

    test('should perform comprehensive security scanning', async () => {
      // Test security analysis on vulnerable files
      const result = await testContext.server.handleAnalyzeSecurity({
        path: path.join(TEST_PROJECT_PATH, 'src/api/insecure'),
        options: {
          minSeverity: 'medium',
          maxFindings: 50
        }
      });

      expect(result.content).toHaveLength(1);
      const securityAnalysis = result.content[0];

      expect(securityAnalysis.success).toBe(true);
      expect(securityAnalysis.summary).toBeDefined();
      expect(securityAnalysis.findings).toBeDefined();
      expect(securityAnalysis.criticalFindings).toBeDefined();

      // Should detect our intentionally vulnerable code
      expect(securityAnalysis.summary.totalFindings).toBeGreaterThan(0);
      expect(securityAnalysis.summary.criticalIssues).toBeGreaterThan(0);
      expect(securityAnalysis.findings.security.length).toBeGreaterThan(0);

      console.log(`🚨 Found ${securityAnalysis.summary.totalFindings} security findings`);
      console.log(`💥 ${securityAnalysis.summary.criticalIssues} critical issues`);
    });

    test('should find specific vulnerability types', async () => {
      // Test vulnerability search for SQL injection
      const sqlInjectionResult = await testContext.server.handleFindVulnerabilities({
        path: TEST_PROJECT_PATH,
        category: 'injection',
        severity: 'high',
        maxResults: 10
      });

      expect(sqlInjectionResult.content).toHaveLength(1);
      const sqlAnalysis = sqlInjectionResult.content[0];

      expect(sqlAnalysis.success).toBe(true);
      expect(sqlAnalysis.summary.total).toBeGreaterThanOrEqual(0);

      // Test authentication vulnerabilities
      const authVulnResult = await testContext.server.handleFindVulnerabilities({
        path: TEST_PROJECT_PATH,
        category: 'authentication',
        maxResults: 10
      });

      expect(authVulnResult.content).toHaveLength(1);
      const authVulnAnalysis = authVulnResult.content[0];

      expect(authVulnAnalysis.success).toBe(true);
      expect(authVulnAnalysis.findings).toBeDefined();

      console.log(`💉 SQL injection vulnerabilities: ${sqlAnalysis.summary.total}`);
      console.log(`🔒 Auth vulnerabilities: ${authVulnAnalysis.summary.total}`);
    });

    test('should learn patterns from codebase', async () => {
      // Test pattern learning
      const result = await testContext.server.handleLearnPatterns({
        projectPath: TEST_PROJECT_PATH,
        categories: ['auth', 'api', 'data_access'],
        minConfidence: 0.7
      });

      expect(result.content).toHaveLength(1);
      const patternAnalysis = result.content[0];

      expect(patternAnalysis.success).toBe(true);
      expect(patternAnalysis.summary).toBeDefined();
      expect(patternAnalysis.summary.totalPatternsLearned).toBeGreaterThanOrEqual(0);
      expect(patternAnalysis.configuration.categories).toEqual(['auth', 'api', 'data_access']);

      console.log(`🧠 Learned ${patternAnalysis.summary.totalPatternsLearned} patterns`);
    });

    test('should validate pattern compliance', async () => {
      // First learn patterns
      await testContext.server.handleLearnPatterns({
        projectPath: TEST_PROJECT_PATH,
        categories: ['auth', 'api'],
        minConfidence: 0.6
      });

      // Then check compliance
      const result = await testContext.server.handleCheckPatternCompliance({
        filePath: path.join(TEST_PROJECT_PATH, 'src/api/users/route.ts'),
        patternCategory: 'api',
        explainViolations: true
      });

      expect(result.content).toHaveLength(1);
      const complianceAnalysis = result.content[0];

      expect(complianceAnalysis.success).toBe(true);
      expect(complianceAnalysis.compliance).toBeDefined();
      expect(complianceAnalysis.violations).toBeDefined();
      expect(complianceAnalysis.patterns).toBeDefined();

      console.log(`📋 Compliance score: ${complianceAnalysis.compliance.overallScore}`);
      console.log(`❌ Violations: ${complianceAnalysis.compliance.violations}`);
    });
  });

  describe('Knowledge System Integration', () => {
    test('should answer system architecture questions', async () => {
      // Test system explanation
      const result = await testContext.server.handleExplainSystem({
        query: 'How does authentication work in this application?',
        detailLevel: 'detailed'
      });

      expect(result.content).toHaveLength(1);
      const explanation = result.content[0];

      expect(explanation.success).toBe(true);
      expect(explanation.answer).toBeDefined();
      expect(explanation.answer.length).toBeGreaterThan(100); // Should provide detailed explanation
      expect(explanation.confidence).toBeGreaterThan(0);

      console.log(`💡 Query confidence: ${explanation.confidence}`);
      console.log(`📚 Answer length: ${explanation.answer.length} characters`);
    });

    test('should analyze change impact', async () => {
      // Test impact analysis
      const result = await testContext.server.handleAnalyzeImpact({
        targetComponent: 'auth.ts',
        changeType: 'modify',
        changeDescription: 'Update authentication middleware to use new JWT validation'
      });

      expect(result.content).toHaveLength(1);
      const impactAnalysis = result.content[0];

      expect(impactAnalysis.success).toBe(true);
      expect(impactAnalysis.summary).toBeDefined();
      expect(impactAnalysis.riskAssessment).toBeDefined();
      expect(impactAnalysis.recommendations).toBeDefined();

      console.log(`⚖️ Impact risk: ${impactAnalysis.summary.overallRisk}`);
      console.log(`📊 Impact score: ${impactAnalysis.summary.impactScore}`);
    });

    test('should generate system documentation', async () => {
      // Test documentation generation
      const result = await testContext.server.handleGetSystemDocs({
        systemName: 'Authentication',
        includeCodeExamples: true,
        includeDiagrams: true
      });

      expect(result.content).toHaveLength(1);
      const docs = result.content[0];

      expect(docs.success).toBe(true);
      expect(docs.documentation).toBeDefined();
      expect(docs.documentation.length).toBeGreaterThan(500); // Should be comprehensive
      expect(docs.metadata).toBeDefined();

      console.log(`📖 Documentation length: ${docs.documentation.length} characters`);
      console.log(`🏗️ Components documented: ${docs.metadata.components}`);
    });

    test('should trace data flows', async () => {
      // Test data flow tracing
      const result = await testContext.server.handleTraceDataFlow({
        startComponent: 'api',
        endComponent: 'database'
      });

      expect(result.content).toHaveLength(1);
      const dataFlow = result.content[0];

      expect(dataFlow.success).toBe(true);
      expect(dataFlow.summary).toBeDefined();
      expect(dataFlow.flows).toBeDefined();

      console.log(`🌊 Data flows found: ${dataFlow.summary.flowsFound}`);
      console.log(`🔒 Security checkpoints: ${dataFlow.summary.totalSecurityCheckpoints}`);
    });

    test('should explain component security', async () => {
      // Test security explanation
      const result = await testContext.server.handleExplainSecurity({
        component: 'database',
        includeThreats: true,
        includeRemediation: true
      });

      expect(result.content).toHaveLength(1);
      const securityExplanation = result.content[0];

      expect(securityExplanation.success).toBe(true);
      expect(securityExplanation.securityExplanation).toBeDefined();
      expect(securityExplanation.summary).toBeDefined();

      console.log(`🛡️ Security level: ${securityExplanation.summary.securityLevel}`);
      console.log(`⚠️ Vulnerabilities: ${securityExplanation.summary.vulnerabilities}`);
    });
  });

  describe('Real-time Intelligence Integration', () => {
    test('should validate code as typed', async () => {
      const testCode = `
export async function GET() {
  const db = getOrgDatabase() // Missing auth
  const data = await db.select().from(users)
  return Response.json(data)
}`;

      // Test real-time validation
      const result = await testContext.server.handleValidateAsTyped({
        filePath: path.join(TEST_PROJECT_PATH, 'src/api/test-route.ts'),
        content: testCode,
        line: 3,
        column: 15
      });

      expect(result.content).toHaveLength(1);
      const validation = result.content[0];

      expect(validation.success).toBe(true);
      expect(validation.issues).toBeDefined();
      expect(validation.suggestions).toBeDefined();

      // Should detect the missing auth issue
      expect(validation.issues.length).toBeGreaterThan(0);

      console.log(`⚡ Real-time issues found: ${validation.issues.length}`);
    });

    test('should suggest next patterns', async () => {
      const partialCode = `
export async function POST() {
  const { user, orgSlug } = await requireAuthWithTenant()
  // cursor here
`;

      // Test pattern suggestion
      const result = await testContext.server.handleSuggestNext({
        filePath: path.join(TEST_PROJECT_PATH, 'src/api/new-route.ts'),
        content: partialCode,
        line: 4,
        column: 3,
        context: 'Creating a new API endpoint with database access',
        maxSuggestions: 3
      });

      expect(result.content).toHaveLength(1);
      const suggestions = result.content[0];

      expect(suggestions.success).toBe(true);
      expect(suggestions.suggestions).toBeDefined();
      expect(suggestions.suggestions.length).toBeGreaterThan(0);

      console.log(`💡 Pattern suggestions: ${suggestions.suggestions.length}`);
    });

    test('should prevent common errors', async () => {
      const problematicCode = `
export async function DELETE() {
  const db = drizzle(connectionString) // Direct DB access
  await db.delete(users).where(eq(users.id, id))
  return Response.json({ success: true })
}`;

      // Test error prevention
      const result = await testContext.server.handlePreventError({
        filePath: path.join(TEST_PROJECT_PATH, 'src/api/dangerous-route.ts'),
        content: problematicCode,
        analysisType: 'comprehensive'
      });

      expect(result.content).toHaveLength(1);
      const errorPrevention = result.content[0];

      expect(errorPrevention.success).toBe(true);
      expect(errorPrevention.potentialErrors).toBeDefined();
      expect(errorPrevention.potentialErrors.length).toBeGreaterThan(0);

      // Should detect security and architectural issues
      const criticalErrors = errorPrevention.potentialErrors.filter(
        (error: any) => error.severity === 'critical'
      );
      expect(criticalErrors.length).toBeGreaterThan(0);

      console.log(`🚫 Potential errors prevented: ${errorPrevention.potentialErrors.length}`);
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle large project analysis efficiently', async () => {
      const startTime = Date.now();
      const startMemory = process.memoryUsage().heapUsed;

      // Analyze the entire test project multiple times to test scalability
      const results = await Promise.all([
        testContext.server.handleAnalyzeProject({
          projectPath: TEST_PROJECT_PATH,
          parallel: true,
          maxConcurrency: 2
        }),
        testContext.server.handleAnalyzeSecurity({
          path: TEST_PROJECT_PATH,
          options: { maxFindings: 100 }
        }),
        testContext.server.handleLearnPatterns({
          projectPath: TEST_PROJECT_PATH,
          categories: ['auth', 'api', 'data_access', 'components']
        })
      ]);

      const endTime = Date.now();
      const endMemory = process.memoryUsage().heapUsed;
      const duration = endTime - startTime;
      const memoryIncrease = endMemory - startMemory;

      // All should succeed
      results.forEach(result => {
        expect(result.content[0].success).toBe(true);
      });

      // Performance assertions
      expect(duration).toBeLessThan(120000); // Under 2 minutes for concurrent analysis
      expect(memoryIncrease).toBeLessThan(500 * 1024 * 1024); // Under 500MB memory increase

      console.log(`⚡ Concurrent analysis completed in ${duration}ms`);
      console.log(`💾 Memory increase: ${Math.round(memoryIncrease / 1024 / 1024)}MB`);
    });

    test('should maintain consistent performance across multiple runs', async () => {
      const durations: number[] = [];
      const memoryUsages: number[] = [];

      // Run the same analysis 5 times
      for (let i = 0; i < 5; i++) {
        const startTime = Date.now();
        const startMemory = process.memoryUsage().heapUsed;

        await testContext.server.handleAnalyzeSecurity({
          path: path.join(TEST_PROJECT_PATH, 'src'),
          options: { maxFindings: 20 }
        });

        const endTime = Date.now();
        const endMemory = process.memoryUsage().heapUsed;

        durations.push(endTime - startTime);
        memoryUsages.push(endMemory - startMemory);

        // Small delay between runs
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      // Calculate consistency metrics
      const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
      const maxDuration = Math.max(...durations);
      const minDuration = Math.min(...durations);
      const varianceRatio = (maxDuration - minDuration) / avgDuration;

      // Performance should be consistent (variance < 50%)
      expect(varianceRatio).toBeLessThan(0.5);
      expect(avgDuration).toBeLessThan(10000); // Average under 10 seconds

      console.log(`🎯 Average duration: ${Math.round(avgDuration)}ms`);
      console.log(`📊 Performance variance: ${Math.round(varianceRatio * 100)}%`);
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle invalid project paths gracefully', async () => {
      const result = await testContext.server.handleAnalyzeProject({
        projectPath: '/nonexistent/path',
        include: ['**/*.ts']
      });

      expect(result.content).toHaveLength(1);
      const analysis = result.content[0];

      expect(analysis.success).toBe(false);
      expect(analysis.errors).toBeDefined();
      expect(analysis.errors!.length).toBeGreaterThan(0);
    });

    test('should handle malformed queries gracefully', async () => {
      const result = await testContext.server.handleExplainSystem({
        query: '', // Empty query
        detailLevel: 'detailed'
      });

      expect(result.content).toHaveLength(1);
      const explanation = result.content[0];

      expect(explanation.success).toBe(false);
      expect(explanation.error).toBeDefined();
    });

    test('should handle concurrent requests without corruption', async () => {
      // Fire multiple concurrent requests
      const promises = Array.from({ length: 10 }, (_, i) =>
        testContext.server.handleAnalyzeSecurity({
          path: path.join(TEST_PROJECT_PATH, 'src/api/users/route.ts'),
          options: { maxFindings: 5 }
        })
      );

      const results = await Promise.allSettled(promises);
      
      // All should complete (either successfully or with graceful errors)
      expect(results.length).toBe(10);
      results.forEach(result => {
        expect(result.status).toBe('fulfilled');
        if (result.status === 'fulfilled') {
          expect(result.value.content).toHaveLength(1);
        }
      });

      console.log(`🔄 Handled ${results.length} concurrent requests successfully`);
    });
  });
});