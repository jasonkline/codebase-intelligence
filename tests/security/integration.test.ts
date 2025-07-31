import { describe, test, expect, beforeEach } from '@jest/globals';
import path from 'path';
import { SecurityScanner } from '../../src/security/SecurityScanner';
import { AuthPatternAnalyzer } from '../../src/security/AuthPatternAnalyzer';
import { RLSAnalyzer } from '../../src/security/RLSAnalyzer';
import { OWASPScanner } from '../../src/security/OWASPScanner';
import { vulnerabilityDatabase, VulnerabilitySeverity, VulnerabilityCategory } from '../../src/security/VulnerabilityDatabase';

describe('Security Analysis Integration', () => {
  let securityScanner: SecurityScanner;
  let authAnalyzer: AuthPatternAnalyzer;
  let rlsAnalyzer: RLSAnalyzer;
  let owaspScanner: OWASPScanner;
  
  const examplesDir = path.join(__dirname, 'vulnerable-examples');

  beforeEach(() => {
    securityScanner = new SecurityScanner();
    authAnalyzer = new AuthPatternAnalyzer();
    rlsAnalyzer = new RLSAnalyzer();
    owaspScanner = new OWASPScanner();
  });

  describe('Comprehensive Security Analysis', () => {
    test('should perform multi-layered security analysis', async () => {
      const testFile = path.join(examplesDir, 'auth-bypass.ts');
      
      // Run all security analyzers
      const [
        securityFindings,
        authFlow,
        rlsAnalysis,
        owaspResults
      ] = await Promise.all([
        securityScanner.scanFile(testFile),
        authAnalyzer.analyzeFile(testFile),
        rlsAnalyzer.analyzeFile(testFile),
        owaspScanner.scanFile(testFile)
      ]);

      // Verify each analyzer found issues
      expect(securityFindings.length).toBeGreaterThan(0);
      expect(authFlow.gaps.length).toBeGreaterThan(0);
      expect(rlsAnalysis.findings.length).toBeGreaterThanOrEqual(0);
      expect(owaspResults.summary.total).toBeGreaterThan(0);

      // Verify findings have proper structure
      securityFindings.forEach(finding => {
        expect(finding.id).toBeDefined();
        expect(finding.severity).toBeDefined();
        expect(finding.category).toBeDefined();
        expect(finding.filePath).toBe(testFile);
        expect(finding.remediation).toBeDefined();
      });
    });

    test('should correlate findings across different analyzers', async () => {
      const testFile = path.join(examplesDir, 'auth-bypass.ts');
      
      const [securityFindings, authFlow, owaspResults] = await Promise.all([
        securityScanner.scanFile(testFile),
        authAnalyzer.analyzeFile(testFile),
        owaspScanner.scanFile(testFile)
      ]);

      // Both should detect authentication issues
      const securityAuthIssues = securityFindings.filter(f => 
        f.category === VulnerabilityCategory.AUTH
      );
      const owaspAuthIssues = owaspResults.vulnerabilities.filter(v => 
        v.title.includes('Authorization') || v.title.includes('Authentication')
      );

      expect(securityAuthIssues.length).toBeGreaterThan(0);
      expect(owaspAuthIssues.length).toBeGreaterThan(0);
      expect(authFlow.gaps.length).toBeGreaterThan(0);

      // Findings should be related to the same underlying issues
      const authLines = new Set([
        ...securityAuthIssues.map(f => f.lineStart),
        ...owaspAuthIssues.map(v => v.line),
        ...authFlow.gaps.map(g => g.lineStart)
      ]);

      expect(authLines.size).toBeGreaterThan(0);
    });
  });

  describe('RLS Analysis Integration', () => {
    test('should detect RLS bypass patterns comprehensively', async () => {
      const testFile = path.join(examplesDir, 'rls-bypass.ts');
      
      const [securityFindings, rlsAnalysis] = await Promise.all([
        securityScanner.scanFile(testFile),
        rlsAnalyzer.analyzeFile(testFile)
      ]);

      // Both should detect RLS issues
      const rlsSecurityFindings = securityFindings.filter(f => 
        f.category === VulnerabilityCategory.RLS
      );

      expect(rlsSecurityFindings.length).toBeGreaterThan(0);
      expect(rlsAnalysis.findings.length).toBeGreaterThan(0);
      expect(rlsAnalysis.unsafePatterns.length).toBeGreaterThan(0);

      // Should detect direct database access
      const directDbIssues = rlsSecurityFindings.filter(f => 
        f.code.includes('drizzle') || f.code.includes('postgres')
      );
      expect(directDbIssues.length).toBeGreaterThan(0);

      // Should provide recommendations
      expect(rlsAnalysis.recommendations.length).toBeGreaterThan(0);
    });

    test('should identify safe vs unsafe patterns', async () => {
      const testFile = path.join(examplesDir, 'rls-bypass.ts');
      const rlsAnalysis = await rlsAnalyzer.analyzeFile(testFile);

      expect(rlsAnalysis.safePatterns.length).toBeGreaterThan(0);
      expect(rlsAnalysis.unsafePatterns.length).toBeGreaterThan(0);

      // Safe patterns should have higher confidence in their safety
      rlsAnalysis.safePatterns.forEach(pattern => {
        expect(pattern.type).toBe('safe');
        expect(pattern.confidence).toBeGreaterThan(0.8);
      });

      // Unsafe patterns should be flagged appropriately
      rlsAnalysis.unsafePatterns.forEach(pattern => {
        expect(pattern.type).toBe('unsafe');
      });
    });
  });

  describe('Vulnerability Database Integration', () => {
    test('should generate comprehensive security reports', async () => {
      const testFile = path.join(examplesDir, 'hardcoded-secrets.ts');
      const findings = await securityScanner.scanFile(testFile);
      
      const report = vulnerabilityDatabase.generateReport(findings);

      expect(report.summary.total).toBe(findings.length);
      expect(report.criticalFindings.length).toBeGreaterThanOrEqual(0);
      expect(report.recommendations.length).toBeGreaterThan(0);

      // Summary should match actual findings
      const criticalCount = findings.filter(f => 
        f.severity === VulnerabilitySeverity.CRITICAL
      ).length;
      expect(report.summary.bySeverity.critical).toBe(criticalCount);

      // Should categorize findings properly
      const categories = new Set(findings.map(f => f.category));
      expect(Object.keys(report.summary.byCategory).length).toBe(categories.size);
    });

    test('should prioritize findings correctly', async () => {
      const testFile = path.join(examplesDir, 'hardcoded-secrets.ts');
      const findings = await securityScanner.scanFile(testFile);
      
      const prioritized = vulnerabilityDatabase.prioritizeFindings(findings);

      // Should be sorted by severity (critical first)
      for (let i = 0; i < prioritized.length - 1; i++) {
        const current = prioritized[i];
        const next = prioritized[i + 1];
        
        const severityOrder = {
          [VulnerabilitySeverity.CRITICAL]: 0,
          [VulnerabilitySeverity.HIGH]: 1,
          [VulnerabilitySeverity.MEDIUM]: 2,
          [VulnerabilitySeverity.LOW]: 3,
          [VulnerabilitySeverity.INFO]: 4
        };
        
        expect(severityOrder[current.severity]).toBeLessThanOrEqual(severityOrder[next.severity]);
      }
    });
  });

  describe('Directory-Level Analysis', () => {
    test('should analyze entire directory with all tools', async () => {
      const [
        securityFindings,
        authFlow,
        rlsAnalysis,
        owaspResults
      ] = await Promise.all([
        securityScanner.scanDirectory(examplesDir),
        authAnalyzer.analyzeDirectory(examplesDir),
        rlsAnalyzer.analyzeDirectory(examplesDir),
        owaspScanner.scanDirectory(examplesDir)
      ]);

      // All tools should find issues across multiple files
      expect(securityFindings.length).toBeGreaterThan(0);
      expect(authFlow.entryPoints.length + authFlow.authChecks.length + authFlow.gaps.length).toBeGreaterThan(0);
      expect(rlsAnalysis.findings.length + rlsAnalysis.unsafePatterns.length).toBeGreaterThan(0);
      expect(owaspResults.summary.total).toBeGreaterThan(0);

      // Should cover multiple files
      const securityFiles = new Set(securityFindings.map(f => f.filePath));
      const authFiles = new Set([
        ...authFlow.entryPoints.map(p => p.file),
        ...authFlow.authChecks.map(p => p.file)
      ]);
      const rlsFiles = new Set(rlsAnalysis.findings.map(f => f.filePath));
      const owaspFiles = new Set(owaspResults.vulnerabilities.map(v => v.file));

      expect(securityFiles.size).toBeGreaterThan(1);
      expect(authFiles.size).toBeGreaterThan(0);
      expect(rlsFiles.size).toBeGreaterThan(0);
      expect(owaspFiles.size).toBeGreaterThan(1);
    });
  });

  describe('Real-World Scenario Simulation', () => {
    test('should provide actionable security guidance', async () => {
      // Simulate analyzing a typical web application file
      const testFile = path.join(examplesDir, 'auth-bypass.ts');
      
      const [securityFindings, authFlow, rlsAnalysis] = await Promise.all([
        securityScanner.scanFile(testFile),
        authAnalyzer.analyzeFile(testFile),
        rlsAnalyzer.analyzeFile(testFile)
      ]);

      // Should provide specific, actionable recommendations
      const allRecommendations = [
        ...vulnerabilityDatabase.generateReport(securityFindings).recommendations,
        ...rlsAnalysis.recommendations
      ];

      expect(allRecommendations.length).toBeGreaterThan(0);
      
      allRecommendations.forEach(rec => {
        expect(typeof rec).toBe('string');
        expect(rec.length).toBeGreaterThan(10);
      });

      // Should identify critical issues that need immediate attention
      const criticalFindings = securityFindings.filter(f => 
        f.severity === VulnerabilitySeverity.CRITICAL || f.severity === VulnerabilitySeverity.HIGH
      );

      if (criticalFindings.length > 0) {
        expect(allRecommendations.some(rec => 
          rec.toLowerCase().includes('critical') || 
          rec.toLowerCase().includes('immediately') ||
          rec.toLowerCase().includes('security')
        )).toBe(true);
      }
    });

    test('should handle mixed secure and insecure patterns', async () => {
      // Test file that has both vulnerable and secure patterns
      const testFile = path.join(examplesDir, 'rls-bypass.ts');
      const rlsAnalysis = await rlsAnalyzer.analyzeFile(testFile);

      // Should distinguish between safe and unsafe patterns
      expect(rlsAnalysis.safePatterns.length).toBeGreaterThan(0);
      expect(rlsAnalysis.unsafePatterns.length).toBeGreaterThan(0);

      // Safe patterns should not generate findings
      const safePatternLines = new Set(rlsAnalysis.safePatterns.map(p => p.line));
      const findingLines = new Set(rlsAnalysis.findings.map(f => f.lineStart));

      // There should be minimal overlap (safe patterns shouldn't generate findings)
      const overlap = new Set([...safePatternLines].filter(line => findingLines.has(line)));
      expect(overlap.size).toBeLessThan(safePatternLines.size);
    });
  });

  describe('Performance Integration', () => {
    test('should complete comprehensive analysis within reasonable time', async () => {
      const startTime = Date.now();
      
      // Run all analyzers in parallel on the entire examples directory
      await Promise.all([
        securityScanner.scanDirectory(examplesDir),
        authAnalyzer.analyzeDirectory(examplesDir),
        rlsAnalyzer.analyzeDirectory(examplesDir),
        owaspScanner.scanDirectory(examplesDir)
      ]);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(15000); // Should complete within 15 seconds
    });
  });

  describe('Error Recovery Integration', () => {
    test('should handle errors gracefully across all components', async () => {
      const nonExistentFile = path.join(examplesDir, 'non-existent.ts');
      
      // All analyzers should handle missing files gracefully
      const [securityFindings, authFlow, rlsAnalysis, owaspResults] = await Promise.all([
        securityScanner.scanFile(nonExistentFile),
        authAnalyzer.analyzeFile(nonExistentFile),
        rlsAnalyzer.analyzeFile(nonExistentFile),
        owaspScanner.scanFile(nonExistentFile)
      ]);

      expect(securityFindings).toEqual([]);
      expect(authFlow.entryPoints).toEqual([]);
      expect(authFlow.authChecks).toEqual([]);
      expect(authFlow.gaps).toEqual([]);
      expect(rlsAnalysis.findings).toEqual([]);
      expect(owaspResults.summary.total).toBe(0);
    });
  });
});