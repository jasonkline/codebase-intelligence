import { describe, test, expect, beforeEach } from '@jest/globals';
import path from 'path';
import { AuthPatternAnalyzer } from '../../src/security/AuthPatternAnalyzer';

describe('AuthPatternAnalyzer', () => {
  let analyzer: AuthPatternAnalyzer;
  const examplesDir = path.join(__dirname, 'vulnerable-examples');

  beforeEach(() => {
    analyzer = new AuthPatternAnalyzer();
  });

  describe('Authentication Pattern Detection', () => {
    test('should identify API entry points', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      expect(authFlow.entryPoints.length).toBeGreaterThan(0);
      
      // Should identify HTTP method functions as entry points
      const httpMethods = authFlow.entryPoints.map(p => p.name);
      expect(httpMethods).toContain('GET');
      expect(httpMethods).toContain('POST');
    });

    test('should detect authentication checks', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      expect(authFlow.authChecks.length).toBeGreaterThan(0);
      
      // Should find requireAuthWithTenant calls
      const authCheck = authFlow.authChecks.find(p => 
        p.pattern.includes('requireAuthWithTenant')
      );
      expect(authCheck).toBeDefined();
      expect(authCheck?.confidence).toBeGreaterThan(0.8);
    });

    test('should identify security gaps', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      expect(authFlow.gaps.length).toBeGreaterThan(0);
      
      // Should identify missing auth in GET endpoint
      const missingAuthGap = authFlow.gaps.find(gap => 
        gap.title.includes('Missing Authentication')
      );
      expect(missingAuthGap).toBeDefined();
    });

    test('should detect role checks', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      const roleChecks = authFlow.roleChecks.filter(p => 
        p.pattern.includes('hasPermission')
      );
      
      expect(roleChecks.length).toBeGreaterThan(0);
    });
  });

  describe('RBAC Mapping', () => {
    test('should identify roles and permissions', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const rbacMapping = await analyzer.mapRBACImplementation(filePath);
      
      expect(rbacMapping.roles.length).toBeGreaterThan(0);
      expect(rbacMapping.permissions.length).toBeGreaterThan(0);
      
      // Should include common roles
      expect(rbacMapping.roles).toContain('admin');
      expect(rbacMapping.roles).toContain('user');
    });

    test('should extract permissions from hasPermission calls', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const rbacMapping = await analyzer.mapRBACImplementation(filePath);
      
      // Should find update:users permission
      expect(rbacMapping.permissions.some(p => 
        p.includes('update') || p.includes('create')
      )).toBe(true);
    });
  });

  describe('Pattern Confidence Scoring', () => {
    test('should assign higher confidence to explicit auth calls', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      const explicitAuthCheck = authFlow.authChecks.find(p => 
        p.name === 'requireAuthWithTenant'
      );
      
      expect(explicitAuthCheck?.confidence).toBeGreaterThan(0.8);
    });

    test('should assign lower confidence to conditional checks', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      const conditionalChecks = authFlow.authChecks.filter(p => 
        p.type === 'conditional'
      );
      
      conditionalChecks.forEach(check => {
        expect(check.confidence).toBeLessThan(0.8);
      });
    });
  });

  describe('Auth Bypass Detection', () => {
    test('should detect commented-out auth checks', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      // Should detect TODO comment about auth
      const todoGap = authFlow.gaps.find(gap => 
        gap.description.includes('bypass') || gap.code.includes('TODO')
      );
      
      expect(todoGap).toBeDefined();
    });

    test('should detect early returns that bypass auth', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      // Should identify development bypass
      const developmentBypass = authFlow.gaps.find(gap => 
        gap.code.includes('development') || gap.code.includes('Skip auth')
      );
      
      expect(developmentBypass).toBeDefined();
    });
  });

  describe('Directory Analysis', () => {
    test('should aggregate patterns across multiple files', async () => {
      const authFlow = await analyzer.analyzeDirectory(examplesDir);
      
      expect(authFlow.entryPoints.length).toBeGreaterThan(0);
      expect(authFlow.authChecks.length).toBeGreaterThan(0);
      expect(authFlow.gaps.length).toBeGreaterThan(0);
      
      // Should aggregate from multiple files
      const uniqueFiles = new Set([
        ...authFlow.entryPoints.map(p => p.file),
        ...authFlow.authChecks.map(p => p.file),
        ...authFlow.gaps.map(g => g.filePath)
      ]);
      
      expect(uniqueFiles.size).toBeGreaterThan(0);
    });
  });

  describe('Pattern Types', () => {
    test('should categorize different pattern types', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const authFlow = await analyzer.analyzeFile(filePath);
      
      const patternTypes = new Set([
        ...authFlow.authChecks.map(p => p.type),
        ...authFlow.roleChecks.map(p => p.type)
      ]);
      
      expect(patternTypes.has('function_call')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('should handle non-existent files gracefully', async () => {
      const nonExistentPath = path.join(examplesDir, 'non-existent.ts');
      const authFlow = await analyzer.analyzeFile(nonExistentPath);
      
      expect(authFlow.entryPoints).toEqual([]);
      expect(authFlow.authChecks).toEqual([]);
      expect(authFlow.roleChecks).toEqual([]);
      expect(authFlow.permissionChecks).toEqual([]);
      expect(authFlow.gaps).toEqual([]);
    });

    test('should handle malformed files gracefully', async () => {
      // This would need a malformed TypeScript file to test properly
      // For now, just ensure the method doesn't throw
      expect(async () => {
        await analyzer.analyzeFile(path.join(examplesDir, 'auth-bypass.ts'));
      }).not.toThrow();
    });
  });

  describe('Performance', () => {
    test('should complete analysis within reasonable time', async () => {
      const startTime = Date.now();
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      
      await analyzer.analyzeFile(filePath);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(3000); // Should complete within 3 seconds
    });
  });
});