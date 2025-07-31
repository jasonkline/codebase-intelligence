import { describe, test, expect, beforeEach } from '@jest/globals';
import path from 'path';
import { SecurityScanner } from '../../src/security/SecurityScanner';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../src/security/VulnerabilityDatabase';

describe('SecurityScanner', () => {
  let scanner: SecurityScanner;
  const examplesDir = path.join(__dirname, 'vulnerable-examples');

  beforeEach(() => {
    scanner = new SecurityScanner();
  });

  describe('SQL Injection Detection', () => {
    test('should detect SQL injection in template literals', async () => {
      const filePath = path.join(examplesDir, 'sql-injection.ts');
      const findings = await scanner.scanFile(filePath);
      
      const sqlInjectionFindings = findings.filter(f => 
        f.category === VulnerabilityCategory.INJECTION && 
        f.title.includes('SQL Injection')
      );
      
      expect(sqlInjectionFindings.length).toBeGreaterThan(0);
      
      // Should detect vulnerableQuery1
      const templateLiteralIssue = sqlInjectionFindings.find(f => 
        f.code.includes('SELECT * FROM users WHERE id = ${userId}')
      );
      expect(templateLiteralIssue).toBeDefined();
      expect(templateLiteralIssue?.severity).toBe(VulnerabilitySeverity.HIGH);
    });

    test('should not flag secure parameterized queries', async () => {
      const filePath = path.join(examplesDir, 'sql-injection.ts');
      const findings = await scanner.scanFile(filePath);
      
      // Should not flag secureQuery or secureQueryBuilder
      const secureFalsePositives = findings.filter(f => 
        f.code.includes('db.prepare') || f.code.includes('db.select')
      );
      
      expect(secureFalsePositives.length).toBe(0);
    });
  });

  describe('Authentication Bypass Detection', () => {
    test('should detect missing authentication in API routes', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const findings = await scanner.scanFile(filePath);
      
      const authFindings = findings.filter(f => 
        f.category === VulnerabilityCategory.AUTH
      );
      
      expect(authFindings.length).toBeGreaterThan(0);
      
      // Should detect GET function without auth
      const missingAuthIssue = authFindings.find(f => 
        f.title.includes('Missing Authentication')
      );
      expect(missingAuthIssue).toBeDefined();
      expect(missingAuthIssue?.severity).toBe(VulnerabilitySeverity.HIGH);
    });

    test('should not flag properly authenticated endpoints', async () => {
      const filePath = path.join(examplesDir, 'auth-bypass.ts');
      const findings = await scanner.scanFile(filePath);
      
      // Should not flag securePOST function
      const secureFalsePositives = findings.filter(f => 
        f.code.includes('securePOST') && 
        f.category === VulnerabilityCategory.AUTH
      );
      
      expect(secureFalsePositives.length).toBe(0);
    });
  });

  describe('RLS Bypass Detection', () => {
    test('should detect direct database client creation', async () => {
      const filePath = path.join(examplesDir, 'rls-bypass.ts');
      const findings = await scanner.scanFile(filePath);
      
      const rlsFindings = findings.filter(f => 
        f.category === VulnerabilityCategory.RLS
      );
      
      expect(rlsFindings.length).toBeGreaterThan(0);
      
      // Should detect drizzle() call
      const directClientIssue = rlsFindings.find(f => 
        f.code.includes('drizzle(connectionString)')
      );
      expect(directClientIssue).toBeDefined();
      expect(directClientIssue?.severity).toBe(VulnerabilitySeverity.CRITICAL);
    });

    test('should detect hardcoded organization IDs', async () => {
      const filePath = path.join(examplesDir, 'rls-bypass.ts');
      const findings = await scanner.scanFile(filePath);
      
      const hardcodedOrgIssue = findings.find(f => 
        f.code.includes("'acme-corp'") && 
        f.title.includes('Hardcoded Organization')
      );
      
      expect(hardcodedOrgIssue).toBeDefined();
      expect(hardcodedOrgIssue?.severity).toBe(VulnerabilitySeverity.MEDIUM);
    });

    test('should not flag secure RLS-enabled access', async () => {
      const filePath = path.join(examplesDir, 'rls-bypass.ts');
      const findings = await scanner.scanFile(filePath);
      
      // Should not flag getSupabaseRLS() or getOrgDatabaseWithAuth()
      const secureFalsePositives = findings.filter(f => 
        (f.code.includes('getSupabaseRLS') || f.code.includes('getOrgDatabaseWithAuth')) &&
        f.category === VulnerabilityCategory.RLS
      );
      
      expect(secureFalsePositives.length).toBe(0);
    });
  });

  describe('XSS Detection', () => {
    test('should detect unsanitized dangerouslySetInnerHTML', async () => {
      const filePath = path.join(examplesDir, 'xss-vulnerabilities.tsx');
      const findings = await scanner.scanFile(filePath);
      
      const xssFindings = findings.filter(f => 
        f.category === VulnerabilityCategory.XSS
      );
      
      expect(xssFindings.length).toBeGreaterThan(0);
      
      // Should detect VulnerableComponent1
      const xssIssue = xssFindings.find(f => 
        f.code.includes('dangerouslySetInnerHTML={{ __html: userContent }}')
      );
      expect(xssIssue).toBeDefined();
      expect(xssIssue?.severity).toBe(VulnerabilitySeverity.HIGH);
    });

    test('should not flag sanitized content', async () => {
      const filePath = path.join(examplesDir, 'xss-vulnerabilities.tsx');
      const findings = await scanner.scanFile(filePath);
      
      // Should not flag SecureComponent1 with DOMPurify
      const secureFalsePositives = findings.filter(f => 
        f.code.includes('DOMPurify.sanitize') &&
        f.category === VulnerabilityCategory.XSS
      );
      
      expect(secureFalsePositives.length).toBe(0);
    });
  });

  describe('Hardcoded Secrets Detection', () => {
    test('should detect hardcoded API keys', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const findings = await scanner.scanFile(filePath);
      
      const secretFindings = findings.filter(f => 
        f.category === VulnerabilityCategory.SECRETS
      );
      
      expect(secretFindings.length).toBeGreaterThan(0);
      
      // Should detect API key
      const apiKeyIssue = secretFindings.find(f => 
        f.code.includes('sk-1234567890abcdefghijklmnopqrstuvwxyz')
      );
      expect(apiKeyIssue).toBeDefined();
      expect(apiKeyIssue?.severity).toBe(VulnerabilitySeverity.CRITICAL);
    });

    test('should detect various types of secrets', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const findings = await scanner.scanFile(filePath);
      
      const secretFindings = findings.filter(f => 
        f.category === VulnerabilityCategory.SECRETS
      );
      
      // Should detect multiple types
      const secretTypes = secretFindings.map(f => f.code);
      
      expect(secretTypes.some(code => code.includes('password'))).toBe(true);
      expect(secretTypes.some(code => code.includes('secret'))).toBe(true);
      expect(secretTypes.some(code => code.includes('token'))).toBe(true);
    });

    test('should not flag environment variable usage', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const findings = await scanner.scanFile(filePath);
      
      // Should not flag process.env usage
      const envFalsePositives = findings.filter(f => 
        f.code.includes('process.env') &&
        f.category === VulnerabilityCategory.SECRETS
      );
      
      expect(envFalsePositives.length).toBe(0);
    });

    test('should not flag obvious test values', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const findings = await scanner.scanFile(filePath);
      
      // Should not flag test/example/placeholder values
      const testFalsePositives = findings.filter(f => 
        (f.code.includes('test_key') || 
         f.code.includes('example') || 
         f.code.includes('placeholder') ||
         f.code.includes('dummy')) &&
        f.category === VulnerabilityCategory.SECRETS
      );
      
      expect(testFalsePositives.length).toBe(0);
    });
  });

  describe('Scan Options', () => {
    test('should filter by severity', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const allFindings = await scanner.scanFile(filePath);
      const criticalOnlyFindings = await scanner.scanFile(filePath, {
        minSeverity: VulnerabilitySeverity.CRITICAL
      });
      
      expect(criticalOnlyFindings.length).toBeLessThanOrEqual(allFindings.length);
      expect(criticalOnlyFindings.every(f => f.severity === VulnerabilitySeverity.CRITICAL)).toBe(true);
    });

    test('should filter by category', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const secretsOnlyFindings = await scanner.scanFile(filePath, {
        includeCategories: [VulnerabilityCategory.SECRETS]
      });
      
      expect(secretsOnlyFindings.every(f => f.category === VulnerabilityCategory.SECRETS)).toBe(true);
    });

    test('should limit number of findings', async () => {
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      const limitedFindings = await scanner.scanFile(filePath, {
        maxFindings: 3
      });
      
      expect(limitedFindings.length).toBeLessThanOrEqual(3);
    });
  });

  describe('Directory Scanning', () => {
    test('should scan entire directory', async () => {
      const findings = await scanner.scanDirectory(examplesDir);
      
      expect(findings.length).toBeGreaterThan(0);
      
      // Should find issues from multiple files
      const uniqueFiles = new Set(findings.map(f => f.filePath));
      expect(uniqueFiles.size).toBeGreaterThan(1);
    });
  });

  describe('Performance', () => {
    test('should complete scan within reasonable time', async () => {
      const startTime = Date.now();
      const filePath = path.join(examplesDir, 'hardcoded-secrets.ts');
      
      await scanner.scanFile(filePath);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });
});