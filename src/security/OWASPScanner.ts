import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface OWASPVulnerability {
  id: string;
  owaspId: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  category: string;
  file: string;
  line: number;
  code: string;
  remediation: string;
  references: string[];
}

export interface OWASPScanResult {
  vulnerabilities: OWASPVulnerability[];
  byCategory: Map<string, OWASPVulnerability[]>;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: SecurityFinding[];
}

export class OWASPScanner {
  private astParser: ASTParser;
  private owaspRules: Map<string, any> = new Map();

  constructor() {
    this.astParser = new ASTParser();
    this.initializeOWASPRules();
  }

  private initializeOWASPRules(): void {
    // A01:2021 - Broken Access Control
    this.owaspRules.set('A01:2021', {
      patterns: [
        'missing-authorization',
        'insecure-direct-object-reference',
        'privilege-escalation',
        'cors-misconfiguration'
      ],
      scanners: [
        this.scanBrokenAccessControl.bind(this)
      ]
    });

    // A02:2021 - Cryptographic Failures
    this.owaspRules.set('A02:2021', {
      patterns: [
        'weak-crypto',
        'hardcoded-secrets',
        'insecure-transmission',
        'weak-random'
      ],
      scanners: [
        this.scanCryptographicFailures.bind(this)
      ]
    });

    // A03:2021 - Injection
    this.owaspRules.set('A03:2021', {
      patterns: [
        'sql-injection',
        'xss',
        'command-injection',
        'ldap-injection'
      ],
      scanners: [
        this.scanInjection.bind(this)
      ]
    });

    // A04:2021 - Insecure Design
    this.owaspRules.set('A04:2021', {
      patterns: [
        'missing-rate-limiting',
        'business-logic-bypass',
        'insecure-workflows'
      ],
      scanners: [
        this.scanInsecureDesign.bind(this)
      ]
    });

    // A05:2021 - Security Misconfiguration
    this.owaspRules.set('A05:2021', {
      patterns: [
        'default-credentials',
        'verbose-errors',
        'missing-security-headers',
        'unnecessary-features'
      ],
      scanners: [
        this.scanSecurityMisconfiguration.bind(this)
      ]
    });

    // A06:2021 - Vulnerable and Outdated Components
    this.owaspRules.set('A06:2021', {
      patterns: [
        'outdated-dependencies',
        'vulnerable-packages',
        'unused-dependencies'
      ],
      scanners: [
        this.scanVulnerableComponents.bind(this)
      ]
    });

    // A07:2021 - Identification and Authentication Failures
    this.owaspRules.set('A07:2021', {
      patterns: [
        'weak-authentication',
        'session-fixation',
        'credential-stuffing',
        'weak-password-recovery'
      ],
      scanners: [
        this.scanAuthenticationFailures.bind(this)
      ]
    });

    // A08:2021 - Software and Data Integrity Failures
    this.owaspRules.set('A08:2021', {
      patterns: [
        'insecure-deserialization',
        'supply-chain-attacks',
        'insecure-ci-cd'
      ],
      scanners: [
        this.scanIntegrityFailures.bind(this)
      ]
    });

    // A09:2021 - Security Logging and Monitoring Failures
    this.owaspRules.set('A09:2021', {
      patterns: [
        'insufficient-logging',
        'log-injection',
        'missing-monitoring'
      ],
      scanners: [
        this.scanLoggingFailures.bind(this)
      ]
    });

    // A10:2021 - Server-Side Request Forgery (SSRF)
    this.owaspRules.set('A10:2021', {
      patterns: [
        'ssrf',
        'unsafe-url-fetch',
        'internal-service-access'
      ],
      scanners: [
        this.scanSSRF.bind(this)
      ]
    });
  }

  public async scanFile(filePath: string): Promise<OWASPScanResult> {
    try {
      logger.info(`Running OWASP scan on: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return this.createEmptyResult();
      }

      const result: OWASPScanResult = {
        vulnerabilities: [],
        byCategory: new Map(),
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        findings: []
      };

      // Run all OWASP scanners
      for (const [owaspId, rule] of this.owaspRules) {
        for (const scanner of rule.scanners) {
          const vulnerabilities = await scanner(content, filePath, owaspId);
          result.vulnerabilities.push(...vulnerabilities);
        }
      }

      // Process results
      this.processResults(result);

      return result;
    } catch (error) {
      logger.error(`Error running OWASP scan on ${filePath}:`, error);
      return this.createEmptyResult();
    }
  }

  public async scanDirectory(dirPath: string): Promise<OWASPScanResult> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const aggregatedResult: OWASPScanResult = {
      vulnerabilities: [],
      byCategory: new Map(),
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      findings: []
    };
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
            continue;
          }
          const subResult = await this.scanDirectory(fullPath);
          this.mergeResults(aggregatedResult, subResult);
        } else if (entry.isFile() && this.isScannableFile(entry.name)) {
          const fileResult = await this.scanFile(fullPath);
          this.mergeResults(aggregatedResult, fileResult);
        }
      }
    } catch (error) {
      logger.error(`Error scanning directory ${dirPath}:`, error);
    }
    
    // Process final results
    this.processResults(aggregatedResult);
    
    return aggregatedResult;
  }

  // A01:2021 - Broken Access Control
  private async scanBrokenAccessControl(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      // Look for missing authorization checks
      if (node.type === AST_NODE_TYPES.FunctionDeclaration || 
          node.type === AST_NODE_TYPES.ArrowFunctionExpression) {
        
        if (this.isAPIEndpoint(node, filePath) && !this.hasAuthorizationCheck(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A01-missing-auth-${node.loc?.start.line}`,
            owaspId,
            title: 'Missing Authorization Check',
            description: 'API endpoint lacks proper authorization verification',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Broken Access Control',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode).slice(0, 200),
            remediation: 'Implement proper authorization checks before processing requests',
            references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
          });
        }
      }

      // Look for insecure direct object references
      if (node.type === AST_NODE_TYPES.CallExpression) {
        if (this.hasInsecureDirectObjectReference(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A01-idor-${node.loc?.start.line}`,
            owaspId,
            title: 'Insecure Direct Object Reference',
            description: 'User-controlled input directly accessing objects without authorization',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Broken Access Control',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Validate user permissions before accessing objects',
            references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // A02:2021 - Cryptographic Failures
  private async scanCryptographicFailures(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    // Check for hardcoded secrets
    const secretPatterns = [
      { pattern: /password\s*[=:]\s*['"][^'"]{3,}['"]/, name: 'Hardcoded Password' },
      { pattern: /secret\s*[=:]\s*['"][^'"]{8,}['"]/, name: 'Hardcoded Secret' },
      { pattern: /key\s*[=:]\s*['"][^'"]{8,}['"]/, name: 'Hardcoded API Key' },
      { pattern: /token\s*[=:]\s*['"][^'"]{8,}['"]/, name: 'Hardcoded Token' }
    ];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      secretPatterns.forEach(({ pattern, name }) => {
        const match = line.match(pattern);
        if (match && !this.isTestCode(line)) {
          vulnerabilities.push({
            id: `A02-secret-${index}`,
            owaspId,
            title: name,
            description: 'Hardcoded credentials detected in source code',
            severity: VulnerabilitySeverity.CRITICAL,
            category: 'Cryptographic Failures',
            file: filePath,
            line: index + 1,
            code: line.trim(),
            remediation: 'Use environment variables or secure secret management',
            references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
          });
        }
      });
    });

    // Check for weak crypto
    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        if (this.hasWeakCrypto(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A02-weak-crypto-${node.loc?.start.line}`,
            owaspId,
            title: 'Weak Cryptographic Algorithm',
            description: 'Use of weak or deprecated cryptographic algorithms',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Cryptographic Failures',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Use strong, modern cryptographic algorithms',
            references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // A03:2021 - Injection
  private async scanInjection(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      // SQL Injection
      if (node.type === AST_NODE_TYPES.TemplateLiteral) {
        if (this.hasSQLInjection(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A03-sql-${node.loc?.start.line}`,
            owaspId,
            title: 'SQL Injection',
            description: 'User input directly embedded in SQL query',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Injection',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Use parameterized queries or prepared statements',
            references: ['https://owasp.org/Top10/A03_2021-Injection/']
          });
        }
      }

      // XSS via dangerouslySetInnerHTML
      if (node.type === AST_NODE_TYPES.JSXAttribute) {
        if (this.hasXSSVulnerability(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A03-xss-${node.loc?.start.line}`,
            owaspId,
            title: 'Cross-Site Scripting (XSS)',
            description: 'Unsanitized user input in dangerouslySetInnerHTML',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Injection',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Sanitize user input before rendering',
            references: ['https://owasp.org/Top10/A03_2021-Injection/']
          });
        }
      }

      // Command injection
      if (node.type === AST_NODE_TYPES.CallExpression) {
        if (this.hasCommandInjection(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A03-cmd-${node.loc?.start.line}`,
            owaspId,
            title: 'Command Injection',
            description: 'User input passed to system command execution',
            severity: VulnerabilitySeverity.CRITICAL,
            category: 'Injection',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Validate and sanitize input, avoid system command execution',
            references: ['https://owasp.org/Top10/A03_2021-Injection/']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // A05:2021 - Security Misconfiguration
  private async scanSecurityMisconfiguration(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    // Check for verbose error handling
    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      if (this.hasVerboseErrorHandling(line)) {
        vulnerabilities.push({
          id: `A05-verbose-error-${index}`,
          owaspId,
          title: 'Verbose Error Messages',
          description: 'Error messages may leak sensitive information',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Security Misconfiguration',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Use generic error messages in production',
          references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
        });
      }

      // Check for debug code
      if (this.hasDebugCode(line)) {
        vulnerabilities.push({
          id: `A05-debug-${index}`,
          owaspId,
          title: 'Debug Code in Production',
          description: 'Debug code may expose sensitive information',
          severity: VulnerabilitySeverity.LOW,
          category: 'Security Misconfiguration',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Remove debug code from production builds',
          references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
        });
      }
    });

    return vulnerabilities;
  }

  // A07:2021 - Identification and Authentication Failures
  private async scanAuthenticationFailures(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      // Check for weak session management
      if (node.type === AST_NODE_TYPES.CallExpression) {
        if (this.hasWeakSessionManagement(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A07-weak-session-${node.loc?.start.line}`,
            owaspId,
            title: 'Weak Session Management',
            description: 'Session tokens may be predictable or insufficiently random',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Authentication Failures',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Use cryptographically secure random tokens',
            references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // A09:2021 - Security Logging and Monitoring Failures
  private async scanLoggingFailures(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      // Check for missing security logging
      if (node.type === AST_NODE_TYPES.FunctionDeclaration || 
          node.type === AST_NODE_TYPES.ArrowFunctionExpression) {
        
        if (this.isSecuritySensitiveFunction(node, content.sourceCode) && 
            !this.hasSecurityLogging(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A09-missing-log-${node.loc?.start.line}`,
            owaspId,
            title: 'Missing Security Logging',
            description: 'Security-sensitive operation lacks proper logging',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Logging and Monitoring Failures',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode).slice(0, 200),
            remediation: 'Add security logging for authentication and authorization events',
            references: ['https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/']
          });
        }
      }

      // Check for log injection
      if (node.type === AST_NODE_TYPES.CallExpression) {
        if (this.hasLogInjection(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A09-log-injection-${node.loc?.start.line}`,
            owaspId,
            title: 'Log Injection',
            description: 'User input directly logged without sanitization',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Logging and Monitoring Failures',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Sanitize user input before logging',
            references: ['https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // A10:2021 - Server-Side Request Forgery (SSRF)
  private async scanSSRF(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    owaspId: string
  ): Promise<OWASPVulnerability[]> {
    const vulnerabilities: OWASPVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        if (this.hasSSRFVulnerability(node, content.sourceCode)) {
          vulnerabilities.push({
            id: `A10-ssrf-${node.loc?.start.line}`,
            owaspId,
            title: 'Server-Side Request Forgery (SSRF)',
            description: 'User-controlled URL in server-side request',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Server-Side Request Forgery',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Validate and whitelist URLs, use URL parsing libraries',
            references: ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // Placeholder scanners for other OWASP categories
  private async scanInsecureDesign(content: any, filePath: string, owaspId: string): Promise<OWASPVulnerability[]> {
    return []; // Implement business logic and design flaw detection
  }

  private async scanVulnerableComponents(content: any, filePath: string, owaspId: string): Promise<OWASPVulnerability[]> {
    return []; // Implement dependency vulnerability scanning
  }

  private async scanIntegrityFailures(content: any, filePath: string, owaspId: string): Promise<OWASPVulnerability[]> {
    return []; // Implement integrity and deserialization checks
  }

  // Helper methods
  private createEmptyResult(): OWASPScanResult {
    return {
      vulnerabilities: [],
      byCategory: new Map(),
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      findings: []
    };
  }

  private mergeResults(target: OWASPScanResult, source: OWASPScanResult): void {
    target.vulnerabilities.push(...source.vulnerabilities);
    target.findings.push(...source.findings);
  }

  private processResults(result: OWASPScanResult): void {
    // Group by category
    result.vulnerabilities.forEach(vuln => {
      const existing = result.byCategory.get(vuln.category) || [];
      existing.push(vuln);
      result.byCategory.set(vuln.category, existing);
    });

    // Calculate summary
    result.summary.total = result.vulnerabilities.length;
    result.vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case VulnerabilitySeverity.CRITICAL:
          result.summary.critical++;
          break;
        case VulnerabilitySeverity.HIGH:
          result.summary.high++;
          break;
        case VulnerabilitySeverity.MEDIUM:
          result.summary.medium++;
          break;
        case VulnerabilitySeverity.LOW:
          result.summary.low++;
          break;
      }
    });

    // Convert vulnerabilities to security findings
    result.vulnerabilities.forEach(vuln => {
      const finding = vulnerabilityDatabase.createFinding(
        vuln.id,
        vuln.file,
        vuln.line,
        vuln.line,
        0,
        vuln.code.length,
        vuln.code
      );
      if (finding) {
        finding.title = vuln.title;
        finding.description = vuln.description;
        finding.remediation = vuln.remediation;
        result.findings.push(finding);
      }
    });
  }

  private isScannableFile(fileName: string): boolean {
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    return extensions.some(ext => fileName.endsWith(ext));
  }

  private getNodeCode(node: TSESTree.Node, sourceCode: string): string {
    if (!node.range) return '';
    return sourceCode.slice(node.range[0], node.range[1]);
  }

  private traverseNode(node: TSESTree.Node, callback: (node: TSESTree.Node) => void): void {
    for (const key in node) {
      const child = (node as any)[key];
      if (child && typeof child === 'object') {
        if (Array.isArray(child)) {
          child.forEach(item => {
            if (item && typeof item === 'object' && item.type) {
              callback(item);
            }
          });
        } else if (child.type) {
          callback(child);
        }
      }
    }
  }

  // Detection helper methods
  private isAPIEndpoint(node: TSESTree.FunctionDeclaration | TSESTree.ArrowFunctionExpression, filePath: string): boolean {
    const functionName = node.type === AST_NODE_TYPES.FunctionDeclaration ? node.id?.name : undefined;
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    return httpMethods.includes(functionName?.toUpperCase() || '') && 
           (filePath.includes('/api/') || filePath.includes('/route.'));
  }

  private hasAuthorizationCheck(node: TSESTree.Node, sourceCode: string): boolean {
    const code = JSON.stringify(node);
    const authPatterns = ['requireAuth', 'checkAuth', 'verifyAuth', 'hasPermission', 'authorize'];
    return authPatterns.some(pattern => code.includes(pattern));
  }

  private hasInsecureDirectObjectReference(node: TSESTree.CallExpression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    // Check if user input is directly used in database operations without authorization
    return this.isDatabaseOperation(code) && this.hasUserInput(node, sourceCode) && !this.hasAuthorizationCheck(node, sourceCode);
  }

  private hasWeakCrypto(node: TSESTree.CallExpression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    const weakAlgorithms = ['md5', 'sha1', 'des', 'rc4'];
    return weakAlgorithms.some(algo => code.toLowerCase().includes(algo));
  }

  private hasSQLInjection(node: TSESTree.TemplateLiteral, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    return this.looksLikeSQL(code) && node.expressions.length > 0;
  }

  private hasXSSVulnerability(node: TSESTree.JSXAttribute, sourceCode: string): boolean {
    if (node.name.type === AST_NODE_TYPES.JSXIdentifier && node.name.name === 'dangerouslySetInnerHTML') {
      const code = this.getNodeCode(node, sourceCode);
      return !code.includes('DOMPurify') && !code.includes('sanitize');
    }
    return false;
  }

  private hasCommandInjection(node: TSESTree.CallExpression, sourceCode: string): boolean {
    if (node.callee.type === AST_NODE_TYPES.Identifier) {
      const dangerousFunctions = ['exec', 'spawn', 'execSync', 'system'];
      return dangerousFunctions.includes(node.callee.name) && this.hasUserInput(node, sourceCode);
    }
    return false;
  }

  private hasVerboseErrorHandling(line: string): boolean {
    const verbosePatterns = [
      /console\.error\([^)]*error[^)]*\)/i,
      /throw.*error\./i,
      /\.stack/i
    ];
    return verbosePatterns.some(pattern => pattern.test(line));
  }

  private hasDebugCode(line: string): boolean {
    const debugPatterns = [
      /console\.log/i,
      /debugger/i,
      /\.debug\(/i
    ];
    return debugPatterns.some(pattern => pattern.test(line));
  }

  private hasWeakSessionManagement(node: TSESTree.CallExpression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    return code.includes('Math.random()') && (code.includes('session') || code.includes('token'));
  }

  private isSecuritySensitiveFunction(node: TSESTree.Node, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    const sensitivePatterns = ['login', 'auth', 'password', 'token', 'permission'];
    return sensitivePatterns.some(pattern => code.toLowerCase().includes(pattern));
  }

  private hasSecurityLogging(node: TSESTree.Node, sourceCode: string): boolean {
    const code = JSON.stringify(node);
    const loggingPatterns = ['logger', 'log', 'audit'];
    return loggingPatterns.some(pattern => code.includes(pattern));
  }

  private hasLogInjection(node: TSESTree.CallExpression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    return this.isLoggingCall(node) && this.hasUserInput(node, sourceCode);
  }

  private hasSSRFVulnerability(node: TSESTree.CallExpression, sourceCode: string): boolean {
    if (node.callee.type === AST_NODE_TYPES.Identifier) {
      const fetchFunctions = ['fetch', 'axios', 'request', 'get', 'post'];
      return fetchFunctions.includes(node.callee.name) && this.hasUserInput(node, sourceCode);
    }
    return false;
  }

  private isDatabaseOperation(code: string): boolean {
    const dbOperations = ['select', 'insert', 'update', 'delete', 'find', 'query'];
    return dbOperations.some(op => code.toLowerCase().includes(op));
  }

  private hasUserInput(node: TSESTree.Node, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    const userInputPatterns = ['req.', 'params', 'body', 'query', 'input'];
    return userInputPatterns.some(pattern => code.includes(pattern));
  }

  private looksLikeSQL(code: string): boolean {
    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE'];
    const upperCode = code.toUpperCase();
    return sqlKeywords.some(keyword => upperCode.includes(keyword));
  }

  private isLoggingCall(node: TSESTree.CallExpression): boolean {
    if (node.callee.type === AST_NODE_TYPES.Identifier) {
      return ['log', 'info', 'warn', 'error', 'debug'].includes(node.callee.name);
    }
    if (node.callee.type === AST_NODE_TYPES.MemberExpression) {
      const prop = node.callee.property;
      if (prop.type === AST_NODE_TYPES.Identifier) {
        return ['log', 'info', 'warn', 'error', 'debug'].includes(prop.name);
      }
    }
    return false;
  }

  private isTestCode(line: string): boolean {
    const testPatterns = ['test', 'spec', 'mock', 'fixture', 'example'];
    return testPatterns.some(pattern => line.toLowerCase().includes(pattern));
  }
}