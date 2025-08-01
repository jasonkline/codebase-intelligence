import { logger } from '../utils/logger';

export interface CheatSheetPattern {
  id: string;
  sheetName: string;
  category: string;
  pattern: string;
  description: string;
  codePattern: RegExp | string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  remediation: string;
  references: string[];
  examples: {
    vulnerable: string;
    secure: string;
  };
  tags: string[];
  context: string[]; // File types or contexts where this applies
}

export interface CheatSheetReference {
  name: string;
  url: string;
  version: string;
  description: string;
  categories: string[];
}

export interface CheatSheetValidation {
  matches: Array<{
    pattern: CheatSheetPattern;
    matches: RegExpMatchArray[];
    lines: number[];
  }>;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  violations: Array<{
    pattern: string;
    severity: string;
    file: string;
    line: number;
    code: string;
    category: string;
    title: string;
    description: string;
    remediation: string;
    references: string[];
  }>;
  compliantPatterns: Array<{
    pattern: string;
    category: string;
    matches: number;
  }>;
  complianceScore: number;
  recommendations: string[];
}

export class OwaspCheatSheets {
  private patterns: Map<string, CheatSheetPattern> = new Map();
  private references: Map<string, CheatSheetReference> = new Map();

  constructor() {
    this.initializeCheatSheetPatterns();
    this.initializeReferences();
  }

  private initializeCheatSheetPatterns(): void {
    const patterns: CheatSheetPattern[] = [
      // Authentication Cheat Sheet patterns
      {
        id: 'cs-auth-001',
        sheetName: 'Authentication Cheat Sheet',
        category: 'authentication',
        pattern: 'Missing Password Complexity',
        description: 'Password requirements do not meet security standards',
        codePattern: /password.*=.*['"][^'"]{1,7}['"]|minlength.*[1-7][^0-9]/gi,
        severity: 'high',
        remediation: 'Implement strong password requirements: minimum 8 characters, complexity rules',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const password = "123"; // Too weak',
          secure: 'const passwordPolicy = { minLength: 12, requireComplexity: true };'
        },
        tags: ['authentication', 'password', 'policy'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },
      {
        id: 'cs-auth-002',
        sheetName: 'Authentication Cheat Sheet',
        category: 'authentication',
        pattern: 'Hardcoded Credentials',
        description: 'Authentication credentials are hardcoded in source code',
        codePattern: /(username|password|secret|key)\s*[=:]\s*['"][^'"]{3,}['"]/gi,
        severity: 'critical',
        remediation: 'Use environment variables or secure credential management systems',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const apiKey = "sk-1234567890abcdef";',
          secure: 'const apiKey = process.env.API_KEY;'
        },
        tags: ['authentication', 'credentials', 'secrets'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },

      // Session Management Cheat Sheet patterns
      {
        id: 'cs-session-001',
        sheetName: 'Session Management Cheat Sheet',
        category: 'session_management',
        pattern: 'Insecure Session Configuration',
        description: 'Session cookies lack security attributes',
        codePattern: /cookie.*(?!.*secure)(?!.*httponly)(?!.*samesite)/gi,
        severity: 'high',
        remediation: 'Configure cookies with secure, httpOnly, and sameSite attributes',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'res.cookie("session", token);',
          secure: 'res.cookie("session", token, { secure: true, httpOnly: true, sameSite: "strict" });'
        },
        tags: ['session', 'cookies', 'security'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },
      {
        id: 'cs-session-002',
        sheetName: 'Session Management Cheat Sheet',
        category: 'session_management',
        pattern: 'Predictable Session ID',
        description: 'Session IDs generated using weak randomness',
        codePattern: /sessionid.*math\.random|sessionid.*date\.now|sessionid.*\+\+/gi,
        severity: 'high',
        remediation: 'Use cryptographically secure random number generation for session IDs',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const sessionId = Math.random().toString();',
          secure: 'const sessionId = crypto.randomUUID();'
        },
        tags: ['session', 'randomness', 'security'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },

      // Input Validation Cheat Sheet patterns
      {
        id: 'cs-input-001',
        sheetName: 'Input Validation Cheat Sheet',
        category: 'input_validation',
        pattern: 'Missing Input Validation',
        description: 'User input is processed without validation',
        codePattern: /(req\.body|req\.query|req\.params|params\.|body\.).*(?!.*validate|.*sanitize|.*parse)/gi,
        severity: 'high',
        remediation: 'Validate and sanitize all user inputs using appropriate libraries',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const userId = req.params.id; db.findUser(userId);',
          secure: 'const userId = validator.isNumeric(req.params.id) ? parseInt(req.params.id) : null;'
        },
        tags: ['input', 'validation', 'sanitization'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },
      {
        id: 'cs-input-002',
        sheetName: 'Input Validation Cheat Sheet',
        category: 'input_validation',
        pattern: 'SQL Injection via String Concatenation',
        description: 'SQL queries constructed using string concatenation with user input',
        codePattern: /query.*\+.*req\.|query.*\$\{.*req\.|sql.*\+.*params|sql.*\$\{.*params/gi,
        severity: 'critical',
        remediation: 'Use parameterized queries or prepared statements',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const query = "SELECT * FROM users WHERE id = " + userId;',
          secure: 'const query = "SELECT * FROM users WHERE id = ?"; db.query(query, [userId]);'
        },
        tags: ['sql', 'injection', 'parameterized'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },

      // Cross-Site Scripting Prevention Cheat Sheet patterns
      {
        id: 'cs-xss-001',
        sheetName: 'Cross Site Scripting Prevention Cheat Sheet',
        category: 'xss_prevention',
        pattern: 'Unsafe innerHTML Usage',
        description: 'Direct use of innerHTML with user data without sanitization',
        codePattern: /dangerouslysetinnerhtml.*(?!.*dompurify|.*sanitize)/gi,
        severity: 'high',
        remediation: 'Sanitize HTML content using libraries like DOMPurify before rendering',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
        examples: {
          vulnerable: '<div dangerouslySetInnerHTML={{__html: userContent}} />',
          secure: '<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />'
        },
        tags: ['xss', 'sanitization', 'html'],
        context: ['*.tsx', '*.jsx']
      },
      {
        id: 'cs-xss-002',
        sheetName: 'Cross Site Scripting Prevention Cheat Sheet',
        category: 'xss_prevention',
        pattern: 'Missing CSP Header',
        description: 'Content Security Policy headers not implemented',
        codePattern: /res\.set.*(?!.*content-security-policy)/gi,
        severity: 'medium',
        remediation: 'Implement Content Security Policy headers to prevent XSS attacks',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'res.setHeader("X-Frame-Options", "DENY");',
          secure: 'res.setHeader("Content-Security-Policy", "default-src \'self\'; script-src \'self\'");'
        },
        tags: ['xss', 'csp', 'headers'],
        context: ['*.ts', '*.js']
      },

      // Cryptographic Storage Cheat Sheet patterns
      {
        id: 'cs-crypto-001',
        sheetName: 'Cryptographic Storage Cheat Sheet',
        category: 'cryptographic_storage',
        pattern: 'Weak Encryption Algorithm',
        description: 'Use of weak or deprecated cryptographic algorithms',
        codePattern: /(md5|sha1|des|rc4|blowfish)(?!.*comment)/gi,
        severity: 'high',
        remediation: 'Use strong encryption algorithms like AES-256, SHA-256 or better',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const hash = crypto.createHash("md5").update(data).digest("hex");',
          secure: 'const hash = crypto.createHash("sha256").update(data).digest("hex");'
        },
        tags: ['crypto', 'encryption', 'hashing'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },
      {
        id: 'cs-crypto-002',
        sheetName: 'Cryptographic Storage Cheat Sheet',
        category: 'cryptographic_storage',
        pattern: 'Missing Salt in Hashing',
        description: 'Password hashing without salt',
        codePattern: /hash.*password.*(?!.*salt|.*bcrypt|.*scrypt|.*argon2)/gi,
        severity: 'high',
        remediation: 'Use salted hashing algorithms like bcrypt, scrypt, or Argon2',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const hash = crypto.createHash("sha256").update(password).digest("hex");',
          secure: 'const hash = await bcrypt.hash(password, saltRounds);'
        },
        tags: ['crypto', 'password', 'salt', 'hashing'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },

      // Access Control Cheat Sheet patterns
      {
        id: 'cs-access-001',
        sheetName: 'Access Control Cheat Sheet',
        category: 'access_control',
        pattern: 'Missing Authorization Check',
        description: 'API endpoints lack proper authorization verification',
        codePattern: /export.*function.*(get|post|put|delete).*(?!.*auth|.*permission|.*role)/gi,
        severity: 'critical',
        remediation: 'Implement proper authorization checks for all API endpoints',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'export async function DELETE(req) { await deleteUser(req.params.id); }',
          secure: 'export async function DELETE(req) { await requireAuth(req); await deleteUser(req.params.id); }'
        },
        tags: ['access', 'authorization', 'api'],
        context: ['*/api/*', '*/route.*']
      },
      {
        id: 'cs-access-002',
        sheetName: 'Access Control Cheat Sheet',
        category: 'access_control',
        pattern: 'Insecure Direct Object Reference',
        description: 'Direct object access without ownership verification',
        codePattern: /(find|get|delete|update).*by.*id.*req\.params\.id.*(?!.*owner|.*user|.*permission)/gi,
        severity: 'high',
        remediation: 'Verify object ownership or permissions before allowing access',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'const doc = await Document.findById(req.params.id);',
          secure: 'const doc = await Document.findOne({ _id: req.params.id, owner: req.user.id });'
        },
        tags: ['access', 'ownership', 'idor'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },

      // Logging Cheat Sheet patterns
      {
        id: 'cs-log-001',
        sheetName: 'Logging Cheat Sheet',
        category: 'logging',
        pattern: 'Sensitive Data in Logs',
        description: 'Logging sensitive information that should not be recorded',
        codePattern: /log.*(?:password|secret|token|key|ssn|credit.*card)(?!.*\*\*\*|.*redacted)/gi,
        severity: 'medium',
        remediation: 'Remove or redact sensitive information from log messages',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'logger.info("User login with password: " + password);',
          secure: 'logger.info("User login attempt for user: " + username);'
        },
        tags: ['logging', 'sensitive', 'privacy'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      },
      {
        id: 'cs-log-002',
        sheetName: 'Logging Cheat Sheet',
        category: 'logging',
        pattern: 'Missing Security Event Logging',
        description: 'Security events not properly logged for monitoring',
        codePattern: /(login|logout|auth.*fail|permission.*denied|account.*locked)(?!.*log)/gi,
        severity: 'medium',
        remediation: 'Implement comprehensive security event logging',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
        examples: {
          vulnerable: 'if (authFailed) return res.status(401).send("Unauthorized");',
          secure: 'if (authFailed) { logger.warn("Auth failed for user", {userId, ip}); return res.status(401).send("Unauthorized"); }'
        },
        tags: ['logging', 'security', 'monitoring'],
        context: ['*.ts', '*.js', '*.tsx', '*.jsx']
      }
    ];

    patterns.forEach(pattern => {
      this.patterns.set(pattern.id, pattern);
    });

    logger.info(`Initialized ${patterns.length} OWASP cheat sheet patterns`);
  }

  private initializeReferences(): void {
    const references: CheatSheetReference[] = [
      {
        name: 'Authentication Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
        version: '4.0',
        description: 'Comprehensive guide for implementing secure authentication',
        categories: ['authentication', 'password', 'multi-factor']
      },
      {
        name: 'Session Management Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        version: '4.0',
        description: 'Best practices for secure session management',
        categories: ['session', 'cookies', 'token']
      },
      {
        name: 'Input Validation Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
        version: '4.0',
        description: 'Guidelines for proper input validation and sanitization',
        categories: ['input', 'validation', 'sanitization']
      },
      {
        name: 'Cross Site Scripting Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        version: '4.0',
        description: 'Comprehensive XSS prevention techniques',
        categories: ['xss', 'prevention', 'sanitization']
      },
      {
        name: 'Cryptographic Storage Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
        version: '4.0',
        description: 'Best practices for cryptographic storage and key management',
        categories: ['cryptography', 'storage', 'encryption']
      },
      {
        name: 'Authorization Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
        version: '4.0',
        description: 'Implementing proper authorization and access control',
        categories: ['authorization', 'access-control', 'rbac']
      },
      {
        name: 'Logging Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
        version: '4.0',
        description: 'Security logging and monitoring best practices',
        categories: ['logging', 'monitoring', 'security']
      }
    ];

    references.forEach(ref => {
      this.references.set(ref.name, ref);
    });

    logger.info(`Initialized ${references.length} OWASP cheat sheet references`);
  }

  public getPattern(id: string): CheatSheetPattern | undefined {
    return this.patterns.get(id);
  }

  public getPatternsByCategory(category: string): CheatSheetPattern[] {
    return Array.from(this.patterns.values()).filter(
      pattern => pattern.category === category
    );
  }

  public getPatternsByContext(context: string): CheatSheetPattern[] {
    return Array.from(this.patterns.values()).filter(
      pattern => pattern.context.some(ctx => 
        ctx === '*' || context.endsWith(ctx.replace('*', '')) || 
        context.includes(ctx.replace('*/', ''))
      )
    );
  }

  public getAllPatterns(): CheatSheetPattern[] {
    return Array.from(this.patterns.values());
  }

  public getReference(name: string): CheatSheetReference | undefined {
    return this.references.get(name);
  }

  public getAllReferences(): CheatSheetReference[] {
    return Array.from(this.references.values());
  }

  public searchPatterns(query: string): CheatSheetPattern[] {
    const lowercaseQuery = query.toLowerCase();
    return Array.from(this.patterns.values()).filter(
      pattern =>
        pattern.pattern.toLowerCase().includes(lowercaseQuery) ||
        pattern.description.toLowerCase().includes(lowercaseQuery) ||
        pattern.tags.some(tag => tag.toLowerCase().includes(lowercaseQuery))
    );
  }

  public validateCode(code: string, filePath: string): CheatSheetValidation {
    const applicablePatterns = this.getPatternsByContext(filePath);
    const results: Array<{
      pattern: CheatSheetPattern;
      matches: RegExpMatchArray[];
      lines: number[];
    }> = [];

    const summary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    const lines = code.split('\n');

    for (const pattern of applicablePatterns) {
      const patternMatches: RegExpMatchArray[] = [];
      const matchingLines: number[] = [];

      if (typeof pattern.codePattern === 'string') {
        // Simple string matching
        lines.forEach((line, index) => {
          if (line.includes(pattern.codePattern as string)) {
            patternMatches.push([line] as RegExpMatchArray);
            matchingLines.push(index + 1);
          }
        });
      } else {
        // RegExp matching
        lines.forEach((line, index) => {
          const matches = Array.from(line.matchAll(pattern.codePattern as RegExp));
          if (matches.length > 0) {
            patternMatches.push(...matches);
            matchingLines.push(index + 1);
          }
        });
      }

      if (patternMatches.length > 0) {
        results.push({
          pattern,
          matches: patternMatches,
          lines: matchingLines
        });

        summary.total += patternMatches.length;
        summary[pattern.severity] += patternMatches.length;
      }
    }

    // Generate violations and compliant patterns
    const violations = results.flatMap(result => 
      result.matches.map((match, idx) => ({
        pattern: result.pattern.pattern,
        severity: result.pattern.severity,
        file: filePath,
        line: result.lines[idx] || 0,
        code: match[0] || '',
        category: result.pattern.category,
        title: result.pattern.pattern,
        description: result.pattern.description,
        remediation: result.pattern.remediation,
        references: result.pattern.references
      }))
    );

    const compliantPatterns = applicablePatterns
      .filter(pattern => !results.some(r => r.pattern.id === pattern.id))
      .map(pattern => ({
        pattern: pattern.pattern,
        category: pattern.category,
        matches: 0
      }));

    const complianceScore = applicablePatterns.length > 0 
      ? Math.round(((applicablePatterns.length - results.length) / applicablePatterns.length) * 100)
      : 100;

    const recommendations = this.generateRecommendations(violations, complianceScore);

    return {
      matches: results,
      summary,
      violations,
      compliantPatterns,
      complianceScore,
      recommendations
    };
  }

  private generateRecommendations(violations: any[], complianceScore: number): string[] {
    const recommendations: string[] = [];
    
    if (violations.length === 0) {
      recommendations.push('✅ All OWASP Cheat Sheet patterns are being followed correctly');
      return recommendations;
    }

    const criticalViolations = violations.filter(v => v.severity === 'critical');
    const highViolations = violations.filter(v => v.severity === 'high');
    
    if (criticalViolations.length > 0) {
      recommendations.push(`🚨 Fix ${criticalViolations.length} critical security pattern violations immediately`);
    }
    
    if (highViolations.length > 0) {
      recommendations.push(`⚠️ Address ${highViolations.length} high-severity security pattern violations`);
    }

    if (complianceScore < 50) {
      recommendations.push('📚 Review OWASP Cheat Sheets for comprehensive security guidance');
      recommendations.push('🔍 Conduct security code review with focus on authentication and session management');
    } else if (complianceScore < 80) {
      recommendations.push('📖 Implement remaining OWASP security patterns');
      recommendations.push('🛡️ Strengthen input validation and output encoding');
    }

    return recommendations.slice(0, 5);
  }

  public getRemediationGuidance(patternId: string): {
    pattern: CheatSheetPattern;
    guidance: string;
    references: string[];
    examples: { vulnerable: string; secure: string };
  } | null {
    const pattern = this.getPattern(patternId);
    if (!pattern) return null;

    return {
      pattern,
      guidance: pattern.remediation,
      references: pattern.references,
      examples: pattern.examples
    };
  }

  public generateSecurityReport(code: string, filePath: string): {
    filePath: string;
    timestamp: string;
    summary: {
      totalIssues: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    findings: Array<{
      id: string;
      pattern: string;
      severity: string;
      line: number;
      description: string;
      remediation: string;
      references: string[];
    }>;
    recommendations: string[];
  } {
    const validation = this.validateCode(code, filePath);
    const findings: Array<{
      id: string;
      pattern: string;
      severity: string;
      line: number;
      description: string;
      remediation: string;
      references: string[];
    }> = [];

    validation.matches.forEach(match => {
      match.lines.forEach(line => {
        findings.push({
          id: match.pattern.id,
          pattern: match.pattern.pattern,
          severity: match.pattern.severity,
          line,
          description: match.pattern.description,
          remediation: match.pattern.remediation,
          references: match.pattern.references
        });
      });
    });

    const recommendations: string[] = [];
    if (validation.summary.critical > 0) {
      recommendations.push(`🚨 Address ${validation.summary.critical} critical security issues immediately`);
    }
    if (validation.summary.high > 0) {
      recommendations.push(`⚠️ Fix ${validation.summary.high} high-severity security issues`);
    }
    if (validation.summary.total === 0) {
      recommendations.push('✅ No OWASP cheat sheet violations detected');
    } else {
      recommendations.push(`📚 Review OWASP cheat sheets for comprehensive security guidance`);
    }

    return {
      filePath,
      timestamp: new Date().toISOString(),
      summary: {
        totalIssues: validation.summary.total,
        critical: validation.summary.critical,
        high: validation.summary.high,
        medium: validation.summary.medium,
        low: validation.summary.low
      },
      findings: findings.slice(0, 50), // Limit findings for readability
      recommendations
    };
  }
}