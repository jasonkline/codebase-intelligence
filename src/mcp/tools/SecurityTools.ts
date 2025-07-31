import { SecurityScanner, SecurityScanOptions } from '../../security/SecurityScanner';
import { AuthPatternAnalyzer, AuthFlow } from '../../security/AuthPatternAnalyzer';
import { RLSAnalyzer, RLSAnalysisResult } from '../../security/RLSAnalyzer';
import { OWASPScanner, OWASPScanResult } from '../../security/OWASPScanner';
import { SecurityFinding, VulnerabilitySeverity, VulnerabilityCategory, vulnerabilityDatabase } from '../../security/VulnerabilityDatabase';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import logger from '../../utils/logger';

export interface SecurityAnalysisArgs {
  path: string;
  options?: SecurityScanOptions;
}

export interface AuthPatternAnalysisArgs {
  path: string;
}

export interface VulnerabilitySearchArgs {
  path: string;
  severity?: VulnerabilitySeverity;
  category?: VulnerabilityCategory;
  maxResults?: number;
}

export class SecurityTools {
  private securityScanner: SecurityScanner;
  private authPatternAnalyzer: AuthPatternAnalyzer;
  private rlsAnalyzer: RLSAnalyzer;
  private owaspScanner: OWASPScanner;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    securityScanner: SecurityScanner,
    authPatternAnalyzer: AuthPatternAnalyzer,
    rlsAnalyzer: RLSAnalyzer,
    owaspScanner: OWASPScanner,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor
  ) {
    this.securityScanner = securityScanner;
    this.authPatternAnalyzer = authPatternAnalyzer;
    this.rlsAnalyzer = rlsAnalyzer;
    this.owaspScanner = owaspScanner;
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
  }

  getToolDefinitions() {
    return [
      {
        name: 'analyze_security',
        description: 'Perform comprehensive security analysis on a file or directory. Detects vulnerabilities including SQL injection, XSS, hardcoded secrets, missing auth checks, and OWASP Top 10 issues.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to file or directory to analyze',
            },
            options: {
              type: 'object',
              properties: {
                includeCategories: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Vulnerability categories to include (authentication, injection, xss, etc.)',
                },
                excludeCategories: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Vulnerability categories to exclude',
                },
                minSeverity: {
                  type: 'string',
                  enum: ['critical', 'high', 'medium', 'low', 'info'],
                  description: 'Minimum severity level to report',
                },
                maxFindings: {
                  type: 'number',
                  description: 'Maximum number of findings to return',
                },
              },
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'check_auth_pattern',
        description: 'Analyze authentication and authorization patterns in code. Maps auth flows, RBAC implementation, and identifies security gaps.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to file or directory to analyze',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'find_vulnerabilities',
        description: 'Search for specific types of security vulnerabilities. Returns detailed findings with remediation guidance.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to file or directory to scan',
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Filter by severity level',
            },
            category: {
              type: 'string',
              enum: ['authentication', 'authorization', 'injection', 'cross_site_scripting', 'sensitive_data_exposure', 'row_level_security'],
              description: 'Filter by vulnerability category',
            },
            maxResults: {
              type: 'number',
              description: 'Maximum number of results to return',
              default: 50,
            },
          },
          required: ['path'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const securityToolNames = ['analyze_security', 'check_auth_pattern', 'find_vulnerabilities'];
    return toolNames.some(name => securityToolNames.includes(name));
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'analyze_security':
          return await this.handleAnalyzeSecurity(args as SecurityAnalysisArgs);
        case 'check_auth_pattern':
          return await this.handleCheckAuthPattern(args as AuthPatternAnalysisArgs);
        case 'find_vulnerabilities':
          return await this.handleFindVulnerabilities(args as VulnerabilitySearchArgs);
        default:
          throw new Error(`Unknown security tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error in security tool ${name}:`, error);
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordSecurityScan(name, duration);
    }
  }

  private async handleAnalyzeSecurity(args: SecurityAnalysisArgs): Promise<{ content: any[] }> {
    logger.info('Security analysis tool called', { args });

    const { path, options = {} } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Starting security analysis of: ${path}`);

    // Run comprehensive security analysis with concurrent scanning
    const [
      securityFindings,
      rlsAnalysis,
      owaspResults
    ] = await Promise.all([
      this.securityScanner.scanFile(path, options),
      this.rlsAnalyzer.analyzeFile(path),
      this.owaspScanner.scanFile(path)
    ]);

    // Generate comprehensive report
    const report = vulnerabilityDatabase.generateReport(securityFindings);
    
    const result = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      summary: {
        totalFindings: securityFindings.length,
        criticalIssues: report.criticalFindings.length,
        bySeverity: report.summary.bySeverity,
        byCategory: report.summary.byCategory,
        rlsIssues: rlsAnalysis.findings.length,
        owaspIssues: owaspResults.summary.total
      },
      findings: {
        security: securityFindings.slice(0, 20), // Limit for readability
        rls: rlsAnalysis.findings.slice(0, 10),
        owasp: owaspResults.vulnerabilities.slice(0, 10)
      },
      criticalFindings: report.criticalFindings,
      recommendations: [
        ...report.recommendations,
        ...rlsAnalysis.recommendations.slice(0, 3)
      ],
      metadata: {
        scanDuration: Date.now() - Date.now(), // Will be filled by performance monitor
        toolsUsed: ['SecurityScanner', 'RLSAnalyzer', 'OWASPScanner'],
        confidence: 'high'
      }
    };

    logger.info(`Security analysis completed. Found ${securityFindings.length} issues`);
    return { content: [result] };
  }

  private async handleCheckAuthPattern(args: AuthPatternAnalysisArgs): Promise<{ content: any[] }> {
    logger.info('Auth pattern analysis tool called', { args });

    const { path } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Analyzing auth patterns in: ${path}`);

    // Run auth pattern analysis
    const [authFlow, rbacMapping] = await Promise.all([
      this.authPatternAnalyzer.analyzeFile(path),
      this.authPatternAnalyzer.mapRBACImplementation(path)
    ]);

    const result = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      authFlow: {
        entryPoints: authFlow.entryPoints.length,
        authChecks: authFlow.authChecks.length,
        roleChecks: authFlow.roleChecks.length,
        permissionChecks: authFlow.permissionChecks.length,
        gaps: authFlow.gaps.length
      },
      rbac: {
        roles: rbacMapping.roles,
        permissions: rbacMapping.permissions,
        issues: rbacMapping.issues.length
      },
      patterns: {
        authPatterns: authFlow.authChecks.map(p => ({
          name: p.name,
          type: p.type,
          line: p.line,
          confidence: p.confidence
        })).slice(0, 10),
        rolePatterns: authFlow.roleChecks.map(p => ({
          name: p.name,
          type: p.type,
          line: p.line,
          confidence: p.confidence
        })).slice(0, 10)
      },
      securityGaps: authFlow.gaps.map(gap => ({
        title: gap.title,
        severity: gap.severity,
        line: gap.lineStart,
        remediation: gap.remediation
      })),
      recommendations: [
        authFlow.entryPoints.length === 0 ? 'No API entry points detected' : `Found ${authFlow.entryPoints.length} API entry points`,
        authFlow.authChecks.length === 0 ? 'No authentication checks detected - this is a critical security issue' : `Found ${authFlow.authChecks.length} authentication checks`,
        authFlow.roleChecks.length === 0 ? 'No role-based checks detected - consider implementing RBAC' : `Found ${authFlow.roleChecks.length} role-based checks`,
        rbacMapping.roles.length === 0 ? 'No roles identified in the codebase' : `Identified roles: ${rbacMapping.roles.join(', ')}`
      ]
    };

    logger.info(`Auth pattern analysis completed. Found ${authFlow.authChecks.length} auth checks, ${authFlow.gaps.length} gaps`);
    return { content: [result] };
  }

  private async handleFindVulnerabilities(args: VulnerabilitySearchArgs): Promise<{ content: any[] }> {
    logger.info('Vulnerability search tool called', { args });

    const { path, severity, category, maxResults = 50 } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Searching for vulnerabilities in: ${path}`);

    // Build scan options based on filters
    const scanOptions: SecurityScanOptions = {};
    
    if (severity) {
      scanOptions.minSeverity = severity as VulnerabilitySeverity;
    }
    
    if (category) {
      scanOptions.includeCategories = [category as VulnerabilityCategory];
    }
    
    if (maxResults) {
      scanOptions.maxFindings = maxResults;
    }

    // Run vulnerability scan
    const findings = await this.securityScanner.scanFile(path, scanOptions);
    
    // Prioritize and categorize findings
    const prioritizedFindings = vulnerabilityDatabase.prioritizeFindings(findings);
    const categorizedFindings = vulnerabilityDatabase.categorizeFindings(prioritizedFindings);

    const result = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      filters: {
        severity: severity || 'all',
        category: category || 'all',
        maxResults
      },
      summary: {
        total: findings.length,
        critical: findings.filter(f => f.severity === VulnerabilitySeverity.CRITICAL).length,
        high: findings.filter(f => f.severity === VulnerabilitySeverity.HIGH).length,
        medium: findings.filter(f => f.severity === VulnerabilitySeverity.MEDIUM).length,
        low: findings.filter(f => f.severity === VulnerabilitySeverity.LOW).length
      },
      findings: prioritizedFindings.slice(0, maxResults).map(finding => ({
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        line: finding.lineStart,
        code: finding.code.slice(0, 200) + (finding.code.length > 200 ? '...' : ''),
        description: finding.description,
        remediation: finding.remediation,
        cweId: finding.cweId,
        confidence: finding.confidence
      })),
      categories: Array.from(categorizedFindings.entries()).map(([cat, findings]) => ({
        category: cat,
        count: findings.length,
        criticalCount: findings.filter(f => f.severity === VulnerabilitySeverity.CRITICAL).length
      })),
      recommendations: [
        findings.length === 0 ? 'No vulnerabilities found with current filters' : `Found ${findings.length} potential security issues`,
        ...Array.from(categorizedFindings.keys()).map(cat => 
          `${cat}: ${categorizedFindings.get(cat)?.length || 0} issues`
        ).slice(0, 5)
      ]
    };

    logger.info(`Vulnerability search completed. Found ${findings.length} issues`);
    return { content: [result] };
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up SecurityTools...');
    // Cleanup any resources if needed
    logger.info('SecurityTools cleanup completed');
  }
}