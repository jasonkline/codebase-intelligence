import { SecurityScanner, SecurityScanOptions } from '../../security/SecurityScanner';
import { AuthPatternAnalyzer, AuthFlow } from '../../security/AuthPatternAnalyzer';
import { RLSAnalyzer, RLSAnalysisResult } from '../../security/RLSAnalyzer';
import { OWASPScanner, OWASPScanResult } from '../../security/OWASPScanner';
import { OwaspCheatSheets } from '../../security/OwaspCheatSheets';
import { ASVSVerifier } from '../../security/ASVSVerifier';
import { ApiSecurityScanner } from '../../security/ApiSecurityScanner';
import { AISecurityScanner } from '../../security/AISecurityScanner';
import { MobileSecurityScanner } from '../../security/MobileSecurityScanner';
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
  private owaspCheatSheets: OwaspCheatSheets;
  private asvsVerifier: ASVSVerifier;
  private apiSecurityScanner: ApiSecurityScanner;
  private aiSecurityScanner: AISecurityScanner;
  private mobileSecurityScanner: MobileSecurityScanner;
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
    this.owaspCheatSheets = new OwaspCheatSheets();
    this.asvsVerifier = new ASVSVerifier();
    this.apiSecurityScanner = new ApiSecurityScanner();
    this.aiSecurityScanner = new AISecurityScanner();
    this.mobileSecurityScanner = new MobileSecurityScanner();
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
  }

  getToolDefinitions() {
    return [
      {
        name: 'analyze_security',
        description: 'Perform comprehensive security analysis with OWASP compliance mapping. Detects vulnerabilities including SQL injection, XSS, hardcoded secrets, missing auth checks, and maps findings to OWASP Top 10, ASVS controls, API Security Top 10, and Mobile Top 10.',
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
      {
        name: 'analyze_owasp_compliance',
        description: 'Perform OWASP-specific compliance analysis including cheat sheet validation, ASVS assessment, API security scanning, AI security analysis, and mobile security scanning.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to file or directory to analyze',
            },
            standards: {
              type: 'array',
              items: {
                type: 'string',
                enum: ['cheatsheets', 'asvs', 'api_security', 'ai_security', 'mobile_security']
              },
              description: 'OWASP standards to apply (default: all)',
            },
            asvsLevel: {
              type: 'number',
              enum: [1, 2, 3],
              description: 'ASVS verification level (1-3, default: 2)',
            },
          },
          required: ['path'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const securityToolNames = ['analyze_security', 'check_auth_pattern', 'find_vulnerabilities', 'analyze_owasp_compliance'];
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
        case 'analyze_owasp_compliance':
          return await this.handleAnalyzeOwaspCompliance(args);
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

    // Run comprehensive security analysis with concurrent scanning including OWASP standards
    const [
      securityFindings,
      rlsAnalysis,
      owaspResults,
      cheatSheetValidation,
      apiSecurityResults,
      aiSecurityResults,
      mobileSecurityResults
    ] = await Promise.all([
      this.securityScanner.scanFile(path, options),
      this.rlsAnalyzer.analyzeFile(path),
      this.owaspScanner.scanFile(path),
      this.owaspCheatSheets.validateCode('', path),
      this.apiSecurityScanner.scanDirectory(path),
      this.aiSecurityScanner.scanDirectory(path),
      this.mobileSecurityScanner.scanDirectory(path)
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
        owaspIssues: owaspResults.summary.total,
        apiSecurityIssues: apiSecurityResults.summary.total,
        aiSecurityIssues: aiSecurityResults.summary.total,
        mobileSecurityIssues: mobileSecurityResults.summary.total
      },
      owaspCompliance: {
        cheatSheets: {
          compliantPatterns: cheatSheetValidation.compliantPatterns.length,
          violations: cheatSheetValidation.violations.length,
          score: cheatSheetValidation.complianceScore
        },
        apiSecurity: {
          totalIssues: apiSecurityResults.summary.total,
          criticalIssues: apiSecurityResults.summary.critical,
          categories: Array.from(apiSecurityResults.summary.categories.entries()).map(([cat, count]) => ({ category: cat, count }))
        },
        aiSecurity: {
          hasAIComponents: aiSecurityResults.analysis.hasMLModels,
          aiLibraries: aiSecurityResults.analysis.aiLibraries,
          totalIssues: aiSecurityResults.summary.total,
          recommendations: aiSecurityResults.recommendations.slice(0, 3)
        },
        mobileSecurity: {
          hasMobileComponents: mobileSecurityResults.analysis.hasMobileFrameworks,
          platforms: mobileSecurityResults.analysis.detectedPlatforms,
          totalIssues: mobileSecurityResults.summary.total
        }
      },
      findings: {
        security: securityFindings.slice(0, 20), // Limit for readability
        rls: rlsAnalysis.findings.slice(0, 10),
        owasp: owaspResults.vulnerabilities.slice(0, 10),
        apiSecurity: apiSecurityResults.vulnerabilities.slice(0, 10),
        aiSecurity: aiSecurityResults.vulnerabilities.slice(0, 10),
        mobileSecurity: mobileSecurityResults.vulnerabilities.slice(0, 10)
      },
      criticalFindings: [
        ...report.criticalFindings,
        ...apiSecurityResults.vulnerabilities.filter(v => v.severity === 'critical'),
        ...aiSecurityResults.vulnerabilities.filter(v => v.severity === 'critical'),
        ...mobileSecurityResults.vulnerabilities.filter(v => v.severity === 'critical')
      ],
      recommendations: [
        ...report.recommendations,
        ...rlsAnalysis.recommendations.slice(0, 3),
        ...cheatSheetValidation.recommendations.slice(0, 3),
        ...apiSecurityResults.recommendations.slice(0, 2),
        ...aiSecurityResults.recommendations.slice(0, 2),
        ...mobileSecurityResults.recommendations.slice(0, 2)
      ],
      metadata: {
        scanDuration: Date.now() - Date.now(), // Will be filled by performance monitor
        toolsUsed: ['SecurityScanner', 'RLSAnalyzer', 'OWASPScanner', 'OwaspCheatSheets', 'ApiSecurityScanner', 'AISecurityScanner', 'MobileSecurityScanner'],
        confidence: 'high',
        owaspStandardsApplied: ['Top 10', 'API Security Top 10', 'AI Security Guide', 'Mobile Top 10', 'Cheat Sheets']
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

  private async handleAnalyzeOwaspCompliance(args: any): Promise<{ content: any[] }> {
    logger.info('OWASP compliance analysis tool called', { args });

    const { path, standards = ['cheatsheets', 'asvs', 'api_security', 'ai_security', 'mobile_security'], asvsLevel = 2 } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Starting OWASP compliance analysis of: ${path}`);

    const results: any = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      standardsAnalyzed: standards,
      compliance: {}
    };

    // Run selected OWASP standard analyses
    const analysisPromises: Promise<any>[] = [];

    if (standards.includes('cheatsheets')) {
      analysisPromises.push(
        Promise.resolve(this.owaspCheatSheets.validateCode('', path)).then(result => ({ type: 'cheatsheets', result }))
      );
    }

    if (standards.includes('asvs')) {
      analysisPromises.push(
        this.asvsVerifier.assessProject(path, asvsLevel).then(result => ({ type: 'asvs', result }))
      );
    }

    if (standards.includes('api_security')) {
      analysisPromises.push(
        this.apiSecurityScanner.scanDirectory(path).then(result => ({ type: 'api_security', result }))
      );
    }

    if (standards.includes('ai_security')) {
      analysisPromises.push(
        this.aiSecurityScanner.scanDirectory(path).then(result => ({ type: 'ai_security', result }))
      );
    }

    if (standards.includes('mobile_security')) {
      analysisPromises.push(
        this.mobileSecurityScanner.scanDirectory(path).then(result => ({ type: 'mobile_security', result }))
      );
    }

    const analysisResults = await Promise.all(analysisPromises);

    // Process results
    let totalIssues = 0;
    let criticalIssues = 0;
    const recommendations: string[] = [];

    analysisResults.forEach(({ type, result }) => {
      switch (type) {
        case 'cheatsheets':
          results.compliance.cheatsheets = {
            complianceScore: result.complianceScore,
            compliantPatterns: result.compliantPatterns.length,
            violations: result.violations.length,
            topViolations: result.violations.slice(0, 5).map((v: any) => ({
              pattern: v.pattern,
              severity: v.severity,
              file: v.file,
              line: v.line
            }))
          };
          totalIssues += result.violations.length;
          recommendations.push(...result.recommendations.slice(0, 2));
          break;

        case 'asvs':
          results.compliance.asvs = {
            level: asvsLevel,
            overallScore: result.overallScore,
            passedControls: result.controlResults.filter((c: any) => c.status === 'pass').length,
            failedControls: result.controlResults.filter((c: any) => c.status === 'fail').length,
            totalControls: result.controlResults.length,
            criticalFailures: result.controlResults.filter((c: any) => c.status === 'fail' && c.severity === 'critical').length
          };
          totalIssues += result.controlResults.filter((c: any) => c.status === 'fail').length;
          criticalIssues += result.controlResults.filter((c: any) => c.status === 'fail' && c.severity === 'critical').length;
          recommendations.push(...result.recommendations.slice(0, 3));
          break;

        case 'api_security':
          results.compliance.apiSecurity = {
            totalVulnerabilities: result.summary.total,
            criticalVulnerabilities: result.summary.critical,
            highVulnerabilities: result.summary.high,
            categories: Array.from(result.summary.categories.entries()).map(([cat, count]) => ({ category: cat, count })),
            endpoints: result.analysis.endpoints.length
          };
          totalIssues += result.summary.total;
          criticalIssues += result.summary.critical;
          recommendations.push(...result.recommendations.slice(0, 2));
          break;

        case 'ai_security':
          results.compliance.aiSecurity = {
            hasAIComponents: result.analysis.hasMLModels,
            aiLibraries: result.analysis.aiLibraries,
            totalVulnerabilities: result.summary.total,
            criticalVulnerabilities: result.summary.critical,
            mlRisks: result.vulnerabilities.filter((v: any) => v.mlRisk === 'high').length
          };
          totalIssues += result.summary.total;
          criticalIssues += result.summary.critical;
          recommendations.push(...result.recommendations.slice(0, 2));
          break;

        case 'mobile_security':
          results.compliance.mobileSecurity = {
            hasMobileComponents: result.analysis.hasMobileFrameworks,
            detectedPlatforms: result.analysis.detectedPlatforms,
            totalVulnerabilities: result.summary.total,
            criticalVulnerabilities: result.summary.critical,
            frameworks: result.analysis.mobileFrameworks
          };
          totalIssues += result.summary.total;
          criticalIssues += result.summary.critical;
          recommendations.push(...result.recommendations.slice(0, 2));
          break;
      }
    });

    results.summary = {
      totalIssues,
      criticalIssues,
      standardsCompliant: totalIssues === 0,
      complianceLevel: criticalIssues === 0 ? (totalIssues < 5 ? 'high' : 'medium') : 'low'
    };

    results.recommendations = recommendations.slice(0, 10); // Limit recommendations

    logger.info(`OWASP compliance analysis completed. Total issues: ${totalIssues}, Critical: ${criticalIssues}`);
    return { content: [results] };
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up SecurityTools...');
    // Cleanup any resources if needed
    logger.info('SecurityTools cleanup completed');
  }
}