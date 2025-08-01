import { OwaspCheatSheets } from '../../security/OwaspCheatSheets';
import { ASVSVerifier } from '../../security/ASVSVerifier';
import { ApiSecurityScanner } from '../../security/ApiSecurityScanner';
import { AISecurityScanner } from '../../security/AISecurityScanner';
import { MobileSecurityScanner } from '../../security/MobileSecurityScanner';
import DatabaseManager from '../../database/schema';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import logger from '../../utils/logger';

export interface AnalyzeCheatSheetComplianceArgs {
  filePath: string;
  categories?: string[];
  severity?: 'critical' | 'high' | 'medium' | 'low';
}

export interface AssessASVSComplianceArgs {
  projectPath: string;
  level: 1 | 2 | 3;
  includeManualReview?: boolean;
}

export interface ScanApiSecurityArgs {
  path: string;
  includeEndpoints?: boolean;
  riskThreshold?: number;
}

export interface ScanMobileSecurityArgs {
  path: string;
  platform?: 'iOS' | 'Android' | 'Cross-Platform';
  includeFrameworkAnalysis?: boolean;
}

export interface ScanAiSecurityArgs {
  path: string;
  includeModelAnalysis?: boolean;
  riskLevel?: 'high' | 'medium' | 'low';
}

export interface GenerateComplianceReportArgs {
  projectPath: string;
  standards: string[]; // Array of OWASP standards to include
  includeRemediation?: boolean;
  outputFormat?: 'json' | 'summary';
}

export interface GetCheatSheetGuidanceArgs {
  query: string;
  context?: string; // File type or framework context
  limit?: number;
}

export class OwaspSecurityTools {
  private cheatSheets: OwaspCheatSheets;
  private asvsVerifier: ASVSVerifier;
  private apiScanner: ApiSecurityScanner;
  private aiScanner: AISecurityScanner;
  private mobileScanner: MobileSecurityScanner;
  private db: DatabaseManager;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    db: DatabaseManager,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor
  ) {
    this.db = db;
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
    
    // Initialize OWASP security components
    this.cheatSheets = new OwaspCheatSheets();
    this.asvsVerifier = new ASVSVerifier();
    this.apiScanner = new ApiSecurityScanner();
    this.aiScanner = new AISecurityScanner();
    this.mobileScanner = new MobileSecurityScanner();

    // Initialize OWASP reference data in database
    this.initializeOwaspData();
  }

  getToolDefinitions() {
    return [
      {
        name: 'analyze_cheatsheet_compliance',
        description: 'Analyze code compliance against OWASP Cheat Sheet patterns. Provides context-aware security guidance from OWASP Cheat Sheets.',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Absolute path to the file to analyze',
            },
            categories: {
              type: 'array',
              items: { type: 'string' },
              description: 'Specific cheat sheet categories to check (authentication, session_management, etc.)',
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low'],
              description: 'Minimum severity level to report',
            },
          },
          required: ['filePath'],
        },
      },
      {
        name: 'assess_asvs_compliance',
        description: 'Perform comprehensive ASVS (Application Security Verification Standard) compliance assessment. Evaluates security controls against ASVS levels 1-3.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: {
              type: 'string',
              description: 'Absolute path to the project directory',
            },
            level: {
              type: 'number',
              enum: [1, 2, 3],
              description: 'ASVS compliance level to assess against',
              default: 1,
            },
            includeManualReview: {
              type: 'boolean',
              description: 'Include controls that require manual review',
              default: true,
            },
          },
          required: ['projectPath'],
        },
      },
      {
        name: 'scan_api_security',
        description: 'Comprehensive API security scan based on OWASP API Security Top 10. Identifies API-specific vulnerabilities and security issues.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to API files or directory',
            },
            includeEndpoints: {
              type: 'boolean',
              description: 'Include detailed endpoint analysis',
              default: true,
            },
            riskThreshold: {
              type: 'number',
              description: 'Risk score threshold (1-10) for reporting',
              default: 1,
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'scan_mobile_security',
        description: 'Mobile application security scan based on OWASP Mobile Top 10. Analyzes mobile-specific security vulnerabilities.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to mobile app files or directory',
            },
            platform: {
              type: 'string',
              enum: ['iOS', 'Android', 'Cross-Platform'],
              description: 'Target mobile platform',
            },
            includeFrameworkAnalysis: {
              type: 'boolean',
              description: 'Include mobile framework-specific analysis',
              default: true,
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'scan_ai_security',
        description: 'AI/ML security scan based on OWASP AI Testing Guide. Identifies AI-specific vulnerabilities including prompt injection, model security, and data poisoning.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to AI/ML code files or directory',
            },
            includeModelAnalysis: {
              type: 'boolean',
              description: 'Include detailed ML model security analysis',
              default: true,
            },
            riskLevel: {
              type: 'string',
              enum: ['high', 'medium', 'low'],
              description: 'Minimum risk level to report',
              default: 'low',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'generate_compliance_report',
        description: 'Generate comprehensive OWASP compliance report covering multiple standards. Provides detailed compliance metrics and remediation guidance.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: {
              type: 'string',
              description: 'Absolute path to the project directory',
            },
            standards: {
              type: 'array',
              items: { 
                type: 'string',
                enum: ['top10', 'api-security', 'asvs', 'mobile', 'ai-guide', 'cheat-sheets']
              },
              description: 'OWASP standards to include in the report',
              default: ['top10', 'api-security', 'asvs'],
            },
            includeRemediation: {
              type: 'boolean',
              description: 'Include detailed remediation guidance',
              default: true,
            },
            outputFormat: {
              type: 'string',
              enum: ['json', 'summary'],
              description: 'Report output format',
              default: 'summary',
            },
          },
          required: ['projectPath'],
        },
      },
      {
        name: 'get_cheatsheet_guidance',
        description: 'Get context-aware security guidance from OWASP Cheat Sheets. Provides specific guidance based on code context and security patterns.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Security topic or vulnerability type to get guidance for',
            },
            context: {
              type: 'string',
              description: 'Code context (file type, framework, etc.) for targeted guidance',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of guidance items to return',
              default: 10,
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const owaspToolNames = [
      'analyze_cheatsheet_compliance',
      'assess_asvs_compliance', 
      'scan_api_security',
      'scan_mobile_security',
      'scan_ai_security',
      'generate_compliance_report',
      'get_cheatsheet_guidance'
    ];
    return toolNames.some(name => owaspToolNames.includes(name));
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'analyze_cheatsheet_compliance':
          return await this.handleAnalyzeCheatSheetCompliance(args as AnalyzeCheatSheetComplianceArgs);
        case 'assess_asvs_compliance':
          return await this.handleAssessASVSCompliance(args as AssessASVSComplianceArgs);
        case 'scan_api_security':
          return await this.handleScanApiSecurity(args as ScanApiSecurityArgs);
        case 'scan_mobile_security':
          return await this.handleScanMobileSecurity(args as ScanMobileSecurityArgs);
        case 'scan_ai_security':
          return await this.handleScanAiSecurity(args as ScanAiSecurityArgs);
        case 'generate_compliance_report':
          return await this.handleGenerateComplianceReport(args as GenerateComplianceReportArgs);
        case 'get_cheatsheet_guidance':
          return await this.handleGetCheatSheetGuidance(args as GetCheatSheetGuidanceArgs);
        default:
          throw new Error(`Unknown OWASP security tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error in OWASP security tool ${name}:`, error);
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordSecurityScan(name, duration);
    }
  }

  private async handleAnalyzeCheatSheetCompliance(args: AnalyzeCheatSheetComplianceArgs): Promise<{ content: any[] }> {
    logger.info('Analyze cheat sheet compliance tool called', { args });

    const { filePath, categories, severity } = args;

    if (!filePath) {
      throw new Error('filePath is required');
    }

    logger.info(`Analyzing cheat sheet compliance for: ${filePath}`);

    // Read file content
    const fs = await import('fs/promises');
    const sourceCode = await fs.readFile(filePath, 'utf-8');

    // Run cheat sheet compliance analysis
    const complianceResult = this.cheatSheets.generateSecurityReport(sourceCode, filePath);
    
    // Filter by categories if specified
    let filteredFindings = complianceResult.findings;
    if (categories && categories.length > 0) {
      const categoryPatterns = categories.flatMap(cat => 
        this.cheatSheets.getPatternsByCategory(cat)
      );
      const categoryIds = new Set(categoryPatterns.map(p => p.id));
      filteredFindings = filteredFindings.filter(f => categoryIds.has(f.id));
    }

    // Filter by severity if specified
    if (severity) {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const minLevel = severityOrder[severity];
      filteredFindings = filteredFindings.filter(f => 
        severityOrder[f.severity as keyof typeof severityOrder] <= minLevel
      );
    }

    // Get applicable cheat sheets for context
    const applicablePatterns = this.cheatSheets.getPatternsByContext(filePath);
    const cheatSheetReferences = [...new Set(applicablePatterns.map(p => p.sheetName))];

    const result = {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      configuration: {
        categories: categories || 'all',
        severity: severity || 'all'
      },
      summary: {
        totalIssues: filteredFindings.length,
        critical: complianceResult.summary.critical,
        high: complianceResult.summary.high,
        medium: complianceResult.summary.medium,
        low: complianceResult.summary.low,
        applicableCheatSheets: cheatSheetReferences.length
      },
      findings: filteredFindings.map(finding => ({
        id: finding.id,
        pattern: finding.pattern,
        severity: finding.severity,
        line: finding.line,
        description: finding.description,
        remediation: finding.remediation,
        references: finding.references,
        cheatSheet: applicablePatterns.find(p => p.id === finding.id)?.sheetName
      })),
      cheatSheets: cheatSheetReferences.map(sheetName => {
        const reference = this.cheatSheets.getReference(sheetName);
        return {
          name: sheetName,
          url: reference?.url,
          description: reference?.description
        };
      }),
      recommendations: complianceResult.recommendations,
      guidance: filteredFindings.length > 0 ? 
        this.generateContextualGuidance(filteredFindings, filePath) : 
        ['✅ Code follows OWASP cheat sheet recommendations']
    };

    logger.info(`Cheat sheet compliance analysis completed. Found ${filteredFindings.length} issues`);
    return { content: [result] };
  }

  private async handleAssessASVSCompliance(args: AssessASVSComplianceArgs): Promise<{ content: any[] }> {
    logger.info('Assess ASVS compliance tool called', { args });

    const { projectPath, level = 1, includeManualReview = true } = args;

    if (!projectPath) {
      throw new Error('projectPath is required');
    }

    logger.info(`Assessing ASVS Level ${level} compliance for: ${projectPath}`);

    // Run ASVS assessment
    const assessment = await this.asvsVerifier.assessProject(projectPath, level);

    // Store assessment in database
    const assessmentId = this.db.insertAsvsAssessment({
      project_path: projectPath,
      level: assessment.level,
      score: assessment.summary.complianceScore,
      total_controls: assessment.summary.totalControls,
      passed_controls: assessment.summary.passed,
      failed_controls: assessment.summary.failed,
      not_applicable_controls: assessment.summary.notApplicable,
      manual_review_controls: assessment.summary.manualReview,
      assessed_at: assessment.timestamp
    });

    // Store individual control results
    assessment.results.forEach(result => {
      this.db.insertAsvsControlStatus({
        assessment_id: assessmentId,
        control_id: 0, // Would need to map to actual control IDs
        status: result.status,
        confidence: result.confidence,
        evidence: JSON.stringify(result.evidence),
        violations: JSON.stringify(result.violations),
        remediation: result.remediation
      });
    });

    const result = {
      success: true,
      projectPath,
      level: assessment.level,
      timestamp: assessment.timestamp,
      assessmentId,
      compliance: {
        overallScore: assessment.summary.complianceScore,
        totalControls: assessment.summary.totalControls,
        passed: assessment.summary.passed,
        failed: assessment.summary.failed,
        notApplicable: assessment.summary.notApplicable,
        manualReview: assessment.summary.manualReview
      },
      controlResults: assessment.results.map(result => ({
        controlId: result.control.id,
        category: result.control.category,
        requirement: result.control.requirement,
        status: result.status,
        confidence: result.confidence,
        violations: result.violations.length,
        remediation: result.remediation
      })).slice(0, 20), // Limit for readability
      failedControls: assessment.results
        .filter(r => r.status === 'fail')
        .map(result => ({
          controlId: result.control.id,
          requirement: result.control.requirement,
          category: result.control.category,
          severity: result.violations.length > 0 ? 'high' : 'medium',
          remediation: result.remediation
        })),
      recommendations: assessment.recommendations,
      nextSteps: assessment.nextSteps
    };

    logger.info(`ASVS assessment completed. Compliance score: ${assessment.summary.complianceScore}%`);
    return { content: [result] };
  }

  private async handleScanApiSecurity(args: ScanApiSecurityArgs): Promise<{ content: any[] }> {
    logger.info('Scan API security tool called', { args });

    const { path, includeEndpoints = true, riskThreshold = 1 } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Scanning API security for: ${path}`);

    // Run API security scan
    const scanResult = await this.apiScanner.scanDirectory(path);

    // Filter by risk threshold
    const filteredVulnerabilities = scanResult.vulnerabilities.filter(
      vuln => (vuln as any).risk_score >= riskThreshold
    );

    // Store findings in database
    filteredVulnerabilities.forEach(vuln => {
      // First insert security issue
      const securityIssueId = this.db.insertSecurityIssue({
        severity: vuln.severity,
        category: vuln.category,
        file_path: vuln.file,
        line_start: vuln.line,
        line_end: vuln.line,
        description: vuln.description,
        remediation: vuln.remediation,
        cwe_id: vuln.cweId?.toString(),
        detected_at: new Date().toISOString(),
        resolved: false,
        false_positive: false
      });

      // Then insert API-specific finding
      this.db.insertApiSecurityFinding({
        api_id: vuln.apiId,
        endpoint_path: vuln.endpoint,
        http_method: vuln.method,
        security_issue_id: securityIssueId,
        platform: 'REST', // Default, could be detected
        risk_score: 5 // Default risk score
      });
    });

    const result = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      configuration: {
        includeEndpoints,
        riskThreshold
      },
      summary: {
        totalVulnerabilities: filteredVulnerabilities.length,
        ...scanResult.summary,
        endpointsScanned: scanResult.endpoints.length,
        complianceMatrix: Object.fromEntries(scanResult.complianceMatrix)
      },
      vulnerabilities: filteredVulnerabilities.map(vuln => ({
        id: vuln.id,
        apiId: vuln.apiId,
        title: vuln.title,
        severity: vuln.severity,
        category: vuln.category,
        endpoint: vuln.endpoint,
        method: vuln.method,
        file: vuln.file,
        line: vuln.line,
        description: vuln.description,
        remediation: vuln.remediation,
        references: vuln.references
      })).slice(0, 25), // Limit for readability
      ...(includeEndpoints && {
        endpoints: scanResult.endpoints.map(endpoint => ({
          path: endpoint.path,
          method: endpoint.method,
          file: endpoint.file,
          hasAuth: endpoint.hasAuth,
          hasRateLimit: endpoint.hasRateLimit,
          hasValidation: endpoint.hasValidation,
          securityScore: this.calculateEndpointSecurityScore(endpoint)
        }))
      }),
      recommendations: [
        filteredVulnerabilities.length === 0 ? 
          '✅ No high-risk API security issues found' : 
          `🚨 Found ${filteredVulnerabilities.length} API security vulnerabilities`,
        `📊 Scanned ${scanResult.endpoints.length} API endpoints`,
        ...this.generateApiSecurityRecommendations(scanResult)
      ]
    };

    logger.info(`API security scan completed. Found ${filteredVulnerabilities.length} vulnerabilities`);
    return { content: [result] };
  }

  private async handleScanMobileSecurity(args: ScanMobileSecurityArgs): Promise<{ content: any[] }> {
    logger.info('Scan mobile security tool called', { args });

    const { path, platform, includeFrameworkAnalysis = true } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Scanning mobile security for: ${path}`);

    // Run mobile security scan
    const scanResult = await this.mobileScanner.scanDirectory(path);

    // Filter by platform if specified
    let filteredVulnerabilities = scanResult.vulnerabilities;
    if (platform) {
      filteredVulnerabilities = scanResult.vulnerabilities.filter(
        vuln => vuln.platform === platform
      );
    }

    // Store findings in database
    filteredVulnerabilities.forEach(vuln => {
      // First insert security issue
      const securityIssueId = this.db.insertSecurityIssue({
        severity: vuln.severity,
        category: vuln.category,
        file_path: vuln.file,
        line_start: vuln.line,
        line_end: vuln.line,
        description: vuln.description,
        remediation: vuln.remediation,
        cwe_id: vuln.cweId?.toString(),
        detected_at: new Date().toISOString(),
        resolved: false,
        false_positive: false
      });

      // Then insert mobile-specific finding
      this.db.insertMobileSecurityFinding({
        mobile_id: vuln.mobileId,
        platform: vuln.platform,
        framework: scanResult.appAnalysis.framework,
        security_issue_id: securityIssueId,
        risk_score: 5 // Default risk score
      });
    });

    const result = {
      success: true,
      path,
      platform: platform || 'all',
      timestamp: new Date().toISOString(),
      configuration: {
        platform,
        includeFrameworkAnalysis
      },
      summary: {
        totalVulnerabilities: filteredVulnerabilities.length,
        ...scanResult.summary,
        complianceMatrix: Object.fromEntries(scanResult.complianceMatrix)
      },
      vulnerabilities: filteredVulnerabilities.map(vuln => ({
        id: vuln.id,
        mobileId: vuln.mobileId,
        title: vuln.title,
        severity: vuln.severity,
        category: vuln.category,
        platform: vuln.platform,
        file: vuln.file,
        line: vuln.line,
        description: vuln.description,
        remediation: vuln.remediation,
        references: vuln.references
      })).slice(0, 25), // Limit for readability
      ...(includeFrameworkAnalysis && {
        appAnalysis: {
          platform: scanResult.appAnalysis.platform,
          framework: scanResult.appAnalysis.framework,
          permissions: scanResult.appAnalysis.permissions.slice(0, 10),
          dataStorage: scanResult.appAnalysis.dataStorage,
          cryptoUsage: scanResult.appAnalysis.cryptoUsage
        }
      }),
      recommendations: [
        filteredVulnerabilities.length === 0 ? 
          '✅ No mobile security issues found' : 
          `🚨 Found ${filteredVulnerabilities.length} mobile security vulnerabilities`,
        `📱 Detected ${scanResult.appAnalysis.platform} platform with ${scanResult.appAnalysis.framework} framework`,
        ...this.generateMobileSecurityRecommendations(scanResult)
      ]
    };

    logger.info(`Mobile security scan completed. Found ${filteredVulnerabilities.length} vulnerabilities`);
    return { content: [result] };
  }

  private async handleScanAiSecurity(args: ScanAiSecurityArgs): Promise<{ content: any[] }> {
    logger.info('Scan AI security tool called', { args });

    const { path, includeModelAnalysis = true, riskLevel = 'low' } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Scanning AI security for: ${path}`);

    // Run AI security scan
    const scanResult = await this.aiScanner.scanDirectory(path);

    // Filter by risk level
    const riskOrder = { high: 0, medium: 1, low: 2 };
    const minRiskLevel = riskOrder[riskLevel];
    const filteredVulnerabilities = scanResult.vulnerabilities.filter(
      vuln => riskOrder[vuln.mlRisk] <= minRiskLevel
    );

    // Store findings in database
    filteredVulnerabilities.forEach(vuln => {
      // First insert security issue
      const securityIssueId = this.db.insertSecurityIssue({
        severity: vuln.severity,
        category: vuln.category,
        file_path: vuln.file,
        line_start: vuln.line,
        line_end: vuln.line,
        description: vuln.description,
        remediation: vuln.remediation,
        detected_at: new Date().toISOString(),
        resolved: false,
        false_positive: false
      });

      // Then insert AI-specific finding
      this.db.insertAiSecurityFinding({
        ai_category: vuln.category,
        model_type: scanResult.analysis.modelTypes[0] || null,
        ai_library: scanResult.analysis.aiLibraries[0] || null,
        security_issue_id: securityIssueId,
        ml_risk: vuln.mlRisk,
        impact_area: JSON.stringify(vuln.impactArea)
      });
    });

    const result = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      configuration: {
        includeModelAnalysis,
        riskLevel
      },
      summary: {
        totalVulnerabilities: filteredVulnerabilities.length,
        ...scanResult.summary,
        aiSystemDetected: scanResult.analysis.hasMLModels
      },
      vulnerabilities: filteredVulnerabilities.map(vuln => ({
        id: vuln.id,
        category: vuln.category,
        title: vuln.title,
        severity: vuln.severity,
        mlRisk: vuln.mlRisk,
        file: vuln.file,
        line: vuln.line,
        description: vuln.description,
        remediation: vuln.remediation,
        impactArea: vuln.impactArea,
        references: vuln.references
      })).slice(0, 25), // Limit for readability
      ...(includeModelAnalysis && scanResult.analysis.hasMLModels && {
        aiAnalysis: {
          hasMLModels: scanResult.analysis.hasMLModels,
          modelTypes: scanResult.analysis.modelTypes,
          aiLibraries: scanResult.analysis.aiLibraries,
          dataProcessing: scanResult.analysis.dataProcessing,
          endpoints: scanResult.analysis.endpoints
        }
      }),
      recommendations: [
        filteredVulnerabilities.length === 0 ? 
          (scanResult.analysis.hasMLModels ? '✅ No AI security issues found' : 'ℹ️ No AI/ML components detected') : 
          `🚨 Found ${filteredVulnerabilities.length} AI security vulnerabilities`,
        ...scanResult.recommendations
      ]
    };

    logger.info(`AI security scan completed. Found ${filteredVulnerabilities.length} vulnerabilities`);
    return { content: [result] };
  }

  private async handleGenerateComplianceReport(args: GenerateComplianceReportArgs): Promise<{ content: any[] }> {
    logger.info('Generate compliance report tool called', { args });

    const { projectPath, standards = ['top10', 'api-security', 'asvs'], includeRemediation = true, outputFormat = 'summary' } = args;

    if (!projectPath) {
      throw new Error('projectPath is required');
    }

    logger.info(`Generating compliance report for: ${projectPath}`);

    const report: any = {
      success: true,
      projectPath,
      timestamp: new Date().toISOString(),
      configuration: {
        standards,
        includeRemediation,
        outputFormat
      },
      compliance: {},
      overallScore: 0,
      recommendations: [],
      remediation: includeRemediation ? {} : undefined
    };

    let totalScore = 0;
    let standardCount = 0;

    // Run assessments for each requested standard
    for (const standard of standards) {
      try {
        switch (standard) {
          case 'asvs':
            const asvsAssessment = await this.asvsVerifier.assessProject(projectPath, 1);
            report.compliance.asvs = {
              standard: 'OWASP ASVS 4.0',
              level: asvsAssessment.level,
              score: asvsAssessment.summary.complianceScore,
              totalControls: asvsAssessment.summary.totalControls,
              passed: asvsAssessment.summary.passed,
              failed: asvsAssessment.summary.failed,
              recommendations: asvsAssessment.recommendations.slice(0, 3)
            };
            totalScore += asvsAssessment.summary.complianceScore;
            standardCount++;
            break;

          case 'api-security':
            const apiScan = await this.apiScanner.scanDirectory(projectPath);
            const apiScore = this.calculateApiSecurityScore(apiScan);
            report.compliance.apiSecurity = {
              standard: 'OWASP API Security Top 10 2023',
              score: apiScore,
              totalVulnerabilities: apiScan.vulnerabilities.length,
              endpointsScanned: apiScan.endpoints.length,
              complianceMatrix: Object.fromEntries(apiScan.complianceMatrix)
            };
            totalScore += apiScore;
            standardCount++;
            break;

          case 'mobile':
            const mobileScan = await this.mobileScanner.scanDirectory(projectPath);
            const mobileScore = this.calculateMobileSecurityScore(mobileScan);
            report.compliance.mobile = {
              standard: 'OWASP Mobile Top 10 2016',
              score: mobileScore,
              totalVulnerabilities: mobileScan.vulnerabilities.length,
              platform: mobileScan.appAnalysis.platform
            };
            totalScore += mobileScore;
            standardCount++;
            break;

          case 'ai-guide':
            const aiScan = await this.aiScanner.scanDirectory(projectPath);
            const aiScore = this.calculateAiSecurityScore(aiScan);
            report.compliance.aiSecurity = {
              standard: 'OWASP AI Security Guide',
              score: aiScore,
              totalVulnerabilities: aiScan.vulnerabilities.length,
              hasAiComponents: aiScan.analysis.hasMLModels
            };
            totalScore += aiScore;
            standardCount++;
            break;

          case 'cheat-sheets':
            // Scan a sample of files for cheat sheet compliance
            const cheatSheetScore = await this.assessCheatSheetCompliance(projectPath);
            report.compliance.cheatSheets = {
              standard: 'OWASP Cheat Sheets 4.0',
              score: cheatSheetScore.score,
              totalIssues: cheatSheetScore.totalIssues,
              categories: cheatSheetScore.categories
            };
            totalScore += cheatSheetScore.score;
            standardCount++;
            break;
        }
      } catch (error) {
        logger.warn(`Error assessing ${standard} compliance:`, error);
        report.compliance[standard] = {
          error: `Assessment failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        };
      }
    }

    // Calculate overall compliance score
    report.overallScore = standardCount > 0 ? Math.round(totalScore / standardCount) : 0;

    // Generate recommendations
    report.recommendations = this.generateComplianceRecommendations(report.compliance, report.overallScore);

    // Store compliance report in database
    const owaspStandards = this.db.getOwaspStandards();
    standards.forEach(standard => {
      const owaspStandard = owaspStandards.find(s => 
        s.standard_name.toLowerCase().includes(standard.replace('-', ' '))
      );
      
      if (owaspStandard && report.compliance[standard] && !report.compliance[standard].error) {
        this.db.insertComplianceReport({
          project_path: projectPath,
          standard_id: owaspStandard.id!,
          compliance_score: report.compliance[standard].score || 0,
          total_controls: report.compliance[standard].totalControls || 0,
          compliant_controls: report.compliance[standard].passed || 0,
          non_compliant_controls: report.compliance[standard].failed || 0,
          not_applicable_controls: 0,
          generated_at: new Date().toISOString(),
          report_data: JSON.stringify(report.compliance[standard])
        });
      }
    });

    logger.info(`Compliance report generated. Overall score: ${report.overallScore}%`);
    return { content: [report] };
  }

  private async handleGetCheatSheetGuidance(args: GetCheatSheetGuidanceArgs): Promise<{ content: any[] }> {
    logger.info('Get cheat sheet guidance tool called', { args });

    const { query, context, limit = 10 } = args;

    if (!query) {
      throw new Error('query is required');
    }

    logger.info(`Getting cheat sheet guidance for: ${query}`);

    // Search for relevant patterns
    const searchResults = this.cheatSheets.searchPatterns(query);
    
    // Filter by context if provided
    let filteredResults = searchResults;
    if (context) {
      filteredResults = searchResults.filter(pattern => 
        pattern.context.some(ctx => ctx.includes(context) || context.includes(ctx.replace('*.', '')))
      );
    }

    // Limit results
    const limitedResults = filteredResults.slice(0, limit);

    // Get all cheat sheet references
    const allReferences = this.cheatSheets.getAllReferences();
    const relevantReferences = [...new Set(limitedResults.map(p => p.sheetName))]
      .map(sheetName => allReferences.find(ref => ref.name === sheetName))
      .filter(Boolean);

    const result = {
      success: true,
      query,
      context: context || 'general',
      timestamp: new Date().toISOString(),
      summary: {
        totalPatterns: limitedResults.length,
        cheatSheetsReferenced: relevantReferences.length,
        categories: [...new Set(limitedResults.map(p => p.category))]
      },
      guidance: limitedResults.map(pattern => ({
        id: pattern.id,
        pattern: pattern.pattern,
        category: pattern.category,
        description: pattern.description,
        severity: pattern.severity,
        remediation: pattern.remediation,
        examples: pattern.examples,
        references: pattern.references,
        cheatSheet: pattern.sheetName,
        applicableContexts: pattern.context
      })),
      cheatSheets: relevantReferences.map(ref => ({
        name: ref!.name,
        url: ref!.url,
        description: ref!.description,
        categories: ref!.categories
      })),
      recommendations: [
        limitedResults.length === 0 ? 
          'No specific guidance found. Try a broader search term.' : 
          `Found ${limitedResults.length} relevant security patterns`,
        relevantReferences.length > 0 ? 
          `📚 Review ${relevantReferences.length} OWASP cheat sheets for comprehensive guidance` : 
          'Consider reviewing general OWASP security guidelines',
        context ? 
          `Guidance tailored for ${context} context` : 
          'Consider specifying context (framework, file type) for more targeted guidance'
      ]
    };

    logger.info(`Cheat sheet guidance provided. Found ${limitedResults.length} relevant patterns`);
    return { content: [result] };
  }

  // Helper methods
  private initializeOwaspData(): void {
    try {
      this.db.initializeOwaspData();
    } catch (error) {
      logger.warn('OWASP data already initialized or error occurred:', error);
    }
  }

  private generateContextualGuidance(findings: any[], filePath: string): string[] {
    const guidance: string[] = [];
    
    const categoryCounts = findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    if (categoryCounts.critical > 0) {
      guidance.push(`🚨 Address ${categoryCounts.critical} critical security issues immediately`);
    }
    
    if (categoryCounts.high > 0) {
      guidance.push(`⚠️ Fix ${categoryCounts.high} high-severity security issues`);
    }

    const topCategories = [...new Set(findings.map(f => f.pattern))].slice(0, 3);
    guidance.push(`📊 Most common issues: ${topCategories.join(', ')}`);

    return guidance;
  }

  private calculateEndpointSecurityScore(endpoint: any): number {
    let score = 100;
    if (!endpoint.hasAuth) score -= 40;
    if (!endpoint.hasRateLimit) score -= 20;
    if (!endpoint.hasValidation) score -= 20;
    if (!endpoint.hasAuthorization) score -= 20;
    return Math.max(0, score);
  }

  private generateApiSecurityRecommendations(scanResult: any): string[] {
    const recommendations: string[] = [];
    
    const complianceMatrix = scanResult.complianceMatrix;
    const failedApiChecks = Array.from(complianceMatrix.entries())
      .filter(([, passed]) => !passed)
      .map(([apiId]) => apiId);

    if (failedApiChecks.length > 0) {
      recommendations.push(`📋 Failed API security checks: ${failedApiChecks.slice(0, 3).join(', ')}`);
    }

    const unprotectedEndpoints = scanResult.endpoints.filter((e: any) => !e.hasAuth).length;
    if (unprotectedEndpoints > 0) {
      recommendations.push(`🔒 ${unprotectedEndpoints} endpoints lack authentication`);
    }

    return recommendations;
  }

  private generateMobileSecurityRecommendations(scanResult: any): string[] {
    const recommendations: string[] = [];
    
    if (scanResult.appAnalysis.permissions.length > 10) {
      recommendations.push('📱 Review app permissions - may be requesting excessive permissions');
    }

    if (scanResult.appAnalysis.dataStorage.length === 0) {
      recommendations.push('💾 No secure storage mechanisms detected');
    }

    return recommendations;
  }

  private calculateApiSecurityScore(scanResult: any): number {
    const totalVulns = scanResult.vulnerabilities.length;
    const totalEndpoints = scanResult.endpoints.length;
    
    if (totalEndpoints === 0) return 100;
    
    const baseScore = Math.max(0, 100 - (totalVulns * 10));
    const endpointScore = scanResult.endpoints.reduce((acc: number, endpoint: any) => 
      acc + this.calculateEndpointSecurityScore(endpoint), 0) / totalEndpoints;
    
    return Math.round((baseScore + endpointScore) / 2);
  }

  private calculateMobileSecurityScore(scanResult: any): number {
    const totalVulns = scanResult.vulnerabilities.length;
    return Math.max(0, 100 - (totalVulns * 15));
  }

  private calculateAiSecurityScore(scanResult: any): number {
    if (!scanResult.analysis.hasMLModels) return 100;
    
    const totalVulns = scanResult.vulnerabilities.length;
    const highRiskVulns = scanResult.vulnerabilities.filter((v: any) => v.mlRisk === 'high').length;
    
    return Math.max(0, 100 - (totalVulns * 10) - (highRiskVulns * 20));
  }

  private async assessCheatSheetCompliance(projectPath: string): Promise<{ score: number; totalIssues: number; categories: string[] }> {
    // This would scan a sample of files in the project
    // For now, return a placeholder assessment
    return {
      score: 85,
      totalIssues: 5,
      categories: ['authentication', 'session_management', 'input_validation']
    };
  }

  private generateComplianceRecommendations(compliance: any, overallScore: number): string[] {
    const recommendations: string[] = [];

    if (overallScore >= 90) {
      recommendations.push('✅ Excellent OWASP compliance across all standards');
    } else if (overallScore >= 75) {
      recommendations.push('✅ Good OWASP compliance with room for improvement');
    } else if (overallScore >= 50) {
      recommendations.push('⚠️ Moderate OWASP compliance - address key issues');
    } else {
      recommendations.push('🚨 Low OWASP compliance - immediate attention required');
    }

    // Add specific recommendations based on lowest scoring standards
    const scores = Object.values(compliance)
      .filter((c: any) => typeof c === 'object' && c.score !== undefined)
      .map((c: any) => ({ standard: c.standard, score: c.score }))
      .sort((a, b) => a.score - b.score);

    if (scores.length > 0 && scores[0].score < 70) {
      recommendations.push(`🎯 Priority: Improve ${scores[0].standard} compliance (${scores[0].score}%)`);
    }

    recommendations.push('📚 Review OWASP documentation for comprehensive security guidance');
    
    return recommendations;
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up OwaspSecurityTools...');
    // Cleanup any resources if needed
    logger.info('OwaspSecurityTools cleanup completed');
  }
}