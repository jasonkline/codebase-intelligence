import { CheckovScanner, CheckovScanOptions, CheckovSeverity } from '../../security/CheckovScanner';
import { DatabaseManager, IaCSecurityFinding, IaCComplianceReport } from '../../database/schema';
import { OwaspCloudMapper, OwaspCloudMapping } from '../../security/OwaspCloudMapper';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import logger from '../../utils/logger';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';

export interface IaCSecurityScanArgs {
  path: string;
  options?: CheckovScanOptions;
}

export interface IaCComplianceCheckArgs {
  path: string;
  frameworks?: string[];
  options?: CheckovScanOptions;
}

export interface IaCFindingStatusArgs {
  findingId: string;
  resolved: boolean;
}

export interface IaCRecommendationsArgs {
  path: string;
  checkType?: string;
  severity?: string;
}

export interface IaCPolicyValidationArgs {
  path: string;
  policyPath?: string;
  customRules?: string[];
}

export class IaCSecurityTools {
  private checkovScanner: CheckovScanner;
  private dbManager: DatabaseManager;
  private owaspCloudMapper: OwaspCloudMapper;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    dbManager: DatabaseManager,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor,
    checkovPath?: string
  ) {
    this.dbManager = dbManager;
    this.checkovScanner = new CheckovScanner(dbManager, checkovPath);
    this.owaspCloudMapper = new OwaspCloudMapper();
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
  }

  getToolDefinitions() {
    return [
      {
        name: 'scan_iac_security',
        description: 'Perform comprehensive Infrastructure as Code (IaC) security scanning using Checkov. Supports Terraform, CloudFormation, Kubernetes, Helm, and other IaC frameworks. Detects security misconfigurations, compliance violations, and provides remediation guidance.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to IaC file or directory to scan',
            },
            options: {
              type: 'object',
              properties: {
                frameworks: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'IaC frameworks to scan (terraform, cloudformation, kubernetes, etc.)',
                },
                excludeChecks: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Checkov check IDs to exclude from scan',
                },
                includeChecks: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Specific Checkov check IDs to include',
                },
                minSeverity: {
                  type: 'string',
                  enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                  description: 'Minimum severity level to report',
                },
                timeout: {
                  type: 'number',
                  description: 'Scan timeout in milliseconds',
                },
                skipDownload: {
                  type: 'boolean',
                  description: 'Skip policy download for faster scans',
                },
                quiet: {
                  type: 'boolean',
                  description: 'Suppress verbose output',
                },
              },
              additionalProperties: false,
            },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
      {
        name: 'check_iac_compliance',
        description: 'Check IaC compliance against security frameworks (CIS, NIST, PCI DSS, HIPAA, etc.). Provides detailed compliance scoring and gap analysis with actionable remediation steps.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to IaC file or directory to check',
            },
            frameworks: {
              type: 'array',
              items: { type: 'string' },
              description: 'Compliance frameworks to check against (cis, nist, pci, hipaa, gdpr, sox)',
            },
            options: {
              type: 'object',
              properties: {
                timeout: {
                  type: 'number',
                  description: 'Scan timeout in milliseconds',
                },
                skipDownload: {
                  type: 'boolean',
                  description: 'Skip policy download for faster scans',
                },
              },
              additionalProperties: false,
            },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
      {
        name: 'get_iac_recommendations',
        description: 'Get intelligent security recommendations for IaC configurations based on findings, industry best practices, and compliance requirements. Provides prioritized action items with implementation guidance.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to project or file to analyze',
            },
            checkType: {
              type: 'string',
              description: 'Filter recommendations by IaC type (terraform, cloudformation, kubernetes)',
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Filter recommendations by severity level',
            },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
      {
        name: 'update_iac_finding_status',
        description: 'Update the resolution status of an IaC security finding. Use this to mark issues as resolved or reopened for tracking remediation progress.',
        inputSchema: {
          type: 'object',
          properties: {
            findingId: {
              type: 'string',
              description: 'Unique identifier of the IaC security finding',
            },
            resolved: {
              type: 'boolean',
              description: 'Whether the finding has been resolved',
            },
          },
          required: ['findingId', 'resolved'],
          additionalProperties: false,
        },
      },
      {
        name: 'validate_iac_policies',
        description: 'Validate IaC configurations against custom security policies and organizational standards. Supports custom policy files and rule definitions.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to IaC files to validate',
            },
            policyPath: {
              type: 'string',
              description: 'Path to custom policy configuration file',
            },
            customRules: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of custom rule IDs to validate against',
            },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
      {
        name: 'get_iac_security_stats',
        description: 'Get comprehensive IaC security statistics and trends for a project. Includes finding distribution, compliance scores, risk analysis, and historical trends.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to project directory',
            },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
      {
        name: 'get_iac_owasp_compliance',
        description: 'Map IaC security findings to OWASP Cloud Security Top 10 controls. Provides detailed compliance analysis, control coverage, and prioritized remediation recommendations based on cloud security best practices.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Absolute path to project directory',
            },
            includeUnmapped: {
              type: 'boolean',
              description: 'Include findings that could not be mapped to OWASP controls',
              default: false,
            },
            minConfidence: {
              type: 'number',
              description: 'Minimum confidence threshold for mappings (0.0-1.0)',
              default: 0.5,
            },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
    ];
  }

  hasTools(): boolean {
    return true;
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      // Check if Checkov is available
      const checkovAvailable = await this.checkovScanner.isAvailable();
      if (!checkovAvailable) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              success: false,
              error: 'Checkov not available',
              message: 'Checkov is not installed or not accessible. Please install Checkov: pip install checkov',
              timestamp: new Date().toISOString()
            }, null, 2)
          }]
        };
      }

      switch (name) {
        case 'scan_iac_security':
          return await this.handleIaCSecurityScan(args as IaCSecurityScanArgs);
        
        case 'check_iac_compliance':
          return await this.handleIaCComplianceCheck(args as IaCComplianceCheckArgs);
        
        case 'get_iac_recommendations':
          return await this.handleIaCRecommendations(args as IaCRecommendationsArgs);
        
        case 'update_iac_finding_status':
          return await this.handleUpdateFindingStatus(args as IaCFindingStatusArgs);
        
        case 'validate_iac_policies':
          return await this.handleIaCPolicyValidation(args as IaCPolicyValidationArgs);
        
        case 'get_iac_security_stats':
          return await this.handleIaCSecurityStats(args as { path: string });
        
        case 'get_iac_owasp_compliance':
          return await this.handleIaCOwaspCompliance(args as { path: string; includeUnmapped?: boolean; minConfidence?: number });
        
        default:
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                success: false,
                error: 'Unknown tool',
                message: `Tool '${name}' is not supported by IaCSecurityTools`,
                timestamp: new Date().toISOString()
              }, null, 2)
            }]
          };
      }
    } catch (error) {
      logger.error(`Error in IaCSecurityTools.${name}:`, error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            error: 'Tool execution failed',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
            timestamp: new Date().toISOString()
          }, null, 2)
        }]
      };
    } finally {
      const duration = Date.now() - startTime;
      // this.performanceMonitor.recordMetric(`iac_security_tools_${name}`, duration);
    }
  }

  private async handleIaCSecurityScan(args: IaCSecurityScanArgs): Promise<any> {
    const { path, options = {} } = args;
    
    logger.info(`Starting IaC security scan for: ${path}`);
    
    try {
      const findings = await this.checkovScanner.scanDirectory(path, options);
      
      if (findings.length === 0) {
        return this.formatSuccess(
          'IaC Security Scan Complete',
          'No security issues found in the scanned IaC configurations.',
          {
            summary: {
              totalFindings: 0,
              criticalFindings: 0,
              highFindings: 0,
              path: path,
              scanOptions: options
            }
          }
        );
      }

      // Group findings by severity and file
      const findingsBySeverity = this.groupBySeverity(findings);
      const findingsByFile = this.groupByFile(findings);
      
      // Generate OWASP mapping for findings
      const owaspCompliance = this.owaspCloudMapper.generateComplianceReport(findings);
      
      return this.formatSuccess(
        'IaC Security Scan Complete',
        `Found ${findings.length} security issues in IaC configurations`,
        {
          summary: {
            totalFindings: findings.length,
            criticalFindings: findingsBySeverity.critical?.length || 0,
            highFindings: findingsBySeverity.high?.length || 0,
            mediumFindings: findingsBySeverity.medium?.length || 0,
            lowFindings: findingsBySeverity.low?.length || 0,
            path: path,
            scanOptions: options
          },
          findingsBySeverity,
          findingsByFile,
          topIssues: findings
            .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
            .slice(0, 10)
            .map(f => ({
              checkId: f.check_id,
              severity: f.severity,
              description: f.description,
              file: f.file_path,
              line: f.line_start,
              remediation: f.remediation,
              riskScore: f.risk_score
            })),
          owaspCompliance: {
            mappedFindings: owaspCompliance.mappedFindings,
            totalFindings: owaspCompliance.totalFindings,
            controlCoverage: Object.entries(owaspCompliance.controlCoverage)
              .filter(([, count]) => count > 0)
              .reduce((acc, [control, count]) => {
                acc[control] = count;
                return acc;
              }, {} as Record<string, number>),
            topRecommendations: owaspCompliance.recommendations.slice(0, 3)
          }
        }
      );
    } catch (error) {
      logger.error('IaC security scan failed:', error);
      return this.formatError(
        'IaC Scan Failed',
        error instanceof Error ? error.message : 'Unknown error during IaC scan'
      );
    }
  }

  private async handleIaCComplianceCheck(args: IaCComplianceCheckArgs): Promise<any> {
    const { path, frameworks = ['cis', 'nist', 'pci'], options = {} } = args;
    
    logger.info(`Starting IaC compliance check for: ${path} with frameworks: ${frameworks.join(', ')}`);
    
    try {
      const result = await this.checkovScanner.validateCompliance(path, frameworks, options);
      
      // Generate compliance report
      const reportId = uuidv4();
      const complianceReport: IaCComplianceReport = {
        report_id: reportId,
        project_path: path,
        scan_type: 'compliance',
        total_checks: result.findings.length,
        passed_checks: result.findings.filter(f => f.severity === 'info').length,
        failed_checks: result.findings.filter(f => f.severity !== 'info').length,
        skipped_checks: 0,
        compliance_score: result.complianceScore,
        frameworks_scanned: JSON.stringify(frameworks),
        generated_at: new Date().toISOString(),
        scan_options: JSON.stringify(options)
      };
      
      // Store compliance report
      this.dbManager.insertIaCComplianceReport(complianceReport);
      
      return this.formatSuccess(
        'IaC Compliance Check Complete',
        `Compliance score: ${result.complianceScore}% across ${frameworks.length} frameworks`,
        {
          overallScore: result.complianceScore,
          frameworkScores: result.frameworkScores,
          totalChecks: result.findings.length,
          passedChecks: complianceReport.passed_checks,
          failedChecks: complianceReport.failed_checks,
          frameworks: frameworks,
          reportId: reportId,
          criticalIssues: result.findings
            .filter(f => f.severity === 'critical')
            .map(f => ({
              checkId: f.check_id,
              description: f.description,
              file: f.file_path,
              remediation: f.remediation
            }))
        }
      );
    } catch (error) {
      logger.error('IaC compliance check failed:', error);
      return this.formatError(
        'Compliance Check Failed',
        error instanceof Error ? error.message : 'Unknown error during compliance check'
      );
    }
  }

  private async handleIaCRecommendations(args: IaCRecommendationsArgs): Promise<any> {
    const { path, checkType, severity } = args;
    
    logger.info(`Getting IaC recommendations for: ${path}`);
    
    try {
      // Get existing findings for the path
      const findings = this.dbManager.getIaCSecurityFindingsByProject(path);
      
      // Filter by checkType and severity if specified
      let filteredFindings = findings;
      if (checkType) {
        filteredFindings = filteredFindings.filter(f => f.check_type === checkType);
      }
      if (severity) {
        filteredFindings = filteredFindings.filter(f => f.severity === severity);
      }
      
      // Generate intelligent recommendations
      const recommendations = this.generateRecommendations(filteredFindings, path);
      
      return this.formatSuccess(
        'IaC Security Recommendations',
        `Generated ${recommendations.length} prioritized recommendations`,
        {
          totalRecommendations: recommendations.length,
          highPriorityCount: recommendations.filter(r => r.priority === 'high').length,
          mediumPriorityCount: recommendations.filter(r => r.priority === 'medium').length,
          lowPriorityCount: recommendations.filter(r => r.priority === 'low').length,
          recommendations: recommendations,
          filterApplied: {
            checkType: checkType || 'all',
            severity: severity || 'all'
          }
        }
      );
    } catch (error) {
      logger.error('Failed to generate IaC recommendations:', error);
      return this.formatError(
        'Recommendations Failed',
        error instanceof Error ? error.message : 'Unknown error generating recommendations'
      );
    }
  }

  private async handleUpdateFindingStatus(args: IaCFindingStatusArgs): Promise<any> {
    const { findingId, resolved } = args;
    
    try {
      this.dbManager.updateIaCFindingStatus(findingId, resolved);
      
      return this.formatSuccess(
        'Finding Status Updated',
        `Finding ${findingId} marked as ${resolved ? 'resolved' : 'unresolved'}`,
        {
          findingId,
          resolved,
          updatedAt: new Date().toISOString()
        }
      );
    } catch (error) {
      logger.error('Failed to update finding status:', error);
      return this.formatError(
        'Status Update Failed',
        error instanceof Error ? error.message : 'Unknown error updating finding status'
      );
    }
  }

  private async handleIaCPolicyValidation(args: IaCPolicyValidationArgs): Promise<any> {
    const { path, policyPath, customRules } = args;
    
    logger.info(`Validating IaC policies for: ${path}`);
    
    try {
      const options: CheckovScanOptions = {};
      if (customRules && customRules.length > 0) {
        options.includeChecks = customRules;
      }
      
      const findings = await this.checkovScanner.scanDirectory(path, options);
      
      return this.formatSuccess(
        'IaC Policy Validation Complete',
        `Validated ${findings.length} policy checks`,
        {
          totalViolations: findings.length,
          policyPath: policyPath || 'default',
          customRules: customRules || [],
          violations: findings.map(f => ({
            ruleId: f.check_id,
            severity: f.severity,
            file: f.file_path,
            line: f.line_start,
            description: f.description,
            remediation: f.remediation
          }))
        }
      );
    } catch (error) {
      logger.error('IaC policy validation failed:', error);
      return this.formatError(
        'Policy Validation Failed',
        error instanceof Error ? error.message : 'Unknown error during policy validation'
      );
    }
  }

  private async handleIaCSecurityStats(args: { path: string }): Promise<any> {
    const { path } = args;
    
    logger.info(`Getting IaC security statistics for: ${path}`);
    
    try {
      const stats = this.dbManager.getIaCSecurityStatsByProject(path);
      const reports = this.dbManager.getIaCComplianceReportsByProject(path);
      
      // Calculate trends if multiple reports exist
      const trends = this.calculateTrends(reports);
      
      return this.formatSuccess(
        'IaC Security Statistics',
        `Security overview for project: ${path}`,
        {
          overview: {
            totalFindings: stats.totalFindings,
            complianceScore: stats.complianceScore,
            lastScanDate: reports[0]?.generated_at || null,
            totalReports: reports.length
          },
          findingsBySeverity: stats.findingsBySeverity,
          findingsByCheckType: stats.findingsByCheckType,
          trends: trends,
          recentReports: reports.slice(0, 5).map(r => ({
            reportId: r.report_id,
            date: r.generated_at,
            complianceScore: r.compliance_score,
            totalChecks: r.total_checks,
            failedChecks: r.failed_checks
          }))
        }
      );
    } catch (error) {
      logger.error('Failed to get IaC security stats:', error);
      return this.formatError(
        'Statistics Failed',
        error instanceof Error ? error.message : 'Unknown error getting security statistics'
      );
    }
  }

  private async handleIaCOwaspCompliance(args: { path: string; includeUnmapped?: boolean; minConfidence?: number }): Promise<any> {
    const { path, includeUnmapped = false, minConfidence = 0.5 } = args;
    
    logger.info(`Getting OWASP compliance analysis for: ${path}`);
    
    try {
      // Get existing findings for the path
      const findings = this.dbManager.getIaCSecurityFindingsByProject(path);
      
      if (findings.length === 0) {
        return this.formatSuccess(
          'No IaC Findings for OWASP Analysis',
          'No IaC security findings found. Run IaC security scan first.',
          {
            totalFindings: 0,
            mappedFindings: 0,
            controlCoverage: {},
            mappings: [],
            recommendations: ['Run IaC security scan to generate findings for OWASP analysis']
          }
        );
      }

      // Generate OWASP compliance report
      const complianceReport = this.owaspCloudMapper.generateComplianceReport(findings);
      
      // Filter mappings by confidence threshold
      const filteredMappings = complianceReport.mappings.filter(m => m.confidence >= minConfidence);
      
      // Get detailed control information
      const controlDetails: Record<string, any> = {};
      for (const [controlId, count] of Object.entries(complianceReport.controlCoverage)) {
        if (count > 0) {
          const control = this.owaspCloudMapper.getCloudControl(controlId);
          if (control) {
            controlDetails[controlId] = {
              title: control.title,
              description: control.description,
              severity: control.severity,
              category: control.category,
              violationCount: count,
              frameworks: control.frameworks,
              remediation: control.remediation
            };
          }
        }
      }

      // Prepare unmapped findings if requested
      const unmappedFindings = includeUnmapped ? 
        findings.filter(f => !filteredMappings.some(m => m.findingId === f.finding_id)) : [];

      return this.formatSuccess(
        'OWASP Cloud Security Compliance Analysis',
        `Analyzed ${findings.length} IaC findings against OWASP Cloud Security Top 10`,
        {
          summary: {
            totalFindings: complianceReport.totalFindings,
            mappedFindings: filteredMappings.length,
            unmappedFindings: complianceReport.unmappedFindings,
            controlsViolated: Object.keys(controlDetails).length,
            averageConfidence: filteredMappings.length > 0 
              ? (filteredMappings.reduce((sum, m) => sum + m.confidence, 0) / filteredMappings.length).toFixed(2)
              : 0
          },
          controlCoverage: controlDetails,
          mappings: filteredMappings.map(m => ({
            findingId: m.findingId,
            owaspId: m.owaspId,
            confidence: m.confidence,
            reason: m.mappingReason,
            context: m.additionalContext
          })),
          recommendations: complianceReport.recommendations,
          owaspControls: this.owaspCloudMapper.getCloudControls().map(c => ({
            id: c.id,
            title: c.title,
            category: c.category,
            severity: c.severity,
            frameworks: c.frameworks,
            violations: complianceReport.controlCoverage[c.id] || 0
          })),
          ...(includeUnmapped && {
            unmappedFindings: unmappedFindings.map(f => ({
              findingId: f.finding_id,
              checkId: f.check_id,
              severity: f.severity,
              description: f.description,
              file: f.file_path
            }))
          })
        }
      );
    } catch (error) {
      logger.error('Failed to generate OWASP compliance analysis:', error);
      return this.formatError(
        'OWASP Compliance Analysis Failed',
        error instanceof Error ? error.message : 'Unknown error during OWASP compliance analysis'
      );
    }
  }

  private groupBySeverity(findings: IaCSecurityFinding[]): Record<string, IaCSecurityFinding[]> {
    return findings.reduce((groups, finding) => {
      const severity = finding.severity;
      if (!groups[severity]) {
        groups[severity] = [];
      }
      groups[severity].push(finding);
      return groups;
    }, {} as Record<string, IaCSecurityFinding[]>);
  }

  private groupByFile(findings: IaCSecurityFinding[]): Record<string, IaCSecurityFinding[]> {
    return findings.reduce((groups, finding) => {
      const file = finding.file_path;
      if (!groups[file]) {
        groups[file] = [];
      }
      groups[file].push(finding);
      return groups;
    }, {} as Record<string, IaCSecurityFinding[]>);
  }

  private generateRecommendations(findings: IaCSecurityFinding[], projectPath: string): any[] {
    const recommendations: any[] = [];
    
    // Group findings by check_id to identify patterns
    const findingsByCheck = findings.reduce((groups, finding) => {
      if (!groups[finding.check_id]) {
        groups[finding.check_id] = [];
      }
      groups[finding.check_id].push(finding);
      return groups;
    }, {} as Record<string, IaCSecurityFinding[]>);
    
    // Generate recommendations for each check type
    Object.entries(findingsByCheck).forEach(([checkId, checkFindings]) => {
      const severity = checkFindings[0].severity;
      const priority = severity === 'critical' ? 'high' : 
                     severity === 'high' ? 'high' :
                     severity === 'medium' ? 'medium' : 'low';
      
      recommendations.push({
        id: `rec_${checkId}`,
        title: `Address ${checkId} violations`,
        description: checkFindings[0].description,
        priority,
        severity,
        affectedFiles: checkFindings.length,
        checkId,
        remediation: checkFindings[0].remediation,
        estimatedEffort: this.estimateEffort(checkFindings),
        complianceFrameworks: checkFindings[0].compliance_frameworks 
          ? JSON.parse(checkFindings[0].compliance_frameworks) 
          : [],
        examples: checkFindings.slice(0, 3).map(f => ({
          file: f.file_path,
          line: f.line_start,
          resource: f.resource_name
        }))
      });
    });
    
    // Sort by priority and impact
    return recommendations.sort((a, b) => {
      const priorityOrder = { high: 0, medium: 1, low: 2 };
      const aPriority = priorityOrder[a.priority as keyof typeof priorityOrder];
      const bPriority = priorityOrder[b.priority as keyof typeof priorityOrder];
      
      if (aPriority !== bPriority) {
        return aPriority - bPriority;
      }
      
      return b.affectedFiles - a.affectedFiles;
    });
  }

  private estimateEffort(findings: IaCSecurityFinding[]): string {
    const count = findings.length;
    const severity = findings[0].severity;
    
    if (severity === 'critical' || count > 10) {
      return 'high';
    } else if (severity === 'high' || count > 5) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  private calculateTrends(reports: IaCComplianceReport[]): any {
    if (reports.length < 2) {
      return { available: false, message: 'Insufficient data for trend analysis' };
    }
    
    const sortedReports = [...reports].sort((a, b) => 
      new Date(a.generated_at).getTime() - new Date(b.generated_at).getTime()
    );
    
    const latest = sortedReports[sortedReports.length - 1];
    const previous = sortedReports[sortedReports.length - 2];
    
    const complianceChange = latest.compliance_score - previous.compliance_score;
    const findingChange = latest.failed_checks - previous.failed_checks;
    
    return {
      available: true,
      complianceScoreChange: complianceChange,
      complianceDirection: complianceChange > 0 ? 'improving' : 
                          complianceChange < 0 ? 'declining' : 'stable',
      findingCountChange: findingChange,
      findingsDirection: findingChange < 0 ? 'improving' : 
                        findingChange > 0 ? 'declining' : 'stable',
      timeRange: {
        from: previous.generated_at,
        to: latest.generated_at
      }
    };
  }

  async cleanup(): Promise<void> {
    // Any cleanup tasks for IaC tools can be added here
    logger.info('IaCSecurityTools cleaned up');
  }

  private formatSuccess(title: string, message: string, data: any): any {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          title,
          message,
          timestamp: new Date().toISOString(),
          data
        }, null, 2)
      }]
    };
  }

  private formatError(title: string, message: string): any {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: false,
          error: title,
          message,
          timestamp: new Date().toISOString()
        }, null, 2)
      }]
    };
  }
}