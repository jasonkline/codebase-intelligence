import { OwaspCheatSheets, CheatSheetValidation } from './OwaspCheatSheets';
import { ASVSVerifier, ASVSAssessment } from './ASVSVerifier';
import { ApiSecurityScanner, ApiScanResult } from './ApiSecurityScanner';
import { AISecurityScanner, AIScanResult } from './AISecurityScanner';
import { MobileSecurityScanner, MobileScanResult } from './MobileSecurityScanner';
import { SecurityFinding, VulnerabilitySeverity } from './VulnerabilityDatabase';
import DatabaseManager from '../database/schema';
import logger from '../utils/logger';

export interface OwaspComplianceReport {
  reportId: string;
  projectPath: string;
  timestamp: string;
  summary: ComplianceSummary;
  standards: {
    cheatSheets: CheatSheetCompliance;
    asvs: ASVSCompliance;
    apiSecurity: ApiSecurityCompliance;
    aiSecurity: AiSecurityCompliance;
    mobileSecurity: MobileSecurityCompliance;
  };
  overallCompliance: OverallCompliance;
  recommendations: ComplianceRecommendation[];
  findings: ComplianceFinding[];
  metrics: ComplianceMetrics;
  trends: ComplianceTrend[];
}

export interface ComplianceSummary {
  totalStandardsEvaluated: number;
  compliantStandards: number;
  nonCompliantStandards: number;
  overallScore: number; // 0-100
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  complianceLevel: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
}

export interface CheatSheetCompliance {
  evaluated: boolean;
  score: number;
  compliantPatterns: number;
  violations: number;
  categories: Map<string, number>;
  topViolations: Array<{
    pattern: string;
    severity: string;
    count: number;
    files: string[];
  }>;
}

export interface ASVSCompliance {
  evaluated: boolean;
  level: number;
  overallScore: number;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  skippedControls: number;
  criticalFailures: number;
  categories: Map<string, { passed: number; failed: number; }>;
}

export interface ApiSecurityCompliance {
  evaluated: boolean;
  endpointsScanned: number;
  vulnerabilities: number;
  criticalVulnerabilities: number;
  categories: Map<string, number>;
  top10Coverage: Map<string, { detected: boolean; count: number; }>;
}

export interface AiSecurityCompliance {
  evaluated: boolean;
  hasAiComponents: boolean;
  aiLibraries: string[];
  vulnerabilities: number;
  criticalVulnerabilities: number;
  categories: Map<string, number>;
  mlRiskLevel: 'high' | 'medium' | 'low' | 'none';
}

export interface MobileSecurityCompliance {
  evaluated: boolean;
  hasMobileComponents: boolean;
  platforms: string[];
  vulnerabilities: number;
  criticalVulnerabilities: number;
  categories: Map<string, number>;
  top10Coverage: Map<string, { detected: boolean; count: number; }>;
}

export interface OverallCompliance {
  score: number; // 0-100
  level: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
  strengths: string[];
  weaknesses: string[];
  riskProfile: 'low' | 'medium' | 'high' | 'critical';
  nextSteps: string[];
}

export interface ComplianceRecommendation {
  id: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  standard: string;
  title: string;
  description: string;
  impact: string;
  effort: 'low' | 'medium' | 'high';
  timeline: string;
  resources: string[];
}

export interface ComplianceFinding {
  id: string;
  standard: string;
  category: string;
  severity: VulnerabilitySeverity;
  title: string;
  description: string;
  file: string;
  line: number;
  code: string;
  remediation: string;
  references: string[];
}

export interface ComplianceMetrics {
  scanDuration: number;
  filesScanned: number;
  linesOfCode: number;
  testCoverage: number;
  securityDebt: number; // Estimated hours to fix all issues
  complianceDebt: number; // Cost of non-compliance
  improvementPotential: number; // Percentage improvement possible
}

export interface ComplianceTrend {
  date: string;
  overallScore: number;
  standardScores: Map<string, number>;
  issueCount: number;
  criticalIssueCount: number;
}

export class OwaspComplianceReporter {
  private owaspCheatSheets: OwaspCheatSheets;
  private asvsVerifier: ASVSVerifier;
  private apiSecurityScanner: ApiSecurityScanner;
  private aiSecurityScanner: AISecurityScanner;
  private mobileSecurityScanner: MobileSecurityScanner;
  private db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.owaspCheatSheets = new OwaspCheatSheets();
    this.asvsVerifier = new ASVSVerifier();
    this.apiSecurityScanner = new ApiSecurityScanner();
    this.aiSecurityScanner = new AISecurityScanner();
    this.mobileSecurityScanner = new MobileSecurityScanner();
    this.db = db;
  }

  async generateComplianceReport(
    projectPath: string,
    options: {
      standards?: string[];
      asvsLevel?: number;
      includeMetrics?: boolean;
      includeTrends?: boolean;
      outputFormat?: 'json' | 'html' | 'pdf' | 'markdown';
    } = {}
  ): Promise<OwaspComplianceReport> {
    const reportId = this.generateReportId();
    const timestamp = new Date().toISOString();
    
    logger.info(`Generating OWASP compliance report for: ${projectPath}`);
    const startTime = Date.now();

    try {
      // Run all compliance scans concurrently
      const scanResults = await this.runComplianceScans(projectPath, options);
      
      // Build compliance report
      const report: OwaspComplianceReport = {
        reportId,
        projectPath,
        timestamp,
        summary: this.buildComplianceSummary(scanResults),
        standards: this.buildStandardsCompliance(scanResults),
        overallCompliance: this.buildOverallCompliance(scanResults),
        recommendations: await this.generateRecommendations(scanResults),
        findings: this.consolidateFindings(scanResults),
        metrics: await this.calculateMetrics(projectPath, scanResults, Date.now() - startTime),
        trends: options.includeTrends ? await this.loadComplianceTrends(projectPath) : []
      };

      // Store report in database
      await this.storeComplianceReport(report);

      logger.info(`OWASP compliance report generated successfully. Overall score: ${report.summary.overallScore}%`);
      return report;
    } catch (error) {
      logger.error('Error generating OWASP compliance report:', error);
      throw error;
    }
  }

  private async runComplianceScans(projectPath: string, options: any) {
    const standardsToRun = options.standards || ['cheatsheets', 'asvs', 'api_security', 'ai_security', 'mobile_security'];
    const results: any = {};

    const scanPromises: Promise<any>[] = [];

    if (standardsToRun.includes('cheatsheets')) {
      scanPromises.push(
        this.owaspCheatSheets.validateCode(projectPath).then(result => ({ type: 'cheatsheets', result }))
      );
    }

    if (standardsToRun.includes('asvs')) {
      scanPromises.push(
        this.asvsVerifier.assessProject(projectPath, options.asvsLevel || 2).then(result => ({ type: 'asvs', result }))
      );
    }

    if (standardsToRun.includes('api_security')) {
      scanPromises.push(
        this.apiSecurityScanner.scanDirectory(projectPath).then(result => ({ type: 'api_security', result }))
      );
    }

    if (standardsToRun.includes('ai_security')) {
      scanPromises.push(
        this.aiSecurityScanner.scanDirectory(projectPath).then(result => ({ type: 'ai_security', result }))
      );
    }

    if (standardsToRun.includes('mobile_security')) {
      scanPromises.push(
        this.mobileSecurityScanner.scanDirectory(projectPath).then(result => ({ type: 'mobile_security', result }))
      );
    }

    const scanResults = await Promise.all(scanPromises);
    
    scanResults.forEach(({ type, result }) => {
      results[type] = result;
    });

    return results;
  }

  private buildComplianceSummary(scanResults: any): ComplianceSummary {
    let totalStandards = 0;
    let compliantStandards = 0;
    let totalIssues = { critical: 0, high: 0, medium: 0, low: 0 };

    Object.keys(scanResults).forEach(standard => {
      totalStandards++;
      const result = scanResults[standard];
      
      switch (standard) {
        case 'cheatsheets':
          if (result.complianceScore >= 80) compliantStandards++;
          result.violations.forEach((v: any) => {
            if (v.severity === 'critical') totalIssues.critical++;
            else if (v.severity === 'high') totalIssues.high++;
            else if (v.severity === 'medium') totalIssues.medium++;
            else totalIssues.low++;
          });
          break;
        case 'asvs':
          if (result.overallScore >= 80) compliantStandards++;
          result.controlResults.forEach((c: any) => {
            if (c.status === 'fail') {
              if (c.severity === 'critical') totalIssues.critical++;
              else if (c.severity === 'high') totalIssues.high++;
              else if (c.severity === 'medium') totalIssues.medium++;
              else totalIssues.low++;
            }
          });
          break;
        case 'api_security':
        case 'ai_security':
        case 'mobile_security':
          if (result.summary.critical === 0 && result.summary.high < 3) compliantStandards++;
          totalIssues.critical += result.summary.critical || 0;
          totalIssues.high += result.summary.high || 0;
          totalIssues.medium += result.summary.medium || 0;
          totalIssues.low += result.summary.low || 0;
          break;
      }
    });

    const overallScore = totalStandards > 0 ? Math.round((compliantStandards / totalStandards) * 100) : 0;
    const complianceLevel = this.determineComplianceLevel(overallScore, totalIssues.critical);

    return {
      totalStandardsEvaluated: totalStandards,
      compliantStandards,
      nonCompliantStandards: totalStandards - compliantStandards,
      overallScore,
      criticalIssues: totalIssues.critical,
      highIssues: totalIssues.high,
      mediumIssues: totalIssues.medium,
      lowIssues: totalIssues.low,
      complianceLevel
    };
  }

  private buildStandardsCompliance(scanResults: any) {
    const standards: any = {};

    if (scanResults.cheatsheets) {
      const result = scanResults.cheatsheets;
      standards.cheatSheets = {
        evaluated: true,
        score: result.complianceScore,
        compliantPatterns: result.compliantPatterns.length,
        violations: result.violations.length,
        categories: new Map(Object.entries(this.groupByCategory(result.violations))),
        topViolations: this.getTopViolations(result.violations)
      };
    }

    if (scanResults.asvs) {
      const result = scanResults.asvs;
      standards.asvs = {
        evaluated: true,
        level: result.level,
        overallScore: result.overallScore,
        totalControls: result.controlResults.length,
        passedControls: result.controlResults.filter((c: any) => c.status === 'pass').length,
        failedControls: result.controlResults.filter((c: any) => c.status === 'fail').length,
        skippedControls: result.controlResults.filter((c: any) => c.status === 'skip').length,
        criticalFailures: result.controlResults.filter((c: any) => c.status === 'fail' && c.severity === 'critical').length,
        categories: new Map()
      };
    }

    if (scanResults.api_security) {
      const result = scanResults.api_security;
      standards.apiSecurity = {
        evaluated: true,
        endpointsScanned: result.analysis.endpoints.length,
        vulnerabilities: result.summary.total,
        criticalVulnerabilities: result.summary.critical,
        categories: result.summary.categories,
        top10Coverage: this.mapApiTop10Coverage(result.vulnerabilities)
      };
    }

    if (scanResults.ai_security) {
      const result = scanResults.ai_security;
      standards.aiSecurity = {
        evaluated: true,
        hasAiComponents: result.analysis.hasMLModels,
        aiLibraries: result.analysis.aiLibraries,
        vulnerabilities: result.summary.total,
        criticalVulnerabilities: result.summary.critical,
        categories: result.summary.categories,
        mlRiskLevel: this.determineMlRiskLevel(result.vulnerabilities)
      };
    }

    if (scanResults.mobile_security) {
      const result = scanResults.mobile_security;
      standards.mobileSecurity = {
        evaluated: true,
        hasMobileComponents: result.analysis.hasMobileFrameworks,
        platforms: result.analysis.detectedPlatforms,
        vulnerabilities: result.summary.total,
        criticalVulnerabilities: result.summary.critical,
        categories: result.summary.categories,
        top10Coverage: this.mapMobileTop10Coverage(result.vulnerabilities)
      };
    }

    return standards;
  }

  private buildOverallCompliance(scanResults: any): OverallCompliance {
    const scores: number[] = [];
    const strengths: string[] = [];
    const weaknesses: string[] = [];
    
    // Calculate individual standard scores
    Object.keys(scanResults).forEach(standard => {
      const result = scanResults[standard];
      let score = 0;
      
      switch (standard) {
        case 'cheatsheets':
          score = result.complianceScore;
          if (score >= 90) strengths.push('Excellent adherence to OWASP Cheat Sheets');
          else if (score < 60) weaknesses.push('Poor adherence to OWASP Cheat Sheets');
          break;
        case 'asvs':
          score = result.overallScore;
          if (score >= 90) strengths.push('Strong ASVS compliance');
          else if (score < 60) weaknesses.push('Weak ASVS compliance');
          break;
        case 'api_security':
          score = Math.max(0, 100 - (result.summary.critical * 20 + result.summary.high * 10));
          if (result.summary.critical === 0) strengths.push('No critical API security issues');
          else weaknesses.push(`${result.summary.critical} critical API security issues`);
          break;
        case 'ai_security':
          if (result.analysis.hasMLModels) {
            score = Math.max(0, 100 - (result.summary.critical * 25 + result.summary.high * 15));
            if (result.summary.critical === 0) strengths.push('Secure AI implementation');
            else weaknesses.push('AI security vulnerabilities detected');
          } else {
            score = 100; // No AI components, so no AI security issues
          }
          break;
        case 'mobile_security':
          if (result.analysis.hasMobileFrameworks) {
            score = Math.max(0, 100 - (result.summary.critical * 20 + result.summary.high * 10));
            if (result.summary.critical === 0) strengths.push('Secure mobile implementation');
            else weaknesses.push('Mobile security vulnerabilities detected');
          } else {
            score = 100; // No mobile components, so no mobile security issues
          }
          break;
      }
      
      scores.push(score);
    });

    const overallScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    const level = this.determineComplianceLevel(overallScore, 0);
    const riskProfile = this.determineRiskProfile(scanResults);
    const nextSteps = this.generateNextSteps(scanResults, overallScore);

    return {
      score: overallScore,
      level,
      strengths,
      weaknesses,
      riskProfile,
      nextSteps
    };
  }

  private async generateRecommendations(scanResults: any): Promise<ComplianceRecommendation[]> {
    const recommendations: ComplianceRecommendation[] = [];
    let recommendationId = 1;

    Object.keys(scanResults).forEach(standard => {
      const result = scanResults[standard];
      
      switch (standard) {
        case 'cheatsheets':
          if (result.violations.length > 0) {
            const criticalViolations = result.violations.filter((v: any) => v.severity === 'critical');
            if (criticalViolations.length > 0) {
              recommendations.push({
                id: `REC-${recommendationId++}`,
                priority: 'critical',
                category: 'Security Patterns',
                standard: 'OWASP Cheat Sheets',
                title: 'Fix Critical Security Pattern Violations',
                description: `Address ${criticalViolations.length} critical violations of OWASP security patterns`,
                impact: 'High security risk reduction',
                effort: 'medium',
                timeline: '1-2 weeks',
                resources: ['Security team', 'Development team']
              });
            }
          }
          break;
        case 'asvs':
          const failedControls = result.controlResults.filter((c: any) => c.status === 'fail');
          if (failedControls.length > 0) {
            recommendations.push({
              id: `REC-${recommendationId++}`,
              priority: 'high',
              category: 'Security Verification',
              standard: 'OWASP ASVS',
              title: 'Implement Missing Security Controls',
              description: `Implement ${failedControls.length} missing ASVS security controls`,
              impact: 'Improved security posture and compliance',
              effort: 'high',
              timeline: '4-6 weeks',
              resources: ['Security architect', 'Development team', 'QA team']
            });
          }
          break;
        case 'api_security':
          if (result.summary.critical > 0) {
            recommendations.push({
              id: `REC-${recommendationId++}`,
              priority: 'critical',
              category: 'API Security',
              standard: 'OWASP API Security Top 10',
              title: 'Fix Critical API Security Issues',
              description: `Address ${result.summary.critical} critical API security vulnerabilities`,
              impact: 'Prevent API attacks and data breaches',
              effort: 'medium',
              timeline: '2-3 weeks',
              resources: ['API team', 'Security team']
            });
          }
          break;
      }
    });

    return recommendations.slice(0, 10); // Limit to top recommendations
  }

  private consolidateFindings(scanResults: any): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    let findingId = 1;

    Object.keys(scanResults).forEach(standard => {
      const result = scanResults[standard];
      
      switch (standard) {
        case 'cheatsheets':
          result.violations.forEach((violation: any) => {
            findings.push({
              id: `FIND-${findingId++}`,
              standard: 'OWASP Cheat Sheets',
              category: violation.category,
              severity: violation.severity as VulnerabilitySeverity,
              title: violation.title,
              description: violation.description,
              file: violation.file,
              line: violation.line,
              code: violation.code,
              remediation: violation.remediation,
              references: violation.references
            });
          });
          break;
        case 'api_security':
        case 'ai_security':
        case 'mobile_security':
          result.vulnerabilities.forEach((vuln: any) => {
            findings.push({
              id: `FIND-${findingId++}`,
              standard: standard === 'api_security' ? 'OWASP API Security Top 10' : 
                       standard === 'ai_security' ? 'OWASP AI Security Guide' : 'OWASP Mobile Top 10',
              category: vuln.category,
              severity: vuln.severity as VulnerabilitySeverity,
              title: vuln.title,
              description: vuln.description,
              file: vuln.file,
              line: vuln.line,
              code: vuln.code,
              remediation: vuln.remediation,
              references: vuln.references || []
            });
          });
          break;
      }
    });

    return findings.slice(0, 100); // Limit findings for performance
  }

  private async calculateMetrics(projectPath: string, scanResults: any, scanDuration: number): Promise<ComplianceMetrics> {
    // This would typically analyze the project structure and calculate real metrics
    const filesScanned = Object.keys(scanResults).reduce((total, standard) => {
      const result = scanResults[standard];
      return total + (result.filesScanned || 0);
    }, 0);

    const totalIssues = Object.keys(scanResults).reduce((total, standard) => {
      const result = scanResults[standard];
      return total + (result.summary?.total || result.violations?.length || 0);
    }, 0);

    return {
      scanDuration,
      filesScanned,
      linesOfCode: 10000, // Placeholder
      testCoverage: 75, // Placeholder
      securityDebt: totalIssues * 2, // Estimated hours to fix
      complianceDebt: totalIssues * 1000, // Estimated cost in dollars
      improvementPotential: Math.min(100, totalIssues > 0 ? (totalIssues / filesScanned) * 100 : 0)
    };
  }

  private async loadComplianceTrends(projectPath: string): Promise<ComplianceTrend[]> {
    // Load historical compliance data from database
    try {
      const database = this.db.getDatabase();
      const trends = database.prepare(`
        SELECT report_date, overall_score, standard_scores, issue_count, critical_issue_count
        FROM compliance_reports 
        WHERE project_path = ? 
        ORDER BY report_date DESC 
        LIMIT 30
      `).all(projectPath) as any[];

      return trends.map((trend: any) => ({
        date: trend.report_date,
        overallScore: trend.overall_score,
        standardScores: new Map(JSON.parse(trend.standard_scores || '{}')),
        issueCount: trend.issue_count,
        criticalIssueCount: trend.critical_issue_count
      }));
    } catch (error) {
      logger.warn('Could not load compliance trends:', error);
      return [];
    }
  }

  private async storeComplianceReport(report: OwaspComplianceReport): Promise<void> {
    try {
      const database = this.db.getDatabase();
      
      // Store main report
      database.prepare(`
        INSERT OR REPLACE INTO compliance_reports (
          report_id, project_path, report_date, overall_score, 
          compliance_level, issue_count, critical_issue_count,
          standard_scores, report_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        report.reportId,
        report.projectPath,
        report.timestamp,
        report.summary.overallScore,
        report.summary.complianceLevel,
        report.summary.criticalIssues + report.summary.highIssues + report.summary.mediumIssues + report.summary.lowIssues,
        report.summary.criticalIssues,
        JSON.stringify({}), // Placeholder for standard scores
        JSON.stringify(report)
      );

      logger.info(`Stored compliance report ${report.reportId} in database`);
    } catch (error) {
      logger.error('Failed to store compliance report:', error);
      throw error;
    }
  }

  // Helper methods
  private generateReportId(): string {
    return `OWASP-COMPLIANCE-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private determineComplianceLevel(score: number, criticalIssues: number): ComplianceSummary['complianceLevel'] {
    if (criticalIssues > 0) return 'critical';
    if (score >= 90) return 'excellent';
    if (score >= 80) return 'good';
    if (score >= 60) return 'fair';
    return 'poor';
  }

  private groupByCategory(violations: any[]): Record<string, number> {
    const groups: Record<string, number> = {};
    violations.forEach(v => {
      groups[v.category] = (groups[v.category] || 0) + 1;
    });
    return groups;
  }

  private getTopViolations(violations: any[]) {
    const grouped = this.groupByCategory(violations);
    return Object.entries(grouped)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([pattern, count]) => ({
        pattern,
        severity: 'high', // Simplified
        count,
        files: [] // Placeholder
      }));
  }

  private mapApiTop10Coverage(vulnerabilities: any[]): Map<string, { detected: boolean; count: number; }> {
    const coverage = new Map();
    const apiTop10 = ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10'];
    
    apiTop10.forEach(api => {
      const count = vulnerabilities.filter(v => v.category.includes(api)).length;
      coverage.set(api, { detected: count > 0, count });
    });
    
    return coverage;
  }

  private mapMobileTop10Coverage(vulnerabilities: any[]): Map<string, { detected: boolean; count: number; }> {
    const coverage = new Map();
    const mobileTop10 = ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7', 'M8', 'M9', 'M10'];
    
    mobileTop10.forEach(m => {
      const count = vulnerabilities.filter(v => v.category.includes(m)).length;
      coverage.set(m, { detected: count > 0, count });
    });
    
    return coverage;
  }

  private determineMlRiskLevel(vulnerabilities: any[]): AiSecurityCompliance['mlRiskLevel'] {
    const highRiskCount = vulnerabilities.filter(v => v.mlRisk === 'high').length;
    if (highRiskCount > 5) return 'high';
    if (highRiskCount > 2) return 'medium';
    if (vulnerabilities.length > 0) return 'low';
    return 'none';
  }

  private determineRiskProfile(scanResults: any): OverallCompliance['riskProfile'] {
    let criticalCount = 0;
    let highCount = 0;
    
    Object.keys(scanResults).forEach(standard => {
      const result = scanResults[standard];
      if (result.summary) {
        criticalCount += result.summary.critical || 0;
        highCount += result.summary.high || 0;
      } else if (result.violations) {
        criticalCount += result.violations.filter((v: any) => v.severity === 'critical').length;
        highCount += result.violations.filter((v: any) => v.severity === 'high').length;
      }
    });
    
    if (criticalCount > 5) return 'critical';
    if (criticalCount > 0 || highCount > 10) return 'high';
    if (highCount > 0) return 'medium';
    return 'low';
  }

  private generateNextSteps(scanResults: any, overallScore: number): string[] {
    const steps: string[] = [];
    
    if (overallScore < 60) {
      steps.push('Conduct security architecture review');
      steps.push('Implement comprehensive security training');
      steps.push('Establish security governance processes');
    } else if (overallScore < 80) {
      steps.push('Address high-priority security findings');
      steps.push('Enhance security testing practices');
      steps.push('Improve security monitoring');
    } else {
      steps.push('Maintain current security posture');
      steps.push('Conduct regular security assessments');
      steps.push('Stay updated with OWASP guidelines');
    }
    
    return steps.slice(0, 5);
  }

  async exportReport(report: OwaspComplianceReport, format: 'json' | 'html' | 'pdf' | 'markdown'): Promise<string> {
    switch (format) {
      case 'json':
        return JSON.stringify(report, null, 2);
      case 'markdown':
        return this.generateMarkdownReport(report);
      case 'html':
        return this.generateHtmlReport(report);
      case 'pdf':
        // Would integrate with PDF generation library
        return 'PDF export not implemented';
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  private generateMarkdownReport(report: OwaspComplianceReport): string {
    return `# OWASP Compliance Report

## Executive Summary
- **Overall Score**: ${report.summary.overallScore}%
- **Compliance Level**: ${report.summary.complianceLevel}
- **Critical Issues**: ${report.summary.criticalIssues}
- **Standards Evaluated**: ${report.summary.totalStandardsEvaluated}

## Standards Compliance

### OWASP Cheat Sheets
${report.standards.cheatSheets?.evaluated ? 
  `- Score: ${report.standards.cheatSheets.score}%
- Violations: ${report.standards.cheatSheets.violations}` : 
  '- Not evaluated'}

### OWASP ASVS
${report.standards.asvs?.evaluated ? 
  `- Level: ${report.standards.asvs.level}
- Score: ${report.standards.asvs.overallScore}%
- Failed Controls: ${report.standards.asvs.failedControls}` : 
  '- Not evaluated'}

## Recommendations
${report.recommendations.map(r => `- **${r.title}**: ${r.description}`).join('\n')}

## Next Steps
${report.overallCompliance.nextSteps.map(step => `- ${step}`).join('\n')}
`;
  }

  private generateHtmlReport(report: OwaspComplianceReport): string {
    return `<!DOCTYPE html>
<html>
<head>
    <title>OWASP Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 8px; }
        .score { font-size: 24px; color: ${this.getScoreColor(report.summary.overallScore)}; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; }
        .critical { color: #d73027; font-weight: bold; }
        .high { color: #fc8d59; font-weight: bold; }
        .medium { color: #fee08b; }
        .low { color: #91cf60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP Compliance Report</h1>
        <p><strong>Project:</strong> ${report.projectPath}</p>
        <p><strong>Generated:</strong> ${new Date(report.timestamp).toLocaleString()}</p>
        <p><strong>Overall Score:</strong> <span class="score">${report.summary.overallScore}%</span></p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <ul>
            <li>Compliance Level: <strong>${report.summary.complianceLevel}</strong></li>
            <li>Critical Issues: <span class="critical">${report.summary.criticalIssues}</span></li>
            <li>High Issues: <span class="high">${report.summary.highIssues}</span></li>
            <li>Medium Issues: <span class="medium">${report.summary.mediumIssues}</span></li>
            <li>Low Issues: <span class="low">${report.summary.lowIssues}</span></li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            ${report.recommendations.map(r => `<li><strong>${r.title}</strong>: ${r.description} (Priority: ${r.priority})</li>`).join('')}
        </ul>
    </div>
</body>
</html>`;
  }

  private getScoreColor(score: number): string {
    if (score >= 90) return '#27ae60';
    if (score >= 80) return '#f39c12';
    if (score >= 60) return '#e67e22';
    return '#e74c3c';
  }
}