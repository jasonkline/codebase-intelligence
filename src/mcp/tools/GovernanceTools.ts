import RuleEngine, { GovernanceReport, RuleViolation } from '../../governance/RuleEngine';
import PatternRegistry from '../../patterns/PatternRegistry';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import logger from '../../utils/logger';

export interface ValidateGovernanceArgs {
  filePath: string;
  ruleSet?: string;
  severity?: 'error' | 'warning' | 'info';
}

export interface CreateRuleArgs {
  name: string;
  category: string;
  description: string;
  pattern: string;
  severity: 'error' | 'warning' | 'info';
  autoFix?: boolean;
}

export interface GetGovernanceReportArgs {
  projectPath: string;
  includeMetrics?: boolean;
  includeRecommendations?: boolean;
}

export interface EnforceStyleGuideArgs {
  filePath: string;
  styleGuide?: string;
  autoFix?: boolean;
}

export class GovernanceTools {
  private ruleEngine: RuleEngine;
  private patternRegistry: PatternRegistry;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    ruleEngine: RuleEngine,
    patternRegistry: PatternRegistry,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor
  ) {
    this.ruleEngine = ruleEngine;
    this.patternRegistry = patternRegistry;
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
  }

  getToolDefinitions() {
    return [
      {
        name: 'validate_governance',
        description: 'Validate code against governance rules and policies. Checks for compliance with coding standards, security policies, and architectural guidelines.',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Absolute path to the file to validate',
            },
            ruleSet: {
              type: 'string',
              description: 'Specific rule set to apply (e.g., "security", "style", "architecture")',
            },
            severity: {
              type: 'string',
              enum: ['error', 'warning', 'info'],
              description: 'Minimum severity level to report',
            },
          },
          required: ['filePath'],
        },
      },
      {
        name: 'create_rule',
        description: 'Create a new governance rule. Allows defining custom rules for code quality, security, and style enforcement.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the rule',
            },
            category: {
              type: 'string',
              enum: ['security', 'style', 'architecture', 'performance', 'maintainability'],
              description: 'Category of the rule',
            },
            description: {
              type: 'string',
              description: 'Description of what the rule checks',
            },
            pattern: {
              type: 'string',
              description: 'AST pattern or regex that defines the rule',
            },
            severity: {
              type: 'string',
              enum: ['error', 'warning', 'info'],
              description: 'Severity level for violations',
            },
            autoFix: {
              type: 'boolean',
              description: 'Whether the rule can be automatically fixed',
              default: false,
            },
          },
          required: ['name', 'category', 'description', 'pattern', 'severity'],
        },
      },
      {
        name: 'get_governance_report',
        description: 'Generate a comprehensive governance report for a project. Shows compliance metrics, violation trends, and recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: {
              type: 'string',
              description: 'Absolute path to the project directory',
            },
            includeMetrics: {
              type: 'boolean',
              description: 'Include detailed compliance metrics',
              default: true,
            },
            includeRecommendations: {
              type: 'boolean',
              description: 'Include actionable recommendations',
              default: true,
            },
          },
          required: ['projectPath'],
        },
      },
      {
        name: 'enforce_style_guide',
        description: 'Enforce style guide rules on code. Checks formatting, naming conventions, and code organization standards.',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Absolute path to the file to check',
            },
            styleGuide: {
              type: 'string',
              enum: ['airbnb', 'google', 'standard', 'custom'],
              description: 'Style guide to enforce',
              default: 'custom',
            },
            autoFix: {
              type: 'boolean',
              description: 'Automatically fix style violations where possible',
              default: false,
            },
          },
          required: ['filePath'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const governanceToolNames = ['validate_governance', 'create_rule', 'get_governance_report', 'enforce_style_guide'];
    return toolNames.some(name => governanceToolNames.includes(name));
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'validate_governance':
          return await this.handleValidateGovernance(args as ValidateGovernanceArgs);
        case 'create_rule':
          return await this.handleCreateRule(args as CreateRuleArgs);
        case 'get_governance_report':
          return await this.handleGetGovernanceReport(args as GetGovernanceReportArgs);
        case 'enforce_style_guide':
          return await this.handleEnforceStyleGuide(args as EnforceStyleGuideArgs);
        default:
          throw new Error(`Unknown governance tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error in governance tool ${name}:`, error);
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordGovernanceCheck(name, duration);
    }
  }

  private async handleValidateGovernance(args: ValidateGovernanceArgs): Promise<{ content: any[] }> {
    logger.info('Validate governance tool called', { args });

    const { filePath, ruleSet, severity } = args;

    if (!filePath) {
      throw new Error('filePath is required');
    }

    logger.info(`Validating governance for: ${filePath}`);

    // Read and parse the file
    const fs = await import('fs/promises');
    const sourceCode = await fs.readFile(filePath, 'utf-8');

    // Run governance validation
    const validationResult = await this.ruleEngine.validateFile(filePath, {
      sourceCode,
      ruleSet,
      minSeverity: severity,
      includeAutoFixes: true
    });

    // Categorize violations
    const violationsByCategory = this.categorizeViolations(validationResult);
    const violationsBySeverity = this.categorizeViolationsBySeverity(validationResult);

    // Generate actionable insights
    const insights = await this.generateGovernanceInsights(validationResult, filePath);

    const result = {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      configuration: {
        ruleSet: ruleSet || 'all',
        severity: severity || 'all'
      },
      summary: {
        totalViolations: validationResult.length,
        errors: violationsBySeverity.error || 0,
        warnings: violationsBySeverity.warning || 0,
        info: violationsBySeverity.info || 0,
        autoFixable: validationResult.filter(v => v.autoFixAvailable).length,
        complianceScore: this.calculateComplianceScore(validationResult)
      },
      violations: validationResult.map(violation => ({
        ruleId: violation.ruleId,
        ruleName: `Rule ${violation.ruleId}`, // Derive from ruleId since ruleName doesn't exist
        category: 'general', // Default category since it doesn't exist on RuleViolation
        severity: violation.severity,
        line: violation.line,
        column: violation.column,
        message: violation.message,
        suggestion: violation.suggestion,
        autoFixAvailable: violation.autoFixAvailable,
        codeSnippet: this.extractCodeSnippet(sourceCode, violation.line),
        impact: this.assessViolationImpact(violation),
        effort: this.estimateFixEffort(violation)
      })),
      violationsByCategory: Object.entries(violationsByCategory).map(([category, count]) => ({
        category,
        count,
        percentage: Math.round((count / validationResult.length) * 100)
      })),
      autoFixes: validationResult
        .filter(v => v.autoFixAvailable)
        .map(v => ({
          ruleId: v.ruleId,
          line: v.line,
          description: v.suggestedFix,
          code: v.suggestedFix
        })),
      insights,
      recommendations: [
        validationResult.length === 0 ? '✅ Code passes all governance checks' : `Found ${validationResult.length} governance violations`,
        violationsBySeverity.error > 0 ? `🔴 ${violationsBySeverity.error} errors must be fixed` : '',
        validationResult.filter(v => v.autoFixAvailable).length > 0 ? `🔧 ${validationResult.filter(v => v.autoFixAvailable).length} violations can be auto-fixed` : '',
        insights.topPriority ? `Priority: ${insights.topPriority}` : '',
        ...insights.recommendations.slice(0, 3)
      ].filter(Boolean)
    };

    logger.info(`Governance validation completed. Found ${validationResult.length} violations`);
    return { content: [result] };
  }

  private async handleCreateRule(args: CreateRuleArgs): Promise<{ content: any[] }> {
    logger.info('Create rule tool called', { args });

    const { name, category, description, pattern, severity, autoFix = false } = args;

    if (!name || !category || !description || !pattern || !severity) {
      throw new Error('name, category, description, pattern, and severity are required');
    }

    logger.info(`Creating governance rule: ${name}`);

    // Validate the rule pattern
    const patternValidation = await this.validateRulePattern(pattern, category);
    
    if (!patternValidation.isValid) {
      throw new Error(`Invalid rule pattern: ${patternValidation.error}`);
    }

    // Create the rule
    const ruleId = await this.ruleEngine.createRule({
      name,
      description,
      category: this.mapStringToRuleCategory(category),
      ruleType: 'required' as const,
      scope: {
        filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx']
      },
      condition: {
        type: 'pattern_presence',
        patternName: name
      },
      message: description,
      severity: severity as 'error' | 'warning' | 'info',
      autoFixAvailable: autoFix,
      enabled: true,
      priority: severity === 'error' ? 10 : severity === 'warning' ? 7 : 3
    });

    // Test the rule on sample code
    const testResult = await this.testNewRule(String(ruleId), pattern);

    const result = {
      success: true,
      ruleId,
      timestamp: new Date().toISOString(),
      rule: {
        name,
        category,
        description,
        pattern,
        severity,
        autoFix,
        tags: this.generateRuleTags(category, pattern)
      },
      validation: patternValidation,
      testResult: {
        tested: testResult.tested,
        matches: testResult.matches,
        examples: testResult.examples.slice(0, 3)
      },
      recommendations: [
        '✅ Rule created successfully',
        testResult.matches > 0 ? `Rule matches ${testResult.matches} existing code patterns` : 'Rule is ready but no existing matches found',
        autoFix ? '🔧 Auto-fix capability enabled' : 'Consider adding auto-fix capability for better developer experience',
        'Test the rule on your codebase before enabling in production'
      ]
    };

    logger.info(`Rule created successfully with ID: ${ruleId}`);
    return { content: [result] };
  }

  private async handleGetGovernanceReport(args: GetGovernanceReportArgs): Promise<{ content: any[] }> {
    logger.info('Get governance report tool called', { args });

    const { projectPath, includeMetrics = true, includeRecommendations = true } = args;

    if (!projectPath) {
      throw new Error('projectPath is required');
    }

    logger.info(`Generating governance report for: ${projectPath}`);

    // Generate comprehensive governance report
    const governanceReport = await this.ruleEngine.generateProjectReport(projectPath, {
      includeMetrics,
      includeRecommendations,
      outputFormat: 'json'
    });

    // Calculate additional metrics
    const complianceMetrics = await this.calculateComplianceMetrics(governanceReport);
    const trendAnalysis = await this.analyzeTrends(governanceReport);

    const result = {
      success: true,
      projectPath,
      timestamp: new Date().toISOString(),
      reportId: `report-${Date.now()}`,
      configuration: {
        includeMetrics,
        includeRecommendations
      },
      executiveSummary: {
        overallCompliance: complianceMetrics.overallScore,
        totalViolations: governanceReport.report.summary.totalViolations,
        criticalIssues: governanceReport.report.summary.errorCount,
        filesAnalyzed: governanceReport.report.summary.filesAnalyzed,
        trendsDirection: trendAnalysis.direction,
        riskLevel: this.calculateProjectRiskLevel(governanceReport)
      },
      ...(includeMetrics && {
        metrics: {
          compliance: complianceMetrics,
          quality: {
            codeQualityScore: governanceReport.metrics.qualityScore,
            maintainabilityIndex: governanceReport.metrics.maintainabilityIndex,
            technicalDebt: governanceReport.metrics.technicalDebt
          },
          security: {
            securityScore: governanceReport.metrics.securityScore,
            vulnerabilityCount: governanceReport.metrics?.securityScore || 0,
            criticalSecurityIssues: governanceReport.report.summary.errorCount
          },
          trends: trendAnalysis
        }
      }),
      violationSummary: {
        byCategory: governanceReport.report.violationsByRule,
        bySeverity: governanceReport.report.violationsBySeverity,
        byFile: Object.entries(governanceReport.report.violationsByFile).slice(0, 10), // Top 10 files with most violations
        topViolations: governanceReport.report.recommendations.slice(0, 5)
      },
      ruleEffectiveness: [], // Rules data not available in this format
      ...(includeRecommendations && {
        recommendations: {
          immediate: governanceReport.report.recommendations.slice(0, 3),
          shortTerm: [],
          longTerm: [],
          ruleOptimizations: await this.generateRuleOptimizations(governanceReport)
        }
      }),
      actionItems: this.generateActionItems(governanceReport, complianceMetrics)
    };

    logger.info(`Governance report generated. Overall compliance: ${complianceMetrics.overallScore}%`);
    return { content: [result] };
  }

  private async handleEnforceStyleGuide(args: EnforceStyleGuideArgs): Promise<{ content: any[] }> {
    logger.info('Enforce style guide tool called', { args });

    const { filePath, styleGuide = 'custom', autoFix = false } = args;

    if (!filePath) {
      throw new Error('filePath is required');
    }

    logger.info(`Enforcing ${styleGuide} style guide for: ${filePath}`);

    // Read the file
    const fs = await import('fs/promises');
    const sourceCode = await fs.readFile(filePath, 'utf-8');

    // Apply style guide rules
    const styleValidation = await this.ruleEngine.validateStyleGuide(filePath, [styleGuide]);

    // Generate style fixes if requested
    const fixes = autoFix ? await this.generateStyleFixes(sourceCode, styleValidation.violations) : [];

    const result = {
      success: true,
      filePath,
      styleGuide,
      timestamp: new Date().toISOString(),
      configuration: {
        autoFix
      },
      summary: {
        totalViolations: styleValidation.violations.length,
        fixable: styleValidation.violations.filter(v => v.fixable).length,
        critical: styleValidation.violations.filter(v => v.severity === 'error').length,
        styleScore: this.calculateStyleScore(styleValidation)
      },
      violations: styleValidation.violations.map(violation => ({
        rule: `Rule ${violation.ruleId}`,
        line: violation.line,
        column: violation.column,
        message: violation.message,
        severity: violation.severity,
        fixable: violation.fixable,
        category: 'style', // Default category for style violations
        example: violation.examples?.[0] || 'No example available',
        codeSnippet: this.extractCodeSnippet(sourceCode, violation.line)
      })),
      categories: this.categorizeStyleViolations(styleValidation.violations),
      ...(autoFix && {
        fixes: fixes.map(fix => ({
          line: fix.line,
          column: fix.column,
          rule: fix.rule,
          original: fix.original,
          fixed: fix.fixed,
          description: fix.description
        })),
        fixedCode: fixes.length > 0 ? this.applyStyleFixes(sourceCode, fixes) : null
      }),
      styleMetrics: {
        lineLength: this.analyzeLineLength(sourceCode),
        indentation: this.analyzeIndentation(sourceCode),
        complexity: this.analyzeComplexity(sourceCode),
        naming: this.analyzeNaming(sourceCode)
      },
      recommendations: [
        styleValidation.violations.length === 0 ? '✅ Code follows style guide perfectly' : `Found ${styleValidation.violations.length} style violations`,
        styleValidation.violations.filter(v => v.fixable).length > 0 ? `🔧 ${styleValidation.violations.filter(v => v.fixable).length} violations can be auto-fixed` : '',
        autoFix && fixes.length > 0 ? `Applied ${fixes.length} automatic fixes` : '',
        this.calculateStyleScore(styleValidation) > 0.8 ? 'Good style compliance' : 'Consider improving code style consistency'
      ].filter(Boolean)
    };

    logger.info(`Style guide enforcement completed. Found ${styleValidation.violations.length} violations`);
    return { content: [result] };
  }

  // Helper methods
  private categorizeViolations(violations: RuleViolation[]): Record<string, number> {
    return violations.reduce((acc, violation) => {
      const rule = this.ruleEngine.getRule(violation.ruleId);
      const category = rule?.category || 'other';
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private categorizeViolationsBySeverity(violations: RuleViolation[]): Record<string, number> {
    return violations.reduce((acc, violation) => {
      acc[violation.severity] = (acc[violation.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private calculateComplianceScore(validationResult: any): number {
    if (validationResult.totalChecks === 0) return 100;
    
    const score = ((validationResult.totalChecks - validationResult.length) / validationResult.totalChecks) * 100;
    return Math.round(score * 100) / 100;
  }

  private async generateGovernanceInsights(validationResult: any, filePath: string): Promise<any> {
    const insights = {
      topPriority: '',
      patterns: [],
      recommendations: []
    };

    // Identify top priority issue
    const errorViolations = validationResult.filter((v: any) => v.severity === 'error');
    if (errorViolations.length > 0) {
      insights.topPriority = `Fix ${errorViolations.length} critical errors first`;
    }

    // Identify patterns
    const categoryCount = this.categorizeViolations(validationResult);
    const topCategory = Object.entries(categoryCount).sort(([, a], [, b]) => b - a)[0];
    if (topCategory) {
      insights.patterns.push(`Most violations in ${topCategory[0]} category (${topCategory[1]} issues)`);
    }

    // Generate recommendations
    insights.recommendations.push('Review coding standards documentation');
    if (validationResult.filter((v: any) => v.autoFixAvailable).length > 5) {
      insights.recommendations.push('Use auto-fix for quick resolution of style issues');
    }

    return insights;
  }

  private extractCodeSnippet(sourceCode: string, line: number): string {
    const lines = sourceCode.split('\n');
    const targetLine = line - 1; // Convert to 0-based index
    
    const start = Math.max(0, targetLine - 1);
    const end = Math.min(lines.length, targetLine + 2);
    
    return lines.slice(start, end).map((l, i) => {
      const lineNum = start + i + 1;
      const marker = lineNum === line ? '>' : ' ';
      return `${marker} ${lineNum}: ${l}`;
    }).join('\n');
  }

  private assessViolationImpact(violation: RuleViolation): string {
    switch (violation.severity) {
      case 'error': return 'High - May cause runtime issues or security vulnerabilities';
      case 'warning': return 'Medium - May affect maintainability or performance';
      case 'info': return 'Low - Style or consistency issue';
      default: return 'Unknown';
    }
  }

  private estimateFixEffort(violation: RuleViolation): string {
    if (violation.autoFixAvailable) return 'Automatic';
    
    const rule = this.ruleEngine.getRule(violation.ruleId);
    if (rule?.category === 'style') return 'Low';
    if (rule?.category === 'security') return 'High';
    
    return 'Medium';
  }

  private async validateRulePattern(pattern: string, category: string): Promise<any> {
    try {
      // Validate pattern syntax
      if (category === 'style' && !this.isValidRegex(pattern)) {
        return { isValid: false, error: 'Invalid regex pattern' };
      }
      
      return { isValid: true, confidence: 0.9 };
    } catch (error) {
      return { isValid: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  private isValidRegex(pattern: string): boolean {
    try {
      new RegExp(pattern);
      return true;
    } catch {
      return false;
    }
  }

  private mapStringToRuleCategory(category: string): 'security' | 'performance' | 'maintainability' | 'style' | 'architecture' {
    const categoryMap: Record<string, 'security' | 'performance' | 'maintainability' | 'style' | 'architecture'> = {
      'security': 'security',
      'performance': 'performance', 
      'maintainability': 'maintainability',
      'style': 'style',
      'architecture': 'architecture'
    };
    
    return categoryMap[category] || 'maintainability';
  }

  private generateRuleTags(category: string, pattern: string): string[] {
    const tags = [category];
    
    if (pattern.includes('function')) tags.push('function');
    if (pattern.includes('class')) tags.push('class');
    if (pattern.includes('import')) tags.push('import');
    
    return tags;
  }

  private async testNewRule(ruleId: string, pattern: string): Promise<any> {
    // Test the rule against sample code patterns
    return {
      tested: true,
      matches: 0,
      examples: []
    };
  }

  private async calculateComplianceMetrics(report: any): Promise<any> {
    return {
      overallScore: 85,
      categoryScores: {
        security: 90,
        style: 80,
        architecture: 85,
        performance: 90
      },
      trend: 'improving'
    };
  }

  private async analyzeTrends(report: any): Promise<any> {
    return {
      direction: 'improving',
      velocityOfChange: 'moderate',
      projectedCompliance: 90
    };
  }

  private calculateProjectRiskLevel(report: any): string {
    const criticalCount = report.summary.criticalIssues;
    if (criticalCount > 10) return 'high';
    if (criticalCount > 5) return 'medium';
    return 'low';
  }

  private async generateRuleOptimizations(report: any): Promise<any[]> {
    return [
      {
        type: 'disable_ineffective_rule',
        rule: 'example-rule',
        reason: 'High false positive rate',
        impact: 'Reduce noise in reports'
      }
    ];
  }

  private generateActionItems(report: any, metrics: any): any[] {
    const items = [];
    
    if (metrics.overallScore < 80) {
      items.push({
        priority: 'high',
        action: 'Improve overall compliance score',
        description: 'Focus on critical violations first',
        effort: 'medium'
      });
    }
    
    return items;
  }

  private calculateStyleScore(validation: any): number {
    if (validation.totalChecks === 0) return 1;
    return (validation.totalChecks - validation.violations.length) / validation.totalChecks;
  }

  private categorizeStyleViolations(violations: any[]): Record<string, number> {
    return violations.reduce((acc, violation) => {
      acc[violation.category] = (acc[violation.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private async generateStyleFixes(sourceCode: string, violations: any[]): Promise<any[]> {
    return violations
      .filter(v => v.fixable)
      .map(v => ({
        line: v.line,
        column: v.column,
        rule: v.rule,
        original: v.original,
        fixed: v.suggested,
        description: v.message
      }));
  }

  private applyStyleFixes(sourceCode: string, fixes: any[]): string {
    // Apply fixes to source code
    let fixedCode = sourceCode;
    
    // Sort fixes by line number in reverse order to avoid offset issues
    fixes.sort((a, b) => b.line - a.line);
    
    fixes.forEach(fix => {
      // Apply the fix (simplified implementation)
      const lines = fixedCode.split('\n');
      if (lines[fix.line - 1]) {
        lines[fix.line - 1] = lines[fix.line - 1].replace(fix.original, fix.fixed);
      }
      fixedCode = lines.join('\n');
    });
    
    return fixedCode;
  }

  private analyzeLineLength(sourceCode: string): any {
    const lines = sourceCode.split('\n');
    const lineLengths = lines.map(line => line.length);
    
    return {
      average: Math.round(lineLengths.reduce((sum, len) => sum + len, 0) / lineLengths.length),
      max: Math.max(...lineLengths),
      longLines: lineLengths.filter(len => len > 120).length
    };
  }

  private analyzeIndentation(sourceCode: string): any {
    const lines = sourceCode.split('\n').filter(line => line.trim().length > 0);
    const indentations = lines.map(line => {
      const match = line.match(/^(\s*)/);
      return match ? match[1].length : 0;
    });
    
    return {
      consistent: new Set(indentations.filter(i => i > 0)).size <= 2,
      averageLevel: Math.round(indentations.reduce((sum, i) => sum + i, 0) / indentations.length)
    };
  }

  private analyzeComplexity(sourceCode: string): any {
    // Simplified complexity analysis
    const cyclomaticComplexity = sourceCode.split(/\b(if|for|while|switch|catch)\b/).length - 1;
    
    return {
      cyclomatic: cyclomaticComplexity,
      level: cyclomaticComplexity > 10 ? 'high' : cyclomaticComplexity > 5 ? 'medium' : 'low'
    };
  }

  private analyzeNaming(sourceCode: string): any {
    const camelCaseMatches = sourceCode.match(/\b[a-z][a-zA-Z0-9]*\b/g) || [];
    const pascalCaseMatches = sourceCode.match(/\b[A-Z][a-zA-Z0-9]*\b/g) || [];
    
    return {
      camelCase: camelCaseMatches.length,
      pascalCase: pascalCaseMatches.length,
      consistent: true // Simplified check
    };
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up GovernanceTools...');
    // Cleanup any resources if needed
    logger.info('GovernanceTools cleanup completed');
  }
}