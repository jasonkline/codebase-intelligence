import { ConfigurationManager } from '../config/ConfigurationManager';
import logger from '../utils/logger';

export interface FormattingOptions {
  maxContentLength?: number;
  includeMetadata?: boolean;
  prioritizeActionable?: boolean;
  includeExamples?: boolean;
  markdownFormatting?: boolean;
  streamingMode?: boolean;
}

export interface ResponseMetadata {
  timestamp: string;
  toolName: string;
  processingTime?: number;
  confidence?: number;
  resultCount?: number;
  version: string;
}

export class ResponseFormatter {
  private configManager: ConfigurationManager;
  private defaultOptions: FormattingOptions;

  constructor(configManager: ConfigurationManager) {
    this.configManager = configManager;
    this.defaultOptions = {
      maxContentLength: 50000, // 50KB max response
      includeMetadata: true,
      prioritizeActionable: true,
      includeExamples: true,
      markdownFormatting: true,
      streamingMode: false
    };
  }

  async formatToolResponse(toolName: string, rawResult: any, options?: FormattingOptions): Promise<any> {
    const startTime = Date.now();
    
    try {
      const formatOptions = { ...this.defaultOptions, ...options };
      
      // Add metadata
      const metadata: ResponseMetadata = {
        timestamp: new Date().toISOString(),
        toolName,
        processingTime: Date.now() - startTime,
        confidence: rawResult.confidence || 1.0,
        resultCount: this.extractResultCount(rawResult),
        version: this.configManager.getConfig().version || '1.0.0'
      };

      // Format based on tool type
      let formattedResult = await this.formatByToolType(toolName, rawResult, formatOptions);

      // Apply general formatting rules
      formattedResult = await this.applyGeneralFormatting(formattedResult, formatOptions);

      // Add Claude Code specific optimizations
      formattedResult = await this.optimizeForClaudeCode(formattedResult, toolName);

      // Limit content size if needed
      if (formatOptions.maxContentLength) {
        formattedResult = this.limitContentSize(formattedResult, formatOptions.maxContentLength);
      }

      // Add metadata if requested
      if (formatOptions.includeMetadata) {
        formattedResult = this.addMetadata(formattedResult, metadata);
      }

      logger.debug(`Response formatted for ${toolName}`, { 
        originalSize: JSON.stringify(rawResult).length,
        formattedSize: JSON.stringify(formattedResult).length,
        processingTime: Date.now() - startTime
      });

      return formattedResult;

    } catch (error) {
      logger.error(`Error formatting response for ${toolName}:`, error);
      return this.createErrorResponse(toolName, error);
    }
  }

  formatErrorResponse(toolName: string, error: any): any {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    return {
      content: [{
        success: false,
        error: true,
        toolName,
        timestamp: new Date().toISOString(),
        errorMessage,
        errorType: error.constructor?.name || 'Unknown',
        suggestion: this.generateErrorSuggestion(toolName, errorMessage),
        recovery: {
          canRetry: this.canRetryError(error),
          suggestion: 'Check your parameters and try again',
          documentation: `See help for ${toolName} tool usage`
        }
      }]
    };
  }

  private async formatByToolType(toolName: string, result: any, options: FormattingOptions): Promise<any> {
    switch (true) {
      case toolName.includes('security'):
        return this.formatSecurityResponse(result, options);
      
      case toolName.includes('pattern'):
        return this.formatPatternResponse(result, options);
      
      case toolName.includes('knowledge') || toolName.includes('explain'):
        return this.formatKnowledgeResponse(result, options);
      
      case toolName.includes('navigation') || toolName.includes('search') || toolName.includes('find'):
        return this.formatNavigationResponse(result, options);
      
      case toolName.includes('governance'):
        return this.formatGovernanceResponse(result, options);
      
      case toolName.includes('realtime'):
        return this.formatRealtimeResponse(result, options);
      
      default:
        return this.formatGenericResponse(result, options);
    }
  }

  private formatSecurityResponse(result: any, options: FormattingOptions): any {
    if (!result.content || !Array.isArray(result.content)) {
      return result;
    }

    return {
      ...result,
      content: result.content.map((item: any) => {
        if (item.success === false) return item;

        // Prioritize critical security issues
        const formatted = {
          ...item,
          // Restructure for Claude Code consumption
          summary: this.createSecuritySummary(item),
          criticalActions: this.extractCriticalActions(item),
          ...(options.includeExamples && item.findings && {
            topFindings: this.formatTopFindings(item.findings, 'security')
          })
        };

        // Add security-specific formatting
        if (item.criticalFindings?.length > 0) {
          formatted.urgentActions = item.criticalFindings.map((finding: any) => ({
            severity: finding.severity,
            title: finding.title,
            location: `${finding.file}:${finding.line}`,
            action: finding.remediation,
            priority: 'immediate'
          }));
        }

        return formatted;
      })
    };
  }

  private formatPatternResponse(result: any, options: FormattingOptions): any {
    if (!result.content || !Array.isArray(result.content)) {
      return result;
    }

    return {
      ...result,
      content: result.content.map((item: any) => {
        if (item.success === false) return item;

        const formatted = {
          ...item,
          summary: this.createPatternSummary(item),
          actionableInsights: this.extractActionableInsights(item, 'pattern')
        };

        // Add pattern-specific formatting
        if (item.patterns && options.includeExamples) {
          formatted.examplePatterns = this.formatPatternExamples(item.patterns);
        }

        if (item.violations?.length > 0) {
          formatted.quickFixes = item.violations
            .filter((v: any) => v.autoFixAvailable)
            .slice(0, 5)
            .map((v: any) => ({
              line: v.line,
              issue: v.message,
              fix: v.suggestion,
              effort: 'low'
            }));
        }

        return formatted;
      })
    };
  }

  private formatKnowledgeResponse(result: any, options: FormattingOptions): any {
    if (!result.content || !Array.isArray(result.content)) {
      return result;
    }

    return {
      ...result,
      content: result.content.map((item: any) => {
        if (item.success === false) return item;

        const formatted = {
          ...item,
          // Structure for better Claude Code understanding
          keyInsights: this.extractKeyInsights(item),
          quickReference: this.createQuickReference(item)
        };

        // Format long answers for readability
        if (item.answer && item.answer.length > 1000) {
          formatted.answerSummary = this.summarizeText(item.answer, 300);
          formatted.fullAnswer = item.answer;
          formatted.readingTime = Math.ceil(item.answer.length / 1000); // ~1000 chars per minute
        }

        // Format code examples for better display
        if (item.codeExamples && options.includeExamples) {
          formatted.practicalExamples = item.codeExamples.map((example: any) => ({
            title: example.title,
            language: this.detectLanguage(example.code),
            code: this.formatCodeBlock(example.code),
            explanation: example.explanation,
            useCase: example.useCase || 'General usage'
          }));
        }

        return formatted;
      })
    };
  }

  private formatNavigationResponse(result: any, options: FormattingOptions): any {
    if (!result.content || !Array.isArray(result.content)) {
      return result;
    }

    return {
      ...result,
      content: result.content.map((item: any) => {
        if (item.success === false) return item;

        const formatted = {
          ...item,
          navigationSummary: this.createNavigationSummary(item),
          quickActions: this.extractQuickActions(item)
        };

        // Format search results for better scanning
        if (item.results && Array.isArray(item.results)) {
          formatted.topResults = item.results.slice(0, 10).map((result: any) => ({
            file: result.file,
            line: result.line,
            preview: result.preview || result.content?.substring(0, 100) + '...',
            relevance: result.relevanceScore || result.confidence || 1.0,
            type: result.symbolType || 'code'
          }));

          if (item.results.length > 10) {
            formatted.additionalResults = {
              count: item.results.length - 10,
              suggestion: 'Use more specific search terms to narrow results'
            };
          }
        }

        return formatted;
      })
    };
  }

  private formatGovernanceResponse(result: any, options: FormattingOptions): any {
    if (!result.content || !Array.isArray(result.content)) {
      return result;
    }

    return {
      ...result,
      content: result.content.map((item: any) => {
        if (item.success === false) return item;

        const formatted = {
          ...item,
          complianceSnapshot: this.createComplianceSnapshot(item),
          prioritizedActions: this.prioritizeGovernanceActions(item)
        };

        // Format violations for actionability
        if (item.violations && Array.isArray(item.violations)) {
          formatted.actionableViolations = item.violations
            .sort((a: any, b: any) => this.getViolationPriority(b) - this.getViolationPriority(a))
            .slice(0, 15)
            .map((violation: any) => ({
              rule: violation.ruleName || violation.ruleId,
              location: `Line ${violation.line}`,
              issue: violation.message,
              impact: violation.impact || this.assessImpact(violation.severity),
              effort: violation.effort || 'medium',
              autoFixable: violation.autoFixAvailable || false
            }));
        }

        return formatted;
      })
    };
  }

  private formatRealtimeResponse(result: any, options: FormattingOptions): any {
    // Real-time responses need to be fast and minimal
    const streamlined = {
      ...result,
      content: result.content?.map((item: any) => ({
        ...item,
        // Remove heavy data for real-time performance
        ...(item.suggestions && { 
          topSuggestions: item.suggestions.slice(0, 3) 
        }),
        ...(item.issues && { 
          criticalIssues: item.issues.filter((i: any) => i.severity === 'error').slice(0, 5) 
        })
      }))
    };

    return streamlined;
  }

  private formatGenericResponse(result: any, options: FormattingOptions): any {
    return result;
  }

  private async applyGeneralFormatting(result: any, options: FormattingOptions): Promise<any> {
    if (!options.markdownFormatting) {
      return result;
    }

    // Apply markdown formatting to string content
    if (result.content && Array.isArray(result.content)) {
      result.content = result.content.map((item: any) => {
        if (typeof item === 'object') {
          return this.applyMarkdownToObject(item);
        }
        return item;
      });
    }

    return result;
  }

  private async optimizeForClaudeCode(result: any, toolName: string): Promise<any> {
    // Claude Code specific optimizations
    const optimized = {
      ...result,
      // Add tool context for Claude Code
      _claudeCodeMeta: {
        toolName,
        optimizedFor: 'claude-code',
        suggestedFollowUp: this.generateFollowUpSuggestions(toolName, result)
      }
    };

    // Prioritize actionable content
    if (result.content && Array.isArray(result.content)) {
      optimized.content = result.content.map((item: any) => {
        if (item.recommendations && Array.isArray(item.recommendations)) {
          // Move actionable recommendations to the top
          item.recommendations = this.prioritizeActionableRecommendations(item.recommendations);
        }
        return item;
      });
    }

    return optimized;
  }

  private limitContentSize(result: any, maxSize: number): any {
    const resultStr = JSON.stringify(result);
    
    if (resultStr.length <= maxSize) {
      return result;
    }

    logger.warn(`Response size ${resultStr.length} exceeds limit ${maxSize}, truncating...`);

    // Implement intelligent truncation
    const truncated = { ...result };
    
    if (truncated.content && Array.isArray(truncated.content)) {
      truncated.content = truncated.content.map((item: any) => {
        // Truncate large arrays
        Object.keys(item).forEach(key => {
          if (Array.isArray(item[key]) && item[key].length > 20) {
            const originalLength = item[key].length;
            item[key] = item[key].slice(0, 20);
            item[`${key}_truncated`] = true;
            item[`${key}_original_count`] = originalLength;
          }
        });

        // Truncate long strings
        Object.keys(item).forEach(key => {
          if (typeof item[key] === 'string' && item[key].length > 2000) {
            item[key] = item[key].substring(0, 2000) + '... (truncated)';
          }
        });

        return item;
      });
    }

    return truncated;
  }

  private addMetadata(result: any, metadata: ResponseMetadata): any {
    return {
      ...result,
      _metadata: metadata
    };
  }

  private createErrorResponse(toolName: string, error: any): any {
    return {
      content: [{
        success: false,
        error: true,
        toolName,
        timestamp: new Date().toISOString(),
        message: error instanceof Error ? error.message : String(error),
        suggestion: 'Please check your input parameters and try again'
      }]
    };
  }

  // Helper methods for formatting specific content types

  private createSecuritySummary(item: any): any {
    return {
      riskLevel: this.calculateOverallRisk(item),
      criticalIssues: item.criticalFindings?.length || 0,
      totalFindings: item.summary?.totalFindings || 0,
      requiresImmediateAction: (item.criticalFindings?.length || 0) > 0
    };
  }

  private extractCriticalActions(item: any): any[] {
    const actions = [];
    
    if (item.criticalFindings?.length > 0) {
      actions.push({
        type: 'security',
        priority: 'critical',
        action: `Address ${item.criticalFindings.length} critical security issues`,
        timeframe: 'immediate'
      });
    }

    return actions;
  }

  private formatTopFindings(findings: any, type: string): any[] {
    const topFindings = Object.values(findings)
      .flat()
      .slice(0, 5);

    return topFindings.map((finding: any) => ({
      type,
      title: finding.title || finding.description,
      severity: finding.severity,
      location: finding.file ? `${finding.file}:${finding.line}` : 'Multiple locations',
      action: finding.remediation || finding.suggestion
    }));
  }

  private createPatternSummary(item: any): any {
    return {
      complianceScore: item.compliance?.overallScore || 0,
      violationsFound: item.violations?.length || 0,
      patternsAnalyzed: Object.values(item.patterns || {}).reduce((sum: number, count: any) => sum + (count || 0), 0),
      needsAttention: (item.violations?.length || 0) > 0
    };
  }

  private extractActionableInsights(item: any, type: string): any[] {
    const insights = [];
    
    if (type === 'pattern' && item.violations?.length > 0) {
      const autoFixable = item.violations.filter((v: any) => v.autoFixAvailable);
      if (autoFixable.length > 0) {
        insights.push({
          type: 'auto-fix',
          description: `${autoFixable.length} violations can be automatically fixed`,
          action: 'Run auto-fix tools',
          effort: 'low'
        });
      }
    }

    return insights;
  }

  private formatPatternExamples(patterns: any): any[] {
    return Object.entries(patterns).map(([category, examples]: [string, any]) => ({
      category,
      exampleCount: Array.isArray(examples) ? examples.length : examples,
      status: examples > 0 ? 'found' : 'missing'
    }));
  }

  private extractKeyInsights(item: any): any[] {
    const insights = [];
    
    if (item.confidence && item.confidence < 0.7) {
      insights.push({
        type: 'confidence',
        message: 'Results have moderate confidence - consider providing more context'
      });
    }

    if (item.relatedTopics?.length > 0) {
      insights.push({
        type: 'related',
        message: `Related topics: ${item.relatedTopics.slice(0, 3).join(', ')}`
      });
    }

    return insights;
  }

  private createQuickReference(item: any): any {
    const reference: any = {};
    
    if (item.keyComponents) {
      reference.components = item.keyComponents.slice(0, 3);
    }
    
    if (item.commonPatterns) {
      reference.patterns = item.commonPatterns.slice(0, 3);
    }

    return reference;
  }

  private summarizeText(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    
    // Find the last complete sentence within the limit
    const truncated = text.substring(0, maxLength);
    const lastPeriod = truncated.lastIndexOf('.');
    
    if (lastPeriod > maxLength * 0.8) {
      return truncated.substring(0, lastPeriod + 1);
    }
    
    return truncated + '...';
  }

  private detectLanguage(code: string): string {
    if (code.includes('function ') || code.includes('const ') || code.includes('import ')) {
      return 'typescript';
    }
    if (code.includes('def ') || code.includes('import ')) {
      return 'python';
    }
    return 'text';
  }

  private formatCodeBlock(code: string): string {
    // Ensure proper indentation and formatting
    const lines = code.split('\n');
    const minIndent = Math.min(...lines.filter(line => line.trim()).map(line => line.match(/^\s*/)?.[0].length || 0));
    
    return lines.map(line => line.substring(minIndent)).join('\n');
  }

  private createNavigationSummary(item: any): any {
    return {
      resultsFound: item.results?.length || item.totalResults || 0,
      searchQuery: item.query || 'N/A',
      resultType: this.determineResultType(item)
    };
  }

  private extractQuickActions(item: any): any[] {
    const actions = [];
    
    if (item.results?.length > 50) {
      actions.push({
        type: 'refine',
        description: 'Too many results - consider refining your search',
        suggestion: 'Add more specific terms or use filters'
      });
    }

    return actions;
  }

  private createComplianceSnapshot(item: any): any {
    return {
      overallScore: item.summary?.complianceScore || item.complianceScore || 0,
      criticalViolations: item.summary?.errors || 0,
      autoFixableCount: item.summary?.autoFixable || 0,
      status: this.determineComplianceStatus(item)
    };
  }

  private prioritizeGovernanceActions(item: any): any[] {
    const actions = [];
    
    if (item.summary?.errors > 0) {
      actions.push({
        priority: 1,
        type: 'critical',
        description: `Fix ${item.summary.errors} critical violations`,
        effort: 'high'
      });
    }

    if (item.summary?.autoFixable > 0) {
      actions.push({
        priority: 2,
        type: 'auto-fix',
        description: `Auto-fix ${item.summary.autoFixable} violations`,
        effort: 'low'
      });
    }

    return actions;
  }

  private getViolationPriority(violation: any): number {
    const severityScores = { error: 3, warning: 2, info: 1 };
    return severityScores[violation.severity as keyof typeof severityScores] || 0;
  }

  private assessImpact(severity: string): string {
    const impacts = {
      error: 'High - May cause issues',
      warning: 'Medium - Consider fixing',
      info: 'Low - Style improvement'
    };
    return impacts[severity as keyof typeof impacts] || 'Unknown';
  }

  private applyMarkdownToObject(obj: any): any {
    const processed = { ...obj };
    
    // Format specific fields with markdown
    if (processed.description && typeof processed.description === 'string') {
      processed.description = this.formatAsMarkdown(processed.description);
    }
    
    if (processed.explanation && typeof processed.explanation === 'string') {
      processed.explanation = this.formatAsMarkdown(processed.explanation);
    }

    return processed;
  }

  private formatAsMarkdown(text: string): string {
    // Simple markdown formatting
    return text
      .replace(/\*\*(.*?)\*\*/g, '**$1**') // Bold
      .replace(/\*(.*?)\*/g, '*$1*') // Italic
      .replace(/`(.*?)`/g, '`$1`'); // Code
  }

  private generateFollowUpSuggestions(toolName: string, result: any): string[] {
    const suggestions = [];
    
    if (toolName.includes('security') && result.content?.[0]?.criticalFindings?.length > 0) {
      suggestions.push('Run security analysis on related files');
      suggestions.push('Check for similar patterns across the codebase');
    }
    
    if (toolName.includes('pattern')) {
      suggestions.push('Apply learned patterns to new code');
      suggestions.push('Run governance validation with updated patterns');
    }

    return suggestions;
  }

  private prioritizeActionableRecommendations(recommendations: string[]): string[] {
    // Move actionable recommendations (those starting with action verbs) to the front
    const actionVerbs = ['fix', 'add', 'remove', 'update', 'implement', 'refactor', 'use', 'apply'];
    
    const actionable = recommendations.filter(rec => 
      actionVerbs.some(verb => rec.toLowerCase().startsWith(verb))
    );
    
    const nonActionable = recommendations.filter(rec => 
      !actionVerbs.some(verb => rec.toLowerCase().startsWith(verb))
    );

    return [...actionable, ...nonActionable];
  }

  private extractResultCount(result: any): number {
    if (result.content && Array.isArray(result.content)) {
      return result.content.reduce((count: number, item: any) => {
        if (item.results) return count + item.results.length;
        if (item.findings) return count + Object.values(item.findings).flat().length;
        if (item.violations) return count + item.violations.length;
        return count + 1;
      }, 0);
    }
    return 1;
  }

  private generateErrorSuggestion(toolName: string, errorMessage: string): string {
    if (errorMessage.includes('required')) {
      return 'Check that all required parameters are provided';
    }
    if (errorMessage.includes('path') || errorMessage.includes('file')) {
      return 'Verify that the file path exists and is accessible';
    }
    if (errorMessage.includes('permission')) {
      return 'Check file permissions and access rights';
    }
    return `Refer to the ${toolName} tool documentation for proper usage`;
  }

  private canRetryError(error: any): boolean {
    const retryableErrors = ['ENOENT', 'EACCES', 'ETIMEDOUT', 'ECONNRESET'];
    return retryableErrors.some(type => error.code === type || error.message?.includes(type));
  }

  private calculateOverallRisk(item: any): string {
    const critical = item.criticalFindings?.length || 0;
    const high = item.summary?.criticalIssues || 0;
    
    if (critical > 5 || high > 10) return 'high';
    if (critical > 0 || high > 5) return 'medium';
    return 'low';
  }

  private determineResultType(item: any): string {
    if (item.symbols || item.definitions) return 'symbols';
    if (item.dependencies) return 'dependencies';
    if (item.structure) return 'structure';
    return 'search';
  }

  private determineComplianceStatus(item: any): string {
    const score = item.summary?.complianceScore || item.complianceScore || 0;
    if (score >= 90) return 'excellent';
    if (score >= 80) return 'good';
    if (score >= 70) return 'fair';
    return 'needs-improvement';
  }
}