import { FileWatcher, FileChange } from '../realtime/FileWatcher';
import { IncrementalAnalyzer, AnalysisResult } from '../realtime/IncrementalAnalyzer';
import { InstantValidator, ValidationResult, ValidationIssue } from '../realtime/InstantValidator';
import { SmartSuggestions, SmartSuggestion, CompletionRequest } from '../intelligence/SmartSuggestions';
import { ErrorPrevention, PotentialError, ErrorPrediction } from '../intelligence/ErrorPrevention';
import { PatternRegistry } from '../patterns/PatternRegistry';
import { RuleEngine } from '../governance/RuleEngine';
import { SecurityScanner } from '../security/SecurityScanner';
import { ASTParser } from '../parser/ASTParser';
import DatabaseManager from '../database/schema';
import { logger } from '../utils/logger';

export interface ValidateAsTypedArgs {
  filePath: string;
  content: string;
  line?: number;
  column?: number;
  triggerCharacter?: string;
}

export interface SuggestNextArgs {
  filePath: string;
  content: string;
  line: number;
  column: number;
  context?: string;
  maxSuggestions?: number;
}

export interface PreventErrorArgs {
  filePath: string;
  content?: string;
  line?: number;
  analysisType?: 'quick' | 'comprehensive';
}

export interface QuickFixArgs {
  filePath: string;
  issueId: string;
  line: number;
  column: number;
}

export interface ExplainWarningArgs {
  issueId: string;
  includeExamples?: boolean;
  includeRemediation?: boolean;
}

export interface StartWatchingArgs {
  projectPath: string;
  patterns?: string[];
  ignored?: string[];
  debounceMs?: number;
}

export interface StopWatchingArgs {
  projectPath: string;
}

export class RealtimeTools {
  private watchers = new Map<string, FileWatcher>();
  private incrementalAnalyzer: IncrementalAnalyzer;
  private instantValidator: InstantValidator;
  private smartSuggestions: SmartSuggestions;
  private errorPrevention: ErrorPrevention;
  
  constructor(
    private database: DatabaseManager,
    private patternRegistry: PatternRegistry,
    private ruleEngine: RuleEngine,
    private securityScanner: SecurityScanner
  ) {
    this.incrementalAnalyzer = new IncrementalAnalyzer();
    this.instantValidator = new InstantValidator(
      this.incrementalAnalyzer,
      this.patternRegistry,
      this.ruleEngine,
      this.securityScanner,
      new ASTParser()
    );
    this.smartSuggestions = new SmartSuggestions(
      this.incrementalAnalyzer,
      this.patternRegistry
    );
    this.errorPrevention = new ErrorPrevention(
      this.incrementalAnalyzer,
      this.patternRegistry
    );
  }

  async validateAsTyped(args: ValidateAsTypedArgs): Promise<{ content: any[] }> {
    logger.info('Real-time validation requested', { filePath: args.filePath });
    
    try {
      const { filePath, content, line, column, triggerCharacter } = args;
      
      if (!filePath || !content) {
        throw new Error('filePath and content are required');
      }

      const startTime = Date.now();
      
      // Perform instant validation
      const result = await this.instantValidator.validateAsTyped(
        filePath,
        content,
        line,
        column
      );

      const response = {
        success: true,
        filePath,
        timestamp: new Date().toISOString(),
        trigger: triggerCharacter,
        position: { line, column },
        performance: {
          responseTime: result.performanceMs,
          fromCache: result.fromCache,
          target: '< 50ms',
          met: result.performanceMs < 50
        },
        validation: {
          totalIssues: result.issues.length,
          errors: result.issues.filter(i => i.type === 'error').length,
          warnings: result.issues.filter(i => i.type === 'warning').length,
          suggestions: result.suggestions.length
        },
        issues: result.issues.map(issue => ({
          id: issue.id,
          type: issue.type,
          category: issue.category,
          severity: issue.severity,
          message: issue.message,
          line: issue.line,
          column: issue.column,
          rule: issue.rule,
          fixable: issue.fixable,
          suggestedFix: issue.suggestedFix,
          examples: issue.examples?.slice(0, 2) // Limit for performance
        })),
        smartSuggestions: result.suggestions.map(suggestion => ({
          id: suggestion.id,
          message: suggestion.message,
          code: suggestion.code,
          confidence: suggestion.confidence,
          category: suggestion.category
        })),
        contextInfo: {
          fileType: this.getFileType(filePath),
          hasSecurityContext: filePath.includes('/api/') || filePath.includes('auth'),
          requiresAuth: this.shouldRequireAuth(filePath, content)
        }
      };

      logger.debug(`Real-time validation completed in ${result.performanceMs}ms`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in validateAsTyped:', error);
      
      const errorResponse = {
        success: false,
        filePath: args.filePath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        performance: {
          responseTime: Date.now() - Date.now(),
          fromCache: false,
          target: '< 50ms',
          met: false
        },
        validation: {
          totalIssues: 0,
          errors: 0,
          warnings: 0,
          suggestions: 0
        },
        issues: [],
        smartSuggestions: [],
        contextInfo: {}
      };

      return { content: [errorResponse] };
    }
  }

  async suggestNext(args: SuggestNextArgs): Promise<{ content: any[] }> {
    logger.info('Next pattern suggestion requested', { filePath: args.filePath });

    try {
      const { filePath, content, line, column, context, maxSuggestions = 5 } = args;

      if (!filePath || !content) {
        throw new Error('filePath and content are required');
      }

      const completionRequest: CompletionRequest = {
        filePath,
        content,
        line,
        column,
        maxSuggestions
      };

      const startTime = Date.now();
      const suggestions = await this.smartSuggestions.getSuggestions(completionRequest);
      const responseTime = Date.now() - startTime;

      // Also get pattern predictions
      const contextData = {
        filePath,
        fileType: this.getFileType(filePath) as any,
        currentLine: content.split('\n')[line - 1] || '',
        previousLines: content.split('\n').slice(Math.max(0, line - 6), line - 1),
        nextLines: content.split('\n').slice(line, Math.min(content.split('\n').length, line + 5)),
        cursorPosition: { line, column },
        symbols: [], // Would be populated by incremental analyzer
        imports: this.extractImports(content),
        patterns: []
      };

      const patternPredictions = await this.smartSuggestions.predictNextPattern(contextData);

      const response = {
        success: true,
        filePath,
        timestamp: new Date().toISOString(),
        position: { line, column },
        context: context || 'auto-detected',
        performance: {
          responseTime,
          target: '< 100ms',
          met: responseTime < 100
        },
        summary: {
          totalSuggestions: suggestions.length,
          patternSuggestions: suggestions.filter(s => s.type === 'pattern').length,
          completionSuggestions: suggestions.filter(s => s.type === 'completion').length,
          securitySuggestions: suggestions.filter(s => s.type === 'security').length,
          predictions: patternPredictions.length
        },
        suggestions: suggestions.map(suggestion => ({
          id: suggestion.id,
          type: suggestion.type,
          priority: suggestion.priority,
          confidence: suggestion.confidence,
          message: suggestion.message,
          description: suggestion.description,
          code: suggestion.code,
          insertPosition: suggestion.insertPosition,
          replaceRange: suggestion.replaceRange,
          category: suggestion.metadata.category,
          tags: suggestion.metadata.tags,
          learnFromChoice: suggestion.metadata.learnFromChoice
        })),
        patterns: patternPredictions.map(pattern => ({
          id: pattern.id,
          type: pattern.type,
          confidence: pattern.confidence,
          message: pattern.message,
          code: pattern.code,
          category: pattern.metadata.category
        })),
        contextAnalysis: {
          intent: this.analyzeIntent(contextData),
          fileType: contextData.fileType,
          currentContext: this.getCurrentContext(content, line, column),
          recommendedActions: this.getRecommendedActions(contextData)
        }
      };

      logger.debug(`Generated ${suggestions.length} suggestions in ${responseTime}ms`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in suggestNext:', error);
      
      const errorResponse = {
        success: false,
        filePath: args.filePath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        performance: {
          responseTime: 0,
          target: '< 100ms',
          met: false
        },
        summary: {
          totalSuggestions: 0,
          patternSuggestions: 0,
          completionSuggestions: 0,
          securitySuggestions: 0,
          predictions: 0
        },
        suggestions: [],
        patterns: [],
        contextAnalysis: {}
      };

      return { content: [errorResponse] };
    }
  }

  async preventError(args: PreventErrorArgs): Promise<{ content: any[] }> {
    logger.info('Error prevention analysis requested', { filePath: args.filePath });

    try {
      const { filePath, content, line, analysisType = 'quick' } = args;

      if (!filePath) {
        throw new Error('filePath is required');
      }

      // If no content provided, try to read the file
      let analysisContent = content;
      if (!analysisContent) {
        try {
          const fs = await import('fs/promises');
          analysisContent = await fs.readFile(filePath, 'utf-8');
        } catch (error) {
          throw new Error(`Could not read file: ${filePath}`);
        }
      }

      const startTime = Date.now();
      
      let prediction: ErrorPrediction;
      
      if (analysisType === 'quick' && line) {
        // Quick analysis for specific line
        const mistakes = await this.errorPrevention.predictCommonMistakes(
          filePath,
          analysisContent,
          line
        );
        
        prediction = {
          errors: mistakes.filter(m => m.severity === 'critical' || m.severity === 'high'),
          warnings: mistakes.filter(m => m.severity === 'medium'),
          suggestions: mistakes.filter(m => m.severity === 'low'),
          riskScore: this.calculateQuickRiskScore(mistakes),
          analysisTime: Date.now() - startTime
        };
      } else {
        // Comprehensive analysis
        prediction = await this.errorPrevention.analyzeForErrors(
          filePath,
          analysisContent
        );
      }

      const response = {
        success: true,
        filePath,
        timestamp: new Date().toISOString(),
        analysisType,
        targetLine: line,
        performance: {
          analysisTime: prediction.analysisTime,
          target: analysisType === 'quick' ? '< 100ms' : '< 500ms',
          met: analysisType === 'quick' 
            ? prediction.analysisTime < 100 
            : prediction.analysisTime < 500
        },
        riskAssessment: {
          overallRiskScore: prediction.riskScore,
          riskLevel: this.getRiskLevel(prediction.riskScore),
          totalIssues: prediction.errors.length + prediction.warnings.length + prediction.suggestions.length,
          criticalErrors: prediction.errors.filter(e => e.severity === 'critical').length,
          highRiskErrors: prediction.errors.filter(e => e.severity === 'high').length
        },
        errorPredictions: {
          errors: prediction.errors.map(error => this.formatPotentialError(error)),
          warnings: prediction.warnings.map(warning => this.formatPotentialError(warning)),
          suggestions: prediction.suggestions.map(suggestion => this.formatPotentialError(suggestion))
        },
        prevention: {
          immediateActions: this.getImmediateActions(prediction.errors),
          recommendedFixes: this.getRecommendedFixes(prediction.warnings),
          bestPractices: this.getBestPractices(prediction.suggestions),
          learningOpportunities: this.getLearningOpportunities(prediction)
        },
        insights: {
          commonPatterns: this.identifyCommonPatterns(prediction),
          riskFactors: this.identifyRiskFactors(prediction),
          preventiveMeasures: this.suggestPreventiveMeasures(prediction)
        }
      };

      logger.debug(`Error prevention completed. Risk score: ${prediction.riskScore}, Issues: ${prediction.errors.length + prediction.warnings.length}`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in preventError:', error);
      
      const errorResponse = {
        success: false,
        filePath: args.filePath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        analysisType: args.analysisType || 'quick',
        riskAssessment: {
          overallRiskScore: 0,
          riskLevel: 'unknown',
          totalIssues: 0,
          criticalErrors: 0,
          highRiskErrors: 0
        },
        errorPredictions: {
          errors: [],
          warnings: [],
          suggestions: []
        },
        prevention: {
          immediateActions: ['Fix the analysis error and try again'],
          recommendedFixes: [],
          bestPractices: [],
          learningOpportunities: []
        }
      };

      return { content: [errorResponse] };
    }
  }

  async quickFix(args: QuickFixArgs): Promise<{ content: any[] }> {
    logger.info('Quick fix requested', { issueId: args.issueId });

    try {
      const { filePath, issueId, line, column } = args;

      if (!filePath || !issueId) {
        throw new Error('filePath and issueId are required');
      }

      // Get the suggested fix from the instant validator
      const suggestedFix = await this.instantValidator.getQuickFix(issueId);
      
      if (!suggestedFix) {
        throw new Error(`No quick fix available for issue: ${issueId}`);
      }

      const response = {
        success: true,
        filePath,
        issueId,
        timestamp: new Date().toISOString(),
        position: { line, column },
        fix: {
          available: true,
          code: suggestedFix,
          description: `Quick fix for ${issueId}`,
          confidence: 0.9,
          automated: true,
          preview: suggestedFix.length > 100 ? suggestedFix.substring(0, 100) + '...' : suggestedFix
        },
        application: {
          method: 'replace',
          targetLine: line,
          targetColumn: column,
          estimatedImpact: 'low',
          requiresValidation: true
        },
        instructions: [
          'Review the suggested fix before applying',
          'Test the fix to ensure it resolves the issue',
          'Consider the impact on surrounding code',
          'Update tests if necessary'
        ]
      };

      logger.debug(`Quick fix provided for ${issueId}`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in quickFix:', error);
      
      const errorResponse = {
        success: false,
        filePath: args.filePath,
        issueId: args.issueId,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        fix: {
          available: false,
          code: '',
          description: 'No fix available',
          confidence: 0,
          automated: false,
          preview: ''
        },
        instructions: ['Manual investigation required']
      };

      return { content: [errorResponse] };
    }
  }

  async explainWarning(args: ExplainWarningArgs): Promise<{ content: any[] }> {
    logger.info('Warning explanation requested', { issueId: args.issueId });

    try {
      const { issueId, includeExamples = true, includeRemediation = true } = args;

      if (!issueId) {
        throw new Error('issueId is required');
      }

      // Get detailed explanation from the instant validator
      const explanation = await this.instantValidator.explainIssue(issueId);

      const response = {
        success: true,
        issueId,
        timestamp: new Date().toISOString(),
        explanation: {
          summary: explanation,
          detailed: this.getDetailedExplanation(issueId),
          whyItMatters: this.getWhyItMatters(issueId),
          commonCauses: this.getCommonCauses(issueId),
          impact: this.getImpactAnalysis(issueId)
        },
        ...(includeExamples && {
          examples: {
            problematic: this.getProblematicExample(issueId),
            corrected: this.getCorrectedExample(issueId),
            bestPractice: this.getBestPracticeExample(issueId)
          }
        }),
        ...(includeRemediation && {
          remediation: {
            immediateSteps: this.getImmediateSteps(issueId),
            longTermSolution: this.getLongTermSolution(issueId),
            preventionStrategy: this.getPreventionStrategy(issueId),
            toolsAndResources: this.getToolsAndResources(issueId)
          }
        }),
        relatedTopics: this.getRelatedTopics(issueId),
        furtherReading: this.getFurtherReading(issueId)
      };

      logger.debug(`Explanation provided for ${issueId}`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in explainWarning:', error);
      
      const errorResponse = {
        success: false,
        issueId: args.issueId,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        explanation: {
          summary: 'Explanation not available',
          detailed: 'An error occurred while generating the explanation',
          whyItMatters: 'Unable to determine',
          commonCauses: [],
          impact: 'Unknown'
        }
      };

      return { content: [errorResponse] };
    }
  }

  async startWatching(args: StartWatchingArgs): Promise<{ content: any[] }> {
    logger.info('Starting file watching', { projectPath: args.projectPath });

    try {
      const { projectPath, patterns, ignored, debounceMs } = args;

      if (!projectPath) {
        throw new Error('projectPath is required');
      }

      // Check if already watching this path
      if (this.watchers.has(projectPath)) {
        throw new Error(`Already watching project: ${projectPath}`);
      }

      // Create new file watcher
      const watcher = new FileWatcher({
        patterns: patterns || ['**/*.{ts,tsx,js,jsx,json}'],
        ignored: ignored || [
          '**/node_modules/**',
          '**/dist/**',
          '**/build/**',
          '**/.git/**',
          '**/.next/**'
        ],
        debounceMs: debounceMs || 300
      });

      // Set up event handlers
      watcher.on('change', async (change: FileChange) => {
        logger.debug(`File changed: ${change.path} (${change.type})`);
        
        try {
          // Process the change through incremental analyzer
          const updates = await this.incrementalAnalyzer.handleFileChange(change);
          
          // Emit real-time notifications (would integrate with MCP notifications)
          for (const update of updates) {
            if (update.result && update.result.securityIssues.length > 0) {
              logger.warn(`Security issues detected in ${update.filePath}:`, update.result.securityIssues);
            }
          }
        } catch (error) {
          logger.error(`Error processing file change for ${change.path}:`, error);
        }
      });

      watcher.on('batch', async (changes: FileChange[]) => {
        logger.info(`Processing batch of ${changes.length} file changes`);
        
        try {
          const updates = await this.incrementalAnalyzer.handleBatch(changes);
          logger.debug(`Processed batch: ${updates.length} updates generated`);
        } catch (error) {
          logger.error('Error processing batch changes:', error);
        }
      });

      watcher.on('error', (error: Error) => {
        logger.error(`File watcher error for ${projectPath}:`, error);
      });

      // Start watching
      await watcher.start(projectPath);
      this.watchers.set(projectPath, watcher);

      const stats = watcher.getStats();

      const response = {
        success: true,
        projectPath,
        timestamp: new Date().toISOString(),
        configuration: {
          patterns: patterns || ['**/*.{ts,tsx,js,jsx,json}'],
          ignored: ignored || ['**/node_modules/**', '**/dist/**'],
          debounceMs: debounceMs || 300
        },
        status: {
          isWatching: stats.isWatching,
          watchedFiles: stats.watchedFiles,
          pendingChanges: stats.pendingChanges
        },
        capabilities: [
          'Real-time file change detection',
          'Incremental analysis updates',
          'Security issue notifications',
          'Pattern compliance monitoring',
          'Performance optimization tracking'
        ],
        instructions: [
          'File changes will be processed automatically',
          'Security issues will be flagged immediately',
          'Use stop_watching to stop monitoring this project',
          'Monitor logs for real-time analysis results'
        ]
      };

      logger.info(`Started watching ${stats.watchedFiles} files in ${projectPath}`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in startWatching:', error);
      
      const errorResponse = {
        success: false,
        projectPath: args.projectPath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        status: {
          isWatching: false,
          watchedFiles: 0,
          pendingChanges: 0
        }
      };

      return { content: [errorResponse] };
    }
  }

  async stopWatching(args: StopWatchingArgs): Promise<{ content: any[] }> {
    logger.info('Stopping file watching', { projectPath: args.projectPath });

    try {
      const { projectPath } = args;

      if (!projectPath) {
        throw new Error('projectPath is required');
      }

      const watcher = this.watchers.get(projectPath);
      if (!watcher) {
        throw new Error(`Not currently watching project: ${projectPath}`);
      }

      const finalStats = watcher.getStats();
      
      // Stop the watcher
      await watcher.stop();
      this.watchers.delete(projectPath);

      const response = {
        success: true,
        projectPath,
        timestamp: new Date().toISOString(),
        finalStats: {
          watchedFiles: finalStats.watchedFiles,
          totalChanges: watcher.getRecentChanges().length,
          uptime: 'Session ended'
        },
        summary: [
          `Stopped watching ${finalStats.watchedFiles} files`,
          'All pending changes have been processed',
          'File watcher resources have been cleaned up'
        ]
      };

      logger.info(`Stopped watching ${projectPath}`);
      return { content: [response] };

    } catch (error) {
      logger.error('Error in stopWatching:', error);
      
      const errorResponse = {
        success: false,
        projectPath: args.projectPath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error)
      };

      return { content: [errorResponse] };
    }
  }

  // Helper methods
  private getFileType(filePath: string): string {
    if (filePath.includes('/api/') || filePath.includes('route.ts')) return 'api';
    if (filePath.endsWith('.tsx') || filePath.endsWith('.jsx')) return 'component';
    if (filePath.includes('/hooks/')) return 'hook';
    if (filePath.includes('/lib/') || filePath.includes('/utils/')) return 'utility';
    if (filePath.includes('.test.') || filePath.includes('.spec.')) return 'test';
    return 'unknown';
  }

  private shouldRequireAuth(filePath: string, content: string): boolean {
    return filePath.includes('/api/') && !content.includes('requireAuth');
  }

  private extractImports(content: string): string[] {
    const imports: string[] = [];
    const lines = content.split('\n');
    
    for (const line of lines) {
      const match = line.match(/import\s+.*?from\s+['"]([^'"]+)['"]/);
      if (match) {
        imports.push(match[1]);
      }
    }
    
    return imports;
  }

  private analyzeIntent(context: any): string {
    const currentLine = context.currentLine.toLowerCase();
    
    if (context.fileType === 'api' && currentLine.includes('export async function')) {
      return 'creating-api-route';
    }
    if (context.fileType === 'component' && currentLine.includes('export function')) {
      return 'creating-component';
    }
    if (currentLine.includes('const') && currentLine.includes('await')) {
      return 'async-operation';
    }
    
    return 'unknown';
  }

  private getCurrentContext(content: string, line: number, column: number): string {
    const lines = content.split('\n');
    const currentLine = lines[line - 1] || '';
    const beforeCursor = currentLine.substring(0, column);
    const afterCursor = currentLine.substring(column);
    
    return `Before: "${beforeCursor}" | After: "${afterCursor}"`;
  }

  private getRecommendedActions(context: any): string[] {
    const actions: string[] = [];
    
    if (context.fileType === 'api' && !context.imports.includes('requireAuthWithTenant')) {
      actions.push('Add authentication import');
    }
    
    if (context.currentLine.includes('drizzle(')) {
      actions.push('Use authenticated database connection');
    }
    
    return actions;
  }

  private calculateQuickRiskScore(mistakes: PotentialError[]): number {
    let score = 0;
    for (const mistake of mistakes) {
      const severityWeight = {
        critical: 25,
        high: 15,
        medium: 8,
        low: 3
      };
      score += severityWeight[mistake.severity] * mistake.probability;
    }
    return Math.min(Math.round(score), 100);
  }

  private getRiskLevel(score: number): string {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  private formatPotentialError(error: PotentialError): any {
    return {
      id: error.id,
      type: error.type,
      severity: error.severity,
      probability: error.probability,
      confidence: error.confidence,
      message: error.message,
      description: error.description,
      line: error.line,
      column: error.column,
      prevention: {
        suggestion: error.prevention.suggestion,
        code: error.prevention.code,
        alternatives: error.prevention.alternativeApproaches
      },
      metadata: {
        category: error.metadata.category,
        tags: error.metadata.tags,
        commonMistake: error.metadata.commonMistake
      }
    };
  }

  private getImmediateActions(errors: PotentialError[]): string[] {
    const actions = errors
      .filter(e => e.severity === 'critical')
      .map(e => e.prevention.suggestion);
    
    return actions.slice(0, 5); // Top 5 actions
  }

  private getRecommendedFixes(warnings: PotentialError[]): string[] {
    return warnings
      .map(w => w.prevention.suggestion)
      .slice(0, 3);
  }

  private getBestPractices(suggestions: PotentialError[]): string[] {
    return suggestions
      .map(s => s.prevention.suggestion)
      .slice(0, 3);
  }

  private getLearningOpportunities(prediction: ErrorPrediction): string[] {
    const opportunities: string[] = [];
    
    const categories = new Set([
      ...prediction.errors.map(e => e.metadata.category),
      ...prediction.warnings.map(w => w.metadata.category)
    ]);
    
    categories.forEach(category => {
      opportunities.push(`Learn more about ${category} best practices`);
    });
    
    return opportunities.slice(0, 3);
  }

  private identifyCommonPatterns(prediction: ErrorPrediction): string[] {
    const allErrors = [...prediction.errors, ...prediction.warnings, ...prediction.suggestions];
    const tagCounts = new Map<string, number>();
    
    allErrors.forEach(error => {
      error.metadata.tags.forEach(tag => {
        tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1);
      });
    });
    
    return Array.from(tagCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([tag, count]) => `${tag} (${count} occurrences)`);
  }

  private identifyRiskFactors(prediction: ErrorPrediction): string[] {
    const factors: string[] = [];
    
    if (prediction.errors.length > 5) {
      factors.push('High number of critical errors');
    }
    
    if (prediction.riskScore > 75) {
      factors.push('Overall risk score is very high');
    }
    
    return factors;
  }

  private suggestPreventiveMeasures(prediction: ErrorPrediction): string[] {
    return [
      'Implement automated code reviews',
      'Add more comprehensive testing',
      'Use stricter TypeScript configuration',
      'Implement security scanning in CI/CD'
    ];
  }

  // Explanation helper methods
  private getDetailedExplanation(issueId: string): string {
    // This would map issue IDs to detailed explanations
    return `Detailed explanation for ${issueId}`;
  }

  private getWhyItMatters(issueId: string): string {
    return `This issue matters because it could lead to security vulnerabilities or runtime errors`;
  }

  private getCommonCauses(issueId: string): string[] {
    return ['Incomplete understanding of the API', 'Copy-paste errors', 'Lack of proper validation'];
  }

  private getImpactAnalysis(issueId: string): string {
    return 'Could result in security vulnerabilities or application crashes';
  }

  private getProblematicExample(issueId: string): string {
    return '// Problematic code example';
  }

  private getCorrectedExample(issueId: string): string {
    return '// Corrected code example';
  }

  private getBestPracticeExample(issueId: string): string {
    return '// Best practice example';
  }

  private getImmediateSteps(issueId: string): string[] {
    return ['Review the code', 'Apply the suggested fix', 'Test the changes'];
  }

  private getLongTermSolution(issueId: string): string {
    return 'Implement proper patterns and governance rules';
  }

  private getPreventionStrategy(issueId: string): string {
    return 'Use automated tooling and code reviews';
  }

  private getToolsAndResources(issueId: string): string[] {
    return ['ESLint', 'TypeScript', 'Security scanners'];
  }

  private getRelatedTopics(issueId: string): string[] {
    return ['Security best practices', 'Code quality', 'Testing strategies'];
  }

  private getFurtherReading(issueId: string): string[] {
    return ['OWASP Guidelines', 'TypeScript Handbook', 'Clean Code principles'];
  }

  // Cleanup method
  async cleanup(): Promise<void> {
    logger.info('Cleaning up realtime tools');
    
    // Stop all watchers
    const stopPromises = Array.from(this.watchers.entries()).map(async ([path, watcher]) => {
      try {
        await watcher.stop();
        logger.debug(`Stopped watcher for ${path}`);
      } catch (error) {
        logger.error(`Error stopping watcher for ${path}:`, error);
      }
    });
    
    await Promise.all(stopPromises);
    this.watchers.clear();
    
    // Cleanup analyzers
    await this.incrementalAnalyzer.destroy();
    this.instantValidator.clearCache();
    this.errorPrevention.clearCache();
    
    logger.info('Realtime tools cleanup completed');
  }
}