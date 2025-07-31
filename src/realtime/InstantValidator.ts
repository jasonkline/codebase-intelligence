import { IncrementalAnalyzer, AnalysisResult } from './IncrementalAnalyzer';
import { PatternRegistry } from '../patterns/PatternRegistry';
import { RuleEngine } from '../governance/RuleEngine';
import { SecurityScanner } from '../security/SecurityScanner';
import { ParsedSymbol, ASTParser } from '../parser/ASTParser';
import { logger } from '../utils/logger';

export interface ValidationIssue {
  id: string;
  type: 'error' | 'warning' | 'info' | 'suggestion';
  category: 'security' | 'pattern' | 'style' | 'logic' | 'performance';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  description?: string;
  filePath: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  rule: string;
  fixable: boolean;
  suggestedFix?: string;
  examples?: string[];
  relatedIssues?: string[];
}

export interface ValidationContext {
  filePath: string;
  content: string;
  line?: number;
  column?: number;
  symbols?: ParsedSymbol[];
  analysisResult?: AnalysisResult;
  isPartialCode?: boolean;
}

export interface ValidationResult {
  issues: ValidationIssue[];
  suggestions: ValidationSuggestion[];
  performanceMs: number;
  fromCache: boolean;
}

export interface ValidationSuggestion {
  id: string;
  message: string;
  code: string;
  confidence: number;
  category: string;
}

interface ValidationCache {
  contentHash: string;
  result: ValidationResult;
  timestamp: number;
}

export class InstantValidator {
  private cache = new Map<string, ValidationCache>();
  private readonly maxCacheAge = 30000; // 30 seconds
  private readonly maxResponseTime = 50; // 50ms target
  
  constructor(
    private incrementalAnalyzer: IncrementalAnalyzer,
    private patternRegistry: PatternRegistry,
    private ruleEngine: RuleEngine,
    private securityScanner: SecurityScanner,
    private astParser: ASTParser
  ) {}

  async validateCode(context: ValidationContext): Promise<ValidationResult> {
    const startTime = Date.now();
    
    try {
      // Check cache first
      const cached = this.getCachedResult(context);
      if (cached) {
        return {
          ...cached,
          performanceMs: Date.now() - startTime,
          fromCache: true
        };
      }

      // Perform fast validation
      const issues = await this.performValidation(context);
      const suggestions = await this.generateSuggestions(context, issues);

      const result: ValidationResult = {
        issues,
        suggestions,
        performanceMs: Date.now() - startTime,
        fromCache: false
      };

      // Cache the result
      this.cacheResult(context, result);

      return result;
    } catch (error) {
      logger.error(`Validation failed for ${context.filePath}:`, error);
      
      return {
        issues: [{
          id: `validation-error-${Date.now()}`,
          type: 'error',
          category: 'logic',
          severity: 'medium',
          message: 'Code validation failed',
          description: error.message,
          filePath: context.filePath,
          line: context.line ?? 1,
          column: context.column ?? 1,
          rule: 'validation-error',
          fixable: false
        }],
        suggestions: [],
        performanceMs: Date.now() - startTime,
        fromCache: false
      };
    }
  }

  async validateAsTyped(
    filePath: string,
    content: string,
    line?: number,
    column?: number
  ): Promise<ValidationResult> {
    const context: ValidationContext = {
      filePath,
      content,
      line,
      column,
      isPartialCode: true
    };

    // For as-typed validation, we want immediate feedback
    const startTime = Date.now();
    const timeoutPromise = new Promise<ValidationResult>((resolve) => {
      setTimeout(() => {
        resolve({
          issues: [],
          suggestions: [],
          performanceMs: Date.now() - startTime,
          fromCache: false
        });
      }, this.maxResponseTime);
    });

    const validationPromise = this.validateCode(context);
    
    return Promise.race([validationPromise, timeoutPromise]);
  }

  private async performValidation(context: ValidationContext): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];
    
    try {
      // Get or perform analysis
      let analysisResult = context.analysisResult;
      if (!analysisResult) {
        analysisResult = await this.incrementalAnalyzer.analyzeFile(context.filePath);
      }

      // Fast syntax and structural validation
      const syntaxIssues = await this.validateSyntax(context, analysisResult);
      issues.push(...syntaxIssues);

      // Pattern compliance (with timeout)
      const patternIssues = await this.validatePatterns(context, analysisResult);
      issues.push(...patternIssues);

      // Security validation (critical issues only for speed)
      const securityIssues = await this.validateSecurity(context, analysisResult);
      issues.push(...securityIssues);

      // Style and convention validation
      const styleIssues = await this.validateStyle(context, analysisResult);
      issues.push(...styleIssues);

      // Logic validation (basic checks)
      const logicIssues = await this.validateLogic(context, analysisResult);
      issues.push(...logicIssues);

    } catch (error) {
      logger.error('Error in validation:', error);
    }

    return issues;
  }

  private async validateSyntax(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];

    // Check for common syntax issues
    if (context.isPartialCode) {
      // For partial code, be more lenient
      const lines = context.content.split('\n');
      const currentLine = context.line ? lines[context.line - 1] : '';
      
      // Check for unclosed brackets, quotes, etc.
      const unclosedBrackets = this.checkUnclosedBrackets(currentLine, context.line ?? 1);
      issues.push(...unclosedBrackets);
    }

    return issues;
  }

  private async validatePatterns(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];

    try {
      // Parse content to get AST for rule engine
      const parsedFile = await this.astParser.parseFile(context.filePath);
      if (!parsedFile) {
        logger.warn(`Could not parse ${context.filePath} for pattern validation`);
        return issues;
      }

      // Use rule engine to check pattern compliance
      const violations = await this.ruleEngine.checkCompliance(
        context.filePath,
        parsedFile.ast,
        context.content,
        undefined // analysisResult from pattern analysis
      );

      for (const violation of violations) {
        issues.push({
          id: `pattern-${violation.ruleId}-${Date.now()}`,
          type: violation.severity === 'error' ? 'error' : 'warning',
          category: 'pattern',
          severity: violation.severity as any,
          message: violation.message,
          description: violation.description,
          filePath: context.filePath,
          line: violation.line || 1,
          column: violation.column || 1,
          rule: violation.ruleId.toString(),
          fixable: violation.fixable,
          suggestedFix: violation.suggestedFix,
          examples: violation.examples
        });
      }
    } catch (error) {
      logger.debug('Pattern validation error:', error);
    }

    return issues;
  }

  private async validateSecurity(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];

    try {
      // Focus on critical security issues for instant feedback
      const criticalChecks = [
        this.checkDirectDatabaseAccess,
        this.checkHardcodedSecrets,
        this.checkAuthBypass,
        this.checkSQLInjection
      ];

      for (const check of criticalChecks) {
        try {
          const checkIssues = await check.call(this, context, analysisResult);
          issues.push(...checkIssues);
        } catch (error) {
          logger.debug('Security check error:', error);
        }
      }
    } catch (error) {
      logger.debug('Security validation error:', error);
    }

    return issues;
  }

  private async validateStyle(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];

    try {
      // Quick style checks
      const lines = context.content.split('\n');
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;

        // Check for common style issues
        if (line.length > 120) {
          issues.push({
            id: `style-line-length-${lineNumber}`,
            type: 'warning',
            category: 'style',
            severity: 'low',
            message: 'Line too long (>120 characters)',
            filePath: context.filePath,
            line: lineNumber,
            column: 121,
            rule: 'max-line-length',
            fixable: false
          });
        }

        // Check for trailing spaces
        if (line.endsWith(' ')) {
          issues.push({
            id: `style-trailing-space-${lineNumber}`,
            type: 'info',
            category: 'style',
            severity: 'info',
            message: 'Trailing whitespace',
            filePath: context.filePath,
            line: lineNumber,
            column: line.length,
            rule: 'no-trailing-spaces',
            fixable: true,
            suggestedFix: line.trimEnd()
          });
        }
      }
    } catch (error) {
      logger.debug('Style validation error:', error);
    }

    return issues;
  }

  private async validateLogic(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];

    try {
      // Check for common logic issues
      const content = context.content;

      // Check for unreachable code
      if (content.includes('return') && content.includes('console.log')) {
        const lines = content.split('\n');
        let foundReturn = false;
        
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          
          if (line.startsWith('return')) {
            foundReturn = true;
          } else if (foundReturn && line.includes('console.log')) {
            issues.push({
              id: `logic-unreachable-${i + 1}`,
              type: 'warning',
              category: 'logic',
              severity: 'medium',
              message: 'Unreachable code after return statement',
              filePath: context.filePath,
              line: i + 1,
              column: 1,
              rule: 'no-unreachable',
              fixable: false
            });
          }
        }
      }

    } catch (error) {
      logger.debug('Logic validation error:', error);
    }

    return issues;
  }

  // Security check methods
  private async checkDirectDatabaseAccess(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];
    const lines = context.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes('drizzle(') && !line.includes('getOrgDatabaseWithAuth')) {
        issues.push({
          id: `security-direct-db-${i + 1}`,
          type: 'error',
          category: 'security',
          severity: 'critical',
          message: 'Direct database access bypasses RLS',
          description: 'Use getOrgDatabaseWithAuth() instead of direct drizzle() calls',
          filePath: context.filePath,
          line: i + 1,
          column: line.indexOf('drizzle(') + 1,
          rule: 'no-direct-db-access',
          fixable: true,
          suggestedFix: 'const db = await getOrgDatabaseWithAuth()',
          examples: ['const db = await getOrgDatabaseWithAuth()']
        });
      }
    }

    return issues;
  }

  private async checkHardcodedSecrets(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];
    const lines = context.content.split('\n');

    const secretPatterns = [
      /api[_-]?key['\s]*[:=]['\s]*[a-zA-Z0-9]{20,}/i,
      /secret['\s]*[:=]['\s]*[a-zA-Z0-9]{20,}/i,
      /password['\s]*[:=]['\s]*[a-zA-Z0-9]{8,}/i,
      /token['\s]*[:=]['\s]*[a-zA-Z0-9]{20,}/i
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const pattern of secretPatterns) {
        if (pattern.test(line)) {
          issues.push({
            id: `security-hardcoded-secret-${i + 1}`,
            type: 'error',
            category: 'security',
            severity: 'critical',
            message: 'Hardcoded secret detected',
            description: 'Use environment variables for secrets',
            filePath: context.filePath,
            line: i + 1,
            column: 1,
            rule: 'no-hardcoded-secrets',
            fixable: false,
            examples: ['const apiKey = process.env.API_KEY']
          });
        }
      }
    }

    return issues;
  }

  private async checkAuthBypass(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];
    const lines = context.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Check for API routes without auth
      if (line.includes('export async function') && (line.includes('GET') || line.includes('POST'))) {
        let foundAuth = false;
        
        // Look ahead for auth check
        for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes('requireAuthWithTenant') || lines[j].includes('requireAuth')) {
            foundAuth = true;
            break;
          }
        }

        if (!foundAuth) {
          issues.push({
            id: `security-missing-auth-${i + 1}`,
            type: 'error',
            category: 'security',
            severity: 'high',
            message: 'API route missing authentication check',
            description: 'Add requireAuthWithTenant() to protect this endpoint',
            filePath: context.filePath,
            line: i + 1,
            column: 1,
            rule: 'require-auth',
            fixable: true,
            suggestedFix: 'const { user, orgSlug } = await requireAuthWithTenant()',
            examples: ['const { user, orgSlug } = await requireAuthWithTenant()']
          });
        }
      }
    }

    return issues;
  }

  private async checkSQLInjection(
    context: ValidationContext,
    analysisResult: AnalysisResult
  ): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];
    const lines = context.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Check for string concatenation in SQL queries
      if ((line.includes('.sql') || line.includes('query')) && line.includes('+')) {
        issues.push({
          id: `security-sql-injection-${i + 1}`,
          type: 'error',
          category: 'security',
          severity: 'high',
          message: 'Potential SQL injection vulnerability',
          description: 'Use parameterized queries instead of string concatenation',
          filePath: context.filePath,
          line: i + 1,
          column: line.indexOf('+') + 1,
          rule: 'no-sql-injection',
          fixable: false,
          examples: ['db.select().from(table).where(eq(table.id, ${id}))']
        });
      }
    }

    return issues;
  }

  private checkUnclosedBrackets(line: string, lineNumber: number): ValidationIssue[] {
    const issues: ValidationIssue[] = [];
    
    const brackets = { '(': ')', '[': ']', '{': '}' };
    const stack: string[] = [];
    
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      
      if (brackets[char]) {
        stack.push(char);
      } else if (Object.values(brackets).includes(char)) {
        const expected = stack.pop();
        if (!expected || brackets[expected] !== char) {
          issues.push({
            id: `syntax-unmatched-bracket-${lineNumber}-${i}`,
            type: 'error',
            category: 'logic',
            severity: 'high',
            message: 'Unmatched bracket',
            filePath: '',
            line: lineNumber,
            column: i + 1,
            rule: 'matching-brackets',
            fixable: false
          });
        }
      }
    }

    // Check for unclosed brackets
    if (stack.length > 0) {
      issues.push({
        id: `syntax-unclosed-bracket-${lineNumber}`,
        type: 'warning',
        category: 'logic',
        severity: 'medium',
        message: 'Unclosed bracket',
        filePath: '',
        line: lineNumber,
        column: line.length,
        rule: 'unclosed-brackets',
        fixable: false
      });
    }

    return issues;
  }

  private async generateSuggestions(
    context: ValidationContext,
    issues: ValidationIssue[]
  ): Promise<ValidationSuggestion[]> {
    const suggestions: ValidationSuggestion[] = [];

    try {
      // Generate context-aware suggestions based on issues and patterns
      const criticalIssues = issues.filter(i => i.severity === 'critical');
      
      for (const issue of criticalIssues) {
        if (issue.fixable && issue.suggestedFix) {
          suggestions.push({
            id: `suggestion-${issue.id}`,
            message: `Fix: ${issue.message}`,
            code: issue.suggestedFix,
            confidence: 0.9,
            category: issue.category
          });
        }
      }

      // Add pattern-based suggestions
      if (context.filePath.endsWith('.tsx') || context.filePath.endsWith('.jsx')) {
        const componentSuggestions = await this.generateComponentSuggestions(context);
        suggestions.push(...componentSuggestions);
      }

    } catch (error) {
      logger.debug('Error generating suggestions:', error);
    }

    return suggestions;
  }

  private async generateComponentSuggestions(
    context: ValidationContext
  ): Promise<ValidationSuggestion[]> {
    const suggestions: ValidationSuggestion[] = [];

    // Check if component needs useOrganization hook
    if (context.content.includes('export function') && 
        context.content.includes('return') &&
        !context.content.includes('useOrganization')) {
      
      suggestions.push({
        id: 'suggestion-use-organization',
        message: 'Consider adding organization context',
        code: 'const { organization } = useOrganization()',
        confidence: 0.7,
        category: 'pattern'
      });
    }

    return suggestions;
  }

  // Cache management
  private getCachedResult(context: ValidationContext): ValidationResult | null {
    const contentHash = require('crypto')
      .createHash('sha256')
      .update(context.content)
      .digest('hex');
    
    const cached = this.cache.get(context.filePath);
    
    if (cached && 
        cached.contentHash === contentHash &&
        Date.now() - cached.timestamp < this.maxCacheAge) {
      return cached.result;
    }

    return null;
  }

  private cacheResult(context: ValidationContext, result: ValidationResult): void {
    const contentHash = require('crypto')
      .createHash('sha256')
      .update(context.content)
      .digest('hex');

    this.cache.set(context.filePath, {
      contentHash,
      result,
      timestamp: Date.now()
    });
  }

  // Public utility methods
  async explainIssue(issueId: string): Promise<string> {
    // This would provide detailed explanations for validation issues
    return `Detailed explanation for issue ${issueId}`;
  }

  async getQuickFix(issueId: string): Promise<string | null> {
    // This would provide quick fixes for specific issues
    return null;
  }

  clearCache(): void {
    this.cache.clear();
  }

  getStats(): {
    cacheSize: number;
    averageResponseTime: number;
    issuesByCategory: Record<string, number>;
  } {
    return {
      cacheSize: this.cache.size,
      averageResponseTime: 0, // Would track this in a real implementation
      issuesByCategory: {} // Would track this in a real implementation
    };
  }
}