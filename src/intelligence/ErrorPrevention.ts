import { IncrementalAnalyzer, AnalysisResult } from '../realtime/IncrementalAnalyzer';
import { PatternRegistry } from '../patterns/PatternRegistry';
import { ParsedSymbol } from '../parser/ASTParser';
import { logger } from '../utils/logger';

export interface PotentialError {
  id: string;
  type: 'runtime' | 'logic' | 'security' | 'performance' | 'maintenance';
  severity: 'critical' | 'high' | 'medium' | 'low';
  probability: number; // 0-1, likelihood this will cause an error
  confidence: number; // 0-1, how confident we are in this prediction
  message: string;
  description: string;
  filePath: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  context: ErrorContext;
  prevention: {
    suggestion: string;
    code?: string;
    alternativeApproaches?: string[];
  };
  metadata: {
    category: string;
    tags: string[];
    commonMistake: boolean;
    hasHistoricalData: boolean;
    relatedErrors?: string[];
  };
}

export interface ErrorContext {
  filePath: string;
  functionName?: string;
  className?: string;
  surroundingCode: string[];
  dependencies: string[];
  imports: string[];
  patterns: string[];
  dataFlow: DataFlowInfo[];
}

export interface DataFlowInfo {
  variable: string;
  type: string;
  source: 'parameter' | 'return' | 'assignment' | 'property';
  nullable: boolean;
  validated: boolean;
}

export interface ErrorPrediction {
  errors: PotentialError[];
  warnings: PotentialError[];
  suggestions: PotentialError[];
  riskScore: number; // 0-100, overall risk assessment
  analysisTime: number;
}

export interface MistakePattern {
  id: string;
  name: string;
  description: string;
  pattern: RegExp | string;
  category: string;
  severity: PotentialError['severity'];
  commonTriggers: string[];
  prevention: string;
  examples: {
    bad: string;
    good: string;
  };
}

export class ErrorPrevention {
  private mistakePatterns: MistakePattern[] = [];
  private historicalErrors = new Map<string, number>(); // Error pattern -> frequency
  private contextCache = new Map<string, ErrorContext>();
  
  constructor(
    private incrementalAnalyzer: IncrementalAnalyzer,
    private patternRegistry: PatternRegistry
  ) {
    this.initializeMistakePatterns();
  }

  async analyzeForErrors(
    filePath: string,
    content: string,
    analysisResult?: AnalysisResult
  ): Promise<ErrorPrediction> {
    const startTime = Date.now();
    
    try {
      // Get analysis result
      const analysis = analysisResult || await this.incrementalAnalyzer.analyzeFile(filePath);
      
      // Build error context
      const context = await this.buildErrorContext(filePath, content, analysis);
      
      // Run various error detection algorithms
      const [
        runtimeErrors,
        logicErrors,
        securityErrors,
        performanceIssues,
        maintenanceIssues
      ] = await Promise.all([
        this.detectRuntimeErrors(context, analysis),
        this.detectLogicErrors(context, analysis),
        this.detectSecurityErrors(context, analysis),
        this.detectPerformanceIssues(context, analysis),
        this.detectMaintenanceIssues(context, analysis)
      ]);

      const allErrors = [
        ...runtimeErrors,
        ...logicErrors,
        ...securityErrors,
        ...performanceIssues,
        ...maintenanceIssues
      ];

      // Categorize by severity
      const errors = allErrors.filter(e => e.severity === 'critical' || e.severity === 'high');
      const warnings = allErrors.filter(e => e.severity === 'medium');
      const suggestions = allErrors.filter(e => e.severity === 'low');

      // Calculate overall risk score
      const riskScore = this.calculateRiskScore(allErrors);

      return {
        errors,
        warnings,
        suggestions,
        riskScore,
        analysisTime: Date.now() - startTime
      };
    } catch (error) {
      logger.error(`Error prevention analysis failed for ${filePath}:`, error);
      
      return {
        errors: [],
        warnings: [],
        suggestions: [],
        riskScore: 0,
        analysisTime: Date.now() - startTime
      };
    }
  }

  async predictCommonMistakes(
    filePath: string,
    content: string,
    line?: number
  ): Promise<PotentialError[]> {
    const errors: PotentialError[] = [];
    
    try {
      const lines = content.split('\n');
      const targetLines = line ? [lines[line - 1]] : lines;
      
      for (let i = 0; i < targetLines.length; i++) {
        const currentLine = targetLines[i];
        const lineNumber = line || (i + 1);
        
        // Check against known mistake patterns
        for (const pattern of this.mistakePatterns) {
          if (this.matchesPattern(currentLine, pattern)) {
            const error = await this.createErrorFromPattern(
              pattern,
              filePath,
              lineNumber,
              currentLine
            );
            
            if (error) {
              errors.push(error);
            }
          }
        }
      }
    } catch (error) {
      logger.error('Error predicting common mistakes:', error);
    }

    return errors;
  }

  private async buildErrorContext(
    filePath: string,
    content: string,
    analysis: AnalysisResult
  ): Promise<ErrorContext> {
    // Check cache first
    const cached = this.contextCache.get(filePath);
    if (cached) {
      return cached;
    }

    const lines = content.split('\n');
    const context: ErrorContext = {
      filePath,
      surroundingCode: lines,
      dependencies: analysis.dependencies,
      imports: analysis.imports,
      patterns: analysis.patterns.map(p => p.name || p.id),
      dataFlow: this.analyzeDataFlow(analysis.symbols, content)
    };

    // Extract function/class context if available
    const symbols = analysis.symbols;
    const functionSymbol = symbols.find(s => s.kind === 'function');
    if (functionSymbol) {
      context.functionName = functionSymbol.name;
    }

    const classSymbol = symbols.find(s => s.kind === 'class');
    if (classSymbol) {
      context.className = classSymbol.name;
    }

    this.contextCache.set(filePath, context);
    return context;
  }

  private analyzeDataFlow(symbols: ParsedSymbol[], content: string): DataFlowInfo[] {
    const dataFlow: DataFlowInfo[] = [];
    
    try {
      // Extract variable declarations and their usage
      const variables = symbols.filter(s => s.kind === 'variable' || s.kind === 'parameter');
      
      for (const variable of variables) {
        dataFlow.push({
          variable: variable.name,
          type: variable.type || 'unknown',
          source: variable.kind === 'parameter' ? 'parameter' : 'assignment',
          nullable: this.isNullable(variable, content),
          validated: this.isValidated(variable, content)
        });
      }
    } catch (error) {
      logger.debug('Error analyzing data flow:', error);
    }

    return dataFlow;
  }

  private isNullable(variable: ParsedSymbol, content: string): boolean {
    // Simple heuristic to check if variable can be null/undefined
    const varUsage = content.includes(`${variable.name}?`) || 
                    content.includes(`${variable.name} || `) ||
                    content.includes(`${variable.name} ?? `);
    return varUsage;
  }

  private isValidated(variable: ParsedSymbol, content: string): boolean {
    // Check if variable is validated before use
    return content.includes(`if (${variable.name})`) ||
           content.includes(`${variable.name} &&`) ||
           content.includes(`typeof ${variable.name}`);
  }

  // Error detection methods
  private async detectRuntimeErrors(
    context: ErrorContext,
    analysis: AnalysisResult
  ): Promise<PotentialError[]> {
    const errors: PotentialError[] = [];
    
    try {
      // Null pointer exceptions
      const nullPointerErrors = this.detectNullPointerErrors(context);
      errors.push(...nullPointerErrors);

      // Type errors
      const typeErrors = this.detectTypeErrors(context, analysis);
      errors.push(...typeErrors);

      // Undefined variable access
      const undefinedErrors = this.detectUndefinedAccess(context);
      errors.push(...undefinedErrors);

      // Array/Object access errors
      const accessErrors = this.detectAccessErrors(context);
      errors.push(...accessErrors);

    } catch (error) {
      logger.debug('Error detecting runtime errors:', error);
    }

    return errors;
  }

  private async detectLogicErrors(
    context: ErrorContext,
    analysis: AnalysisResult
  ): Promise<PotentialError[]> {
    const errors: PotentialError[] = [];
    
    try {
      // Infinite loops
      const loopErrors = this.detectInfiniteLoops(context);
      errors.push(...loopErrors);

      // Dead code
      const deadCodeErrors = this.detectDeadCode(context);
      errors.push(...deadCodeErrors);

      // Logic inconsistencies
      const logicErrors = this.detectLogicInconsistencies(context);
      errors.push(...logicErrors);

      // Missing edge cases
      const edgeCaseErrors = this.detectMissingEdgeCases(context);
      errors.push(...edgeCaseErrors);

    } catch (error) {
      logger.debug('Error detecting logic errors:', error);
    }

    return errors;
  }

  private async detectSecurityErrors(
    context: ErrorContext,
    analysis: AnalysisResult
  ): Promise<PotentialError[]> {
    const errors: PotentialError[] = [];
    
    try {
      // Authentication bypass
      const authErrors = this.detectAuthenticationIssues(context);
      errors.push(...authErrors);

      // Input validation issues
      const validationErrors = this.detectValidationIssues(context);
      errors.push(...validationErrors);

      // Injection vulnerabilities
      const injectionErrors = this.detectInjectionVulns(context);
      errors.push(...injectionErrors);

    } catch (error) {
      logger.debug('Error detecting security errors:', error);
    }

    return errors;
  }

  private async detectPerformanceIssues(
    context: ErrorContext,
    analysis: AnalysisResult
  ): Promise<PotentialError[]> {
    const errors: PotentialError[] = [];
    
    try {
      // N+1 queries
      const queryErrors = this.detectNPlusOneQueries(context);
      errors.push(...queryErrors);

      // Memory leaks
      const memoryErrors = this.detectMemoryLeaks(context);
      errors.push(...memoryErrors);

      // Inefficient algorithms
      const algorithmErrors = this.detectInefficiencies(context);
      errors.push(...algorithmErrors);

    } catch (error) {
      logger.debug('Error detecting performance issues:', error);
    }

    return errors;
  }

  private async detectMaintenanceIssues(
    context: ErrorContext,
    analysis: AnalysisResult
  ): Promise<PotentialError[]> {
    const errors: PotentialError[] = [];
    
    try {
      // Code complexity
      const complexityErrors = this.detectComplexity(context);
      errors.push(...complexityErrors);

      // Coupling issues
      const couplingErrors = this.detectTightCoupling(context);
      errors.push(...couplingErrors);

      // Naming issues
      const namingErrors = this.detectNamingIssues(context);
      errors.push(...namingErrors);

    } catch (error) {
      logger.debug('Error detecting maintenance issues:', error);
    }

    return errors;
  }

  // Specific error detection implementations
  private detectNullPointerErrors(context: ErrorContext): PotentialError[] {
    const errors: PotentialError[] = [];
    
    for (let i = 0; i < context.surroundingCode.length; i++) {
      const line = context.surroundingCode[i];
      
      // Look for property access without null checks
      const propertyAccess = /(\w+)\.(\w+)/g;
      let match;
      
      while ((match = propertyAccess.exec(line)) !== null) {
        const variable = match[1];
        const property = match[2];
        
        // Check if variable is in data flow and nullable
        const dataFlowInfo = context.dataFlow.find(df => df.variable === variable);
        
        if (dataFlowInfo && dataFlowInfo.nullable && !dataFlowInfo.validated) {
          errors.push({
            id: `null-pointer-${i}-${match.index}`,
            type: 'runtime',
            severity: 'high',
            probability: 0.7,
            confidence: 0.8,
            message: `Potential null pointer access: ${variable}.${property}`,
            description: `Variable '${variable}' might be null or undefined when accessing property '${property}'`,
            filePath: context.filePath,
            line: i + 1,
            column: match.index + 1,
            context,
            prevention: {
              suggestion: `Add null check before accessing property`,
              code: `${variable}?.${property} or if (${variable}) { ${variable}.${property} }`,
              alternativeApproaches: [
                'Use optional chaining (?.) operator',
                'Add explicit null check',
                'Use nullish coalescing (??)'
              ]
            },
            metadata: {
              category: 'null-safety',
              tags: ['null-pointer', 'property-access', 'runtime-error'],
              commonMistake: true,
              hasHistoricalData: true
            }
          });
        }
      }
    }
    
    return errors;
  }

  private detectTypeErrors(context: ErrorContext, analysis: AnalysisResult): PotentialError[] {
    const errors: PotentialError[] = [];
    
    // This would implement TypeScript-specific type checking
    // For now, we'll do basic type mismatch detection
    
    for (let i = 0; i < context.surroundingCode.length; i++) {
      const line = context.surroundingCode[i];
      
      // Detect string/number mismatches
      if (line.includes('parseInt') && !line.includes('parseInt(') && line.includes('+')) {
        errors.push({
          id: `type-error-${i}`,
          type: 'runtime',
          severity: 'medium',
          probability: 0.6,
          confidence: 0.7,
          message: 'Potential type coercion issue',
          description: 'Mixing string concatenation with numeric operations',
          filePath: context.filePath,
          line: i + 1,
          column: 1,
          context,
          prevention: {
            suggestion: 'Use explicit type conversion',
            code: 'Number(value) or parseInt(value, 10)',
            alternativeApproaches: ['Use TypeScript for type safety']
          },
          metadata: {
            category: 'type-safety',
            tags: ['type-coercion', 'string-number'],
            commonMistake: true,
            hasHistoricalData: false
          }
        });
      }
    }
    
    return errors;
  }

  private detectUndefinedAccess(context: ErrorContext): PotentialError[] {
    const errors: PotentialError[] = [];
    
    // Detect access to potentially undefined variables
    for (let i = 0; i < context.surroundingCode.length; i++) {
      const line = context.surroundingCode[i];
      
      // Look for array destructuring without defaults
      const destructuring = /const\s*\{\s*(\w+)\s*\}\s*=\s*(\w+)/;
      const match = destructuring.exec(line);
      
      if (match) {
        const property = match[1];
        const object = match[2];
        
        errors.push({
          id: `undefined-access-${i}`,
          type: 'runtime',
          severity: 'medium',
          probability: 0.4,
          confidence: 0.6,
          message: `Property '${property}' might be undefined`,
          description: `Destructuring '${property}' from '${object}' without default value`,
          filePath: context.filePath,
          line: i + 1,
          column: 1,
          context,
          prevention: {
            suggestion: 'Provide default values in destructuring',
            code: `const { ${property} = defaultValue } = ${object}`,
            alternativeApproaches: ['Add property existence check']
          },
          metadata: {
            category: 'undefined-access',
            tags: ['destructuring', 'undefined'],
            commonMistake: true,
            hasHistoricalData: false
          }
        });
      }
    }
    
    return errors;
  }

  private detectAccessErrors(context: ErrorContext): PotentialError[] {
    // Array bounds, object property access errors
    return [];
  }

  private detectInfiniteLoops(context: ErrorContext): PotentialError[] {
    const errors: PotentialError[] = [];
    
    for (let i = 0; i < context.surroundingCode.length; i++) {
      const line = context.surroundingCode[i];
      
      // Simple heuristic: while(true) without break
      if (line.includes('while(true)') || line.includes('while (true)')) {
        // Look for break statement in next few lines
        let hasBreak = false;
        for (let j = i + 1; j < Math.min(i + 10, context.surroundingCode.length); j++) {
          if (context.surroundingCode[j].includes('break')) {
            hasBreak = true;
            break;
          }
        }
        
        if (!hasBreak) {
          errors.push({
            id: `infinite-loop-${i}`,
            type: 'logic',
            severity: 'critical',
            probability: 0.9,
            confidence: 0.8,
            message: 'Potential infinite loop detected',
            description: 'while(true) loop without visible break condition',
            filePath: context.filePath,
            line: i + 1,
            column: 1,
            context,
            prevention: {
              suggestion: 'Add break condition or use finite loop',
              code: 'Add if (condition) break; inside the loop',
              alternativeApproaches: ['Use for loop with counter', 'Use recursive approach']
            },
            metadata: {
              category: 'infinite-loop',
              tags: ['while-loop', 'break-condition'],
              commonMistake: true,
              hasHistoricalData: true
            }
          });
        }
      }
    }
    
    return errors;
  }

  private detectDeadCode(context: ErrorContext): PotentialError[] {
    const errors: PotentialError[] = [];
    
    for (let i = 0; i < context.surroundingCode.length - 1; i++) {
      const line = context.surroundingCode[i];
      const nextLine = context.surroundingCode[i + 1];
      
      // Code after return statement
      if (line.trim().startsWith('return') && 
          nextLine.trim() && 
          !nextLine.trim().startsWith('}') &&
          !nextLine.trim().startsWith('catch') &&
          !nextLine.trim().startsWith('finally')) {
        
        errors.push({
          id: `dead-code-${i + 1}`,
          type: 'logic',
          severity: 'low',
          probability: 1.0,
          confidence: 0.9,
          message: 'Unreachable code after return',
          description: 'Code after return statement will never execute',
          filePath: context.filePath,
          line: i + 2,
          column: 1,
          context,
          prevention: {
            suggestion: 'Remove unreachable code or restructure logic',
            alternativeApproaches: ['Move code before return', 'Use conditional returns']
          },
          metadata: {
            category: 'dead-code',
            tags: ['unreachable', 'return-statement'],
            commonMistake: true,
            hasHistoricalData: false
          }
        });
      }
    }
    
    return errors;
  }

  private detectLogicInconsistencies(context: ErrorContext): PotentialError[] {
    // Complex logic analysis would go here
    return [];
  }

  private detectMissingEdgeCases(context: ErrorContext): PotentialError[] {
    // Edge case detection logic
    return [];
  }

  private detectAuthenticationIssues(context: ErrorContext): PotentialError[] {
    const errors: PotentialError[] = [];
    
    // Check for API routes without auth
    if (context.filePath.includes('/api/') || context.filePath.includes('route.ts')) {
      const hasAuth = context.imports.includes('requireAuthWithTenant') ||
                     context.surroundingCode.some(line => line.includes('requireAuth'));
      
      if (!hasAuth) {
        errors.push({
          id: 'missing-auth',
          type: 'security',
          severity: 'critical',
          probability: 0.9,
          confidence: 0.95,
          message: 'API route missing authentication',
          description: 'This API endpoint does not require authentication, making it publicly accessible',
          filePath: context.filePath,
          line: 1,
          column: 1,
          context,
          prevention: {
            suggestion: 'Add authentication check',
            code: 'const { user, orgSlug } = await requireAuthWithTenant()',
            alternativeApproaches: ['Use middleware for auth', 'Add role-based permissions']
          },
          metadata: {
            category: 'authentication',
            tags: ['api', 'auth', 'public-access'],
            commonMistake: true,
            hasHistoricalData: true
          }
        });
      }
    }
    
    return errors;
  }

  private detectValidationIssues(context: ErrorContext): PotentialError[] {
    // Input validation detection
    return [];
  }

  private detectInjectionVulns(context: ErrorContext): PotentialError[] {
    // SQL injection, XSS detection
    return [];
  }

  private detectNPlusOneQueries(context: ErrorContext): PotentialError[] {
    // Database query analysis
    return [];
  }

  private detectMemoryLeaks(context: ErrorContext): PotentialError[] {
    // Memory leak detection
    return [];
  }

  private detectInefficiencies(context: ErrorContext): PotentialError[] {
    // Algorithm efficiency analysis
    return [];
  }

  private detectComplexity(context: ErrorContext): PotentialError[] {
    // Cyclomatic complexity
    return [];
  }

  private detectTightCoupling(context: ErrorContext): PotentialError[] {
    // Coupling analysis
    return [];
  }

  private detectNamingIssues(context: ErrorContext): PotentialError[] {
    // Naming convention analysis
    return [];
  }

  // Helper methods
  private initializeMistakePatterns(): void {
    this.mistakePatterns = [
      {
        id: 'direct-db-access',
        name: 'Direct Database Access',
        description: 'Using drizzle() directly bypasses RLS',
        pattern: /drizzle\(/,
        category: 'security',
        severity: 'critical',
        commonTriggers: ['database', 'query'],
        prevention: 'Use getOrgDatabaseWithAuth() instead',
        examples: {
          bad: 'const db = drizzle(connectionString)',
          good: 'const db = await getOrgDatabaseWithAuth()'
        }
      },
      {
        id: 'hardcoded-secrets',
        name: 'Hardcoded Secrets',
        description: 'Secrets should not be hardcoded',
        pattern: /(api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"]{8,}/i,
        category: 'security',
        severity: 'critical',
        commonTriggers: ['api_key', 'secret', 'password'],
        prevention: 'Use environment variables',
        examples: {
          bad: 'const apiKey = "sk-1234567890abcdef"',
          good: 'const apiKey = process.env.API_KEY'
        }
      },
      {
        id: 'missing-await',
        name: 'Missing Await',
        description: 'Async function call without await',
        pattern: /(?<!await\s+)\w+\(\)\.then\(/,
        category: 'logic',
        severity: 'high',
        commonTriggers: ['promise', 'async'],
        prevention: 'Use await instead of .then()',
        examples: {
          bad: 'getData().then(result => ...)',
          good: 'const result = await getData()'
        }
      }
    ];
  }

  private matchesPattern(line: string, pattern: MistakePattern): boolean {
    if (pattern.pattern instanceof RegExp) {
      return pattern.pattern.test(line);
    }
    return line.includes(pattern.pattern);
  }

  private async createErrorFromPattern(
    pattern: MistakePattern,
    filePath: string,
    line: number,
    content: string
  ): Promise<PotentialError | null> {
    try {
      const frequency = this.historicalErrors.get(pattern.id) || 0;
      
      return {
        id: `${pattern.id}-${line}`,
        type: 'logic',
        severity: pattern.severity,
        probability: Math.min(0.3 + (frequency * 0.1), 0.9),
        confidence: 0.8,
        message: pattern.name,
        description: pattern.description,
        filePath,
        line,
        column: 1,
        context: this.contextCache.get(filePath) || {} as ErrorContext,
        prevention: {
          suggestion: pattern.prevention,
          code: pattern.examples.good,
          alternativeApproaches: []
        },
        metadata: {
          category: pattern.category,
          tags: pattern.commonTriggers,
          commonMistake: true,
          hasHistoricalData: frequency > 0
        }
      };
    } catch (error) {
      logger.debug('Error creating error from pattern:', error);
      return null;
    }
  }

  private calculateRiskScore(errors: PotentialError[]): number {
    let score = 0;
    
    for (const error of errors) {
      const severityWeight = {
        critical: 25,
        high: 15,
        medium: 8,
        low: 3
      };
      
      score += severityWeight[error.severity] * error.probability * error.confidence;
    }
    
    return Math.min(Math.round(score), 100);
  }

  // Public methods for learning and feedback
  recordActualError(
    filePath: string,
    line: number,
    errorType: string,
    description: string
  ): void {
    const key = `${errorType}-${filePath}`;
    const current = this.historicalErrors.get(key) || 0;
    this.historicalErrors.set(key, current + 1);
    
    logger.info(`Recorded actual error: ${errorType} at ${filePath}:${line}`);
  }

  getErrorStats(): {
    totalPredictions: number;
    accuracyRate: number;
    commonPatterns: Array<{ pattern: string; frequency: number }>;
  } {
    const totalPredictions = Array.from(this.historicalErrors.values())
      .reduce((sum, count) => sum + count, 0);
    
    const commonPatterns = Array.from(this.historicalErrors.entries())
      .map(([pattern, frequency]) => ({ pattern, frequency }))
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 10);

    return {
      totalPredictions,
      accuracyRate: 0.75, // Would track this in a real implementation
      commonPatterns
    };
  }

  clearCache(): void {
    this.contextCache.clear();
  }
}