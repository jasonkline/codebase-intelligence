import { IncrementalAnalyzer, AnalysisResult } from '../realtime/IncrementalAnalyzer';
import { PatternRegistry, Pattern } from '../patterns/PatternRegistry';
import { ParsedSymbol } from '../parser/ASTParser';
import { logger } from '../utils/logger';

export interface SmartSuggestion {
  id: string;
  type: 'completion' | 'pattern' | 'refactor' | 'security' | 'optimization';
  priority: 'high' | 'medium' | 'low';
  confidence: number; // 0-1
  message: string;
  description?: string;
  code: string;
  insertPosition?: {
    line: number;
    column: number;
  };
  replaceRange?: {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
  };
  context: SuggestionContext;
  metadata: {
    category: string;
    tags: string[];
    learnFromChoice?: boolean;
    relatedPatterns?: string[];
  };
}

export interface SuggestionContext {
  filePath: string;
  fileType: 'component' | 'api' | 'service' | 'hook' | 'utility' | 'test' | 'config';
  currentLine: string;
  previousLines: string[];
  nextLines: string[];
  cursorPosition: {
    line: number;
    column: number;
  };
  symbols: ParsedSymbol[];
  imports: string[];
  patterns: Pattern[];
  intent?: string; // What we think the developer is trying to do
}

export interface CompletionRequest {
  filePath: string;
  content: string;
  line: number;
  column: number;
  triggerCharacter?: string;
  maxSuggestions?: number;
}

export interface LearningData {
  suggestion: SmartSuggestion;
  accepted: boolean;
  timestamp: number;
  context: SuggestionContext;
}

export class SmartSuggestions {
  private learningData: LearningData[] = [];
  private patternFrequency = new Map<string, number>();
  private userPreferences = new Map<string, any>();
  private contextAnalyzer: ContextAnalyzer;
  
  constructor(
    private incrementalAnalyzer: IncrementalAnalyzer,
    private patternRegistry: PatternRegistry
  ) {
    this.contextAnalyzer = new ContextAnalyzer();
  }

  async getSuggestions(request: CompletionRequest): Promise<SmartSuggestion[]> {
    const startTime = Date.now();
    
    try {
      // Build context
      const context = await this.buildContext(request);
      
      // Generate suggestions from multiple sources
      const suggestions = await Promise.all([
        this.getPatternSuggestions(context),
        this.getCompletionSuggestions(context),
        this.getSecuritySuggestions(context),
        this.getRefactoringSuggestions(context),
        this.getOptimizationSuggestions(context)
      ]);

      const allSuggestions = suggestions.flat();
      
      // Rank and filter suggestions
      const rankedSuggestions = this.rankSuggestions(allSuggestions, context);
      
      // Apply learning to improve rankings
      const personalizedSuggestions = this.personalizeSuggestions(rankedSuggestions, context);
      
      const responseTime = Date.now() - startTime;
      logger.debug(`Generated ${personalizedSuggestions.length} suggestions in ${responseTime}ms`);
      
      return personalizedSuggestions.slice(0, request.maxSuggestions ?? 10);
    } catch (error) {
      logger.error('Error generating smart suggestions:', error);
      return [];
    }
  }

  async predictNextPattern(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];
    
    try {
      // Analyze current context to predict what comes next
      const intent = this.contextAnalyzer.detectIntent(context);
      
      switch (intent) {
        case 'creating-api-route':
          suggestions.push(...await this.suggestAPIRoute(context));
          break;
        case 'creating-component':
          suggestions.push(...await this.suggestComponent(context));
          break;
        case 'database-query':
          suggestions.push(...await this.suggestDatabasePattern(context));
          break;
        case 'authentication':
          suggestions.push(...await this.suggestAuthPattern(context));
          break;
        case 'error-handling':
          suggestions.push(...await this.suggestErrorHandling(context));
          break;
        default:
          suggestions.push(...await this.suggestGenericPatterns(context));
      }
    } catch (error) {
      logger.error('Error predicting next pattern:', error);
    }

    return suggestions;
  }

  private async buildContext(request: CompletionRequest): Promise<SuggestionContext> {
    const lines = request.content.split('\n');
    const currentLine = lines[request.line - 1] || '';
    const previousLines = lines.slice(Math.max(0, request.line - 6), request.line - 1);
    const nextLines = lines.slice(request.line, Math.min(lines.length, request.line + 5));

    // Get analysis result
    const analysisResult = await this.incrementalAnalyzer.analyzeFile(request.filePath);
    
    // Determine file type
    const fileType = this.determineFileType(request.filePath, request.content);
    
    // Extract imports
    const imports = this.extractImports(analysisResult.symbols);
    
    // Get relevant patterns
    const patterns = await this.patternRegistry.getPatternsByFile(request.filePath);

    return {
      filePath: request.filePath,
      fileType,
      currentLine,
      previousLines,
      nextLines,
      cursorPosition: {
        line: request.line,
        column: request.column
      },
      symbols: analysisResult.symbols,
      imports,
      patterns,
      intent: this.contextAnalyzer.detectIntent({
        filePath: request.filePath,
        fileType,
        currentLine,
        previousLines,
        nextLines,
        cursorPosition: { line: request.line, column: request.column },
        symbols: analysisResult.symbols,
        imports,
        patterns
      })
    };
  }

  private determineFileType(filePath: string, content: string): SuggestionContext['fileType'] {
    if (filePath.includes('/api/') || filePath.includes('/route.ts')) return 'api';
    if (filePath.endsWith('.tsx') || filePath.endsWith('.jsx')) return 'component';
    if (filePath.includes('/hooks/') || filePath.startsWith('use')) return 'hook';
    if (filePath.includes('/lib/') || filePath.includes('/utils/')) return 'utility';
    if (filePath.includes('.test.') || filePath.includes('.spec.')) return 'test';
    if (filePath.includes('config') || filePath.endsWith('.config.ts')) return 'config';
    
    // Analyze content for service patterns
    if (content.includes('async function') && content.includes('database')) return 'service';
    
    return 'utility';
  }

  private extractImports(symbols: ParsedSymbol[]): string[] {
    return symbols
      .filter(symbol => symbol.kind === 'import')
      .map(symbol => symbol.name)
      .filter(Boolean);
  }

  private async getPatternSuggestions(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];
    
    try {
      // Get patterns relevant to current context
      const relevantPatterns = context.patterns.filter(pattern => 
        this.isPatternRelevant(pattern, context)
      );

      for (const pattern of relevantPatterns) {
        const suggestion = await this.createPatternSuggestion(pattern, context);
        if (suggestion) {
          suggestions.push(suggestion);
        }
      }
    } catch (error) {
      logger.debug('Error getting pattern suggestions:', error);
    }

    return suggestions;
  }

  private async getCompletionSuggestions(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];
    
    try {
      // Analyze current line for completion opportunities
      const currentLine = context.currentLine.trim();
      const partialText = currentLine.substring(0, context.cursorPosition.column);

      // Import completions
      if (partialText.includes('import')) {
        suggestions.push(...this.getImportCompletions(context));
      }

      // Function call completions
      if (partialText.endsWith('.')) {
        suggestions.push(...this.getMethodCompletions(context, partialText));
      }

      // Variable completions
      if (/\b[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(partialText)) {
        suggestions.push(...this.getVariableCompletions(context));
      }

    } catch (error) {
      logger.debug('Error getting completion suggestions:', error);
    }

    return suggestions;
  }

  private async getSecuritySuggestions(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];
    
    try {
      // Check for security-sensitive contexts
      const currentLine = context.currentLine;
      
      // Database access without auth
      if (currentLine.includes('drizzle(') && !currentLine.includes('getOrgDatabaseWithAuth')) {
        suggestions.push({
          id: 'security-auth-db',
          type: 'security',
          priority: 'high',
          confidence: 0.95,
          message: 'Use authenticated database connection',
          description: 'Direct database access bypasses Row Level Security',
          code: 'const db = await getOrgDatabaseWithAuth()',
          context,
          metadata: {
            category: 'security',
            tags: ['database', 'auth', 'rls'],
            learnFromChoice: true
          }
        });
      }

      // API route without auth
      if (context.fileType === 'api' && !context.imports.includes('requireAuthWithTenant')) {
        suggestions.push({
          id: 'security-api-auth',
          type: 'security',
          priority: 'high',
          confidence: 0.9,
          message: 'Add authentication to API route',
          code: 'const { user, orgSlug, role } = await requireAuthWithTenant()',
          insertPosition: {
            line: context.cursorPosition.line + 1,
            column: 2
          },
          context,
          metadata: {
            category: 'security',
            tags: ['api', 'auth'],
            learnFromChoice: true
          }
        });
      }

    } catch (error) {
      logger.debug('Error getting security suggestions:', error);
    }

    return suggestions;
  }

  private async getRefactoringSuggestions(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];
    
    try {
      // Look for refactoring opportunities
      const content = [
        ...context.previousLines,
        context.currentLine,
        ...context.nextLines
      ].join('\n');

      // Suggest extracting repetitive code
      if (this.hasRepetitiveCode(content)) {
        suggestions.push({
          id: 'refactor-extract-function',
          type: 'refactor',
          priority: 'medium',
          confidence: 0.7,
          message: 'Extract repeated code into function',
          description: 'Reduce duplication by extracting common functionality',
          code: '// Extract to reusable function',
          context,
          metadata: {
            category: 'refactoring',
            tags: ['duplication', 'functions']
          }
        });
      }

      // Suggest better error handling
      if (content.includes('try') && !content.includes('finally')) {
        suggestions.push({
          id: 'refactor-error-handling',
          type: 'refactor',
          priority: 'low',
          confidence: 0.6,
          message: 'Consider adding finally block',
          code: 'finally {\n  // Cleanup code\n}',
          context,
          metadata: {
            category: 'error-handling',
            tags: ['try-catch', 'cleanup']
          }
        });
      }

    } catch (error) {
      logger.debug('Error getting refactoring suggestions:', error);
    }

    return suggestions;
  }

  private async getOptimizationSuggestions(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];
    
    try {
      // Performance optimization suggestions
      if (context.fileType === 'component') {
        // Suggest React optimizations
        if (!context.imports.includes('useCallback') && context.currentLine.includes('onClick')) {
          suggestions.push({
            id: 'optimize-callback',
            type: 'optimization',
            priority: 'low',
            confidence: 0.5,
            message: 'Consider using useCallback for event handlers',
            code: 'const handleClick = useCallback(() => {\n  // handler code\n}, [dependencies])',
            context,
            metadata: {
              category: 'performance',
              tags: ['react', 'useCallback', 'memoization']
            }
          });
        }

        // Suggest memo for expensive computations
        if (context.currentLine.includes('useMemo') === false && 
            context.currentLine.includes('expensive')) {
          suggestions.push({
            id: 'optimize-memo',
            type: 'optimization',
            priority: 'medium',
            confidence: 0.7,
            message: 'Consider using useMemo for expensive calculations',
            code: 'const result = useMemo(() => {\n  // expensive calculation\n}, [dependencies])',
            context,
            metadata: {
              category: 'performance',
              tags: ['react', 'useMemo', 'performance']
            }
          });
        }
      }

    } catch (error) {
      logger.debug('Error getting optimization suggestions:', error);
    }

    return suggestions;
  }

  // Specific pattern suggestion methods
  private async suggestAPIRoute(context: SuggestionContext): Promise<SmartSuggestion[]> {
    return [{
      id: 'pattern-api-route',
      type: 'pattern',
      priority: 'high',
      confidence: 0.9,
      message: 'Create authenticated API route',
      code: `export async function GET() {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant()
    
    const db = await getOrgDatabaseWithAuth()
    const data = await db.select().from(table)
    
    return Response.json({ data })
  } catch (error) {
    console.error('API Error:', error)
    return new Response('Internal Server Error', { status: 500 })
  }
}`,
      context,
      metadata: {
        category: 'api-pattern',
        tags: ['api', 'auth', 'database', 'error-handling'],
        learnFromChoice: true,
        relatedPatterns: ['auth-pattern', 'db-pattern']
      }
    }];
  }

  private async suggestComponent(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const componentName = this.extractComponentName(context.filePath);
    
    return [{
      id: 'pattern-component',
      type: 'pattern',
      priority: 'high',
      confidence: 0.85,
      message: 'Create React component with organization context',
      code: `export function ${componentName}({ }: {  }) {
  const { organization } = useOrganization()
  
  return (
    <div>
      {/* Component content */}
    </div>
  )
}`,
      context,
      metadata: {
        category: 'component-pattern',
        tags: ['react', 'component', 'organization'],
        learnFromChoice: true
      }
    }];
  }

  private async suggestDatabasePattern(context: SuggestionContext): Promise<SmartSuggestion[]> {
    return [{
      id: 'pattern-database',
      type: 'pattern',
      priority: 'high',
      confidence: 0.9,
      message: 'Use authenticated database connection',
      code: `const db = await getOrgDatabaseWithAuth()
const result = await db.select().from(table).where(/* conditions */)`,
      context,
      metadata: {
        category: 'database-pattern',
        tags: ['database', 'auth', 'rls'],
        learnFromChoice: true
      }
    }];
  }

  private async suggestAuthPattern(context: SuggestionContext): Promise<SmartSuggestion[]> {
    return [{
      id: 'pattern-auth',
      type: 'pattern',
      priority: 'high',
      confidence: 0.95,
      message: 'Add authentication check',
      code: `const { user, orgSlug, role } = await requireAuthWithTenant()

// Check permissions if needed
if (!hasPermission(role, 'permission:resource')) {
  return new Response('Forbidden', { status: 403 })
}`,
      context,
      metadata: {
        category: 'auth-pattern',
        tags: ['auth', 'permissions', 'rbac'],
        learnFromChoice: true
      }
    }];
  }

  private async suggestErrorHandling(context: SuggestionContext): Promise<SmartSuggestion[]> {
    return [{
      id: 'pattern-error-handling',
      type: 'pattern',
      priority: 'medium',
      confidence: 0.8,
      message: 'Add proper error handling',
      code: `try {
  // Your code here
} catch (error) {
  console.error('Error:', error)
  // Handle error appropriately
  throw error // or return error response
}`,
      context,
      metadata: {
        category: 'error-handling',
        tags: ['error-handling', 'try-catch'],
        learnFromChoice: true
      }
    }];
  }

  private async suggestGenericPatterns(context: SuggestionContext): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = [];

    // Based on current line content, suggest common patterns
    const currentLine = context.currentLine.toLowerCase();

    if (currentLine.includes('const') && currentLine.includes('=')) {
      suggestions.push({
        id: 'pattern-const-destructuring',
        type: 'pattern',
        priority: 'low',
        confidence: 0.6,
        message: 'Consider destructuring assignment',
        code: 'const { property } = object',
        context,
        metadata: {
          category: 'syntax',
          tags: ['destructuring', 'const']
        }
      });
    }

    return suggestions;
  }

  // Helper methods
  private isPatternRelevant(pattern: Pattern, context: SuggestionContext): boolean {
    // Check if pattern is relevant to current context
    if (pattern.category === 'auth' && context.fileType === 'api') return true;
    if (pattern.category === 'component' && context.fileType === 'component') return true;
    if (pattern.category === 'database' && context.currentLine.includes('db')) return true;
    
    return false;
  }

  private async createPatternSuggestion(
    pattern: Pattern, 
    context: SuggestionContext
  ): Promise<SmartSuggestion | null> {
    try {
      return {
        id: `pattern-${pattern.id}`,
        type: 'pattern',
        priority: 'medium',
        confidence: pattern.confidence || 0.8,
        message: `Apply ${pattern.name} pattern`,
        description: pattern.description,
        code: pattern.template || '',
        context,
        metadata: {
          category: pattern.category,
          tags: pattern.tags || [],
          learnFromChoice: true,
          relatedPatterns: [pattern.id]
        }
      };
    } catch (error) {
      logger.debug('Error creating pattern suggestion:', error);
      return null;
    }
  }

  private getImportCompletions(context: SuggestionContext): SmartSuggestion[] {
    const suggestions: SmartSuggestion[] = [];
    
    const commonImports = [
      { name: 'requireAuthWithTenant', from: '@/lib/supabase-auth' },
      { name: 'getOrgDatabaseWithAuth', from: '@/lib/database' },
      { name: 'useOrganization', from: '@/hooks/useOrganization' }
    ];

    for (const imp of commonImports) {
      if (!context.imports.includes(imp.name)) {
        suggestions.push({
          id: `import-${imp.name}`,
          type: 'completion',
          priority: 'medium',
          confidence: 0.8,
          message: `Import ${imp.name}`,
          code: `import { ${imp.name} } from '${imp.from}'`,
          context,
          metadata: {
            category: 'imports',
            tags: ['import', 'auto-complete']
          }
        });
      }
    }

    return suggestions;
  }

  private getMethodCompletions(context: SuggestionContext, partialText: string): SmartSuggestion[] {
    // Method completion logic would go here
    return [];
  }

  private getVariableCompletions(context: SuggestionContext): SmartSuggestion[] {
    // Variable completion logic would go here
    return [];
  }

  private hasRepetitiveCode(content: string): boolean {
    // Simple heuristic to detect repetitive code
    const lines = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    const uniqueLines = new Set(lines);
    
    return lines.length > uniqueLines.size * 1.5; // More than 50% repetition
  }

  private extractComponentName(filePath: string): string {
    const fileName = filePath.split('/').pop()?.replace(/\.(tsx?|jsx?)$/, '') || 'Component';
    return fileName.charAt(0).toUpperCase() + fileName.slice(1);
  }

  private rankSuggestions(
    suggestions: SmartSuggestion[], 
    context: SuggestionContext
  ): SmartSuggestion[] {
    return suggestions.sort((a, b) => {
      // Sort by priority, then confidence
      const priorityOrder = { high: 3, medium: 2, low: 1 };
      const priorityDiff = priorityOrder[b.priority] - priorityOrder[a.priority];
      
      if (priorityDiff !== 0) return priorityDiff;
      
      return b.confidence - a.confidence;
    });
  }

  private personalizeSuggestions(
    suggestions: SmartSuggestion[], 
    context: SuggestionContext
  ): SmartSuggestion[] {
    // Apply learning and personalization
    return suggestions.map(suggestion => {
      const frequency = this.patternFrequency.get(suggestion.metadata.category) || 0;
      const adjustedConfidence = suggestion.confidence * (1 + frequency * 0.1);
      
      return {
        ...suggestion,
        confidence: Math.min(adjustedConfidence, 1.0)
      };
    });
  }

  // Learning methods
  recordChoice(suggestion: SmartSuggestion, accepted: boolean, context: SuggestionContext): void {
    const learningData: LearningData = {
      suggestion,
      accepted,
      timestamp: Date.now(),
      context
    };

    this.learningData.push(learningData);

    if (accepted && suggestion.metadata.learnFromChoice) {
      const category = suggestion.metadata.category;
      const currentFreq = this.patternFrequency.get(category) || 0;
      this.patternFrequency.set(category, currentFreq + 1);
    }

    // Keep only recent learning data
    if (this.learningData.length > 1000) {
      this.learningData = this.learningData.slice(-500);
    }
  }

  getPreferences(): Record<string, any> {
    return Object.fromEntries(this.userPreferences);
  }

  setPreference(key: string, value: any): void {
    this.userPreferences.set(key, value);
  }
}

class ContextAnalyzer {
  detectIntent(context: SuggestionContext): string {
    const currentLine = context.currentLine.toLowerCase();
    const previousContent = context.previousLines.join(' ').toLowerCase();

    // Detect what the developer is trying to do
    if (context.fileType === 'api' && currentLine.includes('export async function')) {
      return 'creating-api-route';
    }

    if (context.fileType === 'component' && currentLine.includes('export function')) {
      return 'creating-component';
    }

    if (currentLine.includes('db.') || currentLine.includes('database') || currentLine.includes('select')) {
      return 'database-query';
    }

    if (currentLine.includes('auth') || currentLine.includes('requireAuth') || previousContent.includes('authentication')) {
      return 'authentication';
    }

    if (currentLine.includes('try') || currentLine.includes('catch') || currentLine.includes('error')) {
      return 'error-handling';
    }

    return 'unknown';
  }
}