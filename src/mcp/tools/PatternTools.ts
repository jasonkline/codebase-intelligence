import PatternRegistry, { PatternAnalysisResult } from '../../patterns/PatternRegistry';
import RuleEngine, { GovernanceReport, RuleViolation } from '../../governance/RuleEngine';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import { ASTParser } from '../../parser/ASTParser';
import logger from '../../utils/logger';

export interface LearnPatternsArgs {
  projectPath: string;
  categories?: string[];
  minConfidence?: number;
}

export interface CheckPatternComplianceArgs {
  filePath: string;
  patternCategory?: string;
  explainViolations?: boolean;
}

export interface GetApprovedPatternArgs {
  category: string;
  name?: string;
}

export interface SuggestPatternArgs {
  filePath: string;
  context?: string;
}

export class PatternTools {
  private patternRegistry: PatternRegistry;
  private ruleEngine: RuleEngine;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;
  private astParser: ASTParser;

  constructor(
    patternRegistry: PatternRegistry,
    ruleEngine: RuleEngine,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor,
    astParser: ASTParser
  ) {
    this.patternRegistry = patternRegistry;
    this.ruleEngine = ruleEngine;
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
    this.astParser = astParser;
  }

  getToolDefinitions() {
    return [
      {
        name: 'learn_patterns',
        description: 'Extract and learn patterns from existing code in a project. Analyzes code structure, identifies common patterns, and builds a knowledge base for pattern matching.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: {
              type: 'string',
              description: 'Absolute path to the project directory to analyze for patterns',
            },
            categories: {
              type: 'array',
              items: { type: 'string' },
              description: 'Pattern categories to learn (auth, api, data_access, components, style)',
              default: ['auth', 'api', 'data_access', 'components', 'style'],
            },
            minConfidence: {
              type: 'number',
              description: 'Minimum confidence threshold for pattern extraction (0.0-1.0)',
              default: 0.8,
            },
          },
          required: ['projectPath'],
        },
      },
      {
        name: 'check_pattern_compliance',
        description: 'Validate code against learned patterns and governance rules. Identifies violations and provides recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Absolute path to the file to check for pattern compliance',
            },
            patternCategory: {
              type: 'string',
              enum: ['auth', 'api', 'data_access', 'components', 'style', 'all'],
              description: 'Specific pattern category to check, or "all" for all categories',
              default: 'all',
            },
            explainViolations: {
              type: 'boolean',
              description: 'Include detailed explanations for violations',
              default: true,
            },
          },
          required: ['filePath'],
        },
      },
      {
        name: 'get_approved_pattern',
        description: 'Retrieve approved patterns for a specific category or use case. Returns the correct implementation pattern with examples.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              enum: ['auth', 'api', 'data_access', 'components', 'style'],
              description: 'Pattern category to retrieve',
            },
            name: {
              type: 'string',
              description: 'Specific pattern name to retrieve (optional)',
            },
          },
          required: ['category'],
        },
      },
      {
        name: 'suggest_pattern',
        description: 'Get pattern suggestions for new code based on context and learned patterns. Provides implementation guidance.',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file where pattern suggestion is needed',
            },
            context: {
              type: 'string',
              description: 'Additional context about what you\'re trying to implement',
            },
          },
          required: ['filePath'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const patternToolNames = ['learn_patterns', 'check_pattern_compliance', 'get_approved_pattern', 'suggest_pattern'];
    return toolNames.some(name => patternToolNames.includes(name));
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'learn_patterns':
          return await this.handleLearnPatterns(args as LearnPatternsArgs);
        case 'check_pattern_compliance':
          return await this.handleCheckPatternCompliance(args as CheckPatternComplianceArgs);
        case 'get_approved_pattern':
          return await this.handleGetApprovedPattern(args as GetApprovedPatternArgs);
        case 'suggest_pattern':
          return await this.handleSuggestPattern(args as SuggestPatternArgs);
        default:
          throw new Error(`Unknown pattern tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error in pattern tool ${name}:`, error);
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordPatternAnalysis(name, duration);
    }
  }

  private async handleLearnPatterns(args: LearnPatternsArgs): Promise<{ content: any[] }> {
    logger.info('Learn patterns tool called', { args });

    const { projectPath, categories = ['auth', 'api', 'data_access', 'components', 'style'], minConfidence = 0.8 } = args;

    if (!projectPath) {
      throw new Error('projectPath is required');
    }

    logger.info(`Learning patterns from project: ${projectPath}`);

    // Update pattern registry configuration
    this.patternRegistry.updateConfig({
      enabledCategories: categories,
      confidenceThreshold: minConfidence
    });

    // Learn patterns from the project - this would integrate with file scanner
    const learningResults = await this.patternRegistry.learnFromProject(projectPath, {
      categories,
      minConfidence,
      maxPatterns: 100
    });

    const result = {
      success: true,
      projectPath,
      timestamp: new Date().toISOString(),
      configuration: {
        categories,
        minConfidence
      },
      summary: {
        filesAnalyzed: 0, // Not available in return type
        totalPatternsLearned: learningResults.patternsLearned,
        patternsByCategory: learningResults.categories,
        duration: learningResults.duration,
        confidence: 0.8 // Not available in return type
      },
      patterns: [], // Not available in return type - would need to fetch separately
      recommendations: [
        learningResults.patternsLearned > 0 ? `Successfully learned ${learningResults.patternsLearned} patterns` : 'No patterns met the confidence threshold',
        'Patterns are now available for compliance checking',
        'Use check_pattern_compliance to validate code against learned patterns',
        categories.length > 3 ? 'Consider focusing on specific categories for better pattern quality' : 'Good category selection for comprehensive learning'
      ]
    };

    logger.info(`Pattern learning completed. Learned ${learningResults.patternsLearned} patterns`);
    return { content: [result] };
  }

  private async handleCheckPatternCompliance(args: CheckPatternComplianceArgs): Promise<{ content: any[] }> {
    logger.info('Check pattern compliance tool called', { args });

    const { filePath, patternCategory = 'all', explainViolations = true } = args;

    if (!filePath) {
      throw new Error('filePath is required');
    }

    logger.info(`Checking pattern compliance for: ${filePath}`);

    // Read and analyze file
    const fs = await import('fs/promises');
    const sourceCode = await fs.readFile(filePath, 'utf-8');
    
    // Parse AST
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    
    // Parse and analyze patterns
    const analysisResult = await this.patternRegistry.analyzeFile(filePath, parsedFile.ast, sourceCode);

    // Run governance checks
    const violations = await this.ruleEngine.checkCompliance(filePath, parsedFile.ast, sourceCode, analysisResult);

    // Filter violations by category if specified
    const filteredViolations = patternCategory === 'all' 
      ? violations 
      : violations.filter(v => {
          const rule = this.ruleEngine.getRule(v.ruleId);
          return rule?.category === patternCategory;
        });

    const result = {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      configuration: {
        patternCategory,
        explainViolations
      },
      compliance: {
        overallScore: analysisResult.overallScore,
        violations: filteredViolations.length,
        issues: analysisResult.issues.length,
        recommendations: analysisResult.recommendations.length,
        grade: this.calculateComplianceGrade(analysisResult.overallScore)
      },
      violations: filteredViolations.map(v => ({
        ruleId: v.ruleId,
        ruleName: this.ruleEngine.getRule(v.ruleId)?.name || 'unknown',
        severity: v.severity,
        line: v.line,
        message: v.message,
        suggestion: v.suggestion,
        autoFixAvailable: v.autoFixAvailable,
        ...(explainViolations && {
          explanation: `This violates the ${this.ruleEngine.getRule(v.ruleId)?.category} governance rule`,
          impact: this.assessViolationImpact(v)
        })
      })),
      patterns: {
        auth: analysisResult.authMatches.length,
        api: analysisResult.apiMatches.length,
        dataAccess: analysisResult.dataAccessMatches.length,
        components: analysisResult.componentMatches.length,
        style: analysisResult.styleMatches.length
      },
      recommendations: [
        ...analysisResult.recommendations,
        filteredViolations.length === 0 ? 'Code follows all applicable patterns' : `${filteredViolations.length} pattern violations found`,
        analysisResult.overallScore > 0.8 ? 'Excellent pattern compliance' : 'Consider improving pattern adherence'
      ]
    };

    logger.info(`Pattern compliance check completed. Score: ${analysisResult.overallScore}, Violations: ${filteredViolations.length}`);
    return { content: [result] };
  }

  private async handleGetApprovedPattern(args: GetApprovedPatternArgs): Promise<{ content: any[] }> {
    logger.info('Get approved pattern tool called', { args });

    const { category, name } = args;

    if (!category) {
      throw new Error('category is required');
    }

    logger.info(`Retrieving approved patterns for category: ${category}`);

    // Search for approved patterns
    const patterns = await this.patternRegistry.searchPatterns({
      category,
      name,
      isApproved: true,
      minConfidence: 0.8
    });

    const result = {
      success: true,
      category,
      timestamp: new Date().toISOString(),
      query: { category, name },
      summary: {
        totalPatterns: patterns.length,
        avgConfidence: patterns.reduce((sum, p) => sum + p.confidence_threshold, 0) / patterns.length || 0,
        hasExamples: patterns.filter(p => p.example_file).length
      },
      patterns: patterns.map(pattern => ({
        id: pattern.id,
        name: pattern.name,
        category: pattern.category,
        description: pattern.description,
        confidence: pattern.confidence_threshold,
        exampleFile: pattern.example_file,
        exampleLine: pattern.example_line,
        astSignature: pattern.ast_signature ? 'Available' : 'Not available',
        usage: `Found in ${pattern.usageCount || 0} files`,
        tags: pattern.tags || []
      })),
      codeExamples: await this.generateCodeExamples(patterns.slice(0, 3)),
      recommendations: [
        patterns.length === 0 ? `No approved patterns found for category: ${category}` : `Found ${patterns.length} approved patterns`,
        'Use these patterns as templates for your implementation',
        'Follow the structure and naming conventions shown in the examples',
        'Consider the confidence scores when choosing patterns'
      ]
    };

    logger.info(`Retrieved ${patterns.length} approved patterns for ${category}`);
    return { content: [result] };
  }

  private async handleSuggestPattern(args: SuggestPatternArgs): Promise<{ content: any[] }> {
    logger.info('Suggest pattern tool called', { args });

    const { filePath, context } = args;

    if (!filePath) {
      throw new Error('filePath is required');
    }

    logger.info(`Suggesting patterns for: ${filePath}`);

    // Determine file type and context
    const fileExtension = filePath.split('.').pop()?.toLowerCase();
    const isAPIRoute = filePath.includes('/api/') || filePath.includes('route.');
    const isComponent = fileExtension === 'tsx' && !isAPIRoute;
    const isUtility = filePath.includes('/lib/') || filePath.includes('/utils/');
    
    // Get relevant patterns based on context
    let suggestions: any[] = [];
    
    if (isAPIRoute) {
      suggestions.push(...await this.generateAPIPatternSuggestions(context));
    }

    if (isComponent) {
      suggestions.push(...await this.generateComponentPatternSuggestions(context));
    }

    if (isUtility) {
      suggestions.push(...await this.generateUtilityPatternSuggestions(context));
    }

    // Add context-specific suggestions
    if (context) {
      suggestions.push(...await this.generateContextSpecificSuggestions(context));
    }

    // Rank suggestions by relevance
    suggestions = suggestions.sort((a, b) => b.relevanceScore - a.relevanceScore);

    const result = {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      context: {
        fileType: fileExtension,
        isAPIRoute,
        isComponent,
        isUtility,
        userContext: context
      },
      suggestions: suggestions.slice(0, 5), // Top 5 suggestions
      alternatives: suggestions.slice(5, 10), // Alternative patterns
      recommendations: [
        'Choose patterns that match your specific use case',
        'Always follow security best practices for your context',
        'Maintain consistency with existing codebase patterns',
        suggestions.length === 0 ? 'No specific patterns found - consider the general coding guidelines' : `Found ${suggestions.length} relevant pattern suggestions`
      ]
    };

    logger.info(`Generated ${suggestions.length} pattern suggestions for ${filePath}`);
    return { content: [result] };
  }

  private calculateComplianceGrade(score: number): string {
    if (score >= 0.9) return 'A';
    if (score >= 0.8) return 'B';
    if (score >= 0.7) return 'C';
    if (score >= 0.6) return 'D';
    return 'F';
  }

  private assessViolationImpact(violation: RuleViolation): string {
    switch (violation.severity) {
      case 'error': return 'High - May cause runtime errors or security issues';
      case 'warning': return 'Medium - May cause maintainability or performance issues';
      case 'info': return 'Low - Style or consistency issue';
      default: return 'Unknown impact';
    }
  }

  private async generateCodeExamples(patterns: any[]): Promise<any[]> {
    // Generate code examples for patterns
    return patterns.map(pattern => ({
      name: pattern.name,
      code: `// Example implementation for ${pattern.name}\n// TODO: Generate actual code example`,
      explanation: pattern.description
    }));
  }

  private async generateAPIPatternSuggestions(context?: string): Promise<any[]> {
    return [
      {
        category: 'API Route',
        pattern: 'Next.js API Route with Authentication',
        relevanceScore: 0.9,
        example: `export async function GET() {
  try {
    const { user, orgSlug } = await requireAuthWithTenant()
    const db = await getOrgDatabaseWithAuth()
    
    const data = await db.select().from(table)
    return Response.json({ data })
  } catch (error) {
    return new Response('Internal Error', { status: 500 })
  }
}`,
        explanation: 'Always include authentication, error handling, and proper response formatting'
      }
    ];
  }

  private async generateComponentPatternSuggestions(context?: string): Promise<any[]> {
    return [
      {
        category: 'React Component',
        pattern: 'Functional Component with TypeScript',
        relevanceScore: 0.85,
        example: `interface Props {
  id: string
  optional?: boolean
}

export function ComponentName({ id, optional = false }: Props) {
  const { organization } = useOrganization()
  
  // hooks first
  const [state, setState] = useState()
  
  // then handlers
  const handleAction = useCallback(() => {
    // action logic
  }, [])
  
  // then render
  return <div>{/* component content */}</div>
}`,
        explanation: 'Use TypeScript interfaces, proper hook ordering, and organization context'
      }
    ];
  }

  private async generateUtilityPatternSuggestions(context?: string): Promise<any[]> {
    return [
      {
        category: 'Utility Function',
        pattern: 'Type-safe utility with error handling',
        relevanceScore: 0.8,
        example: `export function utilityFunction<T>(input: T): Result<T, Error> {
  try {
    // utility logic
    return { success: true, data: input }
  } catch (error) {
    return { success: false, error: error as Error }
  }
}`,
        explanation: 'Use TypeScript generics and consistent error handling'
      }
    ];
  }

  private async generateContextSpecificSuggestions(context: string): Promise<any[]> {
    const suggestions: any[] = [];
    
    if (context.toLowerCase().includes('auth')) {
      suggestions.push({
        category: 'Authentication',
        pattern: 'Authentication Check',
        relevanceScore: 0.95,
        example: 'const { user, orgSlug, role } = await requireAuthWithTenant()',
        explanation: 'Always validate authentication before accessing protected resources'
      });
    }
    
    if (context.toLowerCase().includes('database')) {
      suggestions.push({
        category: 'Database Security',
        pattern: 'Row Level Security',
        relevanceScore: 0.9,
        example: 'const db = await getOrgDatabaseWithAuth() // Automatic tenant isolation',
        explanation: 'Use RLS-enabled database connections for automatic tenant isolation'
      });
    }
    
    return suggestions;
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up PatternTools...');
    // Cleanup any resources if needed
    logger.info('PatternTools cleanup completed');
  }
}