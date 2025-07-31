import { TSESTree } from '@typescript-eslint/types';
import { ASTPattern } from '../PatternLearner';
import PatternMatcher, { MatchResult } from '../PatternMatcher';
import logger from '../../utils/logger';

export interface APIPattern {
  name: string;
  description: string;
  category: 'route_handler' | 'error_handling' | 'validation' | 'response_format' | 'middleware';
  httpMethods: string[];
  examples: string[];
  bestPractices: string[];
  commonMistakes: string[];
}

export interface APIPatternMatch {
  pattern: APIPattern;
  matchResult: MatchResult;
  httpMethod?: string;
  issues: Array<{
    severity: 'info' | 'warning' | 'error' | 'critical';
    message: string;
    suggestion: string;
  }>;
  recommendations: string[];
}

export class APIPatternsAnalyzer {
  private matcher: PatternMatcher;
  private knownPatterns: Map<string, APIPattern> = new Map();

  constructor() {
    this.matcher = new PatternMatcher({
      minSimilarity: 0.65,
      ignoreVariableNames: true,
      ignoreLiteralValues: false, // Keep HTTP status codes and method names
      allowPartialMatches: true
    });

    this.initializeKnownPatterns();
  }

  private initializeKnownPatterns(): void {
    const patterns: APIPattern[] = [
      {
        name: 'nextjsRouteHandler',
        description: 'Next.js API route handler with proper structure',
        category: 'route_handler',
        httpMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        examples: [
          'export async function GET() { ... }',
          'export async function POST(request: Request) { ... }',
          'export async function DELETE(request: Request, { params }: { params: { id: string } }) { ... }'
        ],
        bestPractices: [
          'Use async functions for all handlers',
          'Include proper TypeScript types',
          'Handle request body parsing',
          'Return Response objects with proper status codes'
        ],
        commonMistakes: [
          'Forgetting to make handler async',
          'Not handling request body properly',
          'Missing error handling',
          'Inconsistent response formats'
        ]
      },
      {
        name: 'properErrorHandling',
        description: 'Consistent error handling in API routes',
        category: 'error_handling',
        httpMethods: ['*'],
        examples: [
          'try { ... } catch (error) { return new Response("Error", { status: 500 }) }',
          'if (!user) { return new Response("Unauthorized", { status: 401 }) }',
          'return Response.json({ error: "Not found" }, { status: 404 })'
        ],
        bestPractices: [
          'Always wrap in try-catch blocks',
          'Return proper HTTP status codes',
          'Use consistent error response format',
          'Log errors for debugging'
        ],
        commonMistakes: [
          'Throwing errors without catching',
          'Using wrong HTTP status codes',
          'Exposing internal error details',
          'Not logging errors'
        ]
      },
      {
        name: 'requestValidation',
        description: 'Input validation and sanitization',
        category: 'validation',
        httpMethods: ['POST', 'PUT', 'PATCH'],
        examples: [
          'const body = await request.json(); if (!body.email) { ... }',
          'const { email, name } = validationSchema.parse(body)',
          'if (typeof body.id !== "string") { return error response }'
        ],
        bestPractices: [
          'Validate all input data',
          'Use schema validation libraries',
          'Sanitize user input',
          'Return clear validation error messages'
        ],
        commonMistakes: [
          'Not validating request body',
          'Trusting user input',
          'Poor validation error messages',
          'Missing type checks'
        ]
      },
      {
        name: 'responseFormat',
        description: 'Consistent API response formatting',
        category: 'response_format',
        httpMethods: ['*'],
        examples: [
          'return Response.json({ data: result })',
          'return Response.json({ data: null, error: "Message" }, { status: 400 })',
          'return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } })'
        ],
        bestPractices: [
          'Use consistent response structure',
          'Include proper Content-Type headers',
          'Return meaningful data structures',
          'Handle both success and error cases'
        ],
        commonMistakes: [
          'Inconsistent response formats',
          'Missing Content-Type headers',
          'Not handling empty responses',
          'Mixing response formats'
        ]
      },
      {
        name: 'authMiddleware',
        description: 'Authentication middleware integration',
        category: 'middleware',
        httpMethods: ['*'],
        examples: [
          'const { user } = await requireAuthWithTenant()',
          'const auth = await validateRequest(request)',
          'if (!isAuthenticated(request)) { return unauthorized() }'
        ],
        bestPractices: [
          'Always check authentication first',
          'Use consistent auth patterns',
          'Validate permissions after auth',
          'Handle auth failures gracefully'
        ],
        commonMistakes: [
          'Missing authentication checks',
          'Inconsistent auth patterns',
          'Not handling auth failures',
          'Bypassing auth for "safe" operations'
        ]
      }
    ];

    for (const pattern of patterns) {
      this.knownPatterns.set(pattern.name, pattern);
    }
  }

  analyzeAPIRoute(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): APIPatternMatch[] {
    const matches: APIPatternMatch[] = [];

    // Only analyze files that appear to be API routes
    if (!this.isAPIRouteFile(filePath)) {
      return matches;
    }

    // Check for route handler patterns
    if (this.isRouteHandler(node)) {
      const handlerMatches = this.analyzeRouteHandler(node, sourceCode);
      matches.push(...handlerMatches);
    }

    // Check for error handling patterns
    const errorHandlingMatches = this.analyzeErrorHandling(node, sourceCode);
    matches.push(...errorHandlingMatches);

    // Check for validation patterns
    const validationMatches = this.analyzeValidation(node, sourceCode);
    matches.push(...validationMatches);

    // Check for response formatting
    const responseMatches = this.analyzeResponseFormatting(node, sourceCode);
    matches.push(...responseMatches);

    return matches;
  }

  private isAPIRouteFile(filePath: string): boolean {
    return filePath.includes('/api/') || 
           filePath.includes('route.ts') || 
           filePath.includes('route.js') ||
           filePath.includes('handler') ||
           (filePath.includes('api') && (filePath.endsWith('.ts') || filePath.endsWith('.js')));
  }

  private isRouteHandler(node: TSESTree.Node): boolean {
    if (node.type === 'ExportNamedDeclaration') {
      const exported = node as TSESTree.ExportNamedDeclaration;
      if (exported.declaration?.type === 'FunctionDeclaration') {
        const func = exported.declaration as TSESTree.FunctionDeclaration;
        const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
        return httpMethods.includes(func.id?.name || '');
      }
    }

    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
      return httpMethods.includes(func.id?.name || '');
    }

    return false;
  }

  private analyzeRouteHandler(node: TSESTree.Node, sourceCode: string): APIPatternMatch[] {
    const matches: APIPatternMatch[] = [];
    const issues: APIPatternMatch['issues'] = [];

    let func: TSESTree.FunctionDeclaration;
    if (node.type === 'ExportNamedDeclaration') {
      func = (node as TSESTree.ExportNamedDeclaration).declaration as TSESTree.FunctionDeclaration;
    } else {
      func = node as TSESTree.FunctionDeclaration;
    }

    const httpMethod = func.id?.name || 'UNKNOWN';
    const pattern = this.knownPatterns.get('nextjsRouteHandler')!;

    // Check if function is async
    if (!func.async) {
      issues.push({
        severity: 'warning',
        message: 'Route handler should be async',
        suggestion: `Make the ${httpMethod} function async`
      });
    }

    // Check parameter structure
    const expectedParams = this.getExpectedParams(httpMethod);
    if (func.params.length < expectedParams.minParams) {
      issues.push({
        severity: 'warning',
        message: `${httpMethod} handler should have at least ${expectedParams.minParams} parameter(s)`,
        suggestion: expectedParams.suggestion
      });
    }

    // Check for proper return statements
    if (!this.hasProperReturnStatements(func, sourceCode)) {
      issues.push({
        severity: 'error',
        message: 'Route handler should return Response objects',
        suggestion: 'Use Response.json() or new Response() for returns'
      });
    }

    // Check for authentication
    if (!this.hasAuthenticationCheck(func, sourceCode)) {
      issues.push({
        severity: 'critical',
        message: 'Route handler missing authentication check',
        suggestion: 'Add requireAuthWithTenant() or similar authentication'
      });
    }

    matches.push({
      pattern,
      matchResult: {
        similarity: issues.length === 0 ? 0.95 : Math.max(0.5, 0.95 - issues.length * 0.1),
        differences: [],
        matchedPattern: {} as ASTPattern,
        isPartialMatch: issues.length > 0,
        confidence: 0.9
      },
      httpMethod,
      issues,
      recommendations: this.generateRouteHandlerRecommendations(httpMethod, issues)
    });

    return matches;
  }

  private analyzeErrorHandling(node: TSESTree.Node, sourceCode: string): APIPatternMatch[] {
    const matches: APIPatternMatch[] = [];
    const issues: APIPatternMatch['issues'] = [];

    // Check for try-catch blocks
    if (node.type === 'FunctionDeclaration' && this.isRouteHandler(node)) {
      const func = node as TSESTree.FunctionDeclaration;
      
      if (!this.hasTryCatchBlock(func)) {
        issues.push({
          severity: 'error',
          message: 'Route handler missing try-catch error handling',
          suggestion: 'Wrap the main logic in a try-catch block'
        });
      }

      if (!this.hasProperErrorResponses(func, sourceCode)) {
        issues.push({
          severity: 'warning',
          message: 'Error responses should use proper HTTP status codes',
          suggestion: 'Return Response objects with appropriate status codes (400, 401, 403, 404, 500)'
        });
      }

      if (issues.length === 0) {
        // Good error handling found
        const pattern = this.knownPatterns.get('properErrorHandling')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.9,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.9
          },
          issues: [],
          recommendations: ['Continue using consistent error handling patterns']
        });
      } else {
        const pattern = this.knownPatterns.get('properErrorHandling')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.4,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: true,
            confidence: 0.6
          },
          issues,
          recommendations: [
            'Add comprehensive error handling',
            'Use consistent error response format',
            'Log errors for debugging purposes'
          ]
        });
      }
    }

    return matches;
  }

  private analyzeValidation(node: TSESTree.Node, sourceCode: string): APIPatternMatch[] {
    const matches: APIPatternMatch[] = [];
    const issues: APIPatternMatch['issues'] = [];

    if (node.type === 'FunctionDeclaration' && this.isRouteHandler(node)) {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethod = func.id?.name || '';

      // Only check validation for methods that typically have request bodies
      if (['POST', 'PUT', 'PATCH'].includes(httpMethod)) {
        if (!this.hasRequestBodyValidation(func, sourceCode)) {
          issues.push({
            severity: 'warning',
            message: 'Request body validation is missing',
            suggestion: 'Validate and sanitize all input data'
          });
        }

        if (!this.hasInputSanitization(func, sourceCode)) {
          issues.push({
            severity: 'warning',
            message: 'Input sanitization may be missing',
            suggestion: 'Ensure user input is properly sanitized'
          });
        }

        const pattern = this.knownPatterns.get('requestValidation')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: issues.length === 0 ? 0.85 : 0.5,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: issues.length > 0,
            confidence: 0.8
          },
          httpMethod,
          issues,
          recommendations: issues.length === 0 
            ? ['Continue using proper validation patterns']
            : ['Add schema validation', 'Validate all user inputs', 'Return clear validation errors']
        });
      }
    }

    return matches;
  }

  private analyzeResponseFormatting(node: TSESTree.Node, sourceCode: string): APIPatternMatch[] {
    const matches: APIPatternMatch[] = [];
    const issues: APIPatternMatch['issues'] = [];

    if (node.type === 'FunctionDeclaration' && this.isRouteHandler(node)) {
      const func = node as TSESTree.FunctionDeclaration;

      if (!this.hasConsistentResponseFormat(func, sourceCode)) {
        issues.push({
          severity: 'warning',
          message: 'Response format may be inconsistent',
          suggestion: 'Use Response.json() for consistent JSON responses'
        });
      }

      if (!this.hasProperContentTypeHeaders(func, sourceCode)) {
        issues.push({
          severity: 'info',
          message: 'Content-Type headers should be explicit',
          suggestion: 'Ensure JSON responses have proper Content-Type headers'
        });
      }

      const pattern = this.knownPatterns.get('responseFormat')!;
      matches.push({
        pattern,
        matchResult: {
          similarity: issues.length === 0 ? 0.8 : 0.6,
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: issues.length > 0,
          confidence: 0.75
        },
        issues,
        recommendations: issues.length === 0
          ? ['Maintain consistent response formatting']
          : ['Use Response.json() for JSON responses', 'Include proper HTTP headers', 'Maintain consistent response structure']
      });
    }

    return matches;
  }

  private getExpectedParams(httpMethod: string): { minParams: number; suggestion: string } {
    switch (httpMethod) {
      case 'GET':
      case 'DELETE':
        return {
          minParams: 0,
          suggestion: 'Consider adding request parameter for URL parameters'
        };
      case 'POST':
      case 'PUT':
      case 'PATCH':
        return {
          minParams: 1,
          suggestion: 'Add request parameter: (request: Request)'
        };
      default:
        return { minParams: 0, suggestion: '' };
    }
  }

  private hasProperReturnStatements(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    // Check if the function body contains Response.json() or new Response()
    return sourceCode.includes('Response.json(') || 
           sourceCode.includes('new Response(') ||
           sourceCode.includes('NextResponse.json(');
  }

  private hasAuthenticationCheck(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    const authPatterns = [
      'requireAuth', 'checkAuth', 'validateAuth', 'authenticate',
      'requireAuthWithTenant', 'getUser', 'verifyToken'
    ];

    return authPatterns.some(pattern => sourceCode.includes(pattern));
  }

  private hasTryCatchBlock(func: TSESTree.FunctionDeclaration): boolean {
    // Recursively check for try-catch blocks in the function body
    return this.findTryCatchInNode(func.body);
  }

  private findTryCatchInNode(node: TSESTree.Node | null): boolean {
    if (!node) return false;

    if (node.type === 'TryStatement') {
      return true;
    }

    // Recursively check child nodes
    for (const key in node) {
      const child = (node as any)[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) {
            if (this.findTryCatchInNode(item)) return true;
          }
        }
      } else if (child && typeof child === 'object' && child.type) {
        if (this.findTryCatchInNode(child)) return true;
      }
    }

    return false;
  }

  private hasProperErrorResponses(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    const errorStatusCodes = ['400', '401', '403', '404', '500'];
    return errorStatusCodes.some(code => 
      sourceCode.includes(`status: ${code}`) || 
      sourceCode.includes(`{ status: ${code}`)
    );
  }

  private hasRequestBodyValidation(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    return sourceCode.includes('await request.json()') ||
           sourceCode.includes('.parse(') ||
           sourceCode.includes('validate(') ||
           sourceCode.includes('schema.');
  }

  private hasInputSanitization(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    return sourceCode.includes('sanitize') ||
           sourceCode.includes('trim()') ||
           sourceCode.includes('typeof ') ||
           sourceCode.includes('instanceof ');
  }

  private hasConsistentResponseFormat(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    const responsePatterns = sourceCode.match(/Response\.json\(/g);
    const newResponsePatterns = sourceCode.match(/new Response\(/g);
    
    // If we have both patterns, it might be inconsistent
    return !(responsePatterns && newResponsePatterns);
  }

  private hasProperContentTypeHeaders(func: TSESTree.FunctionDeclaration, sourceCode: string): boolean {
    return sourceCode.includes('Content-Type') ||
           sourceCode.includes('Response.json('); // Response.json() sets proper headers automatically
  }

  private generateRouteHandlerRecommendations(
    httpMethod: string,
    issues: APIPatternMatch['issues']
  ): string[] {
    const recommendations: string[] = [];

    if (issues.some(i => i.message.includes('async'))) {
      recommendations.push(`Make ${httpMethod} handler async for proper error handling`);
    }

    if (issues.some(i => i.message.includes('parameter'))) {
      recommendations.push('Add proper request parameters for body parsing');
    }

    if (issues.some(i => i.message.includes('authentication'))) {
      recommendations.push('Add authentication check at the beginning of the handler');
    }

    if (issues.some(i => i.message.includes('Response'))) {
      recommendations.push('Use Response.json() for consistent JSON responses');
    }

    if (recommendations.length === 0) {
      recommendations.push('Route handler follows good practices');
    }

    return recommendations;
  }

  getKnownPatterns(): Map<string, APIPattern> {
    return this.knownPatterns;
  }

  addCustomPattern(pattern: APIPattern): void {
    this.knownPatterns.set(pattern.name, pattern);
    logger.info(`Added custom API pattern: ${pattern.name}`);
  }

  generateAPIReport(matches: APIPatternMatch[]): string {
    const report = ['# API Pattern Analysis Report\n'];
    
    const byCategory = new Map<string, APIPatternMatch[]>();
    for (const match of matches) {
      const category = match.pattern.category;
      if (!byCategory.has(category)) {
        byCategory.set(category, []);
      }
      byCategory.get(category)!.push(match);
    }

    for (const [category, categoryMatches] of byCategory) {
      report.push(`## ${category.replace('_', ' ').toUpperCase()}\n`);
      
      for (const match of categoryMatches) {
        report.push(`### ${match.pattern.name}`);
        if (match.httpMethod) {
          report.push(`**HTTP Method:** ${match.httpMethod}`);
        }
        report.push(match.pattern.description);
        
        if (match.issues.length > 0) {
          report.push('\n**Issues Found:**');
          match.issues.forEach(issue => {
            report.push(`- **${issue.severity.toUpperCase()}:** ${issue.message}`);
            report.push(`  *Suggestion:* ${issue.suggestion}`);
          });
        }
        
        if (match.recommendations.length > 0) {
          report.push('\n**Recommendations:**');
          match.recommendations.forEach(rec => report.push(`- ${rec}`));
        }
        
        report.push('');
      }
    }

    return report.join('\n');
  }
}

export default APIPatternsAnalyzer;