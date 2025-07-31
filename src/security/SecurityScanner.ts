import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface SecurityScanOptions {
  includeCategories?: VulnerabilityCategory[];
  excludeCategories?: VulnerabilityCategory[];
  minSeverity?: VulnerabilitySeverity;
  maxFindings?: number;
  includeTests?: boolean;
}

export class SecurityScanner {
  private astParser: ASTParser;

  constructor() {
    this.astParser = new ASTParser();
  }

  public async scanFile(filePath: string, options: SecurityScanOptions = {}): Promise<SecurityFinding[]> {
    try {
      logger.info(`Scanning file for security issues: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return [];
      }

      const findings: SecurityFinding[] = [];
      
      // Scan for different vulnerability types
      findings.push(...await this.scanForDirectDatabaseAccess(content, filePath));
      findings.push(...await this.scanForHardcodedSecrets(content, filePath));
      findings.push(...await this.scanForSQLInjection(content, filePath));
      findings.push(...await this.scanForMissingAuthChecks(content, filePath));
      findings.push(...await this.scanForXSSVulnerabilities(content, filePath));
      findings.push(...await this.scanForUnvalidatedInput(content, filePath));
      findings.push(...await this.scanForInsecureDirectObjectReferences(content, filePath));

      // Filter based on options
      return this.filterFindings(findings, options);
    } catch (error) {
      logger.error(`Error scanning file ${filePath}:`, error);
      return [];
    }
  }

  public async scanDirectory(dirPath: string, options: SecurityScanOptions = {}): Promise<SecurityFinding[]> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const findings: SecurityFinding[] = [];
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          // Skip common directories to ignore
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
            continue;
          }
          findings.push(...await this.scanDirectory(fullPath, options));
        } else if (entry.isFile() && this.isScannableFile(entry.name)) {
          findings.push(...await this.scanFile(fullPath, options));
        }
      }
    } catch (error) {
      logger.error(`Error scanning directory ${dirPath}:`, error);
    }
    
    return findings;
  }

  private isScannableFile(fileName: string): boolean {
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    return extensions.some(ext => fileName.endsWith(ext));
  }

  private async scanForDirectDatabaseAccess(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    const traverse = (node: TSESTree.Node) => {
      // Look for direct database client creation
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const callee = node.callee;
        
        // Check for drizzle(), createClient(), new Pool(), etc.
        if (callee.type === AST_NODE_TYPES.Identifier) {
          const dangerousFunctions = ['drizzle', 'createClient'];
          if (dangerousFunctions.includes(callee.name)) {
            // Check if this is inside an authenticated context
            if (!this.isInAuthenticatedContext(node, content.ast)) {
              const finding = vulnerabilityDatabase.createFinding(
                'direct-db-access-without-auth',
                filePath,
                node.loc?.start.line || 0,
                node.loc?.end.line || 0,
                node.loc?.start.column || 0,
                node.loc?.end.column || 0,
                this.getNodeCode(node, content.sourceCode)
              );
              if (finding) findings.push(finding);
            }
          }
        }
        
        // Check for new Pool(), new Client()
        if (callee.type === AST_NODE_TYPES.NewExpression) {
          const constructor = callee.callee;
          if (constructor.type === AST_NODE_TYPES.Identifier) {
            const dangerousConstructors = ['Pool', 'Client'];
            if (dangerousConstructors.includes(constructor.name)) {
              const finding = vulnerabilityDatabase.createFinding(
                'direct-db-access-without-auth',
                filePath,
                node.loc?.start.line || 0,
                node.loc?.end.line || 0,
                node.loc?.start.column || 0,
                node.loc?.end.column || 0,
                this.getNodeCode(node, content.sourceCode)
              );
              if (finding) findings.push(finding);
            }
          }
        }
      }
      
      // Recursively traverse child nodes
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                traverse(item);
              }
            });
          } else if (child.type) {
            traverse(child);
          }
        }
      }
    };
    
    traverse(content.ast);
    return findings;
  }

  private async scanForHardcodedSecrets(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    // Regex patterns for common secrets
    const secretPatterns = [
      /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{3,}['"]/gi,
      /(?:secret|api_secret)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
      /(?:key|api_key|apikey)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
      /(?:token|access_token|auth_token)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
      /sk-[a-zA-Z0-9]{32,}/g, // OpenAI API key pattern
      /ghp_[a-zA-Z0-9]{36}/g, // GitHub personal access token
      /ya29\.[a-zA-Z0-9_-]{68}/g, // Google OAuth token
    ];
    
    const lines = content.sourceCode.split('\n');
    
    lines.forEach((line, index) => {
      // Skip comments and obvious test/example code
      if (line.trim().startsWith('//') || 
          line.trim().startsWith('*') ||
          line.includes('example') ||
          line.includes('test') ||
          line.includes('placeholder')) {
        return;
      }
      
      secretPatterns.forEach(pattern => {
        const matches = line.matchAll(pattern);
        for (const match of matches) {
          // Additional validation to reduce false positives
          if (this.isLikelySecret(match[0])) {
            const finding = vulnerabilityDatabase.createFinding(
              'hardcoded-secrets',
              filePath,
              index + 1,
              index + 1,
              match.index || 0,
              (match.index || 0) + match[0].length,
              line.trim()
            );
            if (finding) findings.push(finding);
          }
        }
      });
    });
    
    return findings;
  }

  private async scanForSQLInjection(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    const traverse = (node: TSESTree.Node) => {
      // Look for template literals that might contain SQL
      if (node.type === AST_NODE_TYPES.TemplateLiteral) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check if this looks like SQL and has expressions
        if (this.looksLikeSQL(code) && node.expressions.length > 0) {
          // Check if expressions contain user input
          const hasUserInput = node.expressions.some(expr => 
            this.couldBeUserInput(expr, content.sourceCode)
          );
          
          if (hasUserInput) {
            const finding = vulnerabilityDatabase.createFinding(
              'sql-injection-template-literal',
              filePath,
              node.loc?.start.line || 0,
              node.loc?.end.line || 0,
              node.loc?.start.column || 0,
              node.loc?.end.column || 0,
              code
            );
            if (finding) findings.push(finding);
          }
        }
      }
      
      // Look for string concatenation with SQL keywords
      if (node.type === AST_NODE_TYPES.BinaryExpression && node.operator === '+') {
        const code = this.getNodeCode(node, content.sourceCode);
        if (this.looksLikeSQL(code)) {
          const finding = vulnerabilityDatabase.createFinding(
            'sql-injection-template-literal',
            filePath,
            node.loc?.start.line || 0,
            node.loc?.end.line || 0,
            node.loc?.start.column || 0,
            node.loc?.end.column || 0,
            code,
            0.7 // Lower confidence for string concatenation
          );
          if (finding) findings.push(finding);
        }
      }
      
      // Recursively traverse
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                traverse(item);
              }
            });
          } else if (child.type) {
            traverse(child);
          }
        }
      }
    };
    
    traverse(content.ast);
    return findings;
  }

  private async scanForMissingAuthChecks(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    // Check if this is an API route file
    if (!this.isAPIRoute(filePath)) {
      return findings;
    }
    
    const traverse = (node: TSESTree.Node) => {
      // Look for exported async functions (API route handlers)
      if (node.type === AST_NODE_TYPES.ExportNamedDeclaration ||
          node.type === AST_NODE_TYPES.ExportDefaultDeclaration) {
        
        let functionNode: TSESTree.FunctionDeclaration | TSESTree.ArrowFunctionExpression | null = null;
        
        if (node.type === AST_NODE_TYPES.ExportNamedDeclaration && node.declaration) {
          if (node.declaration.type === AST_NODE_TYPES.FunctionDeclaration) {
            functionNode = node.declaration;
          }
        }
        
        if (functionNode && this.isHTTPMethod(functionNode.id?.name)) {
          // Check if function body contains auth check
          if (!this.hasAuthCheck(functionNode)) {
            const finding = vulnerabilityDatabase.createFinding(
              'missing-auth-api-route',
              filePath,
              functionNode.loc?.start.line || 0,
              functionNode.loc?.end.line || 0,
              functionNode.loc?.start.column || 0,
              functionNode.loc?.end.column || 0,
              this.getNodeCode(functionNode, content.sourceCode)
            );
            if (finding) findings.push(finding);
          }
        }
      }
      
      // Recursively traverse
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                traverse(item);
              }
            });
          } else if (child.type) {
            traverse(child);
          }
        }
      }
    };
    
    traverse(content.ast);
    return findings;
  }

  private async scanForXSSVulnerabilities(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    const traverse = (node: TSESTree.Node) => {
      // Look for dangerouslySetInnerHTML
      if (node.type === AST_NODE_TYPES.JSXAttribute && 
          node.name.type === AST_NODE_TYPES.JSXIdentifier &&
          node.name.name === 'dangerouslySetInnerHTML') {
        
        if (node.value && node.value.type === AST_NODE_TYPES.JSXExpressionContainer) {
          const expr = node.value.expression;
          
          // Check if the content could be user input and is not sanitized
          if (expr.type !== AST_NODE_TYPES.JSXEmptyExpression &&
              this.couldContainUserInput(expr, content.sourceCode) && 
              !this.isSanitized(expr, content.sourceCode)) {
            const finding = vulnerabilityDatabase.createFinding(
              'xss-dangerouslysetinnerhtml',
              filePath,
              node.loc?.start.line || 0,
              node.loc?.end.line || 0,
              node.loc?.start.column || 0,
              node.loc?.end.column || 0,
              this.getNodeCode(node, content.sourceCode)
            );
            if (finding) findings.push(finding);
          }
        }
      }
      
      // Recursively traverse
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                traverse(item);
              }
            });
          } else if (child.type) {
            traverse(child);
          }
        }
      }
    };
    
    traverse(content.ast);
    return findings;
  }

  private async scanForUnvalidatedInput(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    const traverse = (node: TSESTree.Node) => {
      // Look for user input sources
      if (node.type === AST_NODE_TYPES.MemberExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for common user input sources
        const userInputPatterns = [
          'req.body',
          'req.query',
          'req.params',
          'searchParams.get',
          'params.',
          'body.',
          'query.'
        ];
        
        if (userInputPatterns.some(pattern => code.includes(pattern))) {
          // Check if this input is validated before use
          if (!this.isInputValidated(node, content.ast)) {
            const finding = vulnerabilityDatabase.createFinding(
              'unvalidated-user-input',
              filePath,
              node.loc?.start.line || 0,
              node.loc?.end.line || 0,
              node.loc?.start.column || 0,
              node.loc?.end.column || 0,
              code,
              0.8 // Moderate confidence
            );
            if (finding) findings.push(finding);
          }
        }
      }
      
      // Recursively traverse
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                traverse(item);
              }
            });
          } else if (child.type) {
            traverse(child);
          }
        }
      }
    };
    
    traverse(content.ast);
    return findings;
  }

  private async scanForInsecureDirectObjectReferences(
    content: { ast: TSESTree.Program; sourceCode: string }, 
    filePath: string
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    // Look for patterns where user-provided IDs are used directly in database queries
    // without proper authorization checks
    
    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Look for database operations using user input
        if (this.isDatabaseOperation(code) && this.containsUserProvidedId(node, content.sourceCode)) {
          // Check if there's proper authorization
          if (!this.hasAuthorizationCheck(node, content.ast)) {
            const finding = vulnerabilityDatabase.createFinding(
              'insecure-direct-object-reference',
              filePath,
              node.loc?.start.line || 0,
              node.loc?.end.line || 0,
              node.loc?.start.column || 0,
              node.loc?.end.column || 0,
              code,
              0.7
            );
            if (finding) findings.push(finding);
          }
        }
      }
      
      // Recursively traverse
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                traverse(item);
              }
            });
          } else if (child.type) {
            traverse(child);
          }
        }
      }
    };
    
    traverse(content.ast);
    return findings;
  }

  // Helper methods
  private isInAuthenticatedContext(node: TSESTree.Node, ast: TSESTree.Program): boolean {
    // This would need more sophisticated analysis to determine if we're in an authenticated context
    // For now, check for common auth function calls in the same scope
    const authFunctions = ['requireAuthWithTenant', 'requireAuth', 'verifyAuth', 'checkAuth'];
    const code = JSON.stringify(ast);
    return authFunctions.some(func => code.includes(func));
  }

  private getNodeCode(node: TSESTree.Node, sourceCode: string): string {
    if (!node.range) return '';
    return sourceCode.slice(node.range[0], node.range[1]);
  }

  private isLikelySecret(text: string): boolean {
    // Exclude obvious test/placeholder values
    const excludePatterns = [
      /test/i,
      /example/i,
      /placeholder/i,
      /dummy/i,
      /fake/i,
      /^['"]$/,
      /^['"]['"]*$/,
      /^['"].*['"]*['"]$/
    ];
    
    return !excludePatterns.some(pattern => pattern.test(text)) && text.length > 8;
  }

  private looksLikeSQL(code: string): boolean {
    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'JOIN'];
    const upperCode = code.toUpperCase();
    return sqlKeywords.some(keyword => upperCode.includes(keyword));
  }

  private couldBeUserInput(node: TSESTree.Expression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    const userInputPatterns = ['req.', 'params', 'body', 'query', 'input', 'userId', 'id'];
    return userInputPatterns.some(pattern => code.includes(pattern));
  }

  private isAPIRoute(filePath: string): boolean {
    return filePath.includes('/api/') || filePath.includes('/route.ts') || filePath.includes('/route.js') || filePath.includes('auth-bypass.ts');
  }

  private isHTTPMethod(name?: string): boolean {
    if (!name) return false;
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    return httpMethods.includes(name.toUpperCase());
  }

  private hasAuthCheck(functionNode: TSESTree.FunctionDeclaration | TSESTree.ArrowFunctionExpression): boolean {
    const code = JSON.stringify(functionNode);
    const authPatterns = [
      'requireAuthWithTenant',
      'requireAuth',
      'verifyAuth',
      'checkAuth',
      'authenticate',
      'authorize'
    ];
    return authPatterns.some(pattern => code.includes(pattern));
  }

  private couldContainUserInput(node: TSESTree.Expression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    return this.couldBeUserInput(node, sourceCode);
  }

  private isSanitized(node: TSESTree.Expression, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    const sanitizationLibraries = ['DOMPurify', 'sanitizeHtml', 'escape', 'validator'];
    return sanitizationLibraries.some(lib => code.includes(lib));
  }

  private isInputValidated(node: TSESTree.Node, ast: TSESTree.Program): boolean {
    // Look for validation libraries in the same scope
    const code = JSON.stringify(ast);
    const validationPatterns = ['zod', 'joi', 'yup', 'validate', 'schema', '.parse(', '.safeParse('];
    return validationPatterns.some(pattern => code.includes(pattern));
  }

  private isDatabaseOperation(code: string): boolean {
    const dbOperations = ['select', 'insert', 'update', 'delete', 'find', 'findById', 'query'];
    return dbOperations.some(op => code.toLowerCase().includes(op));
  }

  private containsUserProvidedId(node: TSESTree.CallExpression, sourceCode: string): boolean {
    return node.arguments.some(arg => {
      if (arg.type === AST_NODE_TYPES.SpreadElement) {
        return false; // Skip spread elements for now
      }
      const argCode = this.getNodeCode(arg, sourceCode);
      return this.couldBeUserInput(arg, sourceCode);
    });
  }

  private hasAuthorizationCheck(node: TSESTree.Node, ast: TSESTree.Program): boolean {
    // Check if there's an authorization check in the same function scope
    const code = JSON.stringify(ast);
    const authzPatterns = ['hasPermission', 'canAccess', 'isAuthorized', 'checkPermission'];
    return authzPatterns.some(pattern => code.includes(pattern));
  }

  private filterFindings(findings: SecurityFinding[], options: SecurityScanOptions): SecurityFinding[] {
    let filtered = findings;
    
    if (options.includeCategories) {
      filtered = filtered.filter(f => options.includeCategories!.includes(f.category));
    }
    
    if (options.excludeCategories) {
      filtered = filtered.filter(f => !options.excludeCategories!.includes(f.category));
    }
    
    if (options.minSeverity) {
      const severityOrder = {
        [VulnerabilitySeverity.CRITICAL]: 0,
        [VulnerabilitySeverity.HIGH]: 1,
        [VulnerabilitySeverity.MEDIUM]: 2,
        [VulnerabilitySeverity.LOW]: 3,
        [VulnerabilitySeverity.INFO]: 4
      };
      const minLevel = severityOrder[options.minSeverity];
      filtered = filtered.filter(f => severityOrder[f.severity] <= minLevel);
    }
    
    if (options.maxFindings) {
      filtered = vulnerabilityDatabase.prioritizeFindings(filtered).slice(0, options.maxFindings);
    }
    
    return filtered;
  }
}