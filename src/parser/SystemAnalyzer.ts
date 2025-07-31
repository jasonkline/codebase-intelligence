import { TSESTree } from '@typescript-eslint/typescript-estree';
import { ParsedFile, ParsedSymbol } from './ASTParser';
import logger from '../utils/logger';

export interface AuthPattern {
  type: 'auth_check' | 'auth_bypass' | 'auth_middleware' | 'auth_required';
  functionName: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  confidence: number;
  context: string;
  metadata?: Record<string, any>;
}

export interface RBACPattern {
  type: 'role_check' | 'permission_check' | 'has_permission' | 'role_assignment';
  role?: string;
  permission?: string;
  resource?: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  confidence: number;
  context: string;
}

export interface DataAccessPattern {
  type: 'database_query' | 'rls_usage' | 'direct_db_access' | 'orm_usage';
  method?: string;
  table?: string;
  isSecure: boolean;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  confidence: number;
  context: string;
  securityRisk?: 'high' | 'medium' | 'low';
}

export interface APIPattern {
  type: 'api_route' | 'middleware' | 'handler' | 'validation';
  method?: string; // GET, POST, etc.
  route?: string;
  hasAuth: boolean;
  hasValidation: boolean;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  confidence: number;
  context: string;
}

export interface SystemDependency {
  from: string;
  to: string;
  type: 'import' | 'call' | 'extend' | 'implements';
  filePath: string;
  line: number;
  strength: number; // 1-10
}

export interface SystemAnalysisResult {
  authPatterns: AuthPattern[];
  rbacPatterns: RBACPattern[];
  dataAccessPatterns: DataAccessPattern[];
  apiPatterns: APIPattern[];
  dependencies: SystemDependency[];
  summary: {
    totalPatterns: number;
    securityIssues: number;
    authCoverage: number;
    rbacCompliance: number;
  };
}

export class SystemAnalyzer {
  private authFunctionNames = [
    'requireAuthWithTenant',
    'requireAuth',
    'checkAuth',
    'verifyAuth',
    'authenticate',
    'isAuthenticated',
    'validateToken',
    'getUser',
    'getCurrentUser'
  ];

  private rbacFunctionNames = [
    'hasPermission',
    'checkPermission',
    'requirePermission',
    'hasRole',
    'checkRole',
    'requireRole',
    'canAccess',
    'isAuthorized'
  ];

  private databasePatterns = [
    'getOrgDatabase',
    'getOrgDatabaseWithAuth',
    'getSupabaseRLS',
    'drizzle',
    'query',
    'select',
    'insert',
    'update',
    'delete',
    'from',
    'where'
  ];

  private apiPatterns = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
    'NextRequest',
    'NextResponse',
    'Response',
    'Request'
  ];

  constructor() {}

  analyzeFile(parsedFile: ParsedFile, sourceCode: string): SystemAnalysisResult {
    try {
      const authPatterns = this.findAuthPatterns(parsedFile, sourceCode);
      const rbacPatterns = this.findRBACPatterns(parsedFile, sourceCode);
      const dataAccessPatterns = this.findDataAccessPatterns(parsedFile, sourceCode);
      const apiPatterns = this.findAPIPatterns(parsedFile, sourceCode);
      const dependencies = this.extractDependencies(parsedFile);

      const summary = this.generateSummary(authPatterns, rbacPatterns, dataAccessPatterns, apiPatterns);

      return {
        authPatterns,
        rbacPatterns,
        dataAccessPatterns,
        apiPatterns,
        dependencies,
        summary
      };
    } catch (error) {
      logger.error(`Failed to analyze file ${parsedFile.filePath}:`, error);
      return {
        authPatterns: [],
        rbacPatterns: [],
        dataAccessPatterns: [],
        apiPatterns: [],
        dependencies: [],
        summary: {
          totalPatterns: 0,
          securityIssues: 0,
          authCoverage: 0,
          rbacCompliance: 0
        }
      };
    }
  }

  private findAuthPatterns(parsedFile: ParsedFile, sourceCode: string): AuthPattern[] {
    const patterns: AuthPattern[] = [];
    const lines = sourceCode.split('\n');

    // Check function calls for auth patterns
    parsedFile.symbols.forEach(symbol => {
      if (symbol.kind === 'function') {
        const symbolSource = this.getSymbolSource(symbol, lines);
        
        // Check for auth function calls
        this.authFunctionNames.forEach(authFunc => {
          if (symbolSource.includes(authFunc)) {
            const confidence = this.calculateAuthConfidence(symbolSource, authFunc);
            
            patterns.push({
              type: this.getAuthPatternType(authFunc),
              functionName: authFunc,
              filePath: parsedFile.filePath,
              lineStart: symbol.lineStart,
              lineEnd: symbol.lineEnd,
              confidence,
              context: symbolSource.substring(0, 200) + (symbolSource.length > 200 ? '...' : ''),
              metadata: {
                containingFunction: symbol.name,
                isExported: symbol.isExported
              }
            });
          }
        });

        // Check for potential auth bypasses
        if (this.hasAuthBypass(symbolSource)) {
          patterns.push({
            type: 'auth_bypass',
            functionName: symbol.name,
            filePath: parsedFile.filePath,
            lineStart: symbol.lineStart,
            lineEnd: symbol.lineEnd,
            confidence: 0.8,
            context: symbolSource.substring(0, 200) + (symbolSource.length > 200 ? '...' : ''),
            metadata: {
              riskLevel: 'high'
            }
          });
        }
      }
    });

    // Check for middleware patterns
    if (parsedFile.filePath.includes('middleware') || parsedFile.filePath.includes('auth')) {
      parsedFile.symbols.forEach(symbol => {
        if (symbol.kind === 'function' && symbol.isExported) {
          patterns.push({
            type: 'auth_middleware',
            functionName: symbol.name,
            filePath: parsedFile.filePath,
            lineStart: symbol.lineStart,
            lineEnd: symbol.lineEnd,
            confidence: 0.9,
            context: `Middleware function: ${symbol.name}`,
            metadata: {
              isMiddleware: true
            }
          });
        }
      });
    }

    return patterns;
  }

  private findRBACPatterns(parsedFile: ParsedFile, sourceCode: string): RBACPattern[] {
    const patterns: RBACPattern[] = [];
    const lines = sourceCode.split('\n');

    parsedFile.symbols.forEach(symbol => {
      if (symbol.kind === 'function') {
        const symbolSource = this.getSymbolSource(symbol, lines);
        
        // Check for RBAC function calls
        this.rbacFunctionNames.forEach(rbacFunc => {
          if (symbolSource.includes(rbacFunc)) {
            const { role, permission, resource } = this.extractRBACDetails(symbolSource, rbacFunc);
            
            patterns.push({
              type: this.getRBACPatternType(rbacFunc),
              role,
              permission,
              resource,
              filePath: parsedFile.filePath,
              lineStart: symbol.lineStart,
              lineEnd: symbol.lineEnd,
              confidence: this.calculateRBACConfidence(symbolSource, rbacFunc),
              context: symbolSource.substring(0, 200) + (symbolSource.length > 200 ? '...' : '')
            });
          }
        });

        // Check for hardcoded roles/permissions
        const hardcodedRoles = this.findHardcodedRoles(symbolSource);
        hardcodedRoles.forEach(role => {
          patterns.push({
            type: 'role_check',
            role,
            filePath: parsedFile.filePath,
            lineStart: symbol.lineStart,
            lineEnd: symbol.lineEnd,
            confidence: 0.7,
            context: `Hardcoded role check: ${role}`
          });
        });
      }
    });

    return patterns;
  }

  private findDataAccessPatterns(parsedFile: ParsedFile, sourceCode: string): DataAccessPattern[] {
    const patterns: DataAccessPattern[] = [];
    const lines = sourceCode.split('\n');

    parsedFile.symbols.forEach(symbol => {
      if (symbol.kind === 'function') {
        const symbolSource = this.getSymbolSource(symbol, lines);
        
        // Check for database access patterns
        this.databasePatterns.forEach(dbPattern => {
          if (symbolSource.includes(dbPattern)) {
            const isSecure = this.isSecureDataAccess(symbolSource, dbPattern);
            const securityRisk = this.assessDataAccessRisk(symbolSource, dbPattern);
            
            patterns.push({
              type: this.getDataAccessType(dbPattern),
              method: dbPattern,
              isSecure,
              securityRisk,
              filePath: parsedFile.filePath,
              lineStart: symbol.lineStart,
              lineEnd: symbol.lineEnd,
              confidence: this.calculateDataAccessConfidence(symbolSource, dbPattern),
              context: symbolSource.substring(0, 200) + (symbolSource.length > 200 ? '...' : '')
            });
          }
        });

        // Check for direct database connections (security risk)
        if (this.hasDirectDatabaseAccess(symbolSource)) {
          patterns.push({
            type: 'direct_db_access',
            isSecure: false,
            securityRisk: 'high',
            filePath: parsedFile.filePath,
            lineStart: symbol.lineStart,
            lineEnd: symbol.lineEnd,
            confidence: 0.9,
            context: 'Direct database access detected'
          });
        }
      }
    });

    return patterns;
  }

  private findAPIPatterns(parsedFile: ParsedFile, sourceCode: string): APIPattern[] {
    const patterns: APIPattern[] = [];
    
    // Check if this is an API route file
    if (parsedFile.filePath.includes('/api/') || parsedFile.filePath.includes('route.ts')) {
      const lines = sourceCode.split('\n');
      
      parsedFile.symbols.forEach(symbol => {
        if (symbol.kind === 'function' && this.apiPatterns.includes(symbol.name)) {
          const symbolSource = this.getSymbolSource(symbol, lines);
          const hasAuth = this.hasAuthInFunction(symbolSource);
          const hasValidation = this.hasValidationInFunction(symbolSource);
          
          patterns.push({
            type: 'api_route',
            method: symbol.name,
            hasAuth,
            hasValidation,
            filePath: parsedFile.filePath,
            lineStart: symbol.lineStart,
            lineEnd: symbol.lineEnd,
            confidence: 0.95,
            context: `API ${symbol.name} handler`
          });
        }
      });

      // Check for middleware usage
      if (sourceCode.includes('middleware') || sourceCode.includes('use(')) {
        patterns.push({
          type: 'middleware',
          hasAuth: this.hasAuthInFunction(sourceCode),
          hasValidation: this.hasValidationInFunction(sourceCode),
          filePath: parsedFile.filePath,
          lineStart: 1,
          lineEnd: lines.length,
          confidence: 0.8,
          context: 'Middleware usage detected'
        });
      }
    }

    return patterns;
  }

  private extractDependencies(parsedFile: ParsedFile): SystemDependency[] {
    const dependencies: SystemDependency[] = [];

    // Extract import dependencies
    parsedFile.imports.forEach(importDecl => {
      dependencies.push({
        from: parsedFile.filePath,
        to: importDecl.source,
        type: 'import',
        filePath: parsedFile.filePath,
        line: importDecl.lineStart,
        strength: this.calculateImportStrength(importDecl)
      });
    });

    // TODO: Add function call dependencies, class inheritance, etc.

    return dependencies;
  }

  private generateSummary(
    authPatterns: AuthPattern[],
    rbacPatterns: RBACPattern[],
    dataAccessPatterns: DataAccessPattern[],
    apiPatterns: APIPattern[]
  ) {
    const totalPatterns = authPatterns.length + rbacPatterns.length + dataAccessPatterns.length + apiPatterns.length;
    
    const securityIssues = [
      ...authPatterns.filter(p => p.type === 'auth_bypass'),
      ...dataAccessPatterns.filter(p => p.securityRisk === 'high'),
      ...apiPatterns.filter(p => !p.hasAuth)
    ].length;

    const authCoverage = apiPatterns.length > 0 ? 
      (apiPatterns.filter(p => p.hasAuth).length / apiPatterns.length) * 100 : 100;

    const rbacCompliance = authPatterns.length > 0 ? 
      (rbacPatterns.length / authPatterns.length) * 100 : 0;

    return {
      totalPatterns,
      securityIssues,
      authCoverage: Math.round(authCoverage),
      rbacCompliance: Math.round(rbacCompliance)
    };
  }

  // Helper methods
  private getSymbolSource(symbol: ParsedSymbol, lines: string[]): string {
    return lines.slice(symbol.lineStart - 1, symbol.lineEnd).join('\n');
  }

  private calculateAuthConfidence(source: string, authFunc: string): number {
    let confidence = 0.7;
    
    if (source.includes('await ' + authFunc)) confidence += 0.1;
    if (source.includes('try') && source.includes('catch')) confidence += 0.1;
    if (source.includes('return') && source.includes('401')) confidence += 0.1;
    
    return Math.min(confidence, 1.0);
  }

  private getAuthPatternType(authFunc: string): AuthPattern['type'] {
    if (authFunc.includes('require')) return 'auth_required';
    if (authFunc.includes('check') || authFunc.includes('verify')) return 'auth_check';
    return 'auth_check';
  }

  private hasAuthBypass(source: string): boolean {
    return source.includes('// TODO: add auth') || 
           source.includes('// FIXME: auth') ||
           source.includes('bypass') ||
           source.includes('skip auth');
  }

  private getRBACPatternType(rbacFunc: string): RBACPattern['type'] {
    if (rbacFunc.includes('Permission')) return 'permission_check';
    if (rbacFunc.includes('Role')) return 'role_check';
    if (rbacFunc.includes('hasPermission')) return 'has_permission';
    return 'permission_check';
  }

  private extractRBACDetails(source: string, rbacFunc: string): { role?: string; permission?: string; resource?: string } {
    // Simple regex-based extraction (could be enhanced)
    const roleMatch = source.match(/['"`](\w+)['"`]/);
    const permissionMatch = source.match(/permission[:\s]*['"`](\w+)['"`]/i);
    const resourceMatch = source.match(/resource[:\s]*['"`](\w+)['"`]/i);
    
    return {
      role: roleMatch?.[1],
      permission: permissionMatch?.[1],
      resource: resourceMatch?.[1]
    };
  }

  private calculateRBACConfidence(source: string, rbacFunc: string): number {
    let confidence = 0.8;
    
    if (source.includes('role') && source.includes('permission')) confidence += 0.1;
    if (source.includes('admin') || source.includes('user') || source.includes('member')) confidence += 0.05;
    
    return Math.min(confidence, 1.0);
  }

  private findHardcodedRoles(source: string): string[] {
    const roles: string[] = [];
    const commonRoles = ['admin', 'user', 'member', 'guest', 'moderator', 'owner', 'approver'];
    
    commonRoles.forEach(role => {
      if (source.includes(`'${role}'`) || source.includes(`"${role}"`)) {
        roles.push(role);
      }
    });
    
    return roles;
  }

  private getDataAccessType(pattern: string): DataAccessPattern['type'] {
    if (pattern.includes('RLS')) return 'rls_usage';
    if (pattern.includes('drizzle') || pattern.includes('query')) return 'orm_usage';
    if (pattern.includes('direct') || pattern === 'query') return 'direct_db_access';
    return 'database_query';
  }

  private isSecureDataAccess(source: string, pattern: string): boolean {
    return source.includes('getOrgDatabaseWithAuth') || 
           source.includes('getSupabaseRLS') ||
           source.includes('RLS');
  }

  private assessDataAccessRisk(source: string, pattern: string): 'high' | 'medium' | 'low' {
    if (source.includes('drizzle(') && !source.includes('Auth')) return 'high';
    if (source.includes('direct') || pattern === 'query') return 'high';
    if (source.includes('getOrgDatabase') && !source.includes('Auth')) return 'medium';
    return 'low';
  }

  private calculateDataAccessConfidence(source: string, pattern: string): number {
    let confidence = 0.8;
    
    if (source.includes('await')) confidence += 0.1;
    if (source.includes('try') && source.includes('catch')) confidence += 0.05;
    
    return Math.min(confidence, 1.0);
  }

  private hasDirectDatabaseAccess(source: string): boolean {
    return source.includes('new Database(') ||
           source.includes('createConnection(') ||
           (source.includes('drizzle(') && !source.includes('getOrg'));
  }

  private hasAuthInFunction(source: string): boolean {
    return this.authFunctionNames.some(func => source.includes(func));
  }

  private hasValidationInFunction(source: string): boolean {
    return source.includes('validate') ||
           source.includes('schema') ||
           source.includes('zod') ||
           source.includes('joi') ||
           source.includes('yup');
  }

  private calculateImportStrength(importDecl: any): number {
    // Simple heuristic based on number of imported items
    const specifierCount = importDecl.specifiers.length;
    if (specifierCount === 0) return 1;
    if (specifierCount <= 2) return 3;
    if (specifierCount <= 5) return 6;
    return 10;
  }
}

export default SystemAnalyzer;