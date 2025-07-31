import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface RLSPattern {
  id: string;
  type: 'safe' | 'unsafe' | 'bypass';
  pattern: string;
  file: string;
  line: number;
  confidence: number;
  dbClient: string;
  hasOrgContext: boolean;
  hasAuthContext: boolean;
}

export interface TenantIsolationIssue {
  type: 'hardcoded_org' | 'missing_org_filter' | 'cross_tenant_access' | 'rls_bypass';
  severity: VulnerabilitySeverity;
  description: string;
  file: string;
  line: number;
  code: string;
  remediation: string;
}

export interface RLSAnalysisResult {
  safePatterns: RLSPattern[];
  unsafePatterns: RLSPattern[];
  bypassPatterns: RLSPattern[];
  tenantIssues: TenantIsolationIssue[];
  findings: SecurityFinding[];
  recommendations: string[];
}

export class RLSAnalyzer {
  private astParser: ASTParser;
  private safeDatabasePatterns: Set<string> = new Set();
  private unsafeDatabasePatterns: Set<string> = new Set();
  private orgContextPatterns: Set<string> = new Set();

  constructor() {
    this.astParser = new ASTParser();
    this.initializePatterns();
  }

  private initializePatterns(): void {
    // Safe database access patterns (RLS-enabled)
    this.safeDatabasePatterns.add('getSupabaseRLS');
    this.safeDatabasePatterns.add('getOrgDatabaseWithAuth');
    this.safeDatabasePatterns.add('getAuthenticatedDatabase');
    this.safeDatabasePatterns.add('createAuthenticatedClient');
    this.safeDatabasePatterns.add('supabase.from');

    // Unsafe database access patterns (bypass RLS)
    this.unsafeDatabasePatterns.add('drizzle');
    this.unsafeDatabasePatterns.add('createClient');
    this.unsafeDatabasePatterns.add('new Pool');
    this.unsafeDatabasePatterns.add('new Client');
    this.unsafeDatabasePatterns.add('pg.connect');
    this.unsafeDatabasePatterns.add('mysql.createConnection');

    // Organization context patterns
    this.orgContextPatterns.add('orgSlug');
    this.orgContextPatterns.add('organizationId');
    this.orgContextPatterns.add('tenantId');
    this.orgContextPatterns.add('orgId');
  }

  public async analyzeFile(filePath: string): Promise<RLSAnalysisResult> {
    try {
      logger.info(`Analyzing RLS patterns in: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return this.createEmptyResult();
      }

      const result: RLSAnalysisResult = {
        safePatterns: [],
        unsafePatterns: [],
        bypassPatterns: [],
        tenantIssues: [],
        findings: [],
        recommendations: []
      };

      await this.analyzeDatabaseAccess(content, filePath, result);
      await this.analyzeTenantIsolation(content, filePath, result);
      await this.analyzeQueryPatterns(content, filePath, result);
      
      // Generate recommendations
      result.recommendations = this.generateRecommendations(result);

      return result;
    } catch (error) {
      logger.error(`Error analyzing RLS patterns in ${filePath}:`, error);
      return this.createEmptyResult();
    }
  }

  public async analyzeDirectory(dirPath: string): Promise<RLSAnalysisResult> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const aggregatedResult: RLSAnalysisResult = {
      safePatterns: [],
      unsafePatterns: [],
      bypassPatterns: [],
      tenantIssues: [],
      findings: [],
      recommendations: []
    };
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
            continue;
          }
          const subResult = await this.analyzeDirectory(fullPath);
          this.mergeResults(aggregatedResult, subResult);
        } else if (entry.isFile() && this.isAnalyzableFile(entry.name)) {
          const fileResult = await this.analyzeFile(fullPath);
          this.mergeResults(aggregatedResult, fileResult);
        }
      }
    } catch (error) {
      logger.error(`Error analyzing directory ${dirPath}:`, error);
    }
    
    // Generate aggregated recommendations
    aggregatedResult.recommendations = this.generateRecommendations(aggregatedResult);
    
    return aggregatedResult;
  }

  private async analyzeDatabaseAccess(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    result: RLSAnalysisResult
  ): Promise<void> {
    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        this.analyzeCallExpression(node, content.sourceCode, filePath, result);
      }

      if (node.type === AST_NODE_TYPES.NewExpression) {
        this.analyzeNewExpression(node, content.sourceCode, filePath, result);
      }

      if (node.type === AST_NODE_TYPES.VariableDeclarator) {
        this.analyzeVariableDeclarator(node, content.sourceCode, filePath, result);
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
  }

  private analyzeCallExpression(
    node: TSESTree.CallExpression,
    sourceCode: string,
    filePath: string,
    result: RLSAnalysisResult
  ): void {
    const code = this.getNodeCode(node, sourceCode);
    
    if (node.callee.type === AST_NODE_TYPES.Identifier) {
      const functionName = node.callee.name;
      
      // Check for safe database patterns
      if (this.safeDatabasePatterns.has(functionName)) {
        const pattern: RLSPattern = {
          id: `safe-${functionName}-${node.loc?.start.line}`,
          type: 'safe',
          pattern: code,
          file: filePath,
          line: node.loc?.start.line || 0,
          confidence: 0.9,
          dbClient: functionName,
          hasOrgContext: this.hasOrganizationContext(node, sourceCode),
          hasAuthContext: this.hasAuthenticationContext(node, sourceCode)
        };
        result.safePatterns.push(pattern);
      }
      
      // Check for unsafe database patterns
      if (this.unsafeDatabasePatterns.has(functionName)) {
        const pattern: RLSPattern = {
          id: `unsafe-${functionName}-${node.loc?.start.line}`,
          type: 'unsafe',
          pattern: code,
          file: filePath,
          line: node.loc?.start.line || 0,
          confidence: 0.9,
          dbClient: functionName,
          hasOrgContext: this.hasOrganizationContext(node, sourceCode),
          hasAuthContext: this.hasAuthenticationContext(node, sourceCode)
        };
        result.unsafePatterns.push(pattern);

        // Create security finding
        const finding = vulnerabilityDatabase.createFinding(
          'rls-bypass-direct-client',
          filePath,
          node.loc?.start.line || 0,
          node.loc?.end.line || 0,
          node.loc?.start.column || 0,
          node.loc?.end.column || 0,
          code
        );
        if (finding) result.findings.push(finding);
      }
    }

    // Check for member expressions like db.query()
    if (node.callee.type === AST_NODE_TYPES.MemberExpression) {
      this.analyzeMemberExpression(node, sourceCode, filePath, result);
    }
  }

  private analyzeNewExpression(
    node: TSESTree.NewExpression,
    sourceCode: string,
    filePath: string,
    result: RLSAnalysisResult
  ): void {
    const code = this.getNodeCode(node, sourceCode);
    
    if (node.callee.type === AST_NODE_TYPES.Identifier) {
      const constructorName = node.callee.name;
      
      // Check for direct database client creation
      const dangerousConstructors = ['Pool', 'Client', 'Database'];
      if (dangerousConstructors.includes(constructorName)) {
        const pattern: RLSPattern = {
          id: `bypass-${constructorName}-${node.loc?.start.line}`,
          type: 'bypass',
          pattern: code,
          file: filePath,
          line: node.loc?.start.line || 0,
          confidence: 0.8,
          dbClient: constructorName,
          hasOrgContext: false,
          hasAuthContext: false
        };
        result.bypassPatterns.push(pattern);

        // Create security finding
        const finding = vulnerabilityDatabase.createFinding(
          'rls-bypass-direct-client',
          filePath,
          node.loc?.start.line || 0,
          node.loc?.end.line || 0,
          node.loc?.start.column || 0,
          node.loc?.end.column || 0,
          code
        );
        if (finding) result.findings.push(finding);
      }
    }
  }

  private analyzeVariableDeclarator(
    node: TSESTree.VariableDeclarator,
    sourceCode: string,
    filePath: string,
    result: RLSAnalysisResult
  ): void {
    if (node.id.type === AST_NODE_TYPES.Identifier && node.init) {
      const varName = node.id.name;
      const initCode = this.getNodeCode(node.init, sourceCode);

      // Check for hardcoded organization IDs
      if (this.isOrganizationVariable(varName) && this.isHardcodedValue(node.init)) {
        const issue: TenantIsolationIssue = {
          type: 'hardcoded_org',
          severity: VulnerabilitySeverity.MEDIUM,
          description: 'Hardcoded organization ID breaks multi-tenancy',
          file: filePath,
          line: node.loc?.start.line || 0,
          code: initCode,
          remediation: 'Use dynamic organization ID from authentication context'
        };
        result.tenantIssues.push(issue);

        // Create security finding
        const finding = vulnerabilityDatabase.createFinding(
          'hardcoded-org-id',
          filePath,
          node.loc?.start.line || 0,
          node.loc?.end.line || 0,
          node.loc?.start.column || 0,
          node.loc?.end.column || 0,
          initCode
        );
        if (finding) result.findings.push(finding);
      }
    }
  }

  private analyzeMemberExpression(
    node: TSESTree.CallExpression,
    sourceCode: string,
    filePath: string,
    result: RLSAnalysisResult
  ): void {
    const callee = node.callee as TSESTree.MemberExpression;
    const code = this.getNodeCode(node, sourceCode);
    
    if (callee.property.type === AST_NODE_TYPES.Identifier) {
      const methodName = callee.property.name;
      
      // Check for raw query methods that might bypass RLS
      const dangerousMethods = ['query', 'execute', 'raw'];
      if (dangerousMethods.includes(methodName)) {
        // Check if the object is a raw database client
        const objectCode = this.getNodeCode(callee.object, sourceCode);
        if (this.isRawDatabaseClient(objectCode)) {
          const pattern: RLSPattern = {
            id: `bypass-${methodName}-${node.loc?.start.line}`,
            type: 'bypass',
            pattern: code,
            file: filePath,
            line: node.loc?.start.line || 0,
            confidence: 0.7,
            dbClient: objectCode,
            hasOrgContext: this.hasOrganizationContext(node, sourceCode),
            hasAuthContext: this.hasAuthenticationContext(node, sourceCode)
          };
          result.bypassPatterns.push(pattern);

          // Only create finding if there's no org context
          if (!pattern.hasOrgContext) {
            const finding = vulnerabilityDatabase.createFinding(
              'rls-bypass-direct-client',
              filePath,
              node.loc?.start.line || 0,
              node.loc?.end.line || 0,
              node.loc?.start.column || 0,
              node.loc?.end.column || 0,
              code,
              0.8
            );
            if (finding) result.findings.push(finding);
          }
        }
      }
    }
  }

  private async analyzeTenantIsolation(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    result: RLSAnalysisResult
  ): Promise<void> {
    const lines = content.sourceCode.split('\n');
    
    lines.forEach((line, index) => {
      // Check for hardcoded organization patterns
      const hardcodedOrgPatterns = [
        /org(?:Id|Slug)\s*[=:]\s*['"][^'"]+['"]/i,
        /organization\s*[=:]\s*['"][^'"]+['"]/i,
        /tenant\s*[=:]\s*['"][^'"]+['"]/i
      ];

      hardcodedOrgPatterns.forEach(pattern => {
        const match = line.match(pattern);
        if (match && !this.isTestOrExample(line)) {
          const issue: TenantIsolationIssue = {
            type: 'hardcoded_org',
            severity: VulnerabilitySeverity.MEDIUM,
            description: 'Hardcoded organization identifier detected',
            file: filePath,
            line: index + 1,
            code: line.trim(),
            remediation: 'Use dynamic organization context from auth'
          };
          result.tenantIssues.push(issue);
        }
      });

      // Check for potential cross-tenant access
      if (this.hasCrossTenantRisk(line)) {
        const issue: TenantIsolationIssue = {
          type: 'cross_tenant_access',
          severity: VulnerabilitySeverity.HIGH,
          description: 'Potential cross-tenant data access detected',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Ensure proper tenant isolation in query'
        };
        result.tenantIssues.push(issue);
      }
    });
  }

  private async analyzeQueryPatterns(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    result: RLSAnalysisResult
  ): Promise<void> {
    const traverse = (node: TSESTree.Node) => {
      // Look for SQL-like queries
      if (node.type === AST_NODE_TYPES.TemplateLiteral) {
        this.analyzeTemplateLiteral(node, content.sourceCode, filePath, result);
      }

      // Look for query builder patterns
      if (node.type === AST_NODE_TYPES.CallExpression) {
        this.analyzeQueryBuilderCall(node, content.sourceCode, filePath, result);
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
  }

  private analyzeTemplateLiteral(
    node: TSESTree.TemplateLiteral,
    sourceCode: string,
    filePath: string,
    result: RLSAnalysisResult
  ): void {
    const code = this.getNodeCode(node, sourceCode);
    
    // Check if this looks like SQL
    if (this.looksLikeSQL(code)) {
      // Check if it has proper WHERE clause with org filtering
      if (!this.hasOrganizationFilter(code)) {
        const issue: TenantIsolationIssue = {
          type: 'missing_org_filter',
          severity: VulnerabilitySeverity.HIGH,
          description: 'SQL query missing organization filter',
          file: filePath,
          line: node.loc?.start.line || 0,
          code: code.slice(0, 100) + (code.length > 100 ? '...' : ''),
          remediation: 'Add WHERE clause filtering by organization'
        };
        result.tenantIssues.push(issue);
      }
    }
  }

  private analyzeQueryBuilderCall(
    node: TSESTree.CallExpression,
    sourceCode: string,
    filePath: string,
    result: RLSAnalysisResult
  ): void {
    if (node.callee.type === AST_NODE_TYPES.MemberExpression) {
      const callee = node.callee;
      if (callee.property.type === AST_NODE_TYPES.Identifier) {
        const methodName = callee.property.name;
        
        // Check for query methods without proper filtering
        const queryMethods = ['select', 'find', 'findMany', 'findFirst'];
        if (queryMethods.includes(methodName)) {
          const code = this.getNodeCode(node, sourceCode);
          
          // Check if this query has organization context
          if (!this.hasOrganizationContext(node, sourceCode) && !this.isFromSafeClient(callee.object, sourceCode)) {
            const issue: TenantIsolationIssue = {
              type: 'missing_org_filter',
              severity: VulnerabilitySeverity.MEDIUM,
              description: 'Query without organization context',
              file: filePath,
              line: node.loc?.start.line || 0,
              code,
              remediation: 'Add organization filter or use authenticated client'
            };
            result.tenantIssues.push(issue);
          }
        }
      }
    }
  }

  // Helper methods
  private createEmptyResult(): RLSAnalysisResult {
    return {
      safePatterns: [],
      unsafePatterns: [],
      bypassPatterns: [],
      tenantIssues: [],
      findings: [],
      recommendations: []
    };
  }

  private mergeResults(target: RLSAnalysisResult, source: RLSAnalysisResult): void {
    target.safePatterns.push(...source.safePatterns);
    target.unsafePatterns.push(...source.unsafePatterns);
    target.bypassPatterns.push(...source.bypassPatterns);
    target.tenantIssues.push(...source.tenantIssues);
    target.findings.push(...source.findings);
  }

  private isAnalyzableFile(fileName: string): boolean {
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    return extensions.some(ext => fileName.endsWith(ext));
  }

  private getNodeCode(node: TSESTree.Node, sourceCode: string): string {
    if (!node.range) return '';
    return sourceCode.slice(node.range[0], node.range[1]);
  }

  private hasOrganizationContext(node: TSESTree.Node, sourceCode: string): boolean {
    // Look for organization context in the surrounding code
    const contextRange = this.getContextRange(node, sourceCode);
    return Array.from(this.orgContextPatterns).some(pattern => 
      contextRange.toLowerCase().includes(pattern.toLowerCase())
    );
  }

  private hasAuthenticationContext(node: TSESTree.Node, sourceCode: string): boolean {
    const contextRange = this.getContextRange(node, sourceCode);
    const authPatterns = ['requireAuth', 'verifyAuth', 'checkAuth', 'user', 'session'];
    return authPatterns.some(pattern => 
      contextRange.toLowerCase().includes(pattern.toLowerCase())
    );
  }

  private getContextRange(node: TSESTree.Node, sourceCode: string): string {
    // Get a larger context around the node (±200 characters)
    const start = Math.max(0, (node.range?.[0] || 0) - 200);
    const end = Math.min(sourceCode.length, (node.range?.[1] || 0) + 200);
    return sourceCode.slice(start, end);
  }

  private isOrganizationVariable(varName: string): boolean {
    const orgVariables = ['orgId', 'orgSlug', 'organizationId', 'tenantId', 'organization'];
    return orgVariables.includes(varName);
  }

  private isHardcodedValue(node: TSESTree.Expression): boolean {
    return node.type === AST_NODE_TYPES.Literal && typeof node.value === 'string';
  }

  private isRawDatabaseClient(objectCode: string): boolean {
    const rawClients = ['db', 'client', 'pool', 'connection'];
    return rawClients.some(client => objectCode.toLowerCase().includes(client));
  }

  private isTestOrExample(line: string): boolean {
    const testPatterns = ['test', 'example', 'placeholder', 'demo', 'mock'];
    return testPatterns.some(pattern => line.toLowerCase().includes(pattern));
  }

  private hasCrossTenantRisk(line: string): boolean {
    // Look for patterns that might indicate cross-tenant access
    const riskPatterns = [
      /SELECT.*FROM.*WHERE.*!=.*org/i,
      /organization.*!=.*current/i,
      /ALL.*organization/i
    ];
    return riskPatterns.some(pattern => pattern.test(line));
  }

  private looksLikeSQL(code: string): boolean {
    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE'];
    const upperCode = code.toUpperCase();
    return sqlKeywords.some(keyword => upperCode.includes(keyword));
  }

  private hasOrganizationFilter(code: string): boolean {
    const orgFilterPatterns = [
      /WHERE.*org/i,
      /organization_id/i,
      /tenant_id/i,
      /org_slug/i
    ];
    return orgFilterPatterns.some(pattern => pattern.test(code));
  }

  private isFromSafeClient(objectNode: TSESTree.Expression, sourceCode: string): boolean {
    const objectCode = this.getNodeCode(objectNode, sourceCode);
    return Array.from(this.safeDatabasePatterns).some(pattern => 
      objectCode.includes(pattern)
    );
  }

  private generateRecommendations(result: RLSAnalysisResult): string[] {
    const recommendations: string[] = [];

    if (result.unsafePatterns.length > 0) {
      recommendations.push('Replace direct database clients with RLS-enabled alternatives like getOrgDatabaseWithAuth()');
    }

    if (result.bypassPatterns.length > 0) {
      recommendations.push('Review and refactor code that bypasses Row Level Security');
    }

    const hardcodedOrgIssues = result.tenantIssues.filter(i => i.type === 'hardcoded_org');
    if (hardcodedOrgIssues.length > 0) {
      recommendations.push('Remove hardcoded organization IDs and use dynamic values from auth context');
    }

    const missingOrgFilters = result.tenantIssues.filter(i => i.type === 'missing_org_filter');
    if (missingOrgFilters.length > 0) {
      recommendations.push('Add organization filtering to all database queries to ensure tenant isolation');
    }

    if (result.safePatterns.length === 0 && result.unsafePatterns.length > 0) {
      recommendations.push('Establish consistent patterns for authenticated database access across the application');
    }

    return recommendations;
  }
}