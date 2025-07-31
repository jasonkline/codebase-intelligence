import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface AuthPattern {
  id: string;
  name: string;
  type: 'function_call' | 'middleware' | 'decorator' | 'conditional';
  pattern: string;
  confidence: number;
  file: string;
  line: number;
  isRequired: boolean;
}

export interface AuthFlow {
  entryPoints: AuthPattern[];
  authChecks: AuthPattern[];
  roleChecks: AuthPattern[];
  permissionChecks: AuthPattern[];
  gaps: SecurityFinding[];
}

export interface RBACMapping {
  roles: string[];
  permissions: string[];
  rolePermissionMap: Map<string, string[]>;
  implementationPatterns: AuthPattern[];
  issues: SecurityFinding[];
}

export class AuthPatternAnalyzer {
  private astParser: ASTParser;
  private knownAuthPatterns: Map<string, AuthPattern> = new Map();
  private knownRoles: Set<string> = new Set();
  private knownPermissions: Set<string> = new Set();

  constructor() {
    this.astParser = new ASTParser();
    this.initializeKnownPatterns();
  }

  private initializeKnownPatterns(): void {
    // Common authentication patterns
    const commonAuthPatterns = [
      'requireAuthWithTenant',
      'requireAuth',
      'verifyAuth',
      'checkAuth',
      'authenticate',
      'validateSession',
      'verifyToken',
      'checkJWT',
      'validateUser'
    ];

    commonAuthPatterns.forEach(pattern => {
      this.knownAuthPatterns.set(pattern, {
        id: `auth-${pattern}`,
        name: pattern,
        type: 'function_call',
        pattern,
        confidence: 0.9,
        file: '',
        line: 0,
        isRequired: true
      });
    });

    // Common role patterns
    const commonRoles = ['admin', 'user', 'member', 'approver', 'owner', 'viewer', 'editor'];
    commonRoles.forEach(role => this.knownRoles.add(role));

    // Common permission patterns
    const commonPermissions = [
      'read', 'write', 'delete', 'create',
      'read:users', 'write:users', 'delete:users',
      'read:projects', 'write:projects', 'delete:projects',
      'approve:timecards', 'manage:organization'
    ];
    commonPermissions.forEach(perm => this.knownPermissions.add(perm));
  }

  public async analyzeFile(filePath: string): Promise<AuthFlow> {
    try {
      logger.info(`Analyzing authentication patterns in: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return this.createEmptyAuthFlow();
      }

      const authFlow: AuthFlow = {
        entryPoints: [],
        authChecks: [],
        roleChecks: [],
        permissionChecks: [],
        gaps: []
      };

      await this.extractAuthPatterns(content, filePath, authFlow);
      await this.identifyAuthGaps(content, filePath, authFlow);

      return authFlow;
    } catch (error) {
      logger.error(`Error analyzing auth patterns in ${filePath}:`, error);
      return this.createEmptyAuthFlow();
    }
  }

  public async analyzeDirectory(dirPath: string): Promise<AuthFlow> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const aggregatedFlow: AuthFlow = {
      entryPoints: [],
      authChecks: [],
      roleChecks: [],
      permissionChecks: [],
      gaps: []
    };
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
            continue;
          }
          const subFlow = await this.analyzeDirectory(fullPath);
          this.mergeAuthFlows(aggregatedFlow, subFlow);
        } else if (entry.isFile() && this.isAnalyzableFile(entry.name)) {
          const fileFlow = await this.analyzeFile(fullPath);
          this.mergeAuthFlows(aggregatedFlow, fileFlow);
        }
      }
    } catch (error) {
      logger.error(`Error analyzing directory ${dirPath}:`, error);
    }
    
    return aggregatedFlow;
  }

  public async mapRBACImplementation(dirPath: string): Promise<RBACMapping> {
    const authFlow = await this.analyzeDirectory(dirPath);
    
    const rbacMapping: RBACMapping = {
      roles: Array.from(this.knownRoles),
      permissions: Array.from(this.knownPermissions),
      rolePermissionMap: new Map(),
      implementationPatterns: [],
      issues: []
    };

    // Extract role-permission mappings from auth patterns
    authFlow.roleChecks.forEach(pattern => {
      this.extractRoleFromPattern(pattern, rbacMapping);
    });

    authFlow.permissionChecks.forEach(pattern => {
      this.extractPermissionFromPattern(pattern, rbacMapping);
    });

    // Identify RBAC implementation issues
    rbacMapping.issues = await this.identifyRBACIssues(authFlow);

    return rbacMapping;
  }

  private async extractAuthPatterns(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    authFlow: AuthFlow
  ): Promise<void> {
    const traverse = (node: TSESTree.Node) => {
      // Look for function calls that match auth patterns
      if (node.type === AST_NODE_TYPES.CallExpression) {
        this.analyzeCallExpression(node, content.sourceCode, filePath, authFlow);
      }

      // Look for middleware patterns
      if (node.type === AST_NODE_TYPES.FunctionDeclaration || 
          node.type === AST_NODE_TYPES.ArrowFunctionExpression) {
        this.analyzeFunction(node, content.sourceCode, filePath, authFlow);
      }

      // Look for conditional auth checks
      if (node.type === AST_NODE_TYPES.IfStatement) {
        this.analyzeConditional(node, content.sourceCode, filePath, authFlow);
      }

      // Look for variable assignments that might contain roles/permissions
      if (node.type === AST_NODE_TYPES.VariableDeclarator) {
        this.analyzeVariableDeclarator(node, content.sourceCode, filePath, authFlow);
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
    authFlow: AuthFlow
  ): void {
    const code = this.getNodeCode(node, sourceCode);
    
    if (node.callee.type === AST_NODE_TYPES.Identifier) {
      const functionName = node.callee.name;
      
      // Check for auth function calls
      if (this.knownAuthPatterns.has(functionName)) {
        const pattern: AuthPattern = {
          id: `auth-${functionName}-${node.loc?.start.line}`,
          name: functionName,
          type: 'function_call',
          pattern: code,
          confidence: 0.9,
          file: filePath,
          line: node.loc?.start.line || 0,
          isRequired: true
        };
        authFlow.authChecks.push(pattern);
      }

      // Check for role/permission functions
      if (this.isRoleCheckFunction(functionName)) {
        const pattern: AuthPattern = {
          id: `role-${functionName}-${node.loc?.start.line}`,
          name: functionName,
          type: 'function_call',
          pattern: code,
          confidence: 0.8,
          file: filePath,
          line: node.loc?.start.line || 0,
          isRequired: false
        };
        authFlow.roleChecks.push(pattern);
        
        // Extract role from arguments
        this.extractRoleFromArguments(node, sourceCode);
      }

      if (this.isPermissionCheckFunction(functionName)) {
        const pattern: AuthPattern = {
          id: `perm-${functionName}-${node.loc?.start.line}`,
          name: functionName,
          type: 'function_call',
          pattern: code,
          confidence: 0.8,
          file: filePath,
          line: node.loc?.start.line || 0,
          isRequired: false
        };
        authFlow.permissionChecks.push(pattern);
        
        // Extract permission from arguments
        this.extractPermissionFromArguments(node, sourceCode);
      }
    }

    // Check for member expressions (e.g., user.hasRole())
    if (node.callee.type === AST_NODE_TYPES.MemberExpression) {
      this.analyzeMemberExpression(node, sourceCode, filePath, authFlow);
    }
  }

  private analyzeFunction(
    node: TSESTree.FunctionDeclaration | TSESTree.ArrowFunctionExpression,
    sourceCode: string,
    filePath: string,
    authFlow: AuthFlow
  ): void {
    const functionName = node.type === AST_NODE_TYPES.FunctionDeclaration ? 
      node.id?.name : 'anonymous';

    // Check if this is an API route handler
    if (this.isAPIRouteHandler(functionName, filePath)) {
      const pattern: AuthPattern = {
        id: `entry-${functionName}-${node.loc?.start.line}`,
        name: functionName || 'anonymous',
        type: 'function_call',
        pattern: this.getNodeCode(node, sourceCode),
        confidence: 0.7,
        file: filePath,
        line: node.loc?.start.line || 0,
        isRequired: true
      };
      authFlow.entryPoints.push(pattern);
    }
  }

  private analyzeConditional(
    node: TSESTree.IfStatement,
    sourceCode: string,
    filePath: string,
    authFlow: AuthFlow
  ): void {
    const testCode = this.getNodeCode(node.test, sourceCode);
    
    // Look for auth-related conditionals
    if (this.containsAuthCheck(testCode)) {
      const pattern: AuthPattern = {
        id: `cond-auth-${node.loc?.start.line}`,
        name: 'conditional-auth',
        type: 'conditional',
        pattern: testCode,
        confidence: 0.6,
        file: filePath,
        line: node.loc?.start.line || 0,
        isRequired: false
      };
      authFlow.authChecks.push(pattern);
    }

    // Look for role-based conditionals
    if (this.containsRoleCheck(testCode)) {
      const pattern: AuthPattern = {
        id: `cond-role-${node.loc?.start.line}`,
        name: 'conditional-role',
        type: 'conditional',
        pattern: testCode,
        confidence: 0.6,
        file: filePath,
        line: node.loc?.start.line || 0,
        isRequired: false
      };
      authFlow.roleChecks.push(pattern);
    }
  }

  private analyzeVariableDeclarator(
    node: TSESTree.VariableDeclarator,
    sourceCode: string,
    filePath: string,
    authFlow: AuthFlow
  ): void {
    if (node.id.type === AST_NODE_TYPES.Identifier && node.init) {
      const varName = node.id.name;
      const initCode = this.getNodeCode(node.init, sourceCode);

      // Look for role assignments
      if (this.isRoleVariable(varName) || this.containsRoleValue(initCode)) {
        this.extractRoleFromValue(initCode);
      }

      // Look for permission assignments
      if (this.isPermissionVariable(varName) || this.containsPermissionValue(initCode)) {
        this.extractPermissionFromValue(initCode);
      }
    }
  }

  private analyzeMemberExpression(
    node: TSESTree.CallExpression,
    sourceCode: string,
    filePath: string,
    authFlow: AuthFlow
  ): void {
    const callee = node.callee as TSESTree.MemberExpression;
    if (callee.property.type === AST_NODE_TYPES.Identifier) {
      const methodName = callee.property.name;
      const code = this.getNodeCode(node, sourceCode);

      if (this.isRoleCheckMethod(methodName)) {
        const pattern: AuthPattern = {
          id: `method-role-${node.loc?.start.line}`,
          name: methodName,
          type: 'function_call',
          pattern: code,
          confidence: 0.8,
          file: filePath,
          line: node.loc?.start.line || 0,
          isRequired: false
        };
        authFlow.roleChecks.push(pattern);
      }

      if (this.isPermissionCheckMethod(methodName)) {
        const pattern: AuthPattern = {
          id: `method-perm-${node.loc?.start.line}`,
          name: methodName,
          type: 'function_call',
          pattern: code,
          confidence: 0.8,
          file: filePath,
          line: node.loc?.start.line || 0,
          isRequired: false
        };
        authFlow.permissionChecks.push(pattern);
      }
    }
  }

  private async identifyAuthGaps(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    authFlow: AuthFlow
  ): Promise<void> {
    // Check if API routes are missing auth
    if (this.isAPIRoute(filePath) && authFlow.entryPoints.length > 0) {
      const hasAuthCheck = authFlow.authChecks.length > 0;
      
      if (!hasAuthCheck) {
        const finding = vulnerabilityDatabase.createFinding(
          'missing-auth-api-route',
          filePath,
          1,
          content.sourceCode.split('\n').length,
          0,
          0,
          'API route missing authentication check'
        );
        if (finding) authFlow.gaps.push(finding);
      }
    }

    // Check for authorization bypass patterns
    this.identifyAuthBypassPatterns(content, filePath, authFlow);
  }

  private identifyAuthBypassPatterns(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    authFlow: AuthFlow
  ): void {
    const bypassPatterns = [
      /\/\*\s*TODO.*auth/i,  // TODO comments about auth
      /\/\/\s*skip.*auth/i,  // Comments about skipping auth
      /return.*early/i,      // Early returns that might bypass auth
      /if.*debug.*return/i   // Debug bypasses
    ];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      bypassPatterns.forEach(pattern => {
        if (pattern.test(line)) {
          const finding = vulnerabilityDatabase.createFinding(
            'auth-bypass-pattern',
            filePath,
            index + 1,
            index + 1,
            0,
            line.length,
            line.trim(),
            0.6
          );
          if (finding) authFlow.gaps.push(finding);
        }
      });
    });
  }

  private async identifyRBACIssues(authFlow: AuthFlow): Promise<SecurityFinding[]> {
    const issues: SecurityFinding[] = [];

    // Check for missing role validation
    if (authFlow.entryPoints.length > 0 && authFlow.roleChecks.length === 0) {
      // This would need more context to create a proper finding
      // For now, we'll skip this check
    }

    // Check for inconsistent permission patterns
    const permissionPatterns = new Set(authFlow.permissionChecks.map(p => p.name));
    if (permissionPatterns.size > 5) {
      // Too many different permission check patterns might indicate inconsistency
      // This would need more sophisticated analysis
    }

    return issues;
  }

  // Helper methods
  private createEmptyAuthFlow(): AuthFlow {
    return {
      entryPoints: [],
      authChecks: [],
      roleChecks: [],
      permissionChecks: [],
      gaps: []
    };
  }

  private mergeAuthFlows(target: AuthFlow, source: AuthFlow): void {
    target.entryPoints.push(...source.entryPoints);
    target.authChecks.push(...source.authChecks);
    target.roleChecks.push(...source.roleChecks);
    target.permissionChecks.push(...source.permissionChecks);
    target.gaps.push(...source.gaps);
  }

  private isAnalyzableFile(fileName: string): boolean {
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    return extensions.some(ext => fileName.endsWith(ext));
  }

  private getNodeCode(node: TSESTree.Node, sourceCode: string): string {
    if (!node.range) return '';
    return sourceCode.slice(node.range[0], node.range[1]);
  }

  private isRoleCheckFunction(functionName: string): boolean {
    const roleCheckFunctions = [
      'hasRole', 'checkRole', 'verifyRole', 'isRole',
      'hasPermission', 'checkPermission', 'canAccess'
    ];
    return roleCheckFunctions.includes(functionName);
  }

  private isPermissionCheckFunction(functionName: string): boolean {
    const permissionFunctions = [
      'hasPermission', 'checkPermission', 'canAccess', 
      'isAuthorized', 'authorize', 'can'
    ];
    return permissionFunctions.includes(functionName);
  }

  private isRoleCheckMethod(methodName: string): boolean {
    const roleCheckMethods = [
      'hasRole', 'isAdmin', 'isMember', 'isOwner',
      'checkRole', 'verifyRole'
    ];
    return roleCheckMethods.includes(methodName);
  }

  private isPermissionCheckMethod(methodName: string): boolean {
    const permissionMethods = [
      'can', 'cannot', 'hasPermission', 'checkPermission',
      'isAuthorized', 'canAccess'
    ];
    return permissionMethods.includes(methodName);
  }

  private isAPIRouteHandler(functionName: string | undefined, filePath: string): boolean {
    if (!functionName) return false;
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    return httpMethods.includes(functionName.toUpperCase()) && this.isAPIRoute(filePath);
  }

  private isAPIRoute(filePath: string): boolean {
    return filePath.includes('/api/') || filePath.includes('/route.ts') || filePath.includes('/route.js');
  }

  private containsAuthCheck(code: string): boolean {
    const authKeywords = ['auth', 'token', 'session', 'user', 'login', 'authenticated'];
    return authKeywords.some(keyword => code.toLowerCase().includes(keyword));
  }

  private containsRoleCheck(code: string): boolean {
    const roleKeywords = ['role', 'admin', 'user', 'member', 'permission'];
    return roleKeywords.some(keyword => code.toLowerCase().includes(keyword));
  }

  private isRoleVariable(varName: string): boolean {
    const roleVariables = ['role', 'userRole', 'currentRole', 'roles'];
    return roleVariables.includes(varName);
  }

  private isPermissionVariable(varName: string): boolean {
    const permVariables = ['permission', 'permissions', 'access', 'privileges'];
    return permVariables.includes(varName);
  }

  private containsRoleValue(code: string): boolean {
    return Array.from(this.knownRoles).some(role => 
      code.toLowerCase().includes(role.toLowerCase())
    );
  }

  private containsPermissionValue(code: string): boolean {
    return Array.from(this.knownPermissions).some(perm => 
      code.toLowerCase().includes(perm.toLowerCase())
    );
  }

  private extractRoleFromArguments(node: TSESTree.CallExpression, sourceCode: string): void {
    node.arguments.forEach(arg => {
      if (arg.type === AST_NODE_TYPES.Literal && typeof arg.value === 'string') {
        this.knownRoles.add(arg.value);
      }
    });
  }

  private extractPermissionFromArguments(node: TSESTree.CallExpression, sourceCode: string): void {
    node.arguments.forEach(arg => {
      if (arg.type === AST_NODE_TYPES.Literal && typeof arg.value === 'string') {
        this.knownPermissions.add(arg.value);
      }
    });
  }

  private extractRoleFromValue(code: string): void {
    const roleMatches = code.match(/['"`]([a-zA-Z_]+)['"`]/g);
    if (roleMatches) {
      roleMatches.forEach(match => {
        const role = match.slice(1, -1);
        this.knownRoles.add(role);
      });
    }
  }

  private extractPermissionFromValue(code: string): void {
    const permMatches = code.match(/['"`]([a-zA-Z_:]+)['"`]/g);
    if (permMatches) {
      permMatches.forEach(match => {
        const perm = match.slice(1, -1);
        this.knownPermissions.add(perm);
      });
    }
  }

  private extractRoleFromPattern(pattern: AuthPattern, rbacMapping: RBACMapping): void {
    // Extract roles mentioned in the pattern
    Array.from(this.knownRoles).forEach(role => {
      if (pattern.pattern.toLowerCase().includes(role.toLowerCase())) {
        if (!rbacMapping.roles.includes(role)) {
          rbacMapping.roles.push(role);
        }
      }
    });
  }

  private extractPermissionFromPattern(pattern: AuthPattern, rbacMapping: RBACMapping): void {
    // Extract permissions mentioned in the pattern
    Array.from(this.knownPermissions).forEach(perm => {
      if (pattern.pattern.toLowerCase().includes(perm.toLowerCase())) {
        if (!rbacMapping.permissions.includes(perm)) {
          rbacMapping.permissions.push(perm);
        }
      }
    });
  }
}