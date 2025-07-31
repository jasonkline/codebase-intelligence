import { TSESTree } from '@typescript-eslint/types';
import { ASTPattern } from '../PatternLearner';
import PatternMatcher, { MatchResult } from '../PatternMatcher';
import logger from '../../utils/logger';

export interface AuthPattern {
  name: string;
  description: string;
  category: 'auth_check' | 'auth_bypass' | 'permission_check' | 'role_validation' | 'token_handling';
  severity: 'info' | 'warning' | 'error' | 'critical';
  examples: string[];
  antiPatterns: string[];
}

export interface AuthPatternMatch {
  pattern: AuthPattern;
  matchResult: MatchResult;
  securityImplications: string[];
  recommendations: string[];
}

export class AuthPatternsAnalyzer {
  private matcher: PatternMatcher;
  private knownPatterns: Map<string, AuthPattern> = new Map();

  constructor() {
    this.matcher = new PatternMatcher({
      minSimilarity: 0.6,
      ignoreVariableNames: true,
      ignoreLiteralValues: true,
      allowPartialMatches: true
    });

    this.initializeKnownPatterns();
  }

  private initializeKnownPatterns(): void {
    // Define common authentication patterns
    const patterns: AuthPattern[] = [
      {
        name: 'requireAuth',
        description: 'Standard authentication requirement pattern',
        category: 'auth_check',
        severity: 'info',
        examples: [
          'const { user } = await requireAuth()',
          'const auth = await requireAuthWithTenant()',
          'if (!user) { throw new Error("Unauthorized") }'
        ],
        antiPatterns: [
          'const user = getUserFromSession() // No validation',
          'if (request.headers.auth) { /* No verification */ }'
        ]
      },
      {
        name: 'directDatabaseAccess',
        description: 'Direct database access without authentication',
        category: 'auth_bypass',
        severity: 'critical',
        examples: [
          'const db = drizzle(connectionString)',
          'const client = new Client(config)',
          'await db.select().from(users)'
        ],
        antiPatterns: [
          'const db = await getOrgDatabaseWithAuth()',
          'const { user } = await requireAuth(); const db = getDB(user.org)'
        ]
      },
      {
        name: 'permissionCheck',
        description: 'Role-based permission checking',
        category: 'permission_check',
        severity: 'warning',
        examples: [
          'if (!hasPermission(user.role, "read:users")) { throw new Error() }',
          'await checkPermission(user, "delete", resource)',
          'const canAccess = await authorize(user, action, resource)'
        ],
        antiPatterns: [
          'if (user.role === "admin") { /* hardcoded role check */ }',
          'if (user.isAdmin) { /* boolean check instead of permission */ }'
        ]
      },
      {
        name: 'tokenValidation',
        description: 'JWT or token validation patterns',
        category: 'token_handling',
        severity: 'error',
        examples: [
          'const decoded = jwt.verify(token, secret)',
          'const user = await validateToken(request.headers.authorization)',
          'if (!token || !isValidToken(token)) { throw new Error() }'
        ],
        antiPatterns: [
          'const user = jwt.decode(token) // No verification',
          'if (token) { /* assumes token is valid */ }'
        ]
      },
      {
        name: 'roleValidation',
        description: 'User role validation patterns',
        category: 'role_validation',
        severity: 'warning',
        examples: [
          'if (!["admin", "moderator"].includes(user.role)) { throw new Error() }',
          'await validateUserRole(user, requiredRoles)',
          'const hasRequiredRole = checkUserRole(user.role, minimumRole)'
        ],
        antiPatterns: [
          'if (user.role) { /* any role accepted */ }',
          'const isAdmin = user.email.includes("admin") // Email-based role check'
        ]
      }
    ];

    for (const pattern of patterns) {
      this.knownPatterns.set(pattern.name, pattern);
    }
  }

  analyzeForAuthPatterns(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): AuthPatternMatch[] {
    const matches: AuthPatternMatch[] = [];

    // Check for authentication patterns
    if (this.isAuthRelatedNode(node)) {
      const authMatches = this.findAuthPatterns(node, sourceCode);
      matches.push(...authMatches);
    }

    // Check for authentication bypasses
    const bypassMatches = this.findAuthBypasses(node, sourceCode, filePath);
    matches.push(...bypassMatches);

    // Check for permission patterns
    const permissionMatches = this.findPermissionPatterns(node, sourceCode);
    matches.push(...permissionMatches);

    return matches;
  }

  private isAuthRelatedNode(node: TSESTree.Node): boolean {
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      const authKeywords = [
        'requireAuth', 'checkAuth', 'validateAuth', 'authenticate',
        'authorize', 'hasPermission', 'checkPermission', 'validateToken',
        'verifyToken', 'requireRole', 'checkRole'
      ];

      return authKeywords.some(keyword => 
        calleeText.toLowerCase().includes(keyword.toLowerCase())
      );
    }

    if (node.type === 'IfStatement') {
      const ifStmt = node as TSESTree.IfStatement;
      const testText = this.getNodeText(ifStmt.test);
      
      const authChecks = ['user', 'auth', 'token', 'role', 'permission'];
      return authChecks.some(check => 
        testText.toLowerCase().includes(check)
      );
    }

    return false;
  }

  private findAuthPatterns(node: TSESTree.Node, sourceCode: string): AuthPatternMatch[] {
    const matches: AuthPatternMatch[] = [];

    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);

      // Check for requireAuth patterns
      if (calleeText.includes('requireAuth')) {
        const pattern = this.knownPatterns.get('requireAuth')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.9,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.9
          },
          securityImplications: [
            'Proper authentication check',
            'User context is established'
          ],
          recommendations: [
            'Ensure error handling for authentication failures',
            'Validate user permissions after authentication'
          ]
        });
      }

      // Check for token validation patterns
      if (calleeText.includes('verify') || calleeText.includes('validate')) {
        const pattern = this.knownPatterns.get('tokenValidation')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.8,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.8
          },
          securityImplications: [
            'Token validation is being performed',
            'Cryptographic verification may be present'
          ],
          recommendations: [
            'Ensure proper error handling for invalid tokens',
            'Use secure token validation libraries'
          ]
        });
      }
    }

    return matches;
  }

  private findAuthBypasses(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): AuthPatternMatch[] {
    const matches: AuthPatternMatch[] = [];

    // Check for direct database access
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);

      // Dangerous patterns that bypass authentication
      const dangerousPatterns = ['drizzle(', 'new Client(', 'createConnection('];
      
      if (dangerousPatterns.some(pattern => calleeText.includes(pattern.slice(0, -1)))) {
        const pattern = this.knownPatterns.get('directDatabaseAccess')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.95,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.95
          },
          securityImplications: [
            'CRITICAL: Direct database access bypasses authentication',
            'Data isolation may be compromised',
            'Row Level Security (RLS) is bypassed'
          ],
          recommendations: [
            'Use getOrgDatabaseWithAuth() instead',
            'Ensure proper authentication before database access',
            'Implement proper tenant isolation'
          ]
        });
      }
    }

    // Check for missing authentication in API routes
    if (this.isAPIRoute(filePath) && !this.hasAuthCheck(node, sourceCode)) {
      matches.push({
        pattern: {
          name: 'missingAuthInAPI',
          description: 'API route without authentication check',
          category: 'auth_bypass',
          severity: 'critical',
          examples: [],
          antiPatterns: []
        },
        matchResult: {
          similarity: 0.9,
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: false,
          confidence: 0.9
        },
        securityImplications: [
          'CRITICAL: API endpoint is publicly accessible',
          'Unauthorized users can access sensitive data'
        ],
        recommendations: [
          'Add requireAuthWithTenant() call',
          'Implement proper authentication middleware',
          'Validate user permissions for the requested action'
        ]
      });
    }

    return matches;
  }

  private findPermissionPatterns(node: TSESTree.Node, sourceCode: string): AuthPatternMatch[] {
    const matches: AuthPatternMatch[] = [];

    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);

      if (calleeText.includes('hasPermission') || calleeText.includes('checkPermission')) {
        const pattern = this.knownPatterns.get('permissionCheck')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.85,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.85
          },
          securityImplications: [
            'Permission-based access control is implemented',
            'Fine-grained authorization is in place'
          ],
          recommendations: [
            'Ensure permissions are validated server-side',
            'Use consistent permission naming conventions',
            'Log permission checks for audit trails'
          ]
        });
      }
    }

    // Check for hardcoded role checks (anti-pattern)
    if (node.type === 'IfStatement' || node.type === 'ConditionalExpression') {
      const testNode = node.type === 'IfStatement' 
        ? (node as TSESTree.IfStatement).test
        : (node as TSESTree.ConditionalExpression).test;

      if (this.hasHardcodedRoleCheck(testNode)) {
        matches.push({
          pattern: {
            name: 'hardcodedRoleCheck',
            description: 'Hardcoded role check instead of permission-based',
            category: 'role_validation',
            severity: 'warning',
            examples: [],
            antiPatterns: ['if (user.role === "admin")', 'user.isAdmin']
          },
          matchResult: {
            similarity: 0.8,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.8
          },
          securityImplications: [
            'Hardcoded role checks are inflexible',
            'May not scale with complex permission requirements'
          ],
          recommendations: [
            'Use permission-based checks instead',
            'Implement hasPermission(user, action, resource)',
            'Consider role hierarchy and inheritance'
          ]
        });
      }
    }

    return matches;
  }

  private getCalleeText(callee: TSESTree.Node): string {
    switch (callee.type) {
      case 'Identifier':
        return (callee as TSESTree.Identifier).name;
      case 'MemberExpression':
        const member = callee as TSESTree.MemberExpression;
        const object = this.getCalleeText(member.object);
        const property = member.computed 
          ? '[computed]' 
          : (member.property as TSESTree.Identifier).name;
        return `${object}.${property}`;
      default:
        return callee.type;
    }
  }

  private getNodeText(node: TSESTree.Node): string {
    // Simplified text extraction - in a real implementation,
    // we'd use the source code to get the exact text
    switch (node.type) {
      case 'Identifier':
        return (node as TSESTree.Identifier).name;
      case 'MemberExpression':
        const member = node as TSESTree.MemberExpression;
        return `${this.getNodeText(member.object)}.${this.getNodeText(member.property)}`;
      case 'BinaryExpression':
        const binary = node as TSESTree.BinaryExpression;
        return `${this.getNodeText(binary.left)} ${binary.operator} ${this.getNodeText(binary.right)}`;
      default:
        return node.type;
    }
  }

  private isAPIRoute(filePath: string): boolean {
    return filePath.includes('/api/') || 
           filePath.includes('/route.ts') || 
           filePath.includes('/route.js') ||
           filePath.includes('api') && (filePath.endsWith('.ts') || filePath.endsWith('.js'));
  }

  private hasAuthCheck(node: TSESTree.Node, sourceCode: string): boolean {
    const authKeywords = [
      'requireAuth', 'checkAuth', 'validateAuth', 'authenticate',
      'requireAuthWithTenant', 'getUser', 'verifyToken'
    ];

    // Check if the source code contains any authentication keywords
    return authKeywords.some(keyword => sourceCode.includes(keyword));
  }

  private hasHardcodedRoleCheck(node: TSESTree.Node): boolean {
    if (node.type === 'BinaryExpression') {
      const binary = node as TSESTree.BinaryExpression;
      
      // Check for patterns like user.role === "admin"
      if (binary.operator === '===' || binary.operator === '==') {
        const left = this.getNodeText(binary.left);
        const right = this.getNodeText(binary.right);
        
        return (left.includes('role') && right.includes('"')) ||
               (right.includes('role') && left.includes('"'));
      }
    }

    if (node.type === 'MemberExpression') {
      const member = node as TSESTree.MemberExpression;
      const text = this.getNodeText(member);
      
      // Check for patterns like user.isAdmin
      return text.includes('isAdmin') || text.includes('isManager');
    }

    return false;
  }

  getKnownPatterns(): Map<string, AuthPattern> {
    return this.knownPatterns;
  }

  addCustomPattern(pattern: AuthPattern): void {
    this.knownPatterns.set(pattern.name, pattern);
    logger.info(`Added custom auth pattern: ${pattern.name}`);
  }

  updatePatternSeverity(patternName: string, severity: AuthPattern['severity']): void {
    const pattern = this.knownPatterns.get(patternName);
    if (pattern) {
      pattern.severity = severity;
      logger.info(`Updated severity for pattern ${patternName} to ${severity}`);
    }
  }

  generateAuthReport(matches: AuthPatternMatch[]): string {
    const report = ['# Authentication Pattern Analysis Report\n'];
    
    const byCategory = new Map<string, AuthPatternMatch[]>();
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
        report.push(`### ${match.pattern.name} (${match.pattern.severity})`);
        report.push(match.pattern.description);
        
        if (match.securityImplications.length > 0) {
          report.push('\n**Security Implications:**');
          match.securityImplications.forEach(impl => report.push(`- ${impl}`));
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

export default AuthPatternsAnalyzer;