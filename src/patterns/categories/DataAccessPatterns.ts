import { TSESTree } from '@typescript-eslint/types';
import { ASTPattern } from '../PatternLearner';
import PatternMatcher, { MatchResult } from '../PatternMatcher';
import logger from '../../utils/logger';

export interface DataAccessPattern {
  name: string;
  description: string;
  category: 'safe_access' | 'rls_compliance' | 'query_pattern' | 'connection_management' | 'data_isolation';
  securityLevel: 'safe' | 'risky' | 'dangerous' | 'critical';
  examples: string[];
  antiPatterns: string[];
  rlsCompliant: boolean;
}

export interface DataAccessMatch {
  pattern: DataAccessPattern;
  matchResult: MatchResult;
  securityRisk: {
    level: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    impact: string[];
  };
  recommendations: string[];
  rlsViolations: string[];
}

export class DataAccessPatternsAnalyzer {
  private matcher: PatternMatcher;
  private knownPatterns: Map<string, DataAccessPattern> = new Map();

  constructor() {
    this.matcher = new PatternMatcher({
      minSimilarity: 0.7,
      ignoreVariableNames: true,
      ignoreLiteralValues: false, // Keep connection strings and table names
      allowPartialMatches: true
    });

    this.initializeKnownPatterns();
  }

  private initializeKnownPatterns(): void {
    const patterns: DataAccessPattern[] = [
      {
        name: 'orgDatabaseWithAuth',
        description: 'Proper authenticated database access with tenant isolation',
        category: 'safe_access',
        securityLevel: 'safe',
        rlsCompliant: true,
        examples: [
          'const db = await getOrgDatabaseWithAuth()',
          'const database = await getSupabaseRLS()',
          'const { database } = await requireAuthWithTenant()'
        ],
        antiPatterns: [
          'const db = drizzle(connectionString)',
          'const client = new Client(config)',
          'const db = createConnection(url)'
        ]
      },
      {
        name: 'directDatabaseConnection',
        description: 'Direct database connection bypassing RLS and authentication',
        category: 'rls_compliance',
        securityLevel: 'critical',
        rlsCompliant: false,
        examples: [
          'drizzle(process.env.DATABASE_URL)',
          'new Client({ connectionString: url })',
          'createConnection({ host, user, password })'
        ],
        antiPatterns: [
          'await getOrgDatabaseWithAuth()',
          'await getSupabaseRLS()'
        ]
      },
      {
        name: 'parameterizedQuery',
        description: 'Safe parameterized queries to prevent SQL injection',
        category: 'query_pattern',
        securityLevel: 'safe',
        rlsCompliant: true,
        examples: [
          'db.select().from(users).where(eq(users.id, userId))',
          'db.query("SELECT * FROM users WHERE id = $1", [userId])',
          'await db.users.findMany({ where: { orgId: user.orgId } })'
        ],
        antiPatterns: [
          'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
          'db.raw("SELECT * FROM users WHERE name = " + userName)',
          'await db.exec("DELETE FROM users WHERE id = " + id)'
        ]
      },
      {
        name: 'hardcodedOrgAccess',
        description: 'Hardcoded organization access breaking multi-tenancy',
        category: 'data_isolation',
        securityLevel: 'dangerous',
        rlsCompliant: false,
        examples: [
          'db.select().from(users).where(eq(users.orgId, "acme-corp"))',
          'WHERE organization_id = "specific-org"',
          'const data = await getOrgData("hardcoded-org")'
        ],
        antiPatterns: [
          'db.select().from(users).where(eq(users.orgId, orgSlug))',
          'WHERE organization_id = $1',
          'const data = await getOrgData(user.orgSlug)'
        ]
      },
      {
        name: 'unsafeRawQuery',
        description: 'Raw SQL queries that may bypass RLS or allow injection',
        category: 'query_pattern',
        securityLevel: 'risky',
        rlsCompliant: false,
        examples: [
          'db.raw("SELECT * FROM sensitive_table")',
          'db.execute("UPDATE users SET role = admin")',
          'await db.query(userProvidedSQL)'
        ],
        antiPatterns: [
          'db.select().from(table).where(condition)',
          'db.update(table).set(values).where(condition)',
          'db.insert(table).values(data)'
        ]
      },
      {
        name: 'properConnectionManagement',
        description: 'Proper database connection lifecycle management',
        category: 'connection_management',
        securityLevel: 'safe',
        rlsCompliant: true,
        examples: [
          'try { const db = await getDB(); ... } finally { await db.close() }',
          'await withDatabase(async (db) => { ... })',
          'const result = await using db = getDatabase(); ...'
        ],
        antiPatterns: [
          'const db = getDatabase(); // Never closed',
          'global.db = createConnection(); // Global connection',
          'const db = new Client(); db.connect(); // Manual management'
        ]
      }
    ];

    for (const pattern of patterns) {
      this.knownPatterns.set(pattern.name, pattern);
    }
  }

  analyzeDataAccess(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): DataAccessMatch[] {
    const matches: DataAccessMatch[] = [];

    // Check for database connection patterns
    if (this.isDatabaseRelatedNode(node)) {
      const connectionMatches = this.analyzeConnectionPatterns(node, sourceCode);
      matches.push(...connectionMatches);
    }

    // Check for query patterns
    if (this.isQueryNode(node)) {
      const queryMatches = this.analyzeQueryPatterns(node, sourceCode);
      matches.push(...queryMatches);
    }

    // Check for RLS compliance
    const rlsMatches = this.analyzeRLSCompliance(node, sourceCode, filePath);
    matches.push(...rlsMatches);

    // Check for data isolation violations
    const isolationMatches = this.analyzeDataIsolation(node, sourceCode);
    matches.push(...isolationMatches);

    return matches;
  }

  private isDatabaseRelatedNode(node: TSESTree.Node): boolean {
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      const dbKeywords = [
        'drizzle', 'createConnection', 'connect', 'getDatabase',
        'getOrgDatabase', 'getSupabaseRLS', 'Client', 'Pool',
        'createClient', 'createPool'
      ];

      return dbKeywords.some(keyword => 
        calleeText.toLowerCase().includes(keyword.toLowerCase())
      );
    }

    if (node.type === 'NewExpression') {
      const newExpr = node as TSESTree.NewExpression;
      const calleeText = this.getCalleeText(newExpr.callee);
      
      return ['Client', 'Pool', 'Connection'].some(keyword =>
        calleeText.includes(keyword)
      );
    }

    return false;
  }

  private isQueryNode(node: TSESTree.Node): boolean {
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      const queryKeywords = [
        'select', 'insert', 'update', 'delete', 'query', 'exec',
        'raw', 'execute', 'find', 'findMany', 'findFirst',
        'create', 'upsert', 'count', 'aggregate'
      ];

      return queryKeywords.some(keyword => 
        calleeText.toLowerCase().includes(keyword.toLowerCase())
      );
    }

    return false;
  }

  private analyzeConnectionPatterns(node: TSESTree.Node, sourceCode: string): DataAccessMatch[] {
    const matches: DataAccessMatch[] = [];

    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);

      // Check for dangerous direct connections
      if (calleeText.includes('drizzle') && call.arguments.length > 0) {
        const pattern = this.knownPatterns.get('directDatabaseConnection')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.95,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.95
          },
          securityRisk: {
            level: 'critical',
            description: 'Direct database connection bypasses RLS and authentication',
            impact: [
              'Complete bypass of Row Level Security',
              'Access to all tenant data',
              'No authentication or authorization checks',
              'Potential for data leakage between organizations'
            ]
          },
          recommendations: [
            'Use getOrgDatabaseWithAuth() instead',
            'Implement proper tenant isolation',
            'Ensure authentication before database access'
          ],
          rlsViolations: [
            'Bypasses Row Level Security completely',
            'No tenant context in database connection'
          ]
        });
      }

      // Check for safe authenticated access
      if (calleeText.includes('getOrgDatabaseWithAuth') || 
          calleeText.includes('getSupabaseRLS')) {
        const pattern = this.knownPatterns.get('orgDatabaseWithAuth')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.9,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.9
          },
          securityRisk: {
            level: 'low',
            description: 'Proper authenticated database access with tenant isolation',
            impact: [
              'Maintains data isolation between tenants',
              'Enforces authentication requirements',
              'Complies with RLS policies'
            ]
          },
          recommendations: [
            'Continue using this secure pattern',
            'Ensure error handling for connection failures'
          ],
          rlsViolations: []
        });
      }
    }

    if (node.type === 'NewExpression') {
      const newExpr = node as TSESTree.NewExpression;
      const calleeText = this.getCalleeText(newExpr.callee);

      if (calleeText.includes('Client') || calleeText.includes('Pool')) {
        const pattern = this.knownPatterns.get('directDatabaseConnection')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.9,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.9
          },
          securityRisk: {
            level: 'critical',
            description: 'Direct database client creation bypasses security layers',
            impact: [
              'No authentication verification',
              'Bypasses tenant isolation',
              'Direct access to database without RLS'
            ]
          },
          recommendations: [
            'Use getOrgDatabaseWithAuth() wrapper',
            'Implement proper connection management',
            'Add authentication and authorization checks'
          ],
          rlsViolations: [
            'Creates direct database connection',
            'No RLS context established'
          ]
        });
      }
    }

    return matches;
  }

  private analyzeQueryPatterns(node: TSESTree.Node, sourceCode: string): DataAccessMatch[] {
    const matches: DataAccessMatch[] = [];

    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);

      // Check for raw queries
      if (calleeText.includes('raw') || calleeText.includes('execute')) {
        const pattern = this.knownPatterns.get('unsafeRawQuery')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.85,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.85
          },
          securityRisk: {
            level: 'high',
            description: 'Raw SQL queries may bypass RLS and allow injection',
            impact: [
              'Potential SQL injection vulnerability',
              'May bypass Row Level Security',
              'Direct database manipulation'
            ]
          },
          recommendations: [
            'Use ORM query builders instead',
            'If raw SQL is necessary, ensure proper parameterization',
            'Validate that RLS policies are enforced'
          ],
          rlsViolations: [
            'Raw queries may bypass RLS policies',
            'No automatic tenant filtering'
          ]
        });
      }

      // Check for parameterized queries (good pattern)
      if (this.isParameterizedQuery(call, sourceCode)) {
        const pattern = this.knownPatterns.get('parameterizedQuery')!;
        matches.push({
          pattern,
          matchResult: {
            similarity: 0.8,
            differences: [],
            matchedPattern: {} as ASTPattern,
            isPartialMatch: false,
            confidence: 0.8
          },
          securityRisk: {
            level: 'low',
            description: 'Safe parameterized query prevents SQL injection',
            impact: [
              'Prevents SQL injection attacks',
              'Uses proper query parameterization'
            ]
          },
          recommendations: [
            'Continue using parameterized queries',
            'Ensure RLS policies are in place'
          ],
          rlsViolations: []
        });
      }

      // Check for string interpolation in queries (dangerous)
      if (this.hasStringInterpolation(call, sourceCode)) {
        matches.push({
          pattern: {
            name: 'sqlInjectionRisk',
            description: 'Query uses string interpolation - SQL injection risk',
            category: 'query_pattern',
            securityLevel: 'dangerous',
            rlsCompliant: false,
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
          securityRisk: {
            level: 'high',
            description: 'String interpolation in queries creates SQL injection risk',
            impact: [
              'SQL injection vulnerability',
              'Potential data breach',
              'Unauthorized data access'
            ]
          },
          recommendations: [
            'Use parameterized queries immediately',
            'Never use string interpolation in SQL',
            'Use ORM query builders'
          ],
          rlsViolations: [
            'May bypass input validation',
            'Could circumvent RLS policies'
          ]
        });
      }
    }

    return matches;
  }

  private analyzeRLSCompliance(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): DataAccessMatch[] {
    const matches: DataAccessMatch[] = [];

    // Check if this is an API route that should have RLS
    if (this.isAPIRoute(filePath)) {
      // Look for database access without proper RLS setup
      if (this.hasDatabaseAccess(node, sourceCode) && 
          !this.hasProperRLSSetup(sourceCode)) {
        matches.push({
          pattern: {
            name: 'missingRLSInAPI',
            description: 'API route with database access missing RLS setup',
            category: 'rls_compliance',
            securityLevel: 'critical',
            rlsCompliant: false,
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
          securityRisk: {
            level: 'critical',
            description: 'Database access in API without proper RLS enforcement',
            impact: [
              'Data from all tenants accessible',
              'No automatic data isolation',
              'Potential for data leakage'
            ]
          },
          recommendations: [
            'Use getOrgDatabaseWithAuth() for automatic RLS',
            'Ensure proper tenant context',
            'Add authentication checks before database access'
          ],
          rlsViolations: [
            'No RLS context established',
            'Missing tenant isolation'
          ]
        });
      }
    }

    return matches;
  }

  private analyzeDataIsolation(node: TSESTree.Node, sourceCode: string): DataAccessMatch[] {
    const matches: DataAccessMatch[] = [];

    // Check for hardcoded organization access
    if (this.hasHardcodedOrgAccess(node, sourceCode)) {
      const pattern = this.knownPatterns.get('hardcodedOrgAccess')!;
      matches.push({
        pattern,
        matchResult: {
          similarity: 0.9,
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: false,
          confidence: 0.9
        },
        securityRisk: {
          level: 'high',
          description: 'Hardcoded organization access breaks multi-tenancy',
          impact: [
            'Breaks tenant isolation',
            'Accesses specific organization data',
            'Not scalable for multi-tenant architecture'
          ]
        },
        recommendations: [
          'Use dynamic organization context from authentication',
          'Access data through user.orgSlug or similar',
          'Ensure all queries are tenant-scoped'
        ],
        rlsViolations: [
          'Circumvents tenant-based filtering',
          'Accesses data outside user context'
        ]
      });
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

  private isParameterizedQuery(call: TSESTree.CallExpression, sourceCode: string): boolean {
    // Check if the query uses proper parameterization
    const calleeText = this.getCalleeText(call.callee);
    
    // ORM methods are generally safe
    const safeOMRMethods = ['select', 'insert', 'update', 'delete', 'where', 'eq', 'ne', 'gt', 'lt'];
    if (safeOMRMethods.some(method => calleeText.includes(method))) {
      return true;
    }

    // Check for parameterized queries with $1, $2, etc.
    if (call.arguments.length > 1 && sourceCode.includes('$1')) {
      return true;
    }

    return false;
  }

  private hasStringInterpolation(call: TSESTree.CallExpression, sourceCode: string): boolean {
    // Look for template literals or string concatenation in query arguments
    for (const arg of call.arguments) {
      if (arg.type === 'TemplateLiteral') {
        return true;
      }
      if (arg.type === 'BinaryExpression') {
        const binary = arg as TSESTree.BinaryExpression;
        if (binary.operator === '+') {
          return true;
        }
      }
    }

    // Check source code for template literals or concatenation
    return sourceCode.includes('${') || 
           sourceCode.includes('" + ') || 
           sourceCode.includes('\' + ');
  }

  private isAPIRoute(filePath: string): boolean {
    return filePath.includes('/api/') || 
           filePath.includes('route.ts') || 
           filePath.includes('route.js') ||
           filePath.includes('handler');
  }

  private hasDatabaseAccess(node: TSESTree.Node, sourceCode: string): boolean {
    const dbKeywords = [
      'db.', 'database.', 'client.', 'connection.',
      'select(', 'insert(', 'update(', 'delete(',
      'query(', 'exec(', 'execute('
    ];

    return dbKeywords.some(keyword => sourceCode.includes(keyword));
  }

  private hasProperRLSSetup(sourceCode: string): boolean {
    const rlsKeywords = [
      'getOrgDatabaseWithAuth', 'getSupabaseRLS',
      'requireAuthWithTenant', 'withRLS'
    ];

    return rlsKeywords.some(keyword => sourceCode.includes(keyword));
  }

  private hasHardcodedOrgAccess(node: TSESTree.Node, sourceCode: string): boolean {
    // Look for hardcoded organization IDs in queries
    const hardcodedPatterns = [
      /organization_id\s*=\s*["'][\w-]+["']/,
      /orgId\s*=\s*["'][\w-]+["']/,
      /org_slug\s*=\s*["'][\w-]+["']/,
      /["'][\w-]+-corp["']/,
      /["'][\w-]+-org["']/
    ];

    return hardcodedPatterns.some(pattern => pattern.test(sourceCode));
  }

  getKnownPatterns(): Map<string, DataAccessPattern> {
    return this.knownPatterns;
  }

  addCustomPattern(pattern: DataAccessPattern): void {
    this.knownPatterns.set(pattern.name, pattern);
    logger.info(`Added custom data access pattern: ${pattern.name}`);
  }

  generateDataAccessReport(matches: DataAccessMatch[]): string {
    const report = ['# Data Access Pattern Analysis Report\n'];
    
    // Group by security level
    const bySecurityLevel = new Map<string, DataAccessMatch[]>();
    for (const match of matches) {
      const level = match.securityRisk.level;
      if (!bySecurityLevel.has(level)) {
        bySecurityLevel.set(level, []);
      }
      bySecurityLevel.get(level)!.push(match);
    }

    // Order by severity
    const severityOrder = ['critical', 'high', 'medium', 'low'];
    
    for (const level of severityOrder) {
      const levelMatches = bySecurityLevel.get(level);
      if (!levelMatches || levelMatches.length === 0) continue;

      report.push(`## ${level.toUpperCase()} SECURITY RISK\n`);
      
      for (const match of levelMatches) {
        report.push(`### ${match.pattern.name}`);
        report.push(`**Category:** ${match.pattern.category}`);
        report.push(`**RLS Compliant:** ${match.pattern.rlsCompliant ? 'Yes' : 'No'}`);
        report.push(match.pattern.description);
        
        report.push('\n**Security Risk:**');
        report.push(match.securityRisk.description);
        if (match.securityRisk.impact.length > 0) {
          report.push('\n**Impact:**');
          match.securityRisk.impact.forEach(impact => report.push(`- ${impact}`));
        }
        
        if (match.rlsViolations.length > 0) {
          report.push('\n**RLS Violations:**');
          match.rlsViolations.forEach(violation => report.push(`- ${violation}`));
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

export default DataAccessPatternsAnalyzer;