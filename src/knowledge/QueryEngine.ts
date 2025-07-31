import { DatabaseManager, SystemKnowledge } from '../database/schema';
import { KnowledgeExtractor, SystemFlow, SystemArchitecture, SecurityModel } from './KnowledgeExtractor';
import logger from '../utils/logger';

export interface QueryResult {
  answer: string;
  confidence: number;
  sources: string[];
  codeExamples?: CodeExample[];
  relatedTopics?: string[];
  followUpQuestions?: string[];
}

export interface CodeExample {
  title: string;
  code: string;
  filePath?: string;
  lineNumber?: number;
  description: string;
}

export interface QueryContext {
  systemName?: string;
  component?: string;
  filePath?: string;
  previousQueries?: string[];
}

export class QueryEngine {
  private db: DatabaseManager;
  private knowledgeExtractor: KnowledgeExtractor;
  private queryPatterns: Map<string, QueryHandler>;

  constructor(db: DatabaseManager, knowledgeExtractor: KnowledgeExtractor) {
    this.db = db;
    this.knowledgeExtractor = knowledgeExtractor;
    this.queryPatterns = new Map();
    this.initializeQueryPatterns();
  }

  private initializeQueryPatterns(): void {
    // Authentication-related queries
    this.queryPatterns.set('authentication', {
      keywords: ['auth', 'login', 'authenticate', 'authentication', 'sign in', 'JWT', 'token'],
      handler: this.handleAuthenticationQuery.bind(this)
    });

    // RBAC-related queries
    this.queryPatterns.set('rbac', {
      keywords: ['rbac', 'role', 'permission', 'authorize', 'authorization', 'access control'],
      handler: this.handleRBACQuery.bind(this)
    });

    // Database-related queries
    this.queryPatterns.set('database', {
      keywords: ['database', 'db', 'data', 'query', 'sql', 'rls', 'row level security'],
      handler: this.handleDatabaseQuery.bind(this)
    });

    // API-related queries
    this.queryPatterns.set('api', {
      keywords: ['api', 'endpoint', 'route', 'request', 'response', 'rest'],
      handler: this.handleAPIQuery.bind(this)
    });

    // Security-related queries
    this.queryPatterns.set('security', {
      keywords: ['security', 'vulnerability', 'secure', 'protection', 'threat', 'risk'],
      handler: this.handleSecurityQuery.bind(this)
    });

    // Architecture-related queries
    this.queryPatterns.set('architecture', {
      keywords: ['architecture', 'structure', 'design', 'system', 'component', 'flow'],
      handler: this.handleArchitectureQuery.bind(this)
    });

    // How-to queries
    this.queryPatterns.set('howto', {
      keywords: ['how', 'implement', 'create', 'build', 'make', 'add'],
      handler: this.handleHowToQuery.bind(this)
    });
  }

  async processQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    try {
      logger.info(`Processing query: "${query}"`);

      // Normalize and analyze the query
      const normalizedQuery = this.normalizeQuery(query);
      const queryType = this.determineQueryType(normalizedQuery);
      const handler = this.queryPatterns.get(queryType);

      if (!handler) {
        return this.handleGenericQuery(normalizedQuery, context);
      }

      const result = await handler.handler(normalizedQuery, context);
      
      // Add follow-up questions
      result.followUpQuestions = this.generateFollowUpQuestions(queryType, result);

      logger.info(`Query processed successfully with confidence: ${result.confidence}`);
      return result;

    } catch (error) {
      logger.error('Failed to process query:', error);
      return {
        answer: 'Sorry, I encountered an error while processing your query. Please try rephrasing or check the system logs.',
        confidence: 0,
        sources: [],
        followUpQuestions: ['Can you rephrase your question?', 'What specific aspect would you like to know about?']
      };
    }
  }

  private normalizeQuery(query: string): string {
    return query.toLowerCase().trim();
  }

  private determineQueryType(query: string): string {
    let bestMatch = 'generic';
    let highestScore = 0;

    for (const [type, pattern] of this.queryPatterns) {
      const score = this.calculateQueryScore(query, pattern.keywords);
      if (score > highestScore) {
        highestScore = score;
        bestMatch = type;
      }
    }

    return bestMatch;
  }

  private calculateQueryScore(query: string, keywords: string[]): number {
    let score = 0;
    const queryWords = query.split(/\s+/);

    keywords.forEach(keyword => {
      queryWords.forEach(word => {
        if (word.includes(keyword) || keyword.includes(word)) {
          score += 1;
        }
      });
    });

    return score / keywords.length;
  }

  private async handleAuthenticationQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    const authFlow = this.knowledgeExtractor.getSystemFlow('authentication');
    const authKnowledge = this.knowledgeExtractor.getSystemKnowledge('Authentication');
    
    let answer = "## Authentication System\n\n";
    
    if (authFlow) {
      answer += `### How Authentication Works\n\n`;
      answer += `${authFlow.description}\n\n`;
      
      answer += `### Authentication Flow Steps:\n`;
      authFlow.steps.forEach(step => {
        answer += `${step.step}. **${step.action}** (${step.component})\n`;
        answer += `   ${step.description}\n\n`;
      });

      if (authFlow.securityCheckpoints.length > 0) {
        answer += `### Security Checkpoints:\n`;
        authFlow.securityCheckpoints.forEach(checkpoint => {
          const status = checkpoint.isImplemented ? "✅" : "❌";
          answer += `- ${status} **${checkpoint.name}** (${checkpoint.severity})\n`;
          answer += `  ${checkpoint.description}\n`;
        });
        answer += '\n';
      }

      if (authFlow.risks.length > 0) {
        answer += `### Security Considerations:\n`;
        authFlow.risks.forEach(risk => {
          answer += `- **${risk.type}** (${risk.impact} impact)\n`;
          answer += `  ${risk.description}\n`;
          answer += `  *Mitigation:* ${risk.mitigation}\n\n`;
        });
      }
    }

    // Add code examples from system knowledge
    const codeExamples: CodeExample[] = [];
    if (authKnowledge.length > 0) {
      answer += `### Implementation Details:\n\n`;
      authKnowledge.forEach(knowledge => {
        answer += `**${knowledge.component}:**\n`;
        answer += `${knowledge.description}\n\n`;
        
        if (knowledge.implementation_details) {
          answer += `*Implementation:* ${knowledge.implementation_details}\n\n`;
        }

        if (knowledge.security_considerations) {
          answer += `*Security Notes:* ${knowledge.security_considerations}\n\n`;
        }
      });
    }

    // Get authentication patterns from database
    const authPatterns = await this.getAuthPatterns();
    if (authPatterns.length > 0) {
      codeExamples.push(...authPatterns);
    }

    return {
      answer,
      confidence: 0.9,
      sources: ['System Analysis', 'Code Patterns', 'Security Analysis'],
      codeExamples,
      relatedTopics: ['RBAC', 'Security', 'API Design', 'JWT Tokens']
    };
  }

  private async handleRBACQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    const rbacKnowledge = this.knowledgeExtractor.getSystemKnowledge('Authentication');
    const securityModel = this.knowledgeExtractor.getSecurityModel();
    
    let answer = "## Role-Based Access Control (RBAC)\n\n";
    
    if (securityModel.authorizationModel) {
      answer += `### Authorization Model\n`;
      answer += `${securityModel.authorizationModel}\n\n`;
    }

    // Get RBAC patterns from database
    const rbacPatterns = await this.getRBACPatterns();
    
    if (rbacPatterns.length > 0) {
      answer += `### Roles and Permissions:\n\n`;
      const roles = new Set(rbacPatterns.map(p => p.role));
      
      roles.forEach(role => {
        const rolePatterns = rbacPatterns.filter(p => p.role === role);
        answer += `**${role.toUpperCase()}:**\n`;
        rolePatterns.forEach(pattern => {
          answer += `- ${pattern.permission}`;
          if (pattern.resource_pattern) {
            answer += ` (${pattern.resource_pattern})`;
          }
          answer += '\n';
        });
        answer += '\n';
      });
    }

    const codeExamples: CodeExample[] = [];
    
    // Add implementation examples
    if (rbacPatterns.length > 0) {
      rbacPatterns.forEach(pattern => {
        if (pattern.implementation_pattern) {
          codeExamples.push({
            title: `${pattern.role} - ${pattern.permission}`,
            code: pattern.implementation_pattern,
            description: `Implementation pattern for ${pattern.role} role accessing ${pattern.permission}`
          });
        }
      });
    }

    return {
      answer,
      confidence: 0.85,
      sources: ['RBAC Analysis', 'Security Model', 'Code Patterns'],
      codeExamples,
      relatedTopics: ['Authentication', 'Security', 'Permissions', 'Organization Isolation']
    };
  }

  private async handleDatabaseQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    const dataFlow = this.knowledgeExtractor.getSystemFlow('data_access');
    const architecture = this.knowledgeExtractor.getArchitecture();
    
    let answer = "## Database Architecture\n\n";
    
    // Find database-related components
    const dbComponents = architecture.systems.filter(s => 
      s.type === 'database' || s.name.toLowerCase().includes('database')
    );
    
    if (dbComponents.length > 0) {
      answer += `### Database Components:\n\n`;
      dbComponents.forEach(comp => {
        answer += `**${comp.name}:**\n`;
        answer += `- Type: ${comp.type}\n`;
        answer += `- Security Level: ${comp.securityLevel}\n`;
        answer += `- ${comp.description}\n`;
        answer += `- Responsibilities: ${comp.responsibilities.join(', ')}\n\n`;
      });
    }

    // Add data stores information
    if (architecture.dataStores.length > 0) {
      answer += `### Data Stores:\n\n`;
      architecture.dataStores.forEach(store => {
        answer += `**${store.name}** (${store.type})\n`;
        answer += `- Sensitivity: ${store.sensitivity}\n`;
        answer += `- Protections: ${store.protections.join(', ')}\n`;
        answer += `- Access Patterns: ${store.access_patterns.join(', ')}\n\n`;
      });
    }

    // Add data access flow
    if (dataFlow) {
      answer += `### Data Access Process:\n\n`;
      dataFlow.steps.forEach(step => {
        answer += `${step.step}. **${step.action}**\n`;
        answer += `   ${step.description}\n\n`;
      });

      if (dataFlow.securityCheckpoints.length > 0) {
        answer += `### Security Controls:\n`;
        dataFlow.securityCheckpoints.forEach(checkpoint => {
          const status = checkpoint.isImplemented ? "✅" : "❌";
          answer += `- ${status} **${checkpoint.name}**\n`;
          answer += `  ${checkpoint.description}\n`;
        });
        answer += '\n';
      }
    }

    const codeExamples = await this.getDataAccessExamples();

    return {
      answer,
      confidence: 0.9,
      sources: ['Architecture Analysis', 'Data Flow Analysis', 'Security Analysis'],
      codeExamples,
      relatedTopics: ['RLS', 'Security', 'Organization Isolation', 'API Design']
    };
  }

  private async handleAPIQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    const apiFlow = this.knowledgeExtractor.getSystemFlow('api_request');
    const architecture = this.knowledgeExtractor.getArchitecture();
    
    let answer = "## API Architecture\n\n";
    
    // Find API-related components
    const apiComponents = architecture.systems.filter(s => 
      s.type === 'api' || s.name.toLowerCase().includes('api')
    );
    
    if (apiComponents.length > 0) {
      answer += `### API Components:\n\n`;
      apiComponents.forEach(comp => {
        answer += `**${comp.name}:**\n`;
        answer += `- Security Level: ${comp.securityLevel}\n`;
        answer += `- ${comp.description}\n`;
        answer += `- Responsibilities: ${comp.responsibilities.join(', ')}\n\n`;
      });
    }

    if (apiFlow) {
      answer += `### API Request Flow:\n\n`;
      apiFlow.steps.forEach(step => {
        answer += `${step.step}. **${step.action}** (${step.component})\n`;
        answer += `   ${step.description}\n\n`;
      });

      if (apiFlow.securityCheckpoints.length > 0) {
        answer += `### Security Checkpoints:\n`;
        apiFlow.securityCheckpoints.forEach(checkpoint => {
          const status = checkpoint.isImplemented ? "✅" : "❌";
          answer += `- ${status} **${checkpoint.name}** (${checkpoint.severity})\n`;
          answer += `  ${checkpoint.description}\n`;
        });
        answer += '\n';
      }
    }

    const codeExamples = await this.getAPIExamples();

    return {
      answer,
      confidence: 0.85,
      sources: ['API Analysis', 'Request Flow Analysis', 'Security Patterns'],
      codeExamples,
      relatedTopics: ['Authentication', 'Authorization', 'Request Validation', 'Error Handling']
    };
  }

  private async handleSecurityQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    const securityModel = this.knowledgeExtractor.getSecurityModel();
    const architecture = this.knowledgeExtractor.getArchitecture();
    
    let answer = "## Security Overview\n\n";
    
    if (securityModel.authenticationMethods.length > 0) {
      answer += `### Authentication Methods:\n`;
      securityModel.authenticationMethods.forEach(method => {
        answer += `- ${method}\n`;
      });
      answer += '\n';
    }

    answer += `### Authorization Model:\n`;
    answer += `${securityModel.authorizationModel}\n\n`;

    if (securityModel.dataProtection.length > 0) {
      answer += `### Data Protection:\n`;
      securityModel.dataProtection.forEach(protection => {
        answer += `- ${protection}\n`;
      });
      answer += '\n';
    }

    if (securityModel.trustBoundaries.length > 0) {
      answer += `### Trust Boundaries:\n`;
      securityModel.trustBoundaries.forEach(boundary => {
        answer += `- ${boundary}\n`;
      });
      answer += '\n';
    }

    // Add security boundaries from architecture
    if (architecture.securityBoundaries.length > 0) {
      answer += `### Security Boundaries:\n\n`;
      architecture.securityBoundaries.forEach(boundary => {
        answer += `**${boundary.name}** (${boundary.protectionLevel} protection)\n`;
        answer += `- Components: ${boundary.components.join(', ')}\n`;
        answer += `- Controls: ${boundary.controls.join(', ')}\n\n`;
      });
    }

    // Add threat model
    if (securityModel.threatModel.length > 0) {
      answer += `### Identified Security Risks:\n\n`;
      securityModel.threatModel.forEach(risk => {
        answer += `**${risk.type}** (${risk.impact} impact, ${risk.likelihood} likelihood)\n`;
        answer += `${risk.description}\n`;
        answer += `*Mitigation:* ${risk.mitigation}\n\n`;
      });
    }

    // Get security issues from database
    const securityIssues = await this.getSecurityIssues();
    const codeExamples: CodeExample[] = [];
    
    if (securityIssues.length > 0) {
      answer += `### Current Security Issues:\n\n`;
      const criticalIssues = securityIssues.filter(i => i.severity === 'critical');
      const highIssues = securityIssues.filter(i => i.severity === 'high');
      
      if (criticalIssues.length > 0) {
        answer += `**CRITICAL (${criticalIssues.length}):**\n`;
        criticalIssues.slice(0, 3).forEach(issue => {
          answer += `- ${issue.description} (${issue.file_path}:${issue.line_start})\n`;
        });
        answer += '\n';
      }
      
      if (highIssues.length > 0) {
        answer += `**HIGH (${highIssues.length}):**\n`;
        highIssues.slice(0, 3).forEach(issue => {
          answer += `- ${issue.description} (${issue.file_path}:${issue.line_start})\n`;
        });
        answer += '\n';
      }
    }

    return {
      answer,
      confidence: 0.9,
      sources: ['Security Model', 'Architecture Analysis', 'Vulnerability Scanning'],
      codeExamples,
      relatedTopics: ['Authentication', 'RBAC', 'Data Protection', 'Threat Modeling']
    };
  }

  private async handleArchitectureQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    const architecture = this.knowledgeExtractor.getArchitecture();
    
    let answer = "## System Architecture\n\n";
    
    if (architecture.systems.length > 0) {
      answer += `### System Components:\n\n`;
      
      const componentsByType = new Map<string, typeof architecture.systems>();
      architecture.systems.forEach(system => {
        if (!componentsByType.has(system.type)) {
          componentsByType.set(system.type, []);
        }
        componentsByType.get(system.type)!.push(system);
      });

      componentsByType.forEach((systems, type) => {
        answer += `**${type.toUpperCase()}:**\n`;
        systems.forEach(system => {
          answer += `- **${system.name}** (${system.securityLevel})\n`;
          answer += `  ${system.description}\n`;
          answer += `  Responsibilities: ${system.responsibilities.join(', ')}\n\n`;
        });
      });
    }

    if (architecture.connections.length > 0) {
      answer += `### System Connections:\n\n`;
      architecture.connections.forEach(conn => {
        const security = conn.security === 'secure' ? '🔒' : 
                        conn.security === 'insecure' ? '⚠️' : '❓';
        answer += `- ${conn.from} → ${conn.to} (${conn.type}) ${security}\n`;
        answer += `  ${conn.description}\n`;
      });
      answer += '\n';
    }

    return {
      answer,
      confidence: 0.85,
      sources: ['Architecture Analysis', 'System Mapping', 'Component Analysis'],
      relatedTopics: ['Security Boundaries', 'Data Flow', 'System Dependencies', 'Component Design']
    };
  }

  private async handleHowToQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    let answer = "## Implementation Guide\n\n";
    
    // Determine what they want to implement
    if (query.includes('api') || query.includes('endpoint')) {
      answer += await this.getAPIImplementationGuide();
    } else if (query.includes('auth') || query.includes('login')) {
      answer += await this.getAuthImplementationGuide();
    } else if (query.includes('database') || query.includes('query')) {
      answer += await this.getDatabaseImplementationGuide();
    } else {
      answer += "I can help you implement:\n";
      answer += "- API endpoints with authentication\n";
      answer += "- Authentication flows\n";
      answer += "- Database queries with RLS\n";
      answer += "- RBAC permission checks\n\n";
      answer += "Please specify what you'd like to implement!";
    }

    const codeExamples = await this.getImplementationExamples(query);

    return {
      answer,
      confidence: 0.8,
      sources: ['Code Patterns', 'Best Practices', 'Security Guidelines'],
      codeExamples,
      relatedTopics: ['Code Patterns', 'Security Best Practices', 'Implementation Guidelines']
    };
  }

  private async handleGenericQuery(query: string, context?: QueryContext): Promise<QueryResult> {
    // Try to search in system knowledge
    const searchResults = await this.searchSystemKnowledge(query);
    
    let answer = "Based on the codebase analysis:\n\n";
    
    if (searchResults.length > 0) {
      searchResults.slice(0, 3).forEach(result => {
        answer += `**${result.system_name} - ${result.component}:**\n`;
        answer += `${result.description}\n\n`;
      });
    } else {
      answer = "I couldn't find specific information about that. Here are some topics I can help with:\n\n";
      answer += "- **Authentication**: How user login and JWT tokens work\n";
      answer += "- **RBAC**: Role-based access control and permissions\n";
      answer += "- **Database**: Data access patterns and RLS\n";
      answer += "- **API**: Endpoint design and security\n";
      answer += "- **Security**: Vulnerabilities and protection measures\n";
      answer += "- **Architecture**: System structure and components\n";
    }

    return {
      answer,
      confidence: 0.6,
      sources: ['System Knowledge', 'General Analysis'],
      relatedTopics: ['Authentication', 'RBAC', 'Database', 'API', 'Security', 'Architecture']
    };
  }

  // Helper methods for database queries
  private async getAuthPatterns(): Promise<CodeExample[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT p.name, p.description, pi.file_path, pi.line_start, pi.metadata
      FROM patterns p
      JOIN pattern_instances pi ON p.id = pi.pattern_id
      WHERE p.category = 'auth'
      LIMIT 5
    `);
    
    const results = stmt.all() as any[];
    return results.map(r => ({
      title: r.name,
      code: r.metadata ? JSON.parse(r.metadata).code || '' : '',
      filePath: r.file_path,
      lineNumber: r.line_start,
      description: r.description || `Authentication pattern: ${r.name}`
    }));
  }

  private async getRBACPatterns(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM rbac_patterns
      ORDER BY role, permission
    `);
    return stmt.all() as any[];
  }

  private async getDataAccessExamples(): Promise<CodeExample[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT p.name, p.description, pi.file_path, pi.line_start, pi.metadata
      FROM patterns p
      JOIN pattern_instances pi ON p.id = pi.pattern_id
      WHERE p.category = 'data_access'
      LIMIT 3
    `);
    
    const results = stmt.all() as any[];
    return results.map(r => ({
      title: r.name,
      code: r.metadata ? JSON.parse(r.metadata).code || '' : '',
      filePath: r.file_path,
      lineNumber: r.line_start,
      description: r.description || `Data access pattern: ${r.name}`
    }));
  }

  private async getAPIExamples(): Promise<CodeExample[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT p.name, p.description, pi.file_path, pi.line_start, pi.metadata
      FROM patterns p
      JOIN pattern_instances pi ON p.id = pi.pattern_id
      WHERE p.category = 'api'
      LIMIT 3
    `);
    
    const results = stmt.all() as any[];
    return results.map(r => ({
      title: r.name,
      code: r.metadata ? JSON.parse(r.metadata).code || '' : '',
      filePath: r.file_path,
      lineNumber: r.line_start,
      description: r.description || `API pattern: ${r.name}`
    }));
  }

  private async getSecurityIssues(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM security_issues 
      WHERE resolved = FALSE 
      ORDER BY 
        CASE severity 
          WHEN 'critical' THEN 1 
          WHEN 'high' THEN 2 
          WHEN 'medium' THEN 3 
          ELSE 4 
        END
      LIMIT 10
    `);
    return stmt.all() as any[];
  }

  private async searchSystemKnowledge(query: string): Promise<SystemKnowledge[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM system_knowledge 
      WHERE description LIKE ? OR implementation_details LIKE ?
      LIMIT 5
    `);
    const searchTerm = `%${query}%`;
    return stmt.all(searchTerm, searchTerm) as SystemKnowledge[];
  }

  private async getAPIImplementationGuide(): Promise<string> {
    return `### Creating a Secure API Endpoint

1. **Authentication Check**
   - Always call \`requireAuthWithTenant()\` first
   - Extract user, orgSlug, and role from the result

2. **Permission Validation**
   - Use \`hasPermission(role, 'action:resource')\` to check authorization
   - Return 403 Forbidden if permission denied

3. **Database Access**
   - Use \`getOrgDatabaseWithAuth()\` for database operations
   - This ensures RLS is applied automatically

4. **Error Handling**
   - Wrap in try-catch block
   - Return appropriate HTTP status codes
   - Log errors without exposing sensitive information

`;
  }

  private async getAuthImplementationGuide(): Promise<string> {
    return `### Implementing Authentication

1. **User Login**
   - Use Supabase Auth for OAuth or email/password
   - Generate JWT token with user claims

2. **Token Validation**
   - Implement middleware to verify JWT on each request
   - Extract user context from token

3. **Session Management**
   - Store minimal session data
   - Implement token refresh mechanism

4. **Multi-tenant Context**
   - Include organization information in JWT
   - Validate organization membership

`;
  }

  private async getDatabaseImplementationGuide(): Promise<string> {
    return `### Secure Database Access

1. **Connection Setup**
   - Never use direct database connections
   - Always use \`getOrgDatabaseWithAuth()\`

2. **Row Level Security**
   - Ensure RLS policies are enabled
   - Test organization isolation

3. **Query Patterns**
   - Use parameterized queries
   - Validate all inputs
   - Apply proper filters

4. **Error Handling**
   - Handle connection failures gracefully
   - Don't expose database structure in errors

`;
  }

  private async getImplementationExamples(query: string): Promise<CodeExample[]> {
    const examples: CodeExample[] = [];
    
    if (query.includes('api')) {
      examples.push({
        title: 'Secure API Endpoint',
        code: `export async function GET() {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant();
    
    if (!hasPermission(role, 'read:data')) {
      return new Response('Forbidden', { status: 403 });
    }
    
    const db = await getOrgDatabaseWithAuth();
    const data = await db.select().from(table);
    
    return Response.json({ data });
  } catch (error) {
    console.error('API Error:', error);
    return new Response('Internal Error', { status: 500 });
  }
}`,
        description: 'Template for a secure API endpoint with authentication and authorization'
      });
    }

    return examples;
  }

  private generateFollowUpQuestions(queryType: string, result: QueryResult): string[] {
    const questions = new Map<string, string[]>([
      ['authentication', [
        'How do I implement JWT token validation?',
        'What authentication methods are supported?',
        'How does session management work?'
      ]],
      ['rbac', [
        'What roles are available in the system?',
        'How do I check permissions in my code?',
        'How is organization isolation implemented?'
      ]],
      ['database', [
        'How does RLS work in practice?',
        'What are the secure database connection patterns?',
        'How do I handle database errors securely?'
      ]],
      ['api', [
        'What security checks should every API have?',
        'How do I implement input validation?',
        'What are the error handling best practices?'
      ]],
      ['security', [
        'What are the current security vulnerabilities?',
        'How do I fix authentication bypasses?',
        'What security patterns should I follow?'
      ]],
      ['architecture', [
        'What are the main system components?',
        'How do systems communicate securely?',
        'What are the trust boundaries?'
      ]]
    ]);

    return questions.get(queryType) || [
      'Can you explain this in more detail?',
      'Are there any security considerations?',
      'Do you have code examples?'
    ];
  }
}

interface QueryHandler {
  keywords: string[];
  handler: (query: string, context?: QueryContext) => Promise<QueryResult>;
}

export default QueryEngine;