import { DatabaseManager, SystemKnowledge } from '../database/schema';
import { 
  KnowledgeExtractor, 
  SystemFlow, 
  SystemArchitecture, 
  SecurityModel,
  SystemComponent,
  SystemConnection,
  SecurityCheckpoint,
  SecurityRisk 
} from './KnowledgeExtractor';
import logger from '../utils/logger';

export interface SystemExplanation {
  title: string;
  overview: string;
  components: ComponentExplanation[];
  dataFlow: DataFlowExplanation[];
  securityModel: SecurityExplanation;
  architecture: ArchitectureExplanation;
  implementationGuide: ImplementationGuide;
  troubleshooting: TroubleshootingGuide;
}

export interface ComponentExplanation {
  name: string;
  purpose: string;
  responsibilities: string[];
  interfaces: string[];
  dependencies: string[];
  securityLevel: string;
  codeLocation: string[];
}

export interface DataFlowExplanation {
  name: string;
  description: string;
  steps: string[];
  securityPoints: string[];
  diagram: string;
}

export interface SecurityExplanation {
  overview: string;
  authenticationMethods: string[];
  authorizationModel: string;
  dataProtection: string[];
  trustBoundaries: string[];
  commonThreats: ThreatExplanation[];
}

export interface ThreatExplanation {
  threat: string;
  description: string;
  impact: string;
  prevention: string[];
  detection: string[];
}

export interface ArchitectureExplanation {
  overview: string;
  layers: LayerExplanation[];
  patterns: PatternExplanation[];
  decisions: ArchitecturalDecision[];
}

export interface LayerExplanation {
  name: string;
  purpose: string;
  components: string[];
  responsibilities: string[];
}

export interface PatternExplanation {
  name: string;
  description: string;
  benefits: string[];
  tradeoffs: string[];
  examples: string[];
}

export interface ArchitecturalDecision {
  decision: string;
  rationale: string;
  alternatives: string[];
  consequences: string[];
}

export interface ImplementationGuide {
  gettingStarted: string[];
  commonPatterns: CodePattern[];
  bestPractices: string[];
  antiPatterns: AntiPattern[];
}

export interface CodePattern {
  name: string;
  description: string;
  code: string;
  explanation: string;
  whenToUse: string;
}

export interface AntiPattern {
  name: string;
  description: string;
  whyBad: string;
  correctApproach: string;
  example: string;
}

export interface TroubleshootingGuide {
  commonIssues: TroubleshootingIssue[];
  debuggingSteps: string[];
  securityChecklist: string[];
}

export interface TroubleshootingIssue {
  problem: string;
  symptoms: string[];
  causes: string[];
  solutions: string[];
}

export interface DataFlowTrace {
  component: string;
  flow: string[];
  dataTypes: string[];
  securityControls: string[];
}

export interface DocumentationConfig {
  includeArchitecture: boolean;
  includeSecurity: boolean;
  includeDataFlow: boolean;
  format: 'markdown' | 'html' | 'json';
}

export interface Documentation {
  title: string;
  content: string;
  sections: string[];
}

export class SystemExplainer {
  private db: DatabaseManager;
  private knowledgeExtractor: KnowledgeExtractor;

  constructor(db: DatabaseManager, knowledgeExtractor: KnowledgeExtractor) {
    this.db = db;
    this.knowledgeExtractor = knowledgeExtractor;
  }

  async explainSystem(systemName: string): Promise<SystemExplanation> {
    try {
      logger.info(`Generating explanation for system: ${systemName}`);

      const architecture = this.knowledgeExtractor.getArchitecture();
      const securityModel = this.knowledgeExtractor.getSecurityModel();
      const systemKnowledge = this.knowledgeExtractor.getSystemKnowledge(systemName);

      const explanation: SystemExplanation = {
        title: `${systemName} System Explanation`,
        overview: await this.generateSystemOverview(systemName, systemKnowledge),
        components: await this.explainComponents(systemName, architecture),
        dataFlow: await this.explainDataFlow(systemName),
        securityModel: this.explainSecurity(securityModel),
        architecture: this.explainArchitecture(architecture),
        implementationGuide: await this.generateImplementationGuide(systemName),
        troubleshooting: await this.generateTroubleshootingGuide(systemName)
      };

      logger.info(`System explanation generated successfully for: ${systemName}`);
      return explanation;

    } catch (error) {
      logger.error(`Failed to generate system explanation for ${systemName}:`, error);
      throw error;
    }
  }

  generateFlowDiagram(flow: SystemFlow): string {
    let diagram = `# ${flow.name}\n\n`;
    diagram += `${flow.description}\n\n`;

    // Create ASCII flow diagram
    diagram += "```\n";
    diagram += "Flow Diagram:\n";
    diagram += "=============\n\n";

    flow.steps.forEach((step, index) => {
      const isLast = index === flow.steps.length - 1;
      const connector = isLast ? "" : "    ↓";
      
      diagram += `${step.step}. [${step.component}]\n`;
      diagram += `   ${step.action}\n`;
      diagram += `   ${step.description}\n`;
      if (!isLast) diagram += `${connector}\n`;
    });

    diagram += "```\n\n";

    // Add security checkpoints
    if (flow.securityCheckpoints.length > 0) {
      diagram += "Security Checkpoints:\n";
      flow.securityCheckpoints.forEach(checkpoint => {
        const status = checkpoint.isImplemented ? "✅" : "❌";
        diagram += `${status} ${checkpoint.name} (${checkpoint.type})\n`;
        diagram += `   ${checkpoint.description}\n`;
        diagram += `   Severity: ${checkpoint.severity}\n\n`;
      });
    }

    // Add data flow
    if (flow.dataFlow.length > 0) {
      diagram += "Data Flow:\n";
      diagram += "```\n";
      flow.dataFlow.forEach(dataStep => {
        const securityIcon = this.getSecurityIcon(dataStep.security);
        const riskIcon = this.getRiskIcon(dataStep.riskLevel);
        diagram += `${dataStep.from} --[${dataStep.data}]--> ${dataStep.to} ${securityIcon} ${riskIcon}\n`;
      });
      diagram += "```\n\n";
    }

    return diagram;
  }

  generateArchitectureDiagram(architecture: SystemArchitecture): string {
    let diagram = "# System Architecture\n\n";
    
    diagram += "```\n";
    diagram += "Architecture Overview:\n";
    diagram += "=====================\n\n";

    // Group components by type
    const componentsByType = new Map<string, SystemComponent[]>();
    architecture.systems.forEach(system => {
      if (!componentsByType.has(system.type)) {
        componentsByType.set(system.type, []);
      }
      componentsByType.get(system.type)!.push(system);
    });

    // Draw layers
    const layerOrder = ['api', 'middleware', 'service', 'database', 'component'];
    layerOrder.forEach(type => {
      const components = componentsByType.get(type) || [];
      if (components.length > 0) {
        diagram += `┌─ ${type.toUpperCase()} LAYER ─────────────────────┐\n`;
        components.forEach(comp => {
          const securityIcon = this.getSecurityLevelIcon(comp.securityLevel);
          diagram += `│ ${securityIcon} ${comp.name.padEnd(25)} │\n`;
        });
        diagram += `└──────────────────────────────────────┘\n`;
        diagram += `              ↓\n`;
      }
    });

    diagram += "```\n\n";

    // Add security boundaries
    if (architecture.securityBoundaries.length > 0) {
      diagram += "Security Boundaries:\n";
      diagram += "```\n";
      architecture.securityBoundaries.forEach(boundary => {
        diagram += `🔒 ${boundary.name} (${boundary.protectionLevel})\n`;
        diagram += `   Components: ${boundary.components.join(', ')}\n`;
        diagram += `   Controls: ${boundary.controls.join(', ')}\n\n`;
      });
      diagram += "```\n\n";
    }

    return diagram;
  }

  generateSecurityDiagram(securityModel: SecurityModel): string {
    let diagram = "# Security Model\n\n";
    
    diagram += "```\n";
    diagram += "Security Architecture:\n";
    diagram += "====================\n\n";

    // Authentication flow
    diagram += "🔐 AUTHENTICATION\n";
    diagram += "Client → Auth Service → JWT Token\n";
    diagram += "                    ↓\n";
    diagram += "               Token Storage\n\n";

    // Authorization flow  
    diagram += "🛡️ AUTHORIZATION\n";
    diagram += "Request → Token Validation → Role Check → Permission Grant\n\n";

    // Data protection
    diagram += "📊 DATA PROTECTION\n";
    securityModel.dataProtection.forEach(protection => {
      diagram += `• ${protection}\n`;
    });
    diagram += "\n";

    // Trust boundaries
    diagram += "🔒 TRUST BOUNDARIES\n";
    securityModel.trustBoundaries.forEach(boundary => {
      diagram += `• ${boundary}\n`;
    });

    diagram += "```\n\n";

    return diagram;
  }

  private async generateSystemOverview(systemName: string, knowledge: SystemKnowledge[]): Promise<string> {
    if (knowledge.length === 0) {
      return `The ${systemName} system is a component of the application architecture. No detailed analysis is currently available.`;
    }

    let overview = `The ${systemName} system is a critical component that handles `;
    
    // Extract main responsibilities
    const responsibilities = new Set<string>();
    knowledge.forEach(k => {
      if (k.description) {
        // Extract key functionality from descriptions
        if (k.description.includes('auth')) responsibilities.add('authentication');
        if (k.description.includes('permission')) responsibilities.add('authorization');
        if (k.description.includes('data')) responsibilities.add('data management');
        if (k.description.includes('api')) responsibilities.add('API operations');
        if (k.description.includes('security')) responsibilities.add('security controls');
      }
    });

    if (responsibilities.size > 0) {
      overview += Array.from(responsibilities).join(', ');
    } else {
      overview += 'core application functionality';
    }

    overview += `. It consists of ${knowledge.length} components working together to provide `;

    // Determine system purpose
    if (systemName.toLowerCase().includes('auth')) {
      overview += 'secure user authentication and session management';
    } else if (systemName.toLowerCase().includes('api')) {
      overview += 'robust API services with proper security controls';
    } else if (systemName.toLowerCase().includes('database')) {
      overview += 'secure data access with multi-tenant isolation';
    } else {
      overview += 'essential application services';
    }

    overview += '.';

    return overview;
  }

  private async explainComponents(systemName: string, architecture: SystemArchitecture): Promise<ComponentExplanation[]> {
    const relevantComponents = architecture.systems.filter(comp => 
      comp.name.toLowerCase().includes(systemName.toLowerCase()) ||
      systemName.toLowerCase().includes(comp.name.toLowerCase()) ||
      systemName.toLowerCase() === 'architecture' // Show all for architecture queries
    );

    return relevantComponents.map(comp => ({
      name: comp.name,
      purpose: this.generateComponentPurpose(comp),
      responsibilities: comp.responsibilities,
      interfaces: this.extractInterfaces(comp),
      dependencies: this.extractDependencies(comp, architecture),
      securityLevel: comp.securityLevel,
      codeLocation: comp.files
    }));
  }

  private async explainDataFlow(systemName: string): Promise<DataFlowExplanation[]> {
    const flows: DataFlowExplanation[] = [];
    
    // Get relevant flows
    const flowNames = ['authentication', 'api_request', 'data_access'];
    
    for (const flowName of flowNames) {
      const flow = this.knowledgeExtractor.getSystemFlow(flowName);
      if (flow && (systemName.toLowerCase() === 'architecture' || 
                   flowName.includes(systemName.toLowerCase()) ||
                   systemName.toLowerCase().includes(flowName))) {
        
        flows.push({
          name: flow.name,
          description: flow.description,
          steps: flow.steps.map(step => `${step.step}. ${step.action}: ${step.description}`),
          securityPoints: flow.securityCheckpoints.map(cp => `${cp.name}: ${cp.description}`),
          diagram: this.generateFlowDiagram(flow)
        });
      }
    }

    return flows;
  }

  private explainSecurity(securityModel: SecurityModel): SecurityExplanation {
    return {
      overview: this.generateSecurityOverview(securityModel),
      authenticationMethods: securityModel.authenticationMethods,
      authorizationModel: securityModel.authorizationModel,
      dataProtection: securityModel.dataProtection,
      trustBoundaries: securityModel.trustBoundaries,
      commonThreats: this.generateThreatExplanations(securityModel.threatModel)
    };
  }

  explainArchitecture(architecture?: SystemArchitecture): ArchitectureExplanation {
    const arch = architecture || this.knowledgeExtractor.getArchitecture();
    return {
      overview: this.generateArchitectureOverview(arch),
      layers: this.generateLayerExplanations(arch),
      patterns: this.generatePatternExplanations(),
      decisions: this.generateArchitecturalDecisions()
    };
  }

  private async generateImplementationGuide(systemName: string): Promise<ImplementationGuide> {
    const patterns = await this.getSystemPatterns(systemName);
    
    return {
      gettingStarted: this.generateGettingStartedSteps(systemName),
      commonPatterns: await this.generateCodePatterns(systemName),
      bestPractices: this.generateBestPractices(systemName),
      antiPatterns: this.generateAntiPatterns(systemName)
    };
  }

  private async generateTroubleshootingGuide(systemName: string): Promise<TroubleshootingGuide> {
    return {
      commonIssues: await this.generateCommonIssues(systemName),
      debuggingSteps: this.generateDebuggingSteps(systemName),
      securityChecklist: this.generateSecurityChecklist(systemName)
    };
  }

  // Helper methods
  private getSecurityIcon(security: string): string {
    switch (security) {
      case 'encrypted': return '🔐';
      case 'authenticated': return '🔑';
      case 'validated': return '✅';
      default: return '⚠️';
    }
  }

  private getRiskIcon(risk: string): string {
    switch (risk) {
      case 'high': return '🔴';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  }

  private getSecurityLevelIcon(level: string): string {
    switch (level) {
      case 'public': return '🌐';
      case 'authenticated': return '🔑';
      case 'authorized': return '🛡️';
      case 'internal': return '🔒';
      default: return '❓';
    }
  }

  private generateComponentPurpose(comp: SystemComponent): string {
    const purposes = new Map([
      ['api', 'Handles HTTP requests and responses, providing the interface between clients and business logic'],
      ['database', 'Manages data persistence, ensuring data integrity and security'],
      ['service', 'Implements core business logic and coordinates between different system components'],
      ['middleware', 'Provides cross-cutting concerns like authentication, logging, and request processing'],
      ['component', 'Implements specific functionality within the application architecture']
    ]);

    return purposes.get(comp.type) || `Implements ${comp.name} functionality within the system`;
  }

  private extractInterfaces(comp: SystemComponent): string[] {
    // This would be enhanced with actual interface analysis
    const interfaces: string[] = [];
    
    if (comp.type === 'api') {
      interfaces.push('HTTP REST API', 'JSON Request/Response');
    }
    if (comp.type === 'database') {
      interfaces.push('SQL Interface', 'Connection Pool');
    }
    if (comp.responsibilities.includes('Authentication')) {
      interfaces.push('JWT Token Interface');
    }

    return interfaces;
  }

  private extractDependencies(comp: SystemComponent, architecture: SystemArchitecture): string[] {
    const dependencies: string[] = [];
    
    architecture.connections.forEach(conn => {
      if (conn.from === comp.name) {
        dependencies.push(`→ ${conn.to} (${conn.type})`);
      }
    });

    return dependencies;
  }

  private generateSecurityOverview(securityModel: SecurityModel): string {
    let overview = `The security model implements ${securityModel.authorizationModel} `;
    overview += `with ${securityModel.authenticationMethods.length} authentication methods. `;
    overview += `Data protection includes ${securityModel.dataProtection.join(', ')}. `;
    overview += `Trust boundaries are established at ${securityModel.trustBoundaries.join(', ')}.`;
    
    if (securityModel.threatModel.length > 0) {
      overview += ` Current threat analysis identifies ${securityModel.threatModel.length} potential security risks.`;
    }

    return overview;
  }

  private generateThreatExplanations(threats: SecurityRisk[]): ThreatExplanation[] {
    return threats.map(threat => ({
      threat: threat.type,
      description: threat.description,
      impact: threat.impact,
      prevention: [threat.mitigation],
      detection: ['Monitor authentication logs', 'Implement anomaly detection', 'Regular security audits']
    }));
  }

  private generateArchitectureOverview(architecture: SystemArchitecture): string {
    const componentTypes = new Set(architecture.systems.map(s => s.type));
    const overview = `The system architecture consists of ${architecture.systems.length} components ` +
                    `organized across ${componentTypes.size} layers (${Array.from(componentTypes).join(', ')}). ` +
                    `It implements ${architecture.securityBoundaries.length} security boundaries ` +
                    `and manages ${architecture.dataStores.length} data stores with appropriate security controls.`;
    
    return overview;
  }

  private generateLayerExplanations(architecture: SystemArchitecture): LayerExplanation[] {
    const layers = new Map<string, SystemComponent[]>();
    
    architecture.systems.forEach(system => {
      if (!layers.has(system.type)) {
        layers.set(system.type, []);
      }
      layers.get(system.type)!.push(system);
    });

    const layerExplanations: LayerExplanation[] = [];
    
    layers.forEach((components, type) => {
      const allResponsibilities = new Set<string>();
      components.forEach(comp => {
        comp.responsibilities.forEach(resp => allResponsibilities.add(resp));
      });

      layerExplanations.push({
        name: type.charAt(0).toUpperCase() + type.slice(1) + ' Layer',
        purpose: this.getLayerPurpose(type),
        components: components.map(c => c.name),
        responsibilities: Array.from(allResponsibilities)
      });
    });

    return layerExplanations;
  }

  private getLayerPurpose(type: string): string {
    const purposes = new Map([
      ['api', 'Provides external interfaces and handles client communication'],
      ['middleware', 'Implements cross-cutting concerns and request processing'],
      ['service', 'Contains business logic and core application functionality'],
      ['database', 'Manages data persistence and ensures data integrity'],
      ['component', 'Implements specific UI and application components']
    ]);

    return purposes.get(type) || `Handles ${type}-related functionality`;
  }

  private generatePatternExplanations(): PatternExplanation[] {
    return [
      {
        name: 'Multi-tenant Architecture',
        description: 'Complete data isolation between organizations using separate database instances',
        benefits: ['Complete data isolation', 'Scalable per-tenant', 'Regulatory compliance'],
        tradeoffs: ['Complex connection management', 'Higher resource usage'],
        examples: ['Organization-scoped database connections', 'Tenant-aware middleware']
      },
      {
        name: 'JWT-based Authentication',
        description: 'Stateless authentication using JSON Web Tokens with embedded claims',
        benefits: ['Stateless', 'Scalable', 'Cross-domain support'],
        tradeoffs: ['Token size', 'Revocation complexity'],
        examples: ['Auth middleware', 'Token validation']
      },
      {
        name: 'Row Level Security (RLS)',
        description: 'Database-level security policies that filter data based on user context',
        benefits: ['Database-enforced security', 'Automatic filtering', 'Audit compliance'],
        tradeoffs: ['Performance overhead', 'Complex policy management'],
        examples: ['Organization-scoped queries', 'User-based data access']
      }
    ];
  }

  private generateArchitecturalDecisions(): ArchitecturalDecision[] {
    return [
      {
        decision: 'Multi-tenant database per organization',
        rationale: 'Complete data isolation and regulatory compliance requirements',
        alternatives: ['Shared database with tenant ID', 'Schema-per-tenant'],
        consequences: ['Complex connection management', 'Higher operational overhead', 'Maximum security']
      },
      {
        decision: 'JWT tokens for authentication',
        rationale: 'Stateless authentication supporting multiple clients and services',
        alternatives: ['Server-side sessions', 'OAuth refresh tokens'],
        consequences: ['Token management complexity', 'Stateless scalability', 'Cross-service auth']
      }
    ];
  }

  private generateGettingStartedSteps(systemName: string): string[] {
    const steps = new Map([
      ['Authentication', [
        'Understand the JWT token structure and claims',
        'Review the requireAuthWithTenant() middleware implementation',
        'Test authentication flow with different user roles',
        'Examine session management and token refresh logic'
      ]],
      ['API', [
        'Study the standard API endpoint pattern',
        'Review authentication and authorization middleware',
        'Understand error handling and response formatting',
        'Examine input validation patterns'
      ]],
      ['Database', [
        'Understand the multi-tenant architecture',
        'Review RLS policies and organization isolation',
        'Study secure connection patterns',
        'Examine query optimization techniques'
      ]]
    ]);

    return steps.get(systemName) || [
      'Review the system architecture documentation',
      'Examine existing code patterns and implementations',
      'Understand security requirements and constraints',
      'Study integration points with other systems'
    ];
  }

  private async generateCodePatterns(systemName: string): Promise<CodePattern[]> {
    // This would be enhanced with actual pattern analysis from the database
    const patterns: CodePattern[] = [];

    if (systemName.toLowerCase().includes('auth')) {
      patterns.push({
        name: 'Secure API Endpoint',
        description: 'Standard pattern for implementing authenticated API endpoints',
        code: `export async function GET() {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant();
    
    if (!hasPermission(role, 'read:resource')) {
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
        explanation: 'This pattern ensures proper authentication, authorization, and error handling',
        whenToUse: 'For any API endpoint that requires user authentication and data access'
      });
    }

    return patterns;
  }

  private generateBestPractices(systemName: string): string[] {
    const practices = new Map([
      ['Authentication', [
        'Always validate JWT tokens on every request',
        'Include organization context in all database operations',
        'Implement proper session timeout and refresh',
        'Log authentication events for audit purposes'
      ]],
      ['API', [
        'Use requireAuthWithTenant() for all protected endpoints',
        'Implement proper input validation and sanitization',
        'Return consistent error responses',
        'Use appropriate HTTP status codes'
      ]],
      ['Database', [
        'Never use direct database connections',
        'Always use getOrgDatabaseWithAuth() for data access',
        'Implement proper connection pooling',
        'Test RLS policies thoroughly'
      ]]
    ]);

    return practices.get(systemName) || [
      'Follow established security patterns',
      'Implement proper error handling',
      'Use consistent coding conventions',
      'Document security considerations'
    ];
  }

  private generateAntiPatterns(systemName: string): AntiPattern[] {
    return [
      {
        name: 'Direct Database Access',
        description: 'Bypassing authentication middleware to access database directly',
        whyBad: 'Circumvents security controls and RLS policies',
        correctApproach: 'Always use getOrgDatabaseWithAuth() for authenticated access',
        example: 'const db = drizzle(connectionString) ❌ → const db = await getOrgDatabaseWithAuth() ✅'
      },
      {
        name: 'Hardcoded Organization IDs',
        description: 'Using fixed organization identifiers in queries',
        whyBad: 'Breaks multi-tenant isolation and security',
        correctApproach: 'Extract orgSlug from authenticated context',
        example: `getOrgData('acme-corp') ❌ → getOrgData(orgSlug) ✅`
      }
    ];
  }

  private async generateCommonIssues(systemName: string): Promise<TroubleshootingIssue[]> {
    return [
      {
        problem: 'Authentication failures',
        symptoms: ['401 Unauthorized responses', 'Token validation errors', 'Login redirects'],
        causes: ['Expired JWT tokens', 'Invalid token signature', 'Missing organization context'],
        solutions: ['Check token expiration', 'Verify JWT secret configuration', 'Ensure organization membership']
      },
      {
        problem: 'Authorization errors',
        symptoms: ['403 Forbidden responses', 'Permission denied errors'],
        causes: ['Insufficient user permissions', 'Incorrect role assignment', 'Missing RBAC checks'],
        solutions: ['Verify user roles', 'Check permission mappings', 'Implement proper authorization checks']
      }
    ];
  }

  private generateDebuggingSteps(systemName: string): string[] {
    return [
      'Check authentication logs for failed login attempts',
      'Verify JWT token structure and claims',
      'Test database connections and RLS policies',
      'Validate API request/response patterns',
      'Review error logs for security issues',
      'Monitor performance metrics and bottlenecks'
    ];
  }

  private generateSecurityChecklist(systemName: string): string[] {
    return [
      '✅ All endpoints use requireAuthWithTenant()',
      '✅ Database access uses getOrgDatabaseWithAuth()',
      '✅ Input validation is implemented',
      '✅ Error messages don\'t expose sensitive data',
      '✅ Audit logging is configured',
      '✅ RLS policies are tested',
      '✅ JWT tokens are properly validated',
      '✅ Organization isolation is enforced'
    ];
  }

  private async getSystemPatterns(systemName: string): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM patterns 
      WHERE category LIKE ? OR name LIKE ?
      LIMIT 10
    `);
    const searchTerm = `%${systemName.toLowerCase()}%`;
    return stmt.all(searchTerm, searchTerm) as any[];
  }

  /**
   * Trace data flow for a specific component
   */
  async traceDataFlow(component: string): Promise<DataFlowTrace> {
    logger.debug(`Tracing data flow for component: ${component}`);
    
    try {
      const architecture = this.knowledgeExtractor.getArchitecture();
      const targetComponent = architecture.systems.find(s => 
        s.name.toLowerCase() === component.toLowerCase() ||
        component.toLowerCase().includes(s.name.toLowerCase())
      );

      if (!targetComponent) {
        return {
          component,
          flow: [`Component "${component}" not found in architecture`],
          dataTypes: [],
          securityControls: []
        };
      }

      const connections = architecture.connections.filter(conn => 
        conn.from === targetComponent.name || conn.to === targetComponent.name
      );

      const flow = connections.map(conn => 
        conn.from === targetComponent.name ? 
        `${conn.from} → ${conn.to} (${conn.type})` :
        `${conn.from} → ${conn.to} (${conn.type})`
      );

      return {
        component: targetComponent.name,
        flow,
        dataTypes: ['user_data', 'system_data'], // Would be extracted from actual analysis
        securityControls: targetComponent.securityLevel ? [targetComponent.securityLevel] : []
      };
    } catch (error) {
      logger.error(`Failed to trace data flow for ${component}:`, error);
      return {
        component,
        flow: ['Error tracing data flow'],
        dataTypes: [],
        securityControls: []
      };
    }
  }

  /**
   * Explain security aspects of a specific component
   */
  async explainComponentSecurity(component: string): Promise<SecurityExplanation> {
    logger.debug(`Explaining security for component: ${component}`);
    
    try {
      const securityModel = this.knowledgeExtractor.getSecurityModel();
      const architecture = this.knowledgeExtractor.getArchitecture();
      
      const targetComponent = architecture.systems.find(s => 
        s.name.toLowerCase() === component.toLowerCase()
      );

      if (!targetComponent) {
        return {
          overview: `Component "${component}" not found for security analysis`,
          authenticationMethods: [],
          authorizationModel: 'unknown',
          dataProtection: [],
          trustBoundaries: [],
          commonThreats: []
        };
      }

      // Filter security information relevant to this component
      const relevantBoundaries = architecture.securityBoundaries
        .filter(boundary => boundary.components.includes(targetComponent.name))
        .map(boundary => boundary.name);

      const componentThreats = securityModel.threatModel.filter(threat =>
        threat.description.toLowerCase().includes(component.toLowerCase()) ||
        threat.type.toLowerCase().includes('component')
      );

      return {
        overview: `Security analysis for ${component}: ${targetComponent.securityLevel} security level`,
        authenticationMethods: securityModel.authenticationMethods,
        authorizationModel: securityModel.authorizationModel,
        dataProtection: securityModel.dataProtection,
        trustBoundaries: relevantBoundaries,
        commonThreats: this.generateThreatExplanations(componentThreats)
      };
    } catch (error) {
      logger.error(`Failed to explain security for ${component}:`, error);
      return {
        overview: 'Error analyzing component security',
        authenticationMethods: [],
        authorizationModel: 'unknown',
        dataProtection: [],
        trustBoundaries: [],
        commonThreats: []
      };
    }
  }

  /**
   * Generate comprehensive system documentation
   */
  async generateSystemDocumentation(config: DocumentationConfig): Promise<Documentation> {
    logger.info('Generating system documentation');
    
    try {
      let content = '';
      const sections: string[] = [];

      if (config.includeArchitecture) {
        const architecture = this.explainArchitecture();
        content += this.formatArchitectureDocumentation(architecture, config.format);
        sections.push('Architecture');
      }

      if (config.includeSecurity) {
        const securityModel = this.knowledgeExtractor.getSecurityModel();
        const security = this.explainSecurity(securityModel);
        content += this.formatSecurityDocumentation(security, config.format);
        sections.push('Security');
      }

      if (config.includeDataFlow) {
        const dataFlow = await this.explainDataFlow('architecture');
        content += this.formatDataFlowDocumentation(dataFlow, config.format);
        sections.push('Data Flow');
      }

      return {
        title: 'System Documentation',
        content,
        sections
      };
    } catch (error) {
      logger.error('Failed to generate system documentation:', error);
      return {
        title: 'System Documentation',
        content: 'Error generating documentation',
        sections: []
      };
    }
  }

  private formatArchitectureDocumentation(architecture: ArchitectureExplanation, format: string): string {
    if (format === 'markdown') {
      let doc = '# Architecture\n\n';
      doc += `${architecture.overview}\n\n`;
      doc += '## Layers\n\n';
      architecture.layers.forEach(layer => {
        doc += `### ${layer.name}\n`;
        doc += `${layer.purpose}\n\n`;
        doc += '**Components:** ' + layer.components.join(', ') + '\n\n';
        doc += '**Responsibilities:**\n';
        layer.responsibilities.forEach(resp => doc += `- ${resp}\n`);
        doc += '\n';
      });
      return doc;
    }
    return JSON.stringify(architecture, null, 2);
  }

  private formatSecurityDocumentation(security: SecurityExplanation, format: string): string {
    if (format === 'markdown') {
      let doc = '# Security Model\n\n';
      doc += `${security.overview}\n\n`;
      doc += '## Authentication Methods\n\n';
      security.authenticationMethods.forEach(method => doc += `- ${method}\n`);
      doc += `\n## Authorization Model\n\n${security.authorizationModel}\n\n`;
      return doc;
    }
    return JSON.stringify(security, null, 2);
  }

  private formatDataFlowDocumentation(dataFlow: DataFlowExplanation[], format: string): string {
    if (format === 'markdown') {
      let doc = '# Data Flow\n\n';
      dataFlow.forEach(flow => {
        doc += `## ${flow.name}\n\n`;
        doc += `${flow.description}\n\n`;
        doc += '### Steps\n\n';
        flow.steps.forEach(step => doc += `- ${step}\n`);
        doc += '\n';
      });
      return doc;
    }
    return JSON.stringify(dataFlow, null, 2);
  }
}

export default SystemExplainer;