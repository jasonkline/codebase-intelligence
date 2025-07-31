import { ParsedFile, ParsedSymbol } from '../parser/ASTParser';
import { 
  SystemAnalysisResult, 
  AuthPattern, 
  RBACPattern, 
  DataAccessPattern, 
  APIPattern,
  SystemDependency 
} from '../parser/SystemAnalyzer';
import { SystemKnowledge } from '../database/schema';
import logger from '../utils/logger';

export interface SystemFlow {
  name: string;
  description: string;
  steps: FlowStep[];
  securityCheckpoints: SecurityCheckpoint[];
  dataFlow: DataFlowStep[];
  risks: SecurityRisk[];
}

export interface FlowStep {
  step: number;
  action: string;
  component: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
}

export interface SecurityCheckpoint {
  name: string;
  type: 'authentication' | 'authorization' | 'validation' | 'sanitization';
  location: string;
  description: string;
  isImplemented: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface DataFlowStep {
  step: number;
  from: string;
  to: string;
  data: string;
  security: 'encrypted' | 'authenticated' | 'validated' | 'none';
  riskLevel: 'high' | 'medium' | 'low';
}

export interface SecurityRisk {
  type: string;
  description: string;
  impact: 'high' | 'medium' | 'low';
  likelihood: 'high' | 'medium' | 'low';
  mitigation: string;
  location?: string;
}

export interface SystemArchitecture {
  systems: SystemComponent[];
  connections: SystemConnection[];
  securityBoundaries: SecurityBoundary[];
  dataStores: DataStore[];
}

export interface SystemComponent {
  name: string;
  type: 'api' | 'database' | 'service' | 'middleware' | 'component';
  description: string;
  responsibilities: string[];
  securityLevel: 'public' | 'authenticated' | 'authorized' | 'internal';
  files: string[];
}

export interface SystemConnection {
  from: string;
  to: string;
  type: 'call' | 'import' | 'data_flow' | 'dependency';
  security: 'secure' | 'insecure' | 'unknown';
  description: string;
}

export interface SecurityBoundary {
  name: string;
  components: string[];
  protectionLevel: 'high' | 'medium' | 'low';
  controls: string[];
}

export interface DataStore {
  name: string;
  type: 'database' | 'cache' | 'file' | 'memory';
  sensitivity: 'high' | 'medium' | 'low';
  protections: string[];
  access_patterns: string[];
}

export interface KnowledgeGraph {
  systems: Map<string, SystemKnowledge>;
  flows: Map<string, SystemFlow>;
  architecture: SystemArchitecture;
  securityModel: SecurityModel;
}

export interface SecurityModel {
  authenticationMethods: string[];
  authorizationModel: string;
  dataProtection: string[];
  trustBoundaries: string[];
  threatModel: SecurityRisk[];
}

export class KnowledgeExtractor {
  private knowledgeGraph: KnowledgeGraph;
  
  constructor() {
    this.knowledgeGraph = {
      systems: new Map(),
      flows: new Map(),
      architecture: {
        systems: [],
        connections: [],
        securityBoundaries: [],
        dataStores: []
      },
      securityModel: {
        authenticationMethods: [],
        authorizationModel: '',
        dataProtection: [],
        trustBoundaries: [],
        threatModel: []
      }
    };
  }

  analyzeSystemKnowledge(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): KnowledgeGraph {
    try {
      logger.info('Starting system knowledge extraction...');

      // Extract system components and their knowledge
      this.extractSystemComponents(parsedFiles, analysisResults);
      
      // Build system flows
      this.buildSystemFlows(parsedFiles, analysisResults);
      
      // Analyze architecture
      this.analyzeArchitecture(parsedFiles, analysisResults);
      
      // Build security model
      this.buildSecurityModel(analysisResults);
      
      logger.info('System knowledge extraction completed');
      return this.knowledgeGraph;

    } catch (error) {
      logger.error('Failed to extract system knowledge:', error);
      return this.knowledgeGraph;
    }
  }

  private extractSystemComponents(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): void {
    const systemMap = new Map<string, SystemComponent>();

    parsedFiles.forEach(file => {
      const analysis = analysisResults.get(file.filePath);
      if (!analysis) return;

      // Identify system based on file path and patterns
      const systemName = this.identifySystem(file.filePath, analysis);
      const systemType = this.identifySystemType(file.filePath, analysis);
      
      if (!systemMap.has(systemName)) {
        systemMap.set(systemName, {
          name: systemName,
          type: systemType,
          description: this.generateSystemDescription(systemName, systemType, analysis),
          responsibilities: this.extractResponsibilities(analysis),
          securityLevel: this.determineSecurityLevel(analysis),
          files: []
        });
      }

      const system = systemMap.get(systemName)!;
      system.files.push(file.filePath);

      // Create knowledge entry
      const knowledge: SystemKnowledge = {
        system_name: systemName,
        component: file.filePath.split('/').pop() || '',
        description: this.generateComponentDescription(file, analysis),
        implementation_details: this.extractImplementationDetails(file, analysis),
        security_considerations: this.extractSecurityConsiderations(analysis),
        related_files: JSON.stringify(system.files),
        related_patterns: JSON.stringify(this.extractRelatedPatterns(analysis)),
        last_updated: new Date().toISOString()
      };

      this.knowledgeGraph.systems.set(`${systemName}:${file.filePath}`, knowledge);
    });

    this.knowledgeGraph.architecture.systems = Array.from(systemMap.values());
  }

  private buildSystemFlows(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): void {
    // Build authentication flow
    const authFlow = this.buildAuthenticationFlow(parsedFiles, analysisResults);
    if (authFlow) {
      this.knowledgeGraph.flows.set('authentication', authFlow);
    }

    // Build API request flow
    const apiFlow = this.buildAPIRequestFlow(parsedFiles, analysisResults);
    if (apiFlow) {
      this.knowledgeGraph.flows.set('api_request', apiFlow);
    }

    // Build data access flow
    const dataFlow = this.buildDataAccessFlow(parsedFiles, analysisResults);
    if (dataFlow) {
      this.knowledgeGraph.flows.set('data_access', dataFlow);
    }
  }

  private buildAuthenticationFlow(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): SystemFlow | null {
    const authPatterns: AuthPattern[] = [];
    const securityCheckpoints: SecurityCheckpoint[] = [];

    // Collect all auth patterns
    analysisResults.forEach(analysis => {
      authPatterns.push(...analysis.authPatterns);
    });

    if (authPatterns.length === 0) return null;

    // Build flow steps
    const steps: FlowStep[] = [
      {
        step: 1,
        action: 'User Login Request',
        component: 'Client',
        description: 'User submits credentials via login form'
      },
      {
        step: 2,
        action: 'Authentication Validation',
        component: 'Auth Service',
        description: 'Validate credentials against authentication provider'
      },
      {
        step: 3,
        action: 'JWT Token Generation',
        component: 'Auth Service', 
        description: 'Generate JWT token with user claims and organization context'
      },
      {
        step: 4,
        action: 'Token Verification',
        component: 'API Middleware',
        description: 'Verify JWT token on each API request'
      },
      {
        step: 5,
        action: 'User Context Extraction',
        component: 'Auth Middleware',
        description: 'Extract user, role, and organization from validated token'
      }
    ];

    // Add security checkpoints
    authPatterns.forEach(pattern => {
      if (pattern.type === 'auth_check' || pattern.type === 'auth_required') {
        securityCheckpoints.push({
          name: pattern.functionName,
          type: 'authentication',
          location: `${pattern.filePath}:${pattern.lineStart}`,
          description: `Authentication check using ${pattern.functionName}`,
          isImplemented: true,
          severity: 'critical'
        });
      }
    });

    return {
      name: 'User Authentication Flow',
      description: 'Complete user authentication process from login to token validation',
      steps,
      securityCheckpoints,
      dataFlow: this.buildAuthDataFlow(),
      risks: this.identifyAuthRisks(authPatterns)
    };
  }

  private buildAPIRequestFlow(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): SystemFlow | null {
    const apiPatterns: APIPattern[] = [];
    
    analysisResults.forEach(analysis => {
      apiPatterns.push(...analysis.apiPatterns);
    });

    if (apiPatterns.length === 0) return null;

    const steps: FlowStep[] = [
      {
        step: 1,
        action: 'API Request',
        component: 'Client',
        description: 'Client sends API request with authentication token'
      },
      {
        step: 2,
        action: 'Authentication Check',
        component: 'API Middleware',
        description: 'Verify JWT token and extract user context'
      },
      {
        step: 3,
        action: 'Authorization Check',
        component: 'RBAC Middleware',
        description: 'Verify user has required permissions for the resource'
      },
      {
        step: 4,
        action: 'Request Processing',
        component: 'API Handler',
        description: 'Process the request with validated user context'
      },
      {
        step: 5,
        action: 'Response',
        component: 'API Handler',
        description: 'Return processed response to client'
      }
    ];

    const securityCheckpoints: SecurityCheckpoint[] = [];
    apiPatterns.forEach(pattern => {
      securityCheckpoints.push({
        name: `${pattern.method} Security`,
        type: pattern.hasAuth ? 'authentication' : 'validation',
        location: `${pattern.filePath}:${pattern.lineStart}`,
        description: `API ${pattern.method} handler security`,
        isImplemented: pattern.hasAuth && pattern.hasValidation,
        severity: pattern.hasAuth ? 'medium' : 'critical'
      });
    });

    return {
      name: 'API Request Processing Flow',
      description: 'Standard API request processing with authentication and authorization',
      steps,
      securityCheckpoints,
      dataFlow: this.buildAPIDataFlow(),
      risks: this.identifyAPIRisks(apiPatterns)
    };
  }

  private buildDataAccessFlow(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): SystemFlow | null {
    const dataPatterns: DataAccessPattern[] = [];
    
    analysisResults.forEach(analysis => {
      dataPatterns.push(...analysis.dataAccessPatterns);
    });

    if (dataPatterns.length === 0) return null;

    const steps: FlowStep[] = [
      {
        step: 1,
        action: 'Database Connection',
        component: 'Database Service',
        description: 'Establish authenticated database connection with organization context'
      },
      {
        step: 2,
        action: 'RLS Application',
        component: 'Database',
        description: 'Apply Row Level Security policies for organization isolation'
      },
      {
        step: 3,
        action: 'Query Execution',
        component: 'Database',
        description: 'Execute query with security context applied'
      },
      {
        step: 4,
        action: 'Result Filtering',
        component: 'Database',
        description: 'Filter results based on user permissions and organization'
      }
    ];

    const securityCheckpoints: SecurityCheckpoint[] = [];
    dataPatterns.forEach(pattern => {
      securityCheckpoints.push({
        name: `${pattern.method} Data Access`,
        type: 'authorization',
        location: `${pattern.filePath}:${pattern.lineStart}`,
        description: `Data access security for ${pattern.method}`,
        isImplemented: pattern.isSecure,
        severity: pattern.securityRisk === 'high' ? 'critical' : 'medium'
      });
    });

    return {
      name: 'Data Access Flow',
      description: 'Secure data access with organization isolation and RLS',
      steps,
      securityCheckpoints,
      dataFlow: this.buildDataAccessDataFlow(),
      risks: this.identifyDataAccessRisks(dataPatterns)
    };
  }

  private analyzeArchitecture(
    parsedFiles: ParsedFile[], 
    analysisResults: Map<string, SystemAnalysisResult>
  ): void {
    // Build system connections
    const connections: SystemConnection[] = [];
    
    analysisResults.forEach(analysis => {
      analysis.dependencies.forEach(dep => {
        connections.push({
          from: this.identifySystem(dep.from, analysis),
          to: this.identifySystem(dep.to, analysis),
          type: dep.type as SystemConnection['type'],
          security: this.assessConnectionSecurity(dep),
          description: `${dep.type} dependency`
        });
      });
    });

    this.knowledgeGraph.architecture.connections = connections;

    // Define security boundaries
    this.knowledgeGraph.architecture.securityBoundaries = [
      {
        name: 'Public API',
        components: ['API Gateway', 'Public Endpoints'],
        protectionLevel: 'high',
        controls: ['Authentication', 'Rate Limiting', 'Input Validation']
      },
      {
        name: 'Authenticated Services',
        components: ['API Handlers', 'Business Logic'],
        protectionLevel: 'high',
        controls: ['JWT Validation', 'RBAC', 'Audit Logging']
      },
      {
        name: 'Data Layer',
        components: ['Database', 'Cache'],
        protectionLevel: 'high',
        controls: ['RLS', 'Encryption', 'Connection Security']
      }
    ];

    // Define data stores
    this.knowledgeGraph.architecture.dataStores = [
      {
        name: 'Primary Database',
        type: 'database',
        sensitivity: 'high',
        protections: ['RLS', 'Encryption at Rest', 'Organization Isolation'],
        access_patterns: ['Authenticated Access Only', 'Organization Scoped']
      }
    ];
  }

  private buildSecurityModel(analysisResults: Map<string, SystemAnalysisResult>): void {
    const authMethods = new Set<string>();
    const dataProtections = new Set<string>();
    const risks: SecurityRisk[] = [];

    analysisResults.forEach(analysis => {
      // Collect auth methods
      analysis.authPatterns.forEach(pattern => {
        authMethods.add(pattern.functionName);
      });

      // Collect data protections
      analysis.dataAccessPatterns.forEach(pattern => {
        if (pattern.isSecure) {
          dataProtections.add(pattern.method || 'secure_access');
        }
      });

      // Collect security risks
      analysis.authPatterns.forEach(pattern => {
        if (pattern.type === 'auth_bypass') {
          risks.push({
            type: 'Authentication Bypass',
            description: `Potential authentication bypass in ${pattern.functionName}`,
            impact: 'high',
            likelihood: 'medium',
            mitigation: 'Implement proper authentication checks',
            location: `${pattern.filePath}:${pattern.lineStart}`
          });
        }
      });

      analysis.dataAccessPatterns.forEach(pattern => {
        if (pattern.securityRisk === 'high') {
          risks.push({
            type: 'Data Access Risk',
            description: `Insecure data access pattern detected`,
            impact: 'high',
            likelihood: 'high',
            mitigation: 'Use authenticated database connections with RLS',
            location: `${pattern.filePath}:${pattern.lineStart}`
          });
        }
      });
    });

    this.knowledgeGraph.securityModel = {
      authenticationMethods: Array.from(authMethods),
      authorizationModel: 'RBAC with Organization Isolation',
      dataProtection: Array.from(dataProtections),
      trustBoundaries: ['Client-API', 'API-Database', 'Organization Boundaries'],
      threatModel: risks
    };
  }

  // Helper methods
  private identifySystem(filePath: string, analysis: SystemAnalysisResult): string {
    if (filePath.includes('/api/')) return 'API';
    if (filePath.includes('/auth')) return 'Authentication';
    if (filePath.includes('/database') || filePath.includes('/db')) return 'Database';
    if (filePath.includes('/middleware')) return 'Middleware';
    if (filePath.includes('/components')) return 'UI Components';
    if (filePath.includes('/lib')) return 'Core Library';
    
    // Analyze patterns to determine system
    if (analysis.authPatterns.length > 0) return 'Authentication';
    if (analysis.dataAccessPatterns.length > 0) return 'Data Access';
    if (analysis.apiPatterns.length > 0) return 'API';
    
    return 'General';
  }

  private identifySystemType(filePath: string, analysis: SystemAnalysisResult): SystemComponent['type'] {
    if (filePath.includes('/api/')) return 'api';
    if (filePath.includes('/database') || filePath.includes('/db')) return 'database';
    if (filePath.includes('/middleware')) return 'middleware';
    if (filePath.includes('/service')) return 'service';
    return 'component';
  }

  private generateSystemDescription(name: string, type: string, analysis: SystemAnalysisResult): string {
    const patterns = analysis.authPatterns.length + analysis.rbacPatterns.length + 
                    analysis.dataAccessPatterns.length + analysis.apiPatterns.length;
    
    return `${name} system with ${patterns} identified patterns. ` +
           `Handles ${type} functionality with ${analysis.summary.securityIssues} security considerations.`;
  }

  private extractResponsibilities(analysis: SystemAnalysisResult): string[] {
    const responsibilities: string[] = [];
    
    if (analysis.authPatterns.length > 0) {
      responsibilities.push('User Authentication', 'Session Management');
    }
    if (analysis.rbacPatterns.length > 0) {
      responsibilities.push('Authorization', 'Permission Checking');
    }
    if (analysis.dataAccessPatterns.length > 0) {
      responsibilities.push('Data Access', 'Database Operations');
    }
    if (analysis.apiPatterns.length > 0) {
      responsibilities.push('API Request Handling', 'Response Processing');
    }
    
    return responsibilities;
  }

  private determineSecurityLevel(analysis: SystemAnalysisResult): SystemComponent['securityLevel'] {
    if (analysis.summary.securityIssues > 0) return 'public';
    if (analysis.authPatterns.length > 0) return 'authenticated';
    if (analysis.rbacPatterns.length > 0) return 'authorized';
    return 'internal';
  }

  private generateComponentDescription(file: ParsedFile, analysis: SystemAnalysisResult): string {
    const functionCount = file.symbols.filter(s => s.kind === 'function').length;
    const classCount = file.symbols.filter(s => s.kind === 'class').length;
    
    return `Component with ${functionCount} functions and ${classCount} classes. ` +
           `Contains ${analysis.authPatterns.length} auth patterns, ` +
           `${analysis.rbacPatterns.length} RBAC patterns, and ` +
           `${analysis.dataAccessPatterns.length} data access patterns.`;
  }

  private extractImplementationDetails(file: ParsedFile, analysis: SystemAnalysisResult): string {
    const details: string[] = [];
    
    details.push(`Language: ${file.language}`);
    details.push(`Imports: ${file.imports.length}`);
    details.push(`Exports: ${file.exports.length}`);
    
    if (analysis.authPatterns.length > 0) {
      details.push(`Auth functions: ${analysis.authPatterns.map(p => p.functionName).join(', ')}`);
    }
    
    return details.join('; ');
  }

  private extractSecurityConsiderations(analysis: SystemAnalysisResult): string {
    const considerations: string[] = [];
    
    if (analysis.summary.securityIssues > 0) {
      considerations.push(`${analysis.summary.securityIssues} security issues identified`);
    }
    
    if (analysis.summary.authCoverage < 100) {
      considerations.push(`Auth coverage: ${analysis.summary.authCoverage}%`);
    }
    
    analysis.dataAccessPatterns.forEach(pattern => {
      if (pattern.securityRisk === 'high') {
        considerations.push(`High-risk data access: ${pattern.method}`);
      }
    });
    
    return considerations.join('; ');
  }

  private extractRelatedPatterns(analysis: SystemAnalysisResult): string[] {
    return [
      ...analysis.authPatterns.map(p => p.type),
      ...analysis.rbacPatterns.map(p => p.type),
      ...analysis.dataAccessPatterns.map(p => p.type),
      ...analysis.apiPatterns.map(p => p.type)
    ];
  }

  private buildAuthDataFlow(): DataFlowStep[] {
    return [
      {
        step: 1,
        from: 'Client',
        to: 'Auth Service',
        data: 'User Credentials',
        security: 'encrypted',
        riskLevel: 'medium'
      },
      {
        step: 2,
        from: 'Auth Service',
        to: 'Client',
        data: 'JWT Token',
        security: 'authenticated',
        riskLevel: 'low'
      }
    ];
  }

  private buildAPIDataFlow(): DataFlowStep[] {
    return [
      {
        step: 1,
        from: 'Client',
        to: 'API',
        data: 'Request with JWT',
        security: 'authenticated',
        riskLevel: 'low'
      },
      {
        step: 2,
        from: 'API',
        to: 'Database',
        data: 'Query with Context',
        security: 'authenticated',
        riskLevel: 'low'
      }
    ];
  }

  private buildDataAccessDataFlow(): DataFlowStep[] {
    return [
      {
        step: 1,
        from: 'API',
        to: 'Database Connection',
        data: 'Organization Context',
        security: 'authenticated',
        riskLevel: 'low'
      },
      {
        step: 2,
        from: 'Database',
        to: 'API',
        data: 'Filtered Results',
        security: 'validated',
        riskLevel: 'low'
      }
    ];
  }

  private identifyAuthRisks(patterns: AuthPattern[]): SecurityRisk[] {
    const risks: SecurityRisk[] = [];
    
    patterns.forEach(pattern => {
      if (pattern.type === 'auth_bypass') {
        risks.push({
          type: 'Authentication Bypass',
          description: `Authentication bypass detected in ${pattern.functionName}`,
          impact: 'high',
          likelihood: 'medium',
          mitigation: 'Remove bypass and implement proper authentication'
        });
      }
    });
    
    return risks;
  }

  private identifyAPIRisks(patterns: APIPattern[]): SecurityRisk[] {
    const risks: SecurityRisk[] = [];
    
    patterns.forEach(pattern => {
      if (!pattern.hasAuth) {
        risks.push({
          type: 'Unauthenticated API',
          description: `API endpoint ${pattern.method} lacks authentication`,
          impact: 'high',
          likelihood: 'high',
          mitigation: 'Add authentication middleware to API endpoint'
        });
      }
      
      if (!pattern.hasValidation) {
        risks.push({
          type: 'Unvalidated Input',
          description: `API endpoint ${pattern.method} lacks input validation`,
          impact: 'medium',
          likelihood: 'high',
          mitigation: 'Add input validation schema'
        });
      }
    });
    
    return risks;
  }

  private identifyDataAccessRisks(patterns: DataAccessPattern[]): SecurityRisk[] {
    const risks: SecurityRisk[] = [];
    
    patterns.forEach(pattern => {
      if (pattern.securityRisk === 'high') {
        risks.push({
          type: 'Insecure Data Access',
          description: `High-risk data access pattern: ${pattern.method}`,
          impact: 'high',
          likelihood: 'high',
          mitigation: 'Use authenticated database connection with RLS'
        });
      }
    });
    
    return risks;
  }

  private assessConnectionSecurity(dep: SystemDependency): 'secure' | 'insecure' | 'unknown' {
    if (dep.type === 'import' && dep.to.includes('auth')) return 'secure';
    if (dep.type === 'call' && dep.strength > 7) return 'unknown';
    return 'secure';
  }

  // Public methods for querying the knowledge graph
  getSystemKnowledge(systemName: string): SystemKnowledge[] {
    const results: SystemKnowledge[] = [];
    this.knowledgeGraph.systems.forEach((knowledge, key) => {
      if (key.startsWith(systemName + ':')) {
        results.push(knowledge);
      }
    });
    return results;
  }

  getSystemFlow(flowName: string): SystemFlow | undefined {
    return this.knowledgeGraph.flows.get(flowName);
  }

  getArchitecture(): SystemArchitecture {
    return this.knowledgeGraph.architecture;
  }

  getSecurityModel(): SecurityModel {
    return this.knowledgeGraph.securityModel;
  }

  generateSystemExplanation(systemName: string): string {
    const knowledge = this.getSystemKnowledge(systemName);
    if (knowledge.length === 0) {
      return `No knowledge found for system: ${systemName}`;
    }

    const explanations = knowledge.map(k => 
      `${k.component}: ${k.description}\n` +
      `Implementation: ${k.implementation_details}\n` +
      `Security: ${k.security_considerations}`
    );

    return `## ${systemName} System\n\n${explanations.join('\n\n')}`;
  }
}

export default KnowledgeExtractor;