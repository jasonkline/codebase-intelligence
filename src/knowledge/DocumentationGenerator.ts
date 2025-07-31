import { DatabaseManager, SystemKnowledge } from '../database/schema';
import { 
  KnowledgeExtractor, 
  SystemFlow, 
  SystemArchitecture, 
  SecurityModel 
} from './KnowledgeExtractor';
import { SystemExplainer } from './SystemExplainer';
import { DependencyAnalyzer } from './DependencyAnalyzer';
import logger from '../utils/logger';

export interface DocumentationConfig {
  outputFormat: 'markdown' | 'html' | 'json';
  includeCodeExamples: boolean;
  includeDiagrams: boolean;
  includeSecurityDetails: boolean;
  includeArchitecture: boolean;
  includeTroubleshooting: boolean;
  sections: DocumentationSection[];
}

export interface DocumentationSection {
  name: string;
  enabled: boolean;
  priority: number;
  customContent?: string;
}

export interface GeneratedDocumentation {
  title: string;
  version: string;
  generatedAt: string;
  sections: DocumentationContent[];
  metadata: DocumentationMetadata;
}

export interface DocumentationContent {
  id: string;
  title: string;
  content: string;
  type: 'overview' | 'technical' | 'guide' | 'reference' | 'security';
  lastUpdated: string;
  dependencies: string[];
}

export interface DocumentationMetadata {
  totalSections: number;
  systemsCovered: string[];
  securityIssuesDocumented: number;
  codeExamplesIncluded: number;
  lastSystemAnalysis: string;
}

export interface APIDocumentation {
  endpoints: APIEndpoint[];
  authentication: AuthenticationDocs;
  errorCodes: ErrorCodeDocs[];
  examples: APIExample[];
}

export interface APIEndpoint {
  path: string;
  method: string;
  description: string;
  parameters: Parameter[];
  responses: Response[];
  authentication: string[];
  permissions: string[];
  codeExample: string;
  securityNotes: string[];
}

export interface Parameter {
  name: string;
  type: string;
  required: boolean;
  description: string;
  example: any;
}

export interface Response {
  status: number;
  description: string;
  schema?: any;
  example?: any;
}

export interface AuthenticationDocs {
  methods: string[];
  flowDiagram: string;
  implementation: string;
  securityConsiderations: string[];
}

export interface ErrorCodeDocs {
  code: number;
  message: string;
  description: string;
  resolution: string;
}

export interface APIExample {
  title: string;
  description: string;
  request: string;
  response: string;
  notes: string[];
}

export interface SecurityDocumentation {
  overview: string;
  threatModel: ThreatModelDoc[];
  securityControls: SecurityControlDoc[];
  vulnerabilities: VulnerabilityDoc[];
  guidelines: SecurityGuidelineDoc[];
  compliance: ComplianceDoc[];
}

export interface ThreatModelDoc {
  threat: string;
  description: string;
  likelihood: string;
  impact: string;
  mitigation: string[];
  residualRisk: string;
}

export interface SecurityControlDoc {
  control: string;
  description: string;
  implementation: string;
  testing: string[];
  effectiveness: string;
}

export interface VulnerabilityDoc {
  id: string;
  severity: string;
  description: string;
  location: string;
  remediation: string;
  status: string;
}

export interface SecurityGuidelineDoc {
  category: string;
  guidelines: string[];
  examples: string[];
  antiPatterns: string[];
}

export interface ComplianceDoc {
  framework: string;
  requirements: string[];
  implementation: string[];
  gaps: string[];
}

export class DocumentationGenerator {
  private db: DatabaseManager;
  private knowledgeExtractor: KnowledgeExtractor;
  private systemExplainer: SystemExplainer;
  private dependencyAnalyzer: DependencyAnalyzer;

  constructor(
    db: DatabaseManager, 
    knowledgeExtractor: KnowledgeExtractor,
    systemExplainer: SystemExplainer,
    dependencyAnalyzer: DependencyAnalyzer
  ) {
    this.db = db;
    this.knowledgeExtractor = knowledgeExtractor;
    this.systemExplainer = systemExplainer;
    this.dependencyAnalyzer = dependencyAnalyzer;
  }

  async generateComprehensiveDocumentation(config: DocumentationConfig): Promise<GeneratedDocumentation> {
    try {
      logger.info('Starting comprehensive documentation generation...');

      const sections: DocumentationContent[] = [];
      const systemsCovered: string[] = [];

      // Generate overview section
      if (this.isSectionEnabled('overview', config)) {
        const overview = await this.generateOverviewSection();
        sections.push(overview);
      }

      // Generate architecture documentation
      if (this.isSectionEnabled('architecture', config) && config.includeArchitecture) {
        const architecture = await this.generateArchitectureDocumentation();
        sections.push(architecture);
        systemsCovered.push('Architecture');
      }

      // Generate system-specific documentation
      const systems = ['Authentication', 'API', 'Database'];
      for (const system of systems) {
        if (this.isSectionEnabled(system.toLowerCase(), config)) {
          const systemDoc = await this.generateSystemDocumentation(system, config);
          sections.push(systemDoc);
          systemsCovered.push(system);
        }
      }

      // Generate API documentation
      if (this.isSectionEnabled('api', config)) {
        const apiDoc = await this.generateAPIDocumentationSection(config);
        sections.push(apiDoc);
      }

      // Generate security documentation
      if (this.isSectionEnabled('security', config) && config.includeSecurityDetails) {
        const securityDoc = await this.generateSecurityDocumentationSection();
        sections.push(securityDoc);
      }

      // Generate troubleshooting guide
      if (this.isSectionEnabled('troubleshooting', config) && config.includeTroubleshooting) {
        const troubleshooting = await this.generateTroubleshootingSection();
        sections.push(troubleshooting);
      }

      // Generate dependency documentation
      if (this.isSectionEnabled('dependencies', config)) {
        const dependencies = await this.generateDependencyDocumentation();
        sections.push(dependencies);
      }

      const documentation: GeneratedDocumentation = {
        title: 'System Documentation',
        version: '1.0.0',
        generatedAt: new Date().toISOString(),
        sections,
        metadata: {
          totalSections: sections.length,
          systemsCovered,
          securityIssuesDocumented: await this.countSecurityIssues(),
          codeExamplesIncluded: this.countCodeExamples(sections),
          lastSystemAnalysis: new Date().toISOString()
        }
      };

      logger.info(`Documentation generation completed. Generated ${sections.length} sections.`);
      return documentation;

    } catch (error) {
      logger.error('Failed to generate documentation:', error);
      throw error;
    }
  }

  async generateAPIDocumentation(): Promise<APIDocumentation> {
    logger.info('Generating API documentation...');

    const apiFlow = this.knowledgeExtractor.getSystemFlow('api_request');
    const authFlow = this.knowledgeExtractor.getSystemFlow('authentication');
    const endpoints = await this.extractAPIEndpoints();

    const documentation: APIDocumentation = {
      endpoints,
      authentication: {
        methods: ['JWT Token', 'Organization Context'],
        flowDiagram: authFlow ? this.systemExplainer.generateFlowDiagram(authFlow) : '',
        implementation: await this.generateAuthImplementationDocs(),
        securityConsiderations: [
          'All endpoints require valid JWT token',
          'Organization context is enforced via RLS',
          'Role-based permissions are checked per endpoint',
          'Request validation is performed on all inputs'
        ]
      },
      errorCodes: this.generateErrorCodeDocs(),
      examples: await this.generateAPIExamples()
    };

    return documentation;
  }

  async generateSecurityDocumentation(): Promise<SecurityDocumentation> {
    logger.info('Generating security documentation...');

    const securityModel = this.knowledgeExtractor.getSecurityModel();
    const vulnerabilities = await this.getSecurityVulnerabilities();

    const documentation: SecurityDocumentation = {
      overview: this.generateSecurityOverview(securityModel),
      threatModel: this.generateThreatModelDocs(securityModel.threatModel),
      securityControls: await this.generateSecurityControlDocs(),
      vulnerabilities: vulnerabilities.map(v => this.convertToVulnerabilityDoc(v)),
      guidelines: this.generateSecurityGuidelines(),
      compliance: this.generateComplianceDocs()
    };

    return documentation;
  }

  generateArchitectureDiagram(): string {
    const architecture = this.knowledgeExtractor.getArchitecture();
    return this.systemExplainer.generateArchitectureDiagram(architecture);
  }

  async updateDocumentation(systemName: string): Promise<DocumentationContent> {
    logger.info(`Updating documentation for system: ${systemName}`);

    const config: DocumentationConfig = {
      outputFormat: 'markdown',
      includeCodeExamples: true,
      includeDiagrams: true,
      includeSecurityDetails: true,
      includeArchitecture: false,
      includeTroubleshooting: true,
      sections: [{ name: systemName.toLowerCase(), enabled: true, priority: 1 }]
    };

    return await this.generateSystemDocumentation(systemName, config);
  }

  // Private helper methods
  private async generateOverviewSection(): Promise<DocumentationContent> {
    const architecture = this.knowledgeExtractor.getArchitecture();
    const securityModel = this.knowledgeExtractor.getSecurityModel();

    let content = "# System Overview\n\n";
    content += "This documentation provides comprehensive information about the system architecture, ";
    content += "security model, and implementation details.\n\n";

    content += "## System Statistics\n\n";
    content += `- **Components**: ${architecture.systems.length}\n`;
    content += `- **Security Boundaries**: ${architecture.securityBoundaries.length}\n`;
    content += `- **Data Stores**: ${architecture.dataStores.length}\n`;
    content += `- **Authentication Methods**: ${securityModel.authenticationMethods.length}\n\n`;

    content += "## Key Features\n\n";
    content += "- Multi-tenant architecture with complete data isolation\n";
    content += "- JWT-based authentication with role-based access control\n";
    content += "- Row-level security for database access\n";
    content += "- Comprehensive audit logging and monitoring\n\n";

    return {
      id: 'overview',
      title: 'System Overview',
      content,
      type: 'overview',
      lastUpdated: new Date().toISOString(),
      dependencies: []
    };
  }

  private async generateArchitectureDocumentation(): Promise<DocumentationContent> {
    const architecture = this.knowledgeExtractor.getArchitecture();
    const explanation = this.systemExplainer.explainArchitecture(architecture);

    let content = "# System Architecture\n\n";
    content += explanation.overview + "\n\n";

    content += "## Architecture Diagram\n\n";
    content += this.systemExplainer.generateArchitectureDiagram(architecture);

    content += "## System Layers\n\n";
    explanation.layers.forEach(layer => {
      content += `### ${layer.name}\n\n`;
      content += `**Purpose**: ${layer.purpose}\n\n`;
      content += `**Components**: ${layer.components.join(', ')}\n\n`;
      content += `**Responsibilities**:\n`;
      layer.responsibilities.forEach(resp => {
        content += `- ${resp}\n`;
      });
      content += '\n';
    });

    content += "## Design Patterns\n\n";
    explanation.patterns.forEach(pattern => {
      content += `### ${pattern.name}\n\n`;
      content += `${pattern.description}\n\n`;
      content += `**Benefits**:\n`;
      pattern.benefits.forEach(benefit => {
        content += `- ${benefit}\n`;
      });
      content += `\n**Trade-offs**:\n`;
      pattern.tradeoffs.forEach(tradeoff => {
        content += `- ${tradeoff}\n`;
      });
      content += '\n';
    });

    return {
      id: 'architecture',
      title: 'System Architecture',
      content,
      type: 'technical',
      lastUpdated: new Date().toISOString(),
      dependencies: ['overview']
    };
  }

  private async generateSystemDocumentation(systemName: string, config: DocumentationConfig): Promise<DocumentationContent> {
    const systemExplanation = await this.systemExplainer.explainSystem(systemName);

    let content = `# ${systemExplanation.title}\n\n`;
    content += systemExplanation.overview + "\n\n";

    // Components
    if (systemExplanation.components.length > 0) {
      content += "## Components\n\n";
      systemExplanation.components.forEach(comp => {
        content += `### ${comp.name}\n\n`;
        content += `**Purpose**: ${comp.purpose}\n\n`;
        content += `**Security Level**: ${comp.securityLevel}\n\n`;
        content += `**Responsibilities**:\n`;
        comp.responsibilities.forEach(resp => {
          content += `- ${resp}\n`;
        });
        if (comp.dependencies.length > 0) {
          content += `\n**Dependencies**: ${comp.dependencies.join(', ')}\n`;
        }
        content += '\n';
      });
    }

    // Data Flow
    if (config.includeDiagrams && systemExplanation.dataFlow.length > 0) {
      content += "## Data Flow\n\n";
      systemExplanation.dataFlow.forEach(flow => {
        content += `### ${flow.name}\n\n`;
        content += `${flow.description}\n\n`;
        content += flow.diagram;
      });
    }

    // Security Model
    if (config.includeSecurityDetails) {
      content += "## Security\n\n";
      content += systemExplanation.securityModel.overview + "\n\n";
      
      if (systemExplanation.securityModel.commonThreats.length > 0) {
        content += "### Common Threats\n\n";
        systemExplanation.securityModel.commonThreats.forEach(threat => {
          content += `**${threat.threat}** (${threat.impact} impact)\n\n`;
          content += `${threat.description}\n\n`;
          content += `**Prevention**:\n`;
          threat.prevention.forEach(prev => {
            content += `- ${prev}\n`;
          });
          content += '\n';
        });
      }
    }

    // Implementation Guide
    if (config.includeCodeExamples) {
      content += "## Implementation Guide\n\n";
      content += "### Getting Started\n\n";
      systemExplanation.implementationGuide.gettingStarted.forEach((step, index) => {
        content += `${index + 1}. ${step}\n`;
      });
      content += '\n';

      if (systemExplanation.implementationGuide.commonPatterns.length > 0) {
        content += "### Common Patterns\n\n";
        systemExplanation.implementationGuide.commonPatterns.forEach(pattern => {
          content += `#### ${pattern.name}\n\n`;
          content += `${pattern.description}\n\n`;
          content += `**When to use**: ${pattern.whenToUse}\n\n`;
          content += "```typescript\n";
          content += pattern.code;
          content += "\n```\n\n";
          content += `${pattern.explanation}\n\n`;
        });
      }
    }

    // Troubleshooting
    if (config.includeTroubleshooting) {
      content += "## Troubleshooting\n\n";
      systemExplanation.troubleshooting.commonIssues.forEach(issue => {
        content += `### ${issue.problem}\n\n`;
        content += `**Symptoms**:\n`;
        issue.symptoms.forEach(symptom => {
          content += `- ${symptom}\n`;
        });
        content += `\n**Possible Causes**:\n`;
        issue.causes.forEach(cause => {
          content += `- ${cause}\n`;
        });
        content += `\n**Solutions**:\n`;
        issue.solutions.forEach(solution => {
          content += `- ${solution}\n`;
        });
        content += '\n';
      });
    }

    return {
      id: systemName.toLowerCase(),
      title: systemExplanation.title,
      content,
      type: 'technical',
      lastUpdated: new Date().toISOString(),
      dependencies: ['overview']
    };
  }

  private async generateAPIDocumentationSection(config: DocumentationConfig): Promise<DocumentationContent> {
    const apiDoc = await this.generateAPIDocumentation();

    let content = "# API Documentation\n\n";
    
    // Authentication
    content += "## Authentication\n\n";
    content += apiDoc.authentication.implementation + "\n\n";
    if (config.includeDiagrams) {
      content += apiDoc.authentication.flowDiagram;
    }

    // Endpoints
    if (apiDoc.endpoints.length > 0) {
      content += "## Endpoints\n\n";
      apiDoc.endpoints.forEach(endpoint => {
        content += `### ${endpoint.method} ${endpoint.path}\n\n`;
        content += `${endpoint.description}\n\n`;
        
        content += `**Authentication**: ${endpoint.authentication.join(', ')}\n\n`;
        content += `**Permissions**: ${endpoint.permissions.join(', ')}\n\n`;
        
        if (endpoint.parameters.length > 0) {
          content += "**Parameters**:\n\n";
          endpoint.parameters.forEach(param => {
            const required = param.required ? '**required**' : 'optional';
            content += `- \`${param.name}\` (${param.type}) - ${required}: ${param.description}\n`;
          });
          content += '\n';
        }

        if (config.includeCodeExamples && endpoint.codeExample) {
          content += "**Example**:\n\n";
          content += "```typescript\n";
          content += endpoint.codeExample;
          content += "\n```\n\n";
        }

        if (config.includeSecurityDetails && endpoint.securityNotes.length > 0) {
          content += "**Security Notes**:\n";
          endpoint.securityNotes.forEach(note => {
            content += `- ${note}\n`;
          });
          content += '\n';
        }
      });
    }

    // Error Codes
    content += "## Error Codes\n\n";
    apiDoc.errorCodes.forEach(error => {
      content += `### ${error.code} - ${error.message}\n\n`;
      content += `${error.description}\n\n`;
      content += `**Resolution**: ${error.resolution}\n\n`;
    });

    return {
      id: 'api',
      title: 'API Documentation',
      content,
      type: 'reference',
      lastUpdated: new Date().toISOString(),
      dependencies: ['authentication']
    };
  }

  private async generateSecurityDocumentationSection(): Promise<DocumentationContent> {
    const securityDoc = await this.generateSecurityDocumentation();

    let content = "# Security Documentation\n\n";
    content += securityDoc.overview + "\n\n";

    // Security Controls
    content += "## Security Controls\n\n";
    securityDoc.securityControls.forEach(control => {
      content += `### ${control.control}\n\n`;
      content += `${control.description}\n\n`;
      content += `**Implementation**: ${control.implementation}\n\n`;
      content += `**Effectiveness**: ${control.effectiveness}\n\n`;
    });

    // Vulnerabilities
    if (securityDoc.vulnerabilities.length > 0) {
      content += "## Current Vulnerabilities\n\n";
      securityDoc.vulnerabilities.forEach(vuln => {
        content += `### ${vuln.id} - ${vuln.severity.toUpperCase()}\n\n`;
        content += `**Location**: ${vuln.location}\n\n`;
        content += `${vuln.description}\n\n`;
        content += `**Remediation**: ${vuln.remediation}\n\n`;
        content += `**Status**: ${vuln.status}\n\n`;
      });
    }

    // Guidelines
    content += "## Security Guidelines\n\n";
    securityDoc.guidelines.forEach(guideline => {
      content += `### ${guideline.category}\n\n`;
      guideline.guidelines.forEach(guide => {
        content += `- ${guide}\n`;
      });
      content += '\n';
    });

    return {
      id: 'security',
      title: 'Security Documentation',
      content,
      type: 'security',
      lastUpdated: new Date().toISOString(),
      dependencies: ['overview', 'architecture']
    };
  }

  private async generateTroubleshootingSection(): Promise<DocumentationContent> {
    let content = "# Troubleshooting Guide\n\n";
    
    content += "## Common Issues\n\n";
    
    // Authentication issues
    content += "### Authentication Problems\n\n";
    content += "**Symptoms**: 401 Unauthorized, token validation errors\n\n";
    content += "**Solutions**:\n";
    content += "1. Check JWT token expiration\n";
    content += "2. Verify token signature\n";
    content += "3. Ensure organization context is included\n\n";

    // Authorization issues
    content += "### Authorization Problems\n\n";
    content += "**Symptoms**: 403 Forbidden responses\n\n";
    content += "**Solutions**:\n";
    content += "1. Verify user role assignments\n";
    content += "2. Check permission mappings\n";
    content += "3. Validate RBAC implementation\n\n";

    // Database issues
    content += "### Database Access Issues\n\n";
    content += "**Symptoms**: Empty results, connection errors\n\n";
    content += "**Solutions**:\n";
    content += "1. Verify RLS policies are active\n";
    content += "2. Check organization context in queries\n";
    content += "3. Validate database connection configuration\n\n";

    return {
      id: 'troubleshooting',
      title: 'Troubleshooting Guide',
      content,
      type: 'guide',
      lastUpdated: new Date().toISOString(),
      dependencies: []
    };
  }

  private async generateDependencyDocumentation(): Promise<DocumentationContent> {
    const dependencyReport = this.dependencyAnalyzer.generateDependencyReport();

    return {
      id: 'dependencies',
      title: 'Dependency Analysis',
      content: dependencyReport,
      type: 'technical',
      lastUpdated: new Date().toISOString(),
      dependencies: ['architecture']
    };
  }

  // Helper methods for specific documentation types
  private async extractAPIEndpoints(): Promise<APIEndpoint[]> {
    // This would be enhanced with actual API analysis
    const patterns = await this.getAPIPatterns();
    
    return patterns.map(pattern => ({
      path: pattern.path || '/api/example',
      method: pattern.method || 'GET',
      description: pattern.description || 'API endpoint',
      parameters: [],
      responses: [
        { status: 200, description: 'Success' },
        { status: 401, description: 'Unauthorized' },
        { status: 403, description: 'Forbidden' },
        { status: 500, description: 'Internal Server Error' }
      ],
      authentication: ['JWT Token'],
      permissions: pattern.permissions || ['read:resource'],
      codeExample: pattern.code_example || '',
      securityNotes: ['Requires valid authentication', 'Organization scoped']
    }));
  }

  private async generateAuthImplementationDocs(): Promise<string> {
    return `## Authentication Implementation

The system uses JWT-based authentication with the following flow:

1. **User Login**: Users authenticate via Supabase Auth
2. **Token Generation**: JWT token is created with user claims and organization context
3. **Token Validation**: Each API request validates the JWT token
4. **Context Extraction**: User, role, and organization info is extracted from the token

### Key Functions

- \`requireAuthWithTenant()\`: Main authentication middleware
- \`hasPermission()\`: Permission checking utility
- \`getOrgDatabaseWithAuth()\`: Database connection with auth context`;
  }

  private generateErrorCodeDocs(): ErrorCodeDocs[] {
    return [
      {
        code: 400,
        message: 'Bad Request',
        description: 'The request was invalid or malformed',
        resolution: 'Check request parameters and format'
      },
      {
        code: 401,
        message: 'Unauthorized',
        description: 'Authentication is required',
        resolution: 'Provide valid JWT token in Authorization header'
      },
      {
        code: 403,
        message: 'Forbidden',
        description: 'User lacks required permissions',
        resolution: 'Ensure user has appropriate role and permissions'
      },
      {
        code: 500,
        message: 'Internal Server Error',
        description: 'An unexpected error occurred',
        resolution: 'Check server logs and contact system administrator'
      }
    ];
  }

  private async generateAPIExamples(): Promise<APIExample[]> {
    return [
      {
        title: 'Authenticated API Request',
        description: 'Standard pattern for making authenticated API requests',
        request: `curl -X GET "https://api.example.com/v1/data" \\
  -H "Authorization: Bearer <jwt-token>" \\
  -H "Content-Type: application/json"`,
        response: `{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100
  }
}`,
        notes: ['Replace <jwt-token> with actual JWT token', 'Organization context is automatically applied']
      }
    ];
  }

  private generateSecurityOverview(securityModel: SecurityModel): string {
    return `## Security Overview

The system implements a comprehensive security model with:

- **Authentication**: ${securityModel.authenticationMethods.join(', ')}
- **Authorization**: ${securityModel.authorizationModel}
- **Data Protection**: ${securityModel.dataProtection.join(', ')}
- **Trust Boundaries**: ${securityModel.trustBoundaries.join(', ')}

Security is enforced at multiple layers to provide defense in depth.`;
  }

  private generateThreatModelDocs(threats: any[]): ThreatModelDoc[] {
    return threats.map(threat => ({
      threat: threat.type,
      description: threat.description,
      likelihood: threat.likelihood,
      impact: threat.impact,
      mitigation: [threat.mitigation],
      residualRisk: 'Low'
    }));
  }

  private async generateSecurityControlDocs(): Promise<SecurityControlDoc[]> {
    return [
      {
        control: 'Authentication',
        description: 'JWT-based authentication with organization context',
        implementation: 'requireAuthWithTenant() middleware on all protected endpoints',
        testing: ['Token validation tests', 'Organization context verification'],
        effectiveness: 'High'
      },
      {
        control: 'Authorization',
        description: 'Role-based access control with permission checking',
        implementation: 'hasPermission() function with role-based checks',
        testing: ['Permission matrix testing', 'Role assignment verification'],
        effectiveness: 'High'
      },
      {
        control: 'Data Isolation',
        description: 'Complete data separation between organizations',
        implementation: 'Row Level Security policies and organization-scoped connections',
        testing: ['Cross-tenant data access tests', 'RLS policy verification'],
        effectiveness: 'High'
      }
    ];
  }

  private convertToVulnerabilityDoc(vulnerability: any): VulnerabilityDoc {
    return {
      id: vulnerability.id?.toString() || 'VULN-' + Date.now(),
      severity: vulnerability.severity,
      description: vulnerability.description,
      location: `${vulnerability.file_path}:${vulnerability.line_start}`,
      remediation: vulnerability.remediation,
      status: vulnerability.resolved ? 'Resolved' : 'Open'
    };
  }

  private generateSecurityGuidelines(): SecurityGuidelineDoc[] {
    return [
      {
        category: 'Authentication',
        guidelines: [
          'Always use requireAuthWithTenant() for protected endpoints',
          'Never bypass authentication checks',
          'Include organization context in all operations'
        ],
        examples: [
          'const { user, orgSlug, role } = await requireAuthWithTenant();'
        ],
        antiPatterns: [
          'Direct database access without authentication',
          'Hardcoded organization IDs'
        ]
      },
      {
        category: 'Data Access',
        guidelines: [
          'Use getOrgDatabaseWithAuth() for all database operations',
          'Never use direct database connections',
          'Always validate input parameters'
        ],
        examples: [
          'const db = await getOrgDatabaseWithAuth();'
        ],
        antiPatterns: [
          'const db = drizzle(connectionString);',
          'Unvalidated user input in queries'
        ]
      }
    ];
  }

  private generateComplianceDocs(): ComplianceDoc[] {
    return [
      {
        framework: 'GDPR',
        requirements: ['Data portability', 'Right to deletion', 'Data protection by design'],
        implementation: ['User data export', 'Account deletion', 'Privacy by default'],
        gaps: []
      },
      {
        framework: 'SOC 2',
        requirements: ['Access controls', 'Audit logging', 'Data encryption'],
        implementation: ['RBAC system', 'Comprehensive logging', 'Encryption at rest and in transit'],
        gaps: []
      }
    ];
  }

  // Utility methods
  private isSectionEnabled(sectionName: string, config: DocumentationConfig): boolean {
    const section = config.sections.find(s => s.name === sectionName);
    return section ? section.enabled : true; // Default to enabled
  }

  private async countSecurityIssues(): Promise<number> {
    const stmt = this.db.getDatabase().prepare('SELECT COUNT(*) as count FROM security_issues WHERE resolved = FALSE');
    const result = stmt.get() as { count: number };
    return result.count;
  }

  private countCodeExamples(sections: DocumentationContent[]): number {
    let count = 0;
    sections.forEach(section => {
      // Count code blocks in markdown
      const codeBlocks = (section.content.match(/```/g) || []).length / 2;
      count += Math.floor(codeBlocks);
    });
    return count;
  }

  private async getAPIPatterns(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM patterns WHERE category = 'api'
    `);
    return stmt.all();
  }

  private async getSecurityVulnerabilities(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM security_issues WHERE resolved = FALSE
      ORDER BY severity DESC
    `);
    return stmt.all();
  }
}

export default DocumentationGenerator;