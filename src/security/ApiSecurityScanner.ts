import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface ApiSecurityVulnerability {
  id: string;
  apiId: string; // API1 - API10
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  category: string;
  file: string;
  line: number;
  endpoint?: string;
  method?: string;
  code: string;
  remediation: string;
  references: string[];
  cweId?: number;
}

export interface ApiEndpoint {
  path: string;
  method: string;
  file: string;
  line: number;
  hasAuth: boolean;
  hasRateLimit: boolean;
  hasValidation: boolean;
  hasAuthorization: boolean;
  parameters: string[];
  responseTypes: string[];
}

export interface ApiSystemAnalysis {
  endpoints: ApiEndpoint[];
  frameworks: string[];
  authMechanisms: string[];
  dataValidation: string[];
  errorHandling: string[];
}

export interface ApiScanResult {
  vulnerabilities: ApiSecurityVulnerability[];
  analysis: ApiSystemAnalysis;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    categories: Map<string, number>;
    endpointsScanned: number;
  };
  recommendations: string[];
}

export interface ApiSecurityScanResult {
  vulnerabilities: ApiSecurityVulnerability[];
  endpoints: ApiEndpoint[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    endpointsScanned: number;
    categories: Map<string, number>;
  };
  complianceMatrix: Map<string, boolean>;
  recommendations: string[];
}

export class ApiSecurityScanner {
  private astParser: ASTParser;
  private apiPatterns: Map<string, any> = new Map();

  constructor() {
    this.astParser = new ASTParser();
    this.initializeApiSecurityPatterns();
  }

  private initializeApiSecurityPatterns(): void {
    // API1:2023 - Broken Object Level Authorization
    this.apiPatterns.set('API1:2023', {
      title: 'Broken Object Level Authorization',
      description: 'APIs expose endpoints that handle object identifiers without proper authorization',
      patterns: [
        'missing-object-level-auth',
        'insecure-direct-object-reference',
        'predictable-object-ids'
      ],
      scanner: this.scanBrokenObjectLevelAuth.bind(this)
    });

    // API2:2023 - Broken Authentication
    this.apiPatterns.set('API2:2023', {
      title: 'Broken Authentication',
      description: 'Authentication mechanisms not properly implemented',
      patterns: [
        'weak-authentication',
        'missing-authentication',
        'credential-stuffing-vulnerability'
      ],
      scanner: this.scanBrokenAuthentication.bind(this)
    });

    // API3:2023 - Broken Object Property Level Authorization
    this.apiPatterns.set('API3:2023', {
      title: 'Broken Object Property Level Authorization',
      description: 'APIs expose object properties without proper authorization',
      patterns: [
        'excessive-data-exposure',
        'mass-assignment',
        'property-level-access-control'
      ],
      scanner: this.scanBrokenPropertyLevelAuth.bind(this)
    });

    // API4:2023 - Unrestricted Resource Consumption
    this.apiPatterns.set('API4:2023', {
      title: 'Unrestricted Resource Consumption',
      description: 'APIs lack proper resource consumption controls',
      patterns: [
        'missing-rate-limiting',
        'resource-exhaustion',
        'dos-vulnerability'
      ],
      scanner: this.scanUnrestrictedResourceConsumption.bind(this)
    });

    // API5:2023 - Broken Function Level Authorization
    this.apiPatterns.set('API5:2023', {
      title: 'Broken Function Level Authorization',
      description: 'APIs lack proper function-level access controls',
      patterns: [
        'missing-function-authorization',
        'privilege-escalation',
        'admin-function-exposure'
      ],
      scanner: this.scanBrokenFunctionLevelAuth.bind(this)
    });

    // API6:2023 - Unrestricted Access to Sensitive Business Flows
    this.apiPatterns.set('API6:2023', {
      title: 'Unrestricted Access to Sensitive Business Flows',
      description: 'APIs allow unrestricted use of sensitive business functionality',
      patterns: [
        'business-logic-bypass',
        'workflow-manipulation',
        'sensitive-operation-abuse'
      ],
      scanner: this.scanUnrestrictedSensitiveAccess.bind(this)
    });

    // API7:2023 - Server Side Request Forgery
    this.apiPatterns.set('API7:2023', {
      title: 'Server Side Request Forgery',
      description: 'APIs vulnerable to Server-Side Request Forgery attacks',
      patterns: [
        'ssrf-vulnerability',
        'url-validation-bypass',
        'internal-network-access'
      ],
      scanner: this.scanSSRF.bind(this)
    });

    // API8:2023 - Security Misconfiguration
    this.apiPatterns.set('API8:2023', {
      title: 'Security Misconfiguration',
      description: 'APIs have security misconfigurations',
      patterns: [
        'verbose-error-messages',
        'missing-security-headers',
        'debug-endpoints-exposed'
      ],
      scanner: this.scanSecurityMisconfiguration.bind(this)
    });

    // API9:2023 - Improper Inventory Management
    this.apiPatterns.set('API9:2023', {
      title: 'Improper Inventory Management',
      description: 'APIs lack proper inventory and version management',
      patterns: [
        'outdated-api-versions',
        'deprecated-endpoints',
        'unnecessary-api-exposure'
      ],
      scanner: this.scanImproperInventoryManagement.bind(this)
    });

    // API10:2023 - Unsafe Consumption of APIs
    this.apiPatterns.set('API10:2023', {
      title: 'Unsafe Consumption of APIs',
      description: 'Unsafe consumption of third-party APIs',
      patterns: [
        'third-party-api-trust',
        'insufficient-api-validation',
        'malicious-payload-acceptance'
      ],
      scanner: this.scanUnsafeApiConsumption.bind(this)
    });
  }

  public async scanFile(filePath: string): Promise<ApiSecurityScanResult> {
    try {
      logger.info(`Running API security scan on: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return this.createEmptyResult();
      }

      const result: ApiSecurityScanResult = {
        vulnerabilities: [],
        endpoints: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, endpointsScanned: 0, categories: new Map() },
        complianceMatrix: new Map(),
        recommendations: []
      };

      // First, discover API endpoints
      result.endpoints = await this.discoverApiEndpoints(content, filePath);
      result.summary.endpointsScanned = result.endpoints.length;

      // Run all API security scanners
      for (const [apiId, pattern] of this.apiPatterns) {
        const vulnerabilities = await pattern.scanner(content, filePath, apiId, result.endpoints);
        result.vulnerabilities.push(...vulnerabilities);
        
        // Update compliance matrix
        result.complianceMatrix.set(apiId, vulnerabilities.length === 0);
      }

      // Process results
      this.processResults(result);

      return result;
    } catch (error) {
      logger.error(`Error running API security scan on ${filePath}:`, error);
      return this.createEmptyResult();
    }
  }

  public async scanDirectory(dirPath: string): Promise<ApiSecurityScanResult> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const aggregatedResult: ApiSecurityScanResult = {
      vulnerabilities: [],
      endpoints: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, endpointsScanned: 0, categories: new Map() },
      complianceMatrix: new Map(),
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
          const subResult = await this.scanDirectory(fullPath);
          this.mergeResults(aggregatedResult, subResult);
        } else if (entry.isFile() && this.isApiFile(entry.name, fullPath)) {
          const fileResult = await this.scanFile(fullPath);
          this.mergeResults(aggregatedResult, fileResult);
        }
      }
    } catch (error) {
      logger.error(`Error scanning directory ${dirPath}:`, error);
    }
    
    // Process final results
    this.processResults(aggregatedResult);
    
    return aggregatedResult;
  }

  private async discoverApiEndpoints(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): Promise<ApiEndpoint[]> {
    const endpoints: ApiEndpoint[] = [];

    const traverse = (node: TSESTree.Node) => {
      // Look for exported async functions (Next.js API routes)
      if (node.type === AST_NODE_TYPES.ExportNamedDeclaration ||
          node.type === AST_NODE_TYPES.ExportDefaultDeclaration) {
        
        let functionNode: TSESTree.FunctionDeclaration | TSESTree.ArrowFunctionExpression | null = null;
        
        if (node.type === AST_NODE_TYPES.ExportNamedDeclaration && node.declaration) {
          if (node.declaration.type === AST_NODE_TYPES.FunctionDeclaration) {
            functionNode = node.declaration;
          }
        }
        
        if (functionNode && this.isHttpMethod(functionNode.id?.name)) {
          const endpoint: ApiEndpoint = {
            path: this.extractApiPath(filePath),
            method: functionNode.id?.name?.toUpperCase() || 'UNKNOWN',
            file: filePath,
            line: functionNode.loc?.start.line || 0,
            hasAuth: this.hasAuthCheck(functionNode, content.sourceCode),
            hasRateLimit: this.hasRateLimit(functionNode, content.sourceCode),
            hasValidation: this.hasInputValidation(functionNode, content.sourceCode),
            hasAuthorization: this.hasAuthorizationCheck(functionNode, content.sourceCode),
            parameters: this.extractParameters(functionNode, content.sourceCode),
            responseTypes: this.extractResponseTypes(functionNode, content.sourceCode)
          };
          
          endpoints.push(endpoint);
        }
      }

      // Look for Express.js style route definitions
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        const routeMatch = code.match(/(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/);
        
        if (routeMatch) {
          const endpoint: ApiEndpoint = {
            path: routeMatch[3],
            method: routeMatch[2].toUpperCase(),
            file: filePath,
            line: node.loc?.start.line || 0,
            hasAuth: /auth|permission|role/.test(code),
            hasRateLimit: /rateLimit|rate.*limit|throttle/.test(code),
            hasValidation: /validate|sanitize|schema|joi|yup|zod/.test(code),
            hasAuthorization: /authorize|permission|role|access/.test(code),
            parameters: this.extractParametersFromCode(code),
            responseTypes: this.extractResponseTypesFromCode(code)
          };
          
          endpoints.push(endpoint);
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return endpoints;
  }

  // API1:2023 - Broken Object Level Authorization
  private async scanBrokenObjectLevelAuth(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for database operations using user-provided IDs without authorization
        if (this.isDatabaseOperation(code) && this.hasUserProvidedId(code)) {
          if (!this.hasOwnershipCheck(code) && !this.hasAuthorizationCheck(node, content.sourceCode)) {
            vulnerabilities.push({
              id: `api1-bola-${node.loc?.start.line}`,
              apiId,
              title: 'Broken Object Level Authorization',
              description: 'Database operation uses user-provided ID without ownership verification',
              severity: VulnerabilitySeverity.HIGH,
              category: 'Access Control',
              file: filePath,
              line: node.loc?.start.line || 0,
              code: code.slice(0, 200),
              remediation: 'Verify object ownership or user permissions before allowing access',
              references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
              cweId: 639
            });
          }
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // API2:2023 - Broken Authentication
  private async scanBrokenAuthentication(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    // Check each endpoint for proper authentication
    endpoints.forEach(endpoint => {
      if (!endpoint.hasAuth && this.isProtectedEndpoint(endpoint)) {
        vulnerabilities.push({
          id: `api2-auth-${endpoint.line}`,
          apiId,
          title: 'Missing Authentication',
          description: `API endpoint ${endpoint.method} ${endpoint.path} lacks authentication`,
          severity: VulnerabilitySeverity.HIGH,
          category: 'Authentication',
          file: filePath,
          line: endpoint.line,
          endpoint: endpoint.path,
          method: endpoint.method,
          code: `${endpoint.method} ${endpoint.path}`,
          remediation: 'Implement proper authentication for all protected endpoints',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
          cweId: 287
        });
      }
    });

    // Check for weak authentication patterns
    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for hardcoded credentials
      if (/(?:username|password|secret|key)\s*[=:]\s*['"][^'"]{3,}['"]/.test(line)) {
        vulnerabilities.push({
          id: `api2-hardcoded-${index}`,
          apiId,
          title: 'Hardcoded Credentials',
          description: 'Authentication credentials are hardcoded in source code',
          severity: VulnerabilitySeverity.CRITICAL,
          category: 'Authentication',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Use environment variables or secure credential management',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
          cweId: 798
        });
      }

      // Check for weak session management
      if (/sessionid.*Math\.random|token.*Math\.random/.test(line)) {
        vulnerabilities.push({
          id: `api2-weak-session-${index}`,
          apiId,
          title: 'Weak Session Token Generation',
          description: 'Session tokens generated using weak randomness',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Authentication',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Use cryptographically secure random number generation',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
          cweId: 330
        });
      }
    });

    return vulnerabilities;
  }

  // API3:2023 - Broken Object Property Level Authorization
  private async scanBrokenPropertyLevelAuth(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      // Check for mass assignment vulnerabilities
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        if (this.isDatabaseUpdateOperation(code) && /req\.body/.test(code) && !this.hasPropertyFiltering(code)) {
          vulnerabilities.push({
            id: `api3-mass-assignment-${node.loc?.start.line}`,
            apiId,
            title: 'Mass Assignment Vulnerability',
            description: 'Database update accepts all properties from request body without filtering',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Input Validation',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Explicitly whitelist allowed properties for updates',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
            cweId: 915
          });
        }
      }

      // Check for excessive data exposure
      if (node.type === AST_NODE_TYPES.ReturnStatement || 
          (node.type === AST_NODE_TYPES.CallExpression && /res\.json|res\.send/.test(this.getNodeCode(node, content.sourceCode)))) {
        
        const code = this.getNodeCode(node, content.sourceCode);
        
        if (this.returnsFullObject(code) && !this.hasFieldSelection(code)) {
          vulnerabilities.push({
            id: `api3-data-exposure-${node.loc?.start.line}`,
            apiId,
            title: 'Excessive Data Exposure',
            description: 'API returns full object without filtering sensitive properties',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Information Disclosure',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Return only necessary fields and filter sensitive data',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
            cweId: 200
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // API4:2023 - Unrestricted Resource Consumption
  private async scanUnrestrictedResourceConsumption(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    // Check each endpoint for rate limiting
    endpoints.forEach(endpoint => {
      if (!endpoint.hasRateLimit && this.isResourceIntensiveEndpoint(endpoint)) {
        vulnerabilities.push({
          id: `api4-rate-limit-${endpoint.line}`,
          apiId,
          title: 'Missing Rate Limiting',
          description: `Resource-intensive endpoint ${endpoint.method} ${endpoint.path} lacks rate limiting`,
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Rate Limiting',
          file: filePath,
          line: endpoint.line,
          endpoint: endpoint.path,
          method: endpoint.method,
          code: `${endpoint.method} ${endpoint.path}`,
          remediation: 'Implement rate limiting to prevent resource exhaustion',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'],
          cweId: 770
        });
      }
    });

    // Check for resource-intensive operations without limits
    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for unlimited database queries
        if (/\.findAll\(|\.find\(\{\}|SELECT \* FROM/.test(code) && !this.hasQueryLimits(code)) {
          vulnerabilities.push({
            id: `api4-unlimited-query-${node.loc?.start.line}`,
            apiId,
            title: 'Unlimited Database Query',
            description: 'Database query without pagination or limits',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Resource Management',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Add pagination and query limits to prevent resource exhaustion',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'],
            cweId: 770
          });
        }

        // Check for file upload without size limits
        if (/multer|upload|file/.test(code) && !this.hasFileSizeLimits(code)) {
          vulnerabilities.push({
            id: `api4-unlimited-upload-${node.loc?.start.line}`,
            apiId,
            title: 'Unlimited File Upload',
            description: 'File upload endpoint without size restrictions',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Resource Management',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Implement file size and type restrictions',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'],
            cweId: 770
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // API5:2023 - Broken Function Level Authorization
  private async scanBrokenFunctionLevelAuth(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    // Check each endpoint for proper function-level authorization
    endpoints.forEach(endpoint => {
      if (this.isAdminFunction(endpoint) && !endpoint.hasAuthorization) {
        vulnerabilities.push({
          id: `api5-function-auth-${endpoint.line}`,
          apiId,
          title: 'Missing Function Level Authorization',
          description: `Administrative function ${endpoint.method} ${endpoint.path} lacks proper authorization`,
          severity: VulnerabilitySeverity.HIGH,
          category: 'Authorization',
          file: filePath,
          line: endpoint.line,
          endpoint: endpoint.path,
          method: endpoint.method,
          code: `${endpoint.method} ${endpoint.path}`,
          remediation: 'Implement role-based access control for administrative functions',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/'],
          cweId: 285
        });
      }
    });

    return vulnerabilities;
  }

  // API6:2023 - Unrestricted Access to Sensitive Business Flows
  private async scanUnrestrictedSensitiveAccess(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    endpoints.forEach(endpoint => {
      if (this.isSensitiveBusinessFlow(endpoint) && !this.hasBusinessFlowProtection(endpoint, content.sourceCode)) {
        vulnerabilities.push({
          id: `api6-sensitive-flow-${endpoint.line}`,
          apiId,
          title: 'Unrestricted Sensitive Business Flow',
          description: `Sensitive business operation ${endpoint.method} ${endpoint.path} lacks proper protection`,
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Business Logic',
          file: filePath,
          line: endpoint.line,
          endpoint: endpoint.path,
          method: endpoint.method,
          code: `${endpoint.method} ${endpoint.path}`,
          remediation: 'Implement additional verification for sensitive business operations',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/'],
          cweId: 840
        });
      }
    });

    return vulnerabilities;
  }

  // API7:2023 - Server Side Request Forgery
  private async scanSSRF(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        if (this.isHttpRequestCall(code) && this.hasUserControlledUrl(code) && !this.hasUrlValidation(code)) {
          vulnerabilities.push({
            id: `api7-ssrf-${node.loc?.start.line}`,
            apiId,
            title: 'Server-Side Request Forgery',
            description: 'HTTP request using user-controlled URL without validation',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Server-Side Request Forgery',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Validate and whitelist URLs, use allowlist for internal requests',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/'],
            cweId: 918
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // API8:2023 - Security Misconfiguration
  private async scanSecurityMisconfiguration(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for verbose error messages
      if (this.hasVerboseErrorHandling(line)) {
        vulnerabilities.push({
          id: `api8-verbose-error-${index}`,
          apiId,
          title: 'Verbose Error Messages',
          description: 'Error messages may expose sensitive system information',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Information Disclosure',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Use generic error messages in production environment',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'],
          cweId: 209
        });
      }

      // Check for debug endpoints
      if (this.isDebugEndpoint(line)) {
        vulnerabilities.push({
          id: `api8-debug-endpoint-${index}`,
          apiId,
          title: 'Debug Endpoint Exposed',
          description: 'Debug or development endpoint may be exposed in production',
          severity: VulnerabilitySeverity.LOW,
          category: 'Information Disclosure',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Remove debug endpoints from production builds',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'],
          cweId: 489
        });
      }
    });

    return vulnerabilities;
  }

  // API9:2023 - Improper Inventory Management
  private async scanImproperInventoryManagement(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    // Check for deprecated API versions
    endpoints.forEach(endpoint => {
      if (this.isDeprecatedApiVersion(endpoint.path)) {
        vulnerabilities.push({
          id: `api9-deprecated-${endpoint.line}`,
          apiId,
          title: 'Deprecated API Version',
          description: `Deprecated API version detected: ${endpoint.path}`,
          severity: VulnerabilitySeverity.LOW,
          category: 'Asset Management',
          file: filePath,
          line: endpoint.line,
          endpoint: endpoint.path,
          method: endpoint.method,
          code: `${endpoint.method} ${endpoint.path}`,
          remediation: 'Remove or properly secure deprecated API versions',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/'],
          cweId: 1059
        });
      }
    });

    return vulnerabilities;
  }

  // API10:2023 - Unsafe Consumption of APIs
  private async scanUnsafeApiConsumption(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    apiId: string,
    endpoints: ApiEndpoint[]
  ): Promise<ApiSecurityVulnerability[]> {
    const vulnerabilities: ApiSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for third-party API calls without proper validation
        if (this.isThirdPartyApiCall(code) && !this.hasApiResponseValidation(code)) {
          vulnerabilities.push({
            id: `api10-unsafe-consumption-${node.loc?.start.line}`,
            apiId,
            title: 'Unsafe API Consumption',
            description: 'Third-party API response used without proper validation',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Input Validation',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Validate and sanitize all third-party API responses',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/'],
            cweId: 20
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // Helper methods
  private createEmptyResult(): ApiSecurityScanResult {
    return {
      vulnerabilities: [],
      endpoints: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, endpointsScanned: 0, categories: new Map() },
      complianceMatrix: new Map(),
      recommendations: []
    };
  }

  private mergeResults(target: ApiSecurityScanResult, source: ApiSecurityScanResult): void {
    target.vulnerabilities.push(...source.vulnerabilities);
    target.endpoints.push(...source.endpoints);
    
    // Merge compliance matrix
    source.complianceMatrix.forEach((value, key) => {
      const existing = target.complianceMatrix.get(key) ?? true;
      target.complianceMatrix.set(key, existing && value);
    });
  }

  private processResults(result: ApiSecurityScanResult): void {
    // Calculate summary
    result.summary.total = result.vulnerabilities.length;
    result.vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case VulnerabilitySeverity.CRITICAL:
          result.summary.critical++;
          break;
        case VulnerabilitySeverity.HIGH:
          result.summary.high++;
          break;
        case VulnerabilitySeverity.MEDIUM:
          result.summary.medium++;
          break;
        case VulnerabilitySeverity.LOW:
          result.summary.low++;
          break;
      }

      // Count by category
      const count = result.summary.categories.get(vuln.category) || 0;
      result.summary.categories.set(vuln.category, count + 1);
    });

    // Generate recommendations
    result.recommendations = this.generateApiRecommendations(result);
  }

  private generateApiRecommendations(result: ApiSecurityScanResult): string[] {
    const recommendations: string[] = [];

    if (result.summary.critical > 0) {
      recommendations.push(`🚨 Fix ${result.summary.critical} critical API security issues immediately`);
    }

    if (result.summary.high > 0) {
      recommendations.push(`⚠️ Address ${result.summary.high} high-severity API security issues`);
    }

    if (result.endpoints.length > 0) {
      recommendations.push(`📊 ${result.endpoints.length} API endpoints analyzed`);
      recommendations.push('🔒 Implement proper authentication for all API endpoints');
    }

    if (result.summary.categories.has('Authentication')) {
      recommendations.push('🔐 Review API authentication mechanisms');
    }

    if (result.summary.categories.has('Authorization')) {
      recommendations.push('🛡️ Implement proper authorization controls');
    }

    if (result.summary.total === 0) {
      recommendations.push('✅ API security appears well-implemented');
    }

    return recommendations.slice(0, 5);
  }

  private isApiFile(fileName: string, fullPath: string): boolean {
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    const isCorrectExtension = extensions.some(ext => fileName.endsWith(ext));
    const isApiPath = fullPath.includes('/api/') || fullPath.includes('/route.');
    
    return isCorrectExtension && isApiPath;
  }

  private getNodeCode(node: TSESTree.Node, sourceCode: string): string {
    if (!node.range) return '';
    return sourceCode.slice(node.range[0], node.range[1]);
  }

  private traverseNode(node: TSESTree.Node, callback: (node: TSESTree.Node) => void): void {
    for (const key in node) {
      const child = (node as any)[key];
      if (child && typeof child === 'object') {
        if (Array.isArray(child)) {
          child.forEach(item => {
            if (item && typeof item === 'object' && item.type) {
              callback(item);
            }
          });
        } else if (child.type) {
          callback(child);
        }
      }
    }
  }

  // Detection helper methods
  private isHttpMethod(name?: string): boolean {
    if (!name) return false;
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    return httpMethods.includes(name.toUpperCase());
  }

  private extractApiPath(filePath: string): string {
    const match = filePath.match(/\/api\/(.+)\.(?:ts|js)$/);
    return match ? `api/${match[1]}` : filePath;
  }

  private hasAuthCheck(node: TSESTree.Node, sourceCode: string): boolean {
    const code = JSON.stringify(node);
    const authPatterns = ['requireAuth', 'checkAuth', 'verifyAuth', 'authenticate', 'auth'];
    return authPatterns.some(pattern => code.includes(pattern));
  }

  private hasRateLimit(node: TSESTree.Node, sourceCode: string): boolean {
    const code = JSON.stringify(node);
    return /rateLimit|rate.*limit|throttle/.test(code);
  }

  private hasInputValidation(node: TSESTree.Node, sourceCode: string): boolean {
    const code = JSON.stringify(node);
    return /validate|sanitize|schema|joi|yup|zod/.test(code);
  }

  private hasAuthorizationCheck(node: TSESTree.Node, sourceCode: string): boolean {
    const code = JSON.stringify(node);
    const authzPatterns = ['hasPermission', 'canAccess', 'isAuthorized', 'checkPermission', 'authorize'];
    return authzPatterns.some(pattern => code.includes(pattern));
  }

  private extractParameters(node: TSESTree.Node, sourceCode: string): string[] {
    // Simplified parameter extraction
    const code = this.getNodeCode(node, sourceCode);
    const paramMatches = code.match(/req\.(body|query|params)\.(\w+)/g) || [];
    return paramMatches.map(match => match.split('.').pop() || '');
  }

  private extractResponseTypes(node: TSESTree.Node, sourceCode: string): string[] {
    // Simplified response type extraction
    const code = this.getNodeCode(node, sourceCode);
    const responseMatches = code.match(/res\.(json|send|status)/g) || [];
    return responseMatches.map(match => match.split('.').pop() || '');
  }

  private extractParametersFromCode(code: string): string[] {
    const paramMatches = code.match(/req\.(body|query|params)\.(\w+)/g) || [];
    return paramMatches.map(match => match.split('.').pop() || '');
  }

  private extractResponseTypesFromCode(code: string): string[] {
    const responseMatches = code.match(/res\.(json|send|status)/g) || [];
    return responseMatches.map(match => match.split('.').pop() || '');
  }

  private isDatabaseOperation(code: string): boolean {
    const dbOperations = ['findById', 'findOne', 'find', 'select', 'update', 'delete', 'query'];
    return dbOperations.some(op => code.includes(op));
  }

  private hasUserProvidedId(code: string): boolean {
    return /req\.params\.id|req\.query\.id|params\.id/.test(code);
  }

  private hasOwnershipCheck(code: string): boolean {
    return /owner|userId|createdBy/.test(code);
  }

  private isProtectedEndpoint(endpoint: ApiEndpoint): boolean {
    const protectedPaths = ['/admin', '/user', '/profile', '/delete', '/update'];
    return protectedPaths.some(path => endpoint.path.includes(path)) ||
           ['DELETE', 'PUT', 'PATCH'].includes(endpoint.method);
  }

  private isDatabaseUpdateOperation(code: string): boolean {
    return /update|save|patch|put/.test(code.toLowerCase());
  }

  private hasPropertyFiltering(code: string): boolean {
    return /pick|omit|whitelist|allowedFields/.test(code);
  }

  private returnsFullObject(code: string): boolean {
    return /return.*user|res\.json.*user|res\.send.*user/.test(code) && !/select|pick|omit/.test(code);
  }

  private hasFieldSelection(code: string): boolean {
    return /select|fields|pick|omit/.test(code);
  }

  private isResourceIntensiveEndpoint(endpoint: ApiEndpoint): boolean {
    const intensiveOperations = ['/search', '/list', '/export', '/report', '/upload'];
    return intensiveOperations.some(op => endpoint.path.includes(op));
  }

  private hasQueryLimits(code: string): boolean {
    return /limit|take|top|\boffset\b|pagination/.test(code);
  }

  private hasFileSizeLimits(code: string): boolean {
    return /fileSize|maxSize|limits/.test(code);
  }

  private isAdminFunction(endpoint: ApiEndpoint): boolean {
    const adminPaths = ['/admin', '/manage', '/system', '/config'];
    return adminPaths.some(path => endpoint.path.includes(path));
  }

  private isSensitiveBusinessFlow(endpoint: ApiEndpoint): boolean {
    const sensitivePaths = ['/payment', '/transfer', '/purchase', '/order', '/withdraw'];
    return sensitivePaths.some(path => endpoint.path.includes(path));
  }

  private hasBusinessFlowProtection(endpoint: ApiEndpoint, sourceCode: string): boolean {
    return /mfa|twoFactor|confirmation|verify/.test(sourceCode);
  }

  private isHttpRequestCall(code: string): boolean {
    const httpCalls = ['fetch', 'axios', 'request', 'http.get', 'http.post'];
    return httpCalls.some(call => code.includes(call));
  }

  private hasUserControlledUrl(code: string): boolean {
    return /req\.(body|query|params).*url|url.*req\./i.test(code);
  }

  private hasUrlValidation(code: string): boolean {
    return /validate.*url|url.*validate|whitelist|allowlist/.test(code);
  }

  private hasVerboseErrorHandling(line: string): boolean {
    const verbosePatterns = [
      /console\.error.*error\./i,
      /throw.*error\./i,
      /\.stack/i,
      /res\.json.*error\./i
    ];
    return verbosePatterns.some(pattern => pattern.test(line));
  }

  private isDebugEndpoint(line: string): boolean {
    return /\/debug|\/test|\/dev|console\.log/i.test(line);
  }

  private isDeprecatedApiVersion(path: string): boolean {
    return /\/v1\/|\/api\/v1\/|deprecated/i.test(path);
  }

  private isThirdPartyApiCall(code: string): boolean {
    const thirdPartyDomains = ['api.', 'external', 'third-party', '.com/', '.net/', '.org/'];
    return thirdPartyDomains.some(domain => code.includes(domain));
  }

  private hasApiResponseValidation(code: string): boolean {
    return /validate|schema|parse|sanitize/.test(code);
  }
}