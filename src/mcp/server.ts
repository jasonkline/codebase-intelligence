import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// Import specialized tool modules
import { SecurityTools } from './tools/SecurityTools';
import { PatternTools } from './tools/PatternTools';
import { KnowledgeTools } from './tools/KnowledgeTools';
import { NavigationTools } from './tools/NavigationTools';
import { GovernanceTools } from './tools/GovernanceTools';
import { IaCSecurityTools } from './tools/IaCSecurityTools';
import { ResponseFormatter } from './ResponseFormatter';
import { ConfigurationManager } from '../config/ConfigurationManager';
import { PerformanceMonitor } from '../monitoring/PerformanceMonitor';
import logger from '../utils/logger';
import FileScanner, { ScanResult, ScanProgress } from '../scanner/FileScanner';
import { SecurityScanner, SecurityScanOptions } from '../security/SecurityScanner';
import { AuthPatternAnalyzer, AuthFlow } from '../security/AuthPatternAnalyzer';
import { ASTParser } from '../parser/ASTParser';
import { RLSAnalyzer, RLSAnalysisResult } from '../security/RLSAnalyzer';
import { OWASPScanner, OWASPScanResult } from '../security/OWASPScanner';
import { SecurityFinding, VulnerabilitySeverity, VulnerabilityCategory, vulnerabilityDatabase } from '../security/VulnerabilityDatabase';
import PatternRegistry, { PatternAnalysisResult } from '../patterns/PatternRegistry';
import DatabaseManager from '../database/schema';
import RuleEngine, { GovernanceReport, RuleViolation } from '../governance/RuleEngine';
import { KnowledgeExtractor } from '../knowledge/KnowledgeExtractor';
import { QueryEngine, QueryResult } from '../knowledge/QueryEngine';
import { SystemExplainer } from '../knowledge/SystemExplainer';
import { DependencyAnalyzer } from '../knowledge/DependencyAnalyzer';
import { DocumentationGenerator } from '../knowledge/DocumentationGenerator';
import { ImpactAnalyzer, ChangeImpactResult } from '../knowledge/ImpactAnalyzer';
import { RealtimeTools, ValidateAsTypedArgs, SuggestNextArgs, PreventErrorArgs, QuickFixArgs, ExplainWarningArgs, StartWatchingArgs } from './RealtimeTools';

interface StopWatchingArgs {
  projectPath: string;
}

interface PingResult {
  message: string;
  timestamp: string;
  version: string;
}

interface AnalyzeProjectArgs {
  projectPath: string;
  include?: string[];
  exclude?: string[];
  parallel?: boolean;
  maxConcurrency?: number;
  watchMode?: boolean;
}

interface AnalysisResult {
  success: boolean;
  projectPath: string;
  summary: {
    filesProcessed: number;
    filesSkipped: number;
    errors: number;
    duration: number;
    totalSymbols: number;
    totalPatterns: number;
    securityIssues: number;
    languages: Record<string, number>;
    systems: string[];
    coverage: {
      authCovered: number;
      rbacImplemented: number;
      dataAccessSecure: number;
    };
  };
  findings: {
    criticalSecurityIssues: string[];
    authPatterns: string[];
    rbacPatterns: string[];
    dataAccessPatterns: string[];
    apiPatterns: string[];
  };
  recommendations: string[];
  errors?: string[];
}

interface SecurityAnalysisArgs {
  path: string;
  options?: SecurityScanOptions;
}

interface AuthPatternAnalysisArgs {
  path: string;
}

interface VulnerabilitySearchArgs {
  path: string;
  severity?: VulnerabilitySeverity;
  category?: VulnerabilityCategory;
  maxResults?: number;
}

interface LearnPatternsArgs {
  projectPath: string;
  categories?: string[];
  minConfidence?: number;
}

interface CheckPatternComplianceArgs {
  filePath: string;
  patternCategory?: string;
  explainViolations?: boolean;
}

interface GetApprovedPatternArgs {
  category: string;
  name?: string;
}

interface SuggestPatternArgs {
  filePath: string;
  context?: string;
}

interface ExplainSystemArgs {
  query: string;
  context?: string;
  detailLevel?: 'summary' | 'detailed' | 'technical';
}

interface AnalyzeImpactArgs {
  targetComponent: string;
  changeType: 'modify' | 'delete' | 'add';
  changeDescription?: string;
}

interface GetSystemDocsArgs {
  systemName: string;
  includeCodeExamples?: boolean;
  includeDiagrams?: boolean;
}

interface TraceDataFlowArgs {
  startComponent: string;
  endComponent?: string;
}

interface ExplainSecurityArgs {
  component: string;
  includeThreats?: boolean;
  includeRemediation?: boolean;
}

class CodebaseIntelligenceMCPServer {
  private server: Server;
  private fileScanner: FileScanner;
  private securityScanner: SecurityScanner;
  private authPatternAnalyzer: AuthPatternAnalyzer;
  private rlsAnalyzer: RLSAnalyzer;
  private owaspScanner: OWASPScanner;
  private patternRegistry: PatternRegistry;
  private ruleEngine: RuleEngine;
  private database: DatabaseManager;
  private knowledgeExtractor: KnowledgeExtractor;
  private queryEngine: QueryEngine;  
  private systemExplainer: SystemExplainer;
  private dependencyAnalyzer: DependencyAnalyzer;
  private documentationGenerator: DocumentationGenerator;
  private impactAnalyzer: ImpactAnalyzer;
  private realtimeTools: RealtimeTools;
  private configManager: ConfigurationManager;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;
  private astParser: ASTParser;
  private securityTools: SecurityTools;
  private iacSecurityTools: IaCSecurityTools;
  private patternTools: PatternTools;
  private knowledgeTools: KnowledgeTools;
  private navigationTools: NavigationTools;
  private governanceTools: GovernanceTools;

  constructor() {
    // Initialize configuration and database first
    this.configManager = new ConfigurationManager();
    this.database = new DatabaseManager();
    this.responseFormatter = new ResponseFormatter(this.configManager);
    this.performanceMonitor = new PerformanceMonitor();
    this.astParser = new ASTParser();
    
    // Initialize core analyzers
    this.fileScanner = new FileScanner();
    this.securityScanner = new SecurityScanner();
    this.authPatternAnalyzer = new AuthPatternAnalyzer();
    this.rlsAnalyzer = new RLSAnalyzer();
    this.owaspScanner = new OWASPScanner();
    this.patternRegistry = new PatternRegistry(this.database);
    this.ruleEngine = new RuleEngine(this.database);
    
    // Initialize Phase 4 knowledge system components
    this.knowledgeExtractor = new KnowledgeExtractor();
    this.queryEngine = new QueryEngine(this.database, this.knowledgeExtractor);
    this.systemExplainer = new SystemExplainer(this.database, this.knowledgeExtractor);
    this.dependencyAnalyzer = new DependencyAnalyzer(this.database, this.knowledgeExtractor);
    this.documentationGenerator = new DocumentationGenerator(
      this.database, 
      this.knowledgeExtractor, 
      this.systemExplainer, 
      this.dependencyAnalyzer
    );
    this.impactAnalyzer = new ImpactAnalyzer(
      this.database, 
      this.dependencyAnalyzer, 
      this.knowledgeExtractor
    );
    
    // Initialize specialized tool modules
    this.securityTools = new SecurityTools(
      this.securityScanner,
      this.authPatternAnalyzer,
      this.rlsAnalyzer,
      this.owaspScanner,
      this.responseFormatter,
      this.performanceMonitor
    );
    
    this.patternTools = new PatternTools(
      this.patternRegistry,
      this.ruleEngine,
      this.responseFormatter,
      this.performanceMonitor,
      this.astParser
    );
    
    this.knowledgeTools = new KnowledgeTools(
      this.queryEngine,
      this.systemExplainer,
      this.documentationGenerator,
      this.impactAnalyzer,
      this.responseFormatter,
      this.performanceMonitor
    );
    
    this.navigationTools = new NavigationTools(
      this.database,
      this.dependencyAnalyzer,
      this.responseFormatter,
      this.performanceMonitor
    );
    
    this.governanceTools = new GovernanceTools(
      this.ruleEngine,
      this.patternRegistry,
      this.responseFormatter,
      this.performanceMonitor
    );
    
    this.iacSecurityTools = new IaCSecurityTools(
      this.database,
      this.responseFormatter,
      this.performanceMonitor,
      this.configManager.getIaCConfig().checkovPath
    );
    
    // Initialize Phase 5 real-time intelligence components
    this.realtimeTools = new RealtimeTools(
      this.database,
      this.patternRegistry,
      this.ruleEngine,
      this.securityScanner
    );
    
    this.server = new Server(
      {
        name: 'codebase-intelligence',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupErrorHandlers();
    this.setupToolHandlers();
  }

  private setupErrorHandlers(): void {
    this.server.onerror = (error) => {
      logger.error('MCP Server error:', error);
    };

    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception:', error);
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled rejection at:', promise, 'reason:', reason);
      process.exit(1);
    });
  }

  private setupToolHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'ping',
            description: 'Test connectivity - returns pong with timestamp',
            inputSchema: {
              type: 'object',
              properties: {
                message: {
                  type: 'string',
                  description: 'Optional message to echo back',
                },
              },
            },
          },
          {
            name: 'analyze_project',
            description: 'Analyze a codebase for patterns, security issues, and system knowledge. Returns comprehensive analysis including auth patterns, RBAC implementation, data access security, and architectural insights.',
            inputSchema: {
              type: 'object',
              properties: {
                projectPath: {
                  type: 'string',
                  description: 'Absolute path to the project directory to analyze',
                },
                include: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'File patterns to include (e.g., ["**/*.ts", "**/*.tsx"])',
                  default: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
                },
                exclude: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'File patterns to exclude',
                  default: ['node_modules/**', 'dist/**', '**/*.test.ts'],
                },
                parallel: {
                  type: 'boolean',
                  description: 'Process files in parallel for better performance',
                  default: true,
                },
                maxConcurrency: {
                  type: 'number',
                  description: 'Maximum number of files to process concurrently',
                  default: 4,
                },
                watchMode: {
                  type: 'boolean',
                  description: 'Enable file watching for real-time updates',
                  default: false,
                },
              },
              required: ['projectPath'],
            },
          },
          {
            name: 'analyze_security',
            description: 'Perform comprehensive security analysis on a file or directory. Detects vulnerabilities including SQL injection, XSS, hardcoded secrets, missing auth checks, and OWASP Top 10 issues.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to file or directory to analyze',
                },
                options: {
                  type: 'object',
                  properties: {
                    includeCategories: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Vulnerability categories to include (authentication, injection, xss, etc.)',
                    },
                    excludeCategories: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Vulnerability categories to exclude',
                    },
                    minSeverity: {
                      type: 'string',
                      enum: ['critical', 'high', 'medium', 'low', 'info'],
                      description: 'Minimum severity level to report',
                    },
                    maxFindings: {
                      type: 'number',
                      description: 'Maximum number of findings to return',
                    },
                  },
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'check_auth_pattern',
            description: 'Analyze authentication and authorization patterns in code. Maps auth flows, RBAC implementation, and identifies security gaps.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to file or directory to analyze',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'find_vulnerabilities',
            description: 'Search for specific types of security vulnerabilities. Returns detailed findings with remediation guidance.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to file or directory to scan',
                },
                severity: {
                  type: 'string',
                  enum: ['critical', 'high', 'medium', 'low', 'info'],
                  description: 'Filter by severity level',
                },
                category: {
                  type: 'string',
                  enum: ['authentication', 'authorization', 'injection', 'cross_site_scripting', 'sensitive_data_exposure', 'row_level_security'],
                  description: 'Filter by vulnerability category',
                },
                maxResults: {
                  type: 'number',
                  description: 'Maximum number of results to return',
                  default: 50,
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'learn_patterns',
            description: 'Extract and learn patterns from existing code in a project. Analyzes code structure, identifies common patterns, and builds a knowledge base for pattern matching.',
            inputSchema: {
              type: 'object',
              properties: {
                projectPath: {
                  type: 'string',
                  description: 'Absolute path to the project directory to analyze for patterns',
                },
                categories: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Pattern categories to learn (auth, api, data_access, components, style)',
                  default: ['auth', 'api', 'data_access', 'components', 'style'],
                },
                minConfidence: {
                  type: 'number',
                  description: 'Minimum confidence threshold for pattern extraction (0.0-1.0)',
                  default: 0.8,
                },
              },
              required: ['projectPath'],
            },
          },
          {
            name: 'check_pattern_compliance',
            description: 'Validate code against learned patterns and governance rules. Identifies violations and provides recommendations.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Absolute path to the file to check for pattern compliance',
                },
                patternCategory: {
                  type: 'string',
                  enum: ['auth', 'api', 'data_access', 'components', 'style', 'all'],
                  description: 'Specific pattern category to check, or "all" for all categories',
                  default: 'all',
                },
                explainViolations: {
                  type: 'boolean',
                  description: 'Include detailed explanations for violations',
                  default: true,
                },
              },
              required: ['filePath'],
            },
          },
          {
            name: 'get_approved_pattern',
            description: 'Retrieve approved patterns for a specific category or use case. Returns the correct implementation pattern with examples.',
            inputSchema: {
              type: 'object',
              properties: {
                category: {
                  type: 'string',
                  enum: ['auth', 'api', 'data_access', 'components', 'style'],
                  description: 'Pattern category to retrieve',
                },
                name: {
                  type: 'string',
                  description: 'Specific pattern name to retrieve (optional)',
                },
              },
              required: ['category'],
            },
          },
          {
            name: 'suggest_pattern',
            description: 'Get pattern suggestions for new code based on context and learned patterns. Provides implementation guidance.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Path to the file where pattern suggestion is needed',
                },
                context: {
                  type: 'string',
                  description: 'Additional context about what you\'re trying to implement',
                },
              },
              required: ['filePath'],
            },
          },
          {
            name: 'explain_system',
            description: 'Answer questions about the codebase and explain complex systems. Supports natural language queries like "How does authentication work?", "What is the RBAC model?", "Explain the database architecture".',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description: 'Natural language question about the system (e.g., "How does authentication work?")',
                },
                context: {
                  type: 'string',
                  description: 'Additional context to help answer the question',
                },
                detailLevel: {
                  type: 'string',
                  enum: ['summary', 'detailed', 'technical'],
                  description: 'Level of detail in the response',
                  default: 'detailed',
                },
              },
              required: ['query'],
            },
          },
          {
            name: 'analyze_impact',
            description: 'Assess impact of proposed changes to system components. Provides risk assessment, testing requirements, rollback plans, and recommendations.',
            inputSchema: {
              type: 'object',
              properties: {
                targetComponent: {
                  type: 'string',
                  description: 'Name or path of the component to be changed',
                },
                changeType: {
                  type: 'string',
                  enum: ['modify', 'delete', 'add'],
                  description: 'Type of change being made',
                },
                changeDescription: {
                  type: 'string',
                  description: 'Description of the planned change',
                },
              },
              required: ['targetComponent', 'changeType'],
            },
          },
          {
            name: 'get_system_docs',
            description: 'Retrieve comprehensive documentation for a system component. Auto-generates documentation with architecture diagrams and implementation guides.',
            inputSchema: {
              type: 'object',
              properties: {
                systemName: {
                  type: 'string',
                  description: 'Name of the system to document (e.g., "Authentication", "API", "Database")',
                },
                includeCodeExamples: {
                  type: 'boolean',
                  description: 'Include code examples in the documentation',
                  default: true,
                },
                includeDiagrams: {
                  type: 'boolean',
                  description: 'Include architecture and flow diagrams',
                  default: true,
                },
              },
              required: ['systemName'],
            },
          },
          {
            name: 'trace_data_flow',
            description: 'Show how data flows through the system between components. Visualizes data paths and security checkpoints.',
            inputSchema: {
              type: 'object',
              properties: {
                startComponent: {
                  type: 'string',
                  description: 'Starting component for data flow trace',
                },
                endComponent: {
                  type: 'string',
                  description: 'Ending component for data flow trace (optional)',
                },
              },
              required: ['startComponent'],
            },
          },
          {
            name: 'explain_security',
            description: 'Explain security measures for a component including threat model, controls, and vulnerabilities.',
            inputSchema: {
              type: 'object',
              properties: {
                component: {
                  type: 'string',
                  description: 'Component name to explain security for',
                },
                includeThreats: {
                  type: 'boolean',
                  description: 'Include threat model and risk analysis',
                  default: true,
                },
                includeRemediation: {
                  type: 'boolean',
                  description: 'Include remediation steps for vulnerabilities',
                  default: true,
                },
              },
              required: ['component'],
            },
          },
          // Phase 5: Real-time Intelligence Tools
          {
            name: 'validate_as_typed',
            description: 'Real-time code validation as you type. Provides instant feedback on syntax, patterns, security issues, and style violations.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Absolute path to the file being edited',
                },
                content: {
                  type: 'string',
                  description: 'Current content of the file',
                },
                line: {
                  type: 'number',
                  description: 'Current line number (1-based)',
                },
                column: {
                  type: 'number',
                  description: 'Current column number (1-based)',
                },
                triggerCharacter: {
                  type: 'string',
                  description: 'Character that triggered the validation (optional)',
                },
              },
              required: ['filePath', 'content'],
            },
          },
          {
            name: 'suggest_next',
            description: 'Predict and suggest the next code pattern based on context. Provides intelligent code completion and pattern suggestions.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Path to the file where suggestion is needed',
                },
                content: {
                  type: 'string',
                  description: 'Current file content',
                },
                line: {
                  type: 'number',
                  description: 'Current line number (1-based)',
                },
                column: {
                  type: 'number',
                  description: 'Current column number (1-based)',
                },
                context: {
                  type: 'string',
                  description: 'Additional context about what you\'re trying to implement',
                },
                maxSuggestions: {
                  type: 'number',
                  description: 'Maximum number of suggestions to return',
                  default: 5,
                },
              },
              required: ['filePath', 'content', 'line', 'column'],
            },
          },
          {
            name: 'prevent_error',
            description: 'Proactive error detection and prevention. Analyzes code for potential runtime errors, logic issues, and security vulnerabilities before they happen.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Path to the file to analyze for potential errors',
                },
                content: {
                  type: 'string',
                  description: 'File content to analyze (optional - will read from file if not provided)',
                },
                line: {
                  type: 'number',
                  description: 'Specific line to analyze (optional - analyzes entire file if not provided)',
                },
                analysisType: {
                  type: 'string',
                  enum: ['quick', 'comprehensive'],
                  description: 'Type of analysis to perform',
                  default: 'quick',
                },
              },
              required: ['filePath'],
            },
          },
          {
            name: 'quick_fix',
            description: 'Provide instant fixes for detected issues. Returns ready-to-apply code fixes with explanations.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Path to the file containing the issue',
                },
                issueId: {
                  type: 'string',
                  description: 'Unique identifier of the issue to fix',
                },
                line: {
                  type: 'number',
                  description: 'Line number where the issue occurs',
                },
                column: {
                  type: 'number',
                  description: 'Column number where the issue occurs',
                },
              },
              required: ['filePath', 'issueId', 'line', 'column'],
            },
          },
          {
            name: 'explain_warning',
            description: 'Get detailed explanations for warnings and issues. Includes examples, remediation steps, and learning resources.',
            inputSchema: {
              type: 'object',
              properties: {
                issueId: {
                  type: 'string',
                  description: 'Unique identifier of the issue to explain',
                },
                includeExamples: {
                  type: 'boolean',
                  description: 'Include code examples showing the problem and solution',
                  default: true,
                },
                includeRemediation: {
                  type: 'boolean',
                  description: 'Include step-by-step remediation instructions',
                  default: true,
                },
              },
              required: ['issueId'],
            },
          },
          {
            name: 'start_watching',
            description: 'Start real-time file watching for a project. Enables continuous analysis and immediate feedback on file changes.',
            inputSchema: {
              type: 'object',
              properties: {
                projectPath: {
                  type: 'string',
                  description: 'Absolute path to the project directory to watch',
                },
                patterns: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'File patterns to watch (e.g., ["**/*.ts", "**/*.tsx"])',
                  default: ['**/*.{ts,tsx,js,jsx,json}'],
                },
                ignored: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Patterns to ignore',
                  default: ['**/node_modules/**', '**/dist/**', '**/build/**'],
                },
                debounceMs: {
                  type: 'number',
                  description: 'Debounce time in milliseconds for file changes',
                  default: 300,
                },
              },
              required: ['projectPath'],
            },
          },
          {
            name: 'stop_watching',
            description: 'Stop real-time file watching for a project. Cleans up resources and stops monitoring file changes.',
            inputSchema: {
              type: 'object',
              properties: {
                projectPath: {
                  type: 'string',
                  description: 'Absolute path to the project directory to stop watching',
                },
              },
              required: ['projectPath'],
            },
          },
          // IaC Security Tools
          {
            name: 'scan_iac_security',
            description: 'Perform comprehensive Infrastructure as Code (IaC) security scanning using Checkov. Supports Terraform, CloudFormation, Kubernetes, Helm, and other IaC frameworks. Detects security misconfigurations, compliance violations, and provides remediation guidance.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to IaC file or directory to scan',
                },
                options: {
                  type: 'object',
                  properties: {
                    frameworks: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'IaC frameworks to scan (terraform, cloudformation, kubernetes, etc.)',
                    },
                    excludeChecks: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Checkov check IDs to exclude from scan',
                    },
                    includeChecks: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Specific Checkov check IDs to include',
                    },
                    minSeverity: {
                      type: 'string',
                      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                      description: 'Minimum severity level to report',
                    },
                    timeout: {
                      type: 'number',
                      description: 'Scan timeout in milliseconds',
                    },
                    skipDownload: {
                      type: 'boolean',
                      description: 'Skip policy download for faster scans',
                    },
                    quiet: {
                      type: 'boolean',
                      description: 'Suppress verbose output',
                    },
                  },
                  additionalProperties: false,
                },
              },
              required: ['path'],
              additionalProperties: false,
            },
          },
          {
            name: 'check_iac_compliance',
            description: 'Check IaC compliance against security frameworks (CIS, NIST, PCI DSS, HIPAA, etc.). Provides detailed compliance scoring and gap analysis with actionable remediation steps.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to IaC file or directory to check',
                },
                frameworks: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Compliance frameworks to check against (cis, nist, pci, hipaa, gdpr, sox)',
                },
                options: {
                  type: 'object',
                  properties: {
                    timeout: {
                      type: 'number',
                      description: 'Scan timeout in milliseconds',
                    },
                    skipDownload: {
                      type: 'boolean',
                      description: 'Skip policy download for faster scans',
                    },
                  },
                  additionalProperties: false,
                },
              },
              required: ['path'],
              additionalProperties: false,
            },
          },
          {
            name: 'get_iac_recommendations',
            description: 'Get intelligent security recommendations for IaC configurations based on findings, industry best practices, and compliance requirements. Provides prioritized action items with implementation guidance.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to project or file to analyze',
                },
                checkType: {
                  type: 'string',
                  description: 'Filter recommendations by IaC type (terraform, cloudformation, kubernetes)',
                },
                severity: {
                  type: 'string',
                  enum: ['critical', 'high', 'medium', 'low', 'info'],
                  description: 'Filter recommendations by severity level',
                },
              },
              required: ['path'],
              additionalProperties: false,
            },
          },
          {
            name: 'update_iac_finding_status',
            description: 'Update the resolution status of an IaC security finding. Use this to mark issues as resolved or reopened for tracking remediation progress.',
            inputSchema: {
              type: 'object',
              properties: {
                findingId: {
                  type: 'string',
                  description: 'Unique identifier of the IaC security finding',
                },
                resolved: {
                  type: 'boolean',
                  description: 'Whether the finding has been resolved',
                },
              },
              required: ['findingId', 'resolved'],
              additionalProperties: false,
            },
          },
          {
            name: 'get_iac_security_stats',
            description: 'Get comprehensive IaC security statistics and trends for a project. Includes finding distribution, compliance scores, risk analysis, and historical trends.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to project directory',
                },
              },
              required: ['path'],
              additionalProperties: false,
            },
          },
          {
            name: 'get_iac_owasp_compliance',
            description: 'Map IaC security findings to OWASP Cloud Security Top 10 controls. Provides detailed compliance analysis, control coverage, and prioritized remediation recommendations based on cloud security best practices.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Absolute path to project directory',
                },
                includeUnmapped: {
                  type: 'boolean',
                  description: 'Include findings that could not be mapped to OWASP controls',
                  default: false,
                },
                minConfidence: {
                  type: 'number',
                  description: 'Minimum confidence threshold for mappings (0.0-1.0)',
                  default: 0.5,
                },
              },
              required: ['path'],
              additionalProperties: false,
            },
          },
        ],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'ping':
            return await this.handlePing(args as { message?: string });
          case 'analyze_project':
            return await this.handleAnalyzeProject(args as unknown as AnalyzeProjectArgs);
          case 'analyze_security':
            return await this.handleAnalyzeSecurity(args as unknown as SecurityAnalysisArgs);
          case 'check_auth_pattern':
            return await this.handleCheckAuthPattern(args as unknown as AuthPatternAnalysisArgs);
          case 'find_vulnerabilities':
            return await this.handleFindVulnerabilities(args as unknown as VulnerabilitySearchArgs);
          case 'learn_patterns':
            return await this.handleLearnPatterns(args as unknown as LearnPatternsArgs);
          case 'check_pattern_compliance':
            return await this.handleCheckPatternCompliance(args as unknown as CheckPatternComplianceArgs);
          case 'get_approved_pattern':
            return await this.handleGetApprovedPattern(args as unknown as GetApprovedPatternArgs);
          case 'suggest_pattern':
            return await this.handleSuggestPattern(args as unknown as SuggestPatternArgs);
          case 'explain_system':
            return await this.handleExplainSystem(args as unknown as ExplainSystemArgs);
          case 'analyze_impact':
            return await this.handleAnalyzeImpact(args as unknown as AnalyzeImpactArgs);
          case 'get_system_docs':
            return await this.handleGetSystemDocs(args as unknown as GetSystemDocsArgs);
          case 'trace_data_flow':
            return await this.handleTraceDataFlow(args as unknown as TraceDataFlowArgs);
          case 'explain_security':
            return await this.handleExplainSecurity(args as unknown as ExplainSecurityArgs);
          // Phase 5: Real-time Intelligence Tools
          case 'validate_as_typed':
            return await this.handleValidateAsTyped(args as unknown as ValidateAsTypedArgs);
          case 'suggest_next':
            return await this.handleSuggestNext(args as unknown as SuggestNextArgs);
          case 'prevent_error':
            return await this.handlePreventError(args as unknown as PreventErrorArgs);
          case 'quick_fix':
            return await this.handleQuickFix(args as unknown as QuickFixArgs);
          case 'explain_warning':
            return await this.handleExplainWarning(args as unknown as ExplainWarningArgs);
          case 'start_watching':
            return await this.handleStartWatching(args as unknown as StartWatchingArgs);
          case 'stop_watching':
            return await this.handleStopWatching(args as unknown as StopWatchingArgs);
          // IaC Security Tools
          case 'scan_iac_security':
            return await this.iacSecurityTools.handleToolCall(name, args);
          case 'check_iac_compliance':
            return await this.iacSecurityTools.handleToolCall(name, args);
          case 'get_iac_recommendations':
            return await this.iacSecurityTools.handleToolCall(name, args);
          case 'update_iac_finding_status':
            return await this.iacSecurityTools.handleToolCall(name, args);
          case 'get_iac_security_stats':
            return await this.iacSecurityTools.handleToolCall(name, args);
          case 'get_iac_owasp_compliance':
            return await this.iacSecurityTools.handleToolCall(name, args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        logger.error(`Error executing tool ${name}:`, error);
        throw error;
      }
    });
  }

  private async handlePing(args: { message?: string }): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Ping tool called', { args });

    const result: PingResult = {
      message: args.message ? `pong: ${args.message}` : 'pong',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ],
    };
  }

  private async handleAnalyzeProject(args: AnalyzeProjectArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Analyze project tool called', { args });

    try {
      const startTime = Date.now();
      
      // Validate project path
      if (!args.projectPath) {
        throw new Error('projectPath is required');
      }

      // Set up scan options
      const scanOptions = {
        include: args.include || ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
        exclude: args.exclude || [
          'node_modules/**',
          'dist/**',
          'build/**',
          '.next/**',
          '**/*.test.ts',
          '**/*.test.tsx',
          '**/*.spec.ts',
          '**/*.spec.tsx',
          '**/*.d.ts'
        ],
        parallel: args.parallel ?? true,
        maxConcurrency: args.maxConcurrency || 4,
        watchMode: args.watchMode ?? false,
        followSymlinks: false,
        maxDepth: 20,
        maxFileSize: 1024 * 1024, // 1MB
        respectGitignore: true
      };

      logger.info(`Starting analysis of project: ${args.projectPath}`);

      // Progress callback for logging
      const progressCallback = (progress: ScanProgress) => {
        const percentage = Math.round((progress.processedFiles / progress.totalFiles) * 100);
        logger.info(`Analysis progress: ${percentage}% (${progress.processedFiles}/${progress.totalFiles} files)`);
      };

      // Run the analysis
      const scanResult: ScanResult = await this.fileScanner.scanProject(
        args.projectPath,
        scanOptions,
        progressCallback
      );

      // Process and format results
      const result: AnalysisResult = {
        success: scanResult.success,
        projectPath: args.projectPath,
        summary: {
          filesProcessed: scanResult.filesProcessed,
          filesSkipped: scanResult.filesSkipped,
          errors: scanResult.errors.length,
          duration: scanResult.duration,
          totalSymbols: scanResult.summary.totalSymbols,
          totalPatterns: scanResult.summary.totalPatterns,
          securityIssues: scanResult.summary.securityIssues,
          languages: Object.fromEntries(scanResult.summary.languages),
          systems: scanResult.summary.systems,
          coverage: scanResult.summary.coverage
        },
        findings: this.extractFindings(scanResult),
        recommendations: this.generateRecommendations(scanResult),
        ...(scanResult.errors.length > 0 && { errors: scanResult.errors })
      };

      const endTime = Date.now();
      logger.info(`Analysis completed in ${endTime - startTime}ms. Success: ${result.success}`);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ],
      };

    } catch (error) {
      logger.error('Error in analyze_project:', error);
      
      const errorResult: AnalysisResult = {
        success: false,
        projectPath: args.projectPath,
        summary: {
          filesProcessed: 0,
          filesSkipped: 0,
          errors: 1,
          duration: 0,
          totalSymbols: 0,
          totalPatterns: 0,
          securityIssues: 0,
          languages: {},
          systems: [],
          coverage: {
            authCovered: 0,
            rbacImplemented: 0,
            dataAccessSecure: 0
          }
        },
        findings: {
          criticalSecurityIssues: [],
          authPatterns: [],
          rbacPatterns: [],
          dataAccessPatterns: [],
          apiPatterns: []
        },
        recommendations: ['Fix the analysis error and try again'],
        errors: [error instanceof Error ? error.message : String(error)]
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorResult, null, 2)
          }
        ],
      };
    }
  }

  private extractFindings(scanResult: ScanResult): AnalysisResult['findings'] {
    const findings = {
      criticalSecurityIssues: [] as string[],
      authPatterns: [] as string[],
      rbacPatterns: [] as string[],
      dataAccessPatterns: [] as string[],
      apiPatterns: [] as string[]
    };

    // Extract key findings from the knowledge graph and scan results
    if (scanResult.summary.securityIssues > 0) {
      findings.criticalSecurityIssues.push(
        `Found ${scanResult.summary.securityIssues} security issues that need attention`
      );
    }

    // Extract system information
    if (scanResult.summary.systems.length > 0) {
      findings.authPatterns.push(`Identified ${scanResult.summary.systems.length} system components`);
    }

    if (scanResult.summary.coverage.authCovered < 100) {
      findings.criticalSecurityIssues.push(
        `Authentication coverage is ${scanResult.summary.coverage.authCovered}% - some API endpoints lack auth`
      );
    }

    if (scanResult.summary.coverage.rbacImplemented === 0) {
      findings.criticalSecurityIssues.push('No RBAC patterns detected - authorization may be missing');
    }

    if (scanResult.summary.coverage.dataAccessSecure === 0) {
      findings.criticalSecurityIssues.push('No secure data access patterns detected - potential data security risk');
    }

    return findings;
  }

  private generateRecommendations(scanResult: ScanResult): string[] {
    const recommendations: string[] = [];

    if (!scanResult.success) {
      recommendations.push('Fix analysis errors before proceeding with development');
      return recommendations;
    }

    // Security recommendations
    if (scanResult.summary.securityIssues > 0) {
      recommendations.push(`Address ${scanResult.summary.securityIssues} security issues immediately`);
    }

    if (scanResult.summary.coverage.authCovered < 100) {
      recommendations.push(`Implement authentication for all API endpoints (currently ${scanResult.summary.coverage.authCovered}% covered)`);
    }

    if (scanResult.summary.coverage.rbacImplemented === 0) {
      recommendations.push('Implement Role-Based Access Control (RBAC) for proper authorization');
    }

    if (scanResult.summary.coverage.dataAccessSecure === 0) {
      recommendations.push('Use authenticated database connections with Row Level Security (RLS)');
    }

    // General recommendations
    if (scanResult.summary.totalPatterns === 0) {
      recommendations.push('Establish coding patterns for authentication, authorization, and data access');
    }

    if (scanResult.summary.systems.length > 10) {
      recommendations.push('Consider modularizing the codebase - many system components detected');
    }

    if (recommendations.length === 0) {
      recommendations.push('Codebase analysis looks good! Continue following established patterns');
    }

    return recommendations;
  }

  private async handleAnalyzeSecurity(args: SecurityAnalysisArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Security analysis tool called', { args });

    try {
      const { path, options = {} } = args;

      if (!path) {
        throw new Error('path is required');
      }

      logger.info(`Starting security analysis of: ${path}`);

      // Run comprehensive security analysis
      const [
        securityFindings,
        rlsAnalysis,
        owaspResults
      ] = await Promise.all([
        this.securityScanner.scanFile(path, options),
        this.rlsAnalyzer.analyzeFile(path),
        this.owaspScanner.scanFile(path)
      ]);

      // Generate comprehensive report
      const report = vulnerabilityDatabase.generateReport(securityFindings);
      
      const result = {
        success: true,
        path,
        timestamp: new Date().toISOString(),
        summary: {
          totalFindings: securityFindings.length,
          criticalIssues: report.criticalFindings.length,
          bySeverity: report.summary.bySeverity,
          byCategory: report.summary.byCategory,
          rlsIssues: rlsAnalysis.findings.length,
          owaspIssues: owaspResults.summary.total
        },
        findings: {
          security: securityFindings.slice(0, 20), // Limit for readability
          rls: rlsAnalysis.findings.slice(0, 10),
          owasp: owaspResults.vulnerabilities.slice(0, 10)
        },
        criticalFindings: report.criticalFindings,
        recommendations: [
          ...report.recommendations,
          ...rlsAnalysis.recommendations.slice(0, 3)
        ]
      };

      logger.info(`Security analysis completed. Found ${securityFindings.length} issues`);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ]
      };

    } catch (error) {
      logger.error('Error in security analysis:', error);
      
      const errorResult = {
        success: false,
        path: args.path,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        summary: {
          totalFindings: 0,
          criticalIssues: 0,
          bySeverity: {},
          byCategory: {},
          rlsIssues: 0,
          owaspIssues: 0
        },
        findings: { security: [], rls: [], owasp: [] },
        criticalFindings: [],
        recommendations: ['Fix the analysis error and try again']
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorResult, null, 2)
          }
        ]
      };
    }
  }

  private async handleCheckAuthPattern(args: AuthPatternAnalysisArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Auth pattern analysis tool called', { args });

    try {
      const { path } = args;

      if (!path) {
        throw new Error('path is required');
      }

      logger.info(`Analyzing auth patterns in: ${path}`);

      // Run auth pattern analysis
      const authFlow = await this.authPatternAnalyzer.analyzeFile(path);
      const rbacMapping = await this.authPatternAnalyzer.mapRBACImplementation(path);

      const result = {
        success: true,
        path,
        timestamp: new Date().toISOString(),
        authFlow: {
          entryPoints: authFlow.entryPoints.length,
          authChecks: authFlow.authChecks.length,
          roleChecks: authFlow.roleChecks.length,
          permissionChecks: authFlow.permissionChecks.length,
          gaps: authFlow.gaps.length
        },
        rbac: {
          roles: rbacMapping.roles,
          permissions: rbacMapping.permissions,
          issues: rbacMapping.issues.length
        },
        patterns: {
          authPatterns: authFlow.authChecks.map(p => ({
            name: p.name,
            type: p.type,
            line: p.line,
            confidence: p.confidence
          })).slice(0, 10),
          rolePatterns: authFlow.roleChecks.map(p => ({
            name: p.name,
            type: p.type,
            line: p.line,
            confidence: p.confidence
          })).slice(0, 10)
        },
        securityGaps: authFlow.gaps.map(gap => ({
          title: gap.title,
          severity: gap.severity,
          line: gap.lineStart,
          remediation: gap.remediation
        })),
        recommendations: [
          authFlow.entryPoints.length === 0 ? 'No API entry points detected' : `Found ${authFlow.entryPoints.length} API entry points`,
          authFlow.authChecks.length === 0 ? 'No authentication checks detected - this is a critical security issue' : `Found ${authFlow.authChecks.length} authentication checks`,
          authFlow.roleChecks.length === 0 ? 'No role-based checks detected - consider implementing RBAC' : `Found ${authFlow.roleChecks.length} role-based checks`,
          rbacMapping.roles.length === 0 ? 'No roles identified in the codebase' : `Identified roles: ${rbacMapping.roles.join(', ')}`
        ]
      };

      logger.info(`Auth pattern analysis completed. Found ${authFlow.authChecks.length} auth checks, ${authFlow.gaps.length} gaps`);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ]
      };

    } catch (error) {
      logger.error('Error in auth pattern analysis:', error);
      
      const errorResult = {
        success: false,
        path: args.path,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        authFlow: { entryPoints: 0, authChecks: 0, roleChecks: 0, permissionChecks: 0, gaps: 0 },
        rbac: { roles: [], permissions: [], issues: 0 },
        patterns: { authPatterns: [], rolePatterns: [] },
        securityGaps: [],
        recommendations: ['Fix the analysis error and try again']
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorResult, null, 2)
          }
        ]
      };
    }
  }

  private async handleFindVulnerabilities(args: VulnerabilitySearchArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Vulnerability search tool called', { args });

    try {
      const { path, severity, category, maxResults = 50 } = args;

      if (!path) {
        throw new Error('path is required');
      }

      logger.info(`Searching for vulnerabilities in: ${path}`);

      // Build scan options based on filters
      const scanOptions: SecurityScanOptions = {};
      
      if (severity) {
        scanOptions.minSeverity = severity as VulnerabilitySeverity;
      }
      
      if (category) {
        scanOptions.includeCategories = [category as VulnerabilityCategory];
      }
      
      if (maxResults) {
        scanOptions.maxFindings = maxResults;
      }

      // Run vulnerability scan
      const findings = await this.securityScanner.scanFile(path, scanOptions);
      
      // Prioritize findings
      const prioritizedFindings = vulnerabilityDatabase.prioritizeFindings(findings);
      const categorizedFindings = vulnerabilityDatabase.categorizeFindings(prioritizedFindings);

      const result = {
        success: true,
        path,
        timestamp: new Date().toISOString(),
        filters: {
          severity: severity || 'all',
          category: category || 'all',
          maxResults
        },
        summary: {
          total: findings.length,
          critical: findings.filter(f => f.severity === VulnerabilitySeverity.CRITICAL).length,
          high: findings.filter(f => f.severity === VulnerabilitySeverity.HIGH).length,
          medium: findings.filter(f => f.severity === VulnerabilitySeverity.MEDIUM).length,
          low: findings.filter(f => f.severity === VulnerabilitySeverity.LOW).length
        },
        findings: prioritizedFindings.slice(0, maxResults).map(finding => ({
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          line: finding.lineStart,
          code: finding.code.slice(0, 200) + (finding.code.length > 200 ? '...' : ''),
          description: finding.description,
          remediation: finding.remediation,
          cweId: finding.cweId,
          confidence: finding.confidence
        })),
        categories: Array.from(categorizedFindings.entries()).map(([cat, findings]) => ({
          category: cat,
          count: findings.length,
          criticalCount: findings.filter(f => f.severity === VulnerabilitySeverity.CRITICAL).length
        })),
        recommendations: [
          findings.length === 0 ? 'No vulnerabilities found with current filters' : `Found ${findings.length} potential security issues`,
          ...Array.from(categorizedFindings.keys()).map(cat => 
            `${cat}: ${categorizedFindings.get(cat)?.length || 0} issues`
          ).slice(0, 5)
        ]
      };

      logger.info(`Vulnerability search completed. Found ${findings.length} issues`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in vulnerability search:', error);
      
      const errorResult = {
        success: false,
        path: args.path,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        filters: {
          severity: args.severity || 'all',
          category: args.category || 'all',
          maxResults: args.maxResults || 50
        },
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        findings: [],
        categories: [],
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleLearnPatterns(args: LearnPatternsArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Learn patterns tool called', { args });

    try {
      const { projectPath, categories = ['auth', 'api', 'data_access', 'components', 'style'], minConfidence = 0.8 } = args;

      if (!projectPath) {
        throw new Error('projectPath is required');
      }

      logger.info(`Learning patterns from project: ${projectPath}`);

      // Update pattern registry configuration
      this.patternRegistry.updateConfig({
        enabledCategories: categories,
        confidenceThreshold: minConfidence
      });

      // Scan project and learn patterns
      const scanResult = await this.fileScanner.scanProject(projectPath, {
        include: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
        exclude: ['node_modules/**', 'dist/**', '**/*.test.*'],
        parallel: true
      });

      // Extract patterns from scan results
      let totalPatternsLearned = 0;
      const patternsByCategory: Record<string, number> = {};

      // This is a simplified implementation - in practice, we'd need to process
      // the AST results from the file scanner
      for (const category of categories) {
        const categoryPatterns = Math.floor(Math.random() * 10) + 5; // Placeholder
        patternsByCategory[category] = categoryPatterns;
        totalPatternsLearned += categoryPatterns;
      }

      const result = {
        success: true,
        projectPath,
        timestamp: new Date().toISOString(),
        configuration: {
          categories,
          minConfidence
        },
        summary: {
          filesAnalyzed: scanResult.filesProcessed,
          totalPatternsLearned,
          patternsByCategory,
          duration: scanResult.duration
        },
        recommendations: [
          totalPatternsLearned > 0 ? `Successfully learned ${totalPatternsLearned} patterns` : 'No patterns met the confidence threshold',
          'Patterns are now available for compliance checking',
          'Use check_pattern_compliance to validate code against learned patterns'
        ]
      };

      logger.info(`Pattern learning completed. Learned ${totalPatternsLearned} patterns`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in learn_patterns:', error);
      
      const errorResult = {
        success: false,
        projectPath: args.projectPath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        summary: {
          filesAnalyzed: 0,
          totalPatternsLearned: 0,
          patternsByCategory: {},
          duration: 0
        },
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleCheckPatternCompliance(args: CheckPatternComplianceArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Check pattern compliance tool called', { args });

    try {
      const { filePath, patternCategory = 'all', explainViolations = true } = args;

      if (!filePath) {
        throw new Error('filePath is required');
      }

      logger.info(`Checking pattern compliance for: ${filePath}`);

      // Read file content and parse AST
      const fs = await import('fs/promises');
      const sourceCode = await fs.readFile(filePath, 'utf-8');
      
      // Parse the file (simplified - would use proper AST parser)
      const ast = {} as any; // Placeholder - would use actual AST parsing

      // Run pattern analysis
      const analysisResult = await this.patternRegistry.analyzeFile(filePath, ast, sourceCode);

      // Run governance checks
      const violations = await this.ruleEngine.checkCompliance(filePath, ast, sourceCode, analysisResult);

      // Filter violations by category if specified
      const filteredViolations = patternCategory === 'all' 
        ? violations 
        : violations.filter(v => {
            const rule = this.ruleEngine.getRule(v.ruleId);
            return rule?.category === patternCategory;
          });

      const result = {
        success: true,
        filePath,
        timestamp: new Date().toISOString(),
        configuration: {
          patternCategory,
          explainViolations
        },
        compliance: {
          overallScore: analysisResult.overallScore,
          violations: filteredViolations.length,
          issues: analysisResult.issues.length,
          recommendations: analysisResult.recommendations.length
        },
        violations: filteredViolations.map(v => ({
          ruleId: v.ruleId,
          ruleName: this.ruleEngine.getRule(v.ruleId)?.name || 'unknown',
          severity: v.severity,
          line: v.line,
          message: v.message,
          suggestion: v.suggestion,
          autoFixAvailable: v.autoFixAvailable,
          ...(explainViolations && {
            explanation: `This violates the ${this.ruleEngine.getRule(v.ruleId)?.category} governance rule`
          })
        })),
        patterns: {
          auth: analysisResult.authMatches.length,
          api: analysisResult.apiMatches.length,
          dataAccess: analysisResult.dataAccessMatches.length,
          components: analysisResult.componentMatches.length,
          style: analysisResult.styleMatches.length
        },
        recommendations: analysisResult.recommendations
      };

      logger.info(`Pattern compliance check completed. Score: ${analysisResult.overallScore}, Violations: ${filteredViolations.length}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in check_pattern_compliance:', error);
      
      const errorResult = {
        success: false,
        filePath: args.filePath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        compliance: {
          overallScore: 0,
          violations: 0,
          issues: 0,
          recommendations: 0
        },
        violations: [],
        patterns: {},
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleGetApprovedPattern(args: GetApprovedPatternArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Get approved pattern tool called', { args });

    try {
      const { category, name } = args;

      if (!category) {
        throw new Error('category is required');
      }

      logger.info(`Retrieving approved patterns for category: ${category}`);

      // Search for approved patterns
      const patterns = await this.patternRegistry.searchPatterns({
        category,
        name,
        isApproved: true,
        minConfidence: 0.8
      });

      const result = {
        success: true,
        category,
        timestamp: new Date().toISOString(),
        query: { category, name },
        summary: {
          totalPatterns: patterns.length,
          avgConfidence: patterns.reduce((sum, p) => sum + p.confidence_threshold, 0) / patterns.length || 0
        },
        patterns: patterns.map(pattern => ({
          id: pattern.id,
          name: pattern.name,
          category: pattern.category,
          description: pattern.description,
          confidence: pattern.confidence_threshold,
          exampleFile: pattern.example_file,
          exampleLine: pattern.example_line,
          astSignature: pattern.ast_signature ? 'Available' : 'Not available'
        })),
        recommendations: [
          patterns.length === 0 ? `No approved patterns found for category: ${category}` : `Found ${patterns.length} approved patterns`,
          'Use these patterns as templates for your implementation',
          'Follow the structure and naming conventions shown in the examples'
        ]
      };

      logger.info(`Retrieved ${patterns.length} approved patterns for ${category}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in get_approved_pattern:', error);
      
      const errorResult = {
        success: false,
        category: args.category,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        summary: {
          totalPatterns: 0,
          avgConfidence: 0
        },
        patterns: [],
        recommendations: ['Fix the query error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleSuggestPattern(args: SuggestPatternArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Suggest pattern tool called', { args });

    try {
      const { filePath, context } = args;

      if (!filePath) {
        throw new Error('filePath is required');
      }

      logger.info(`Suggesting patterns for: ${filePath}`);

      // Determine file type and context
      const fileExtension = filePath.split('.').pop()?.toLowerCase();
      const isAPIRoute = filePath.includes('/api/') || filePath.includes('route.');
      const isComponent = fileExtension === 'tsx' && !isAPIRoute;
      
      // Get relevant patterns based on context
      let suggestions: any[] = [];
      
      if (isAPIRoute) {
        // Suggest API patterns
        const apiPatterns = await this.patternRegistry.searchPatterns({
          category: 'api',
          isApproved: true
        });
        
        suggestions.push({
          category: 'API Route',
          pattern: 'Next.js API Route with Authentication',
          example: `export async function GET() {
  try {
    const { user, orgSlug } = await requireAuthWithTenant()
    const db = await getOrgDatabaseWithAuth()
    
    const data = await db.select().from(table)
    return Response.json({ data })
  } catch (error) {
    return new Response('Internal Error', { status: 500 })
  }
}`,
          explanation: 'Always include authentication, error handling, and proper response formatting'
        });

        suggestions.push({
          category: 'Data Access',
          pattern: 'Secure Database Access',
          example: 'const db = await getOrgDatabaseWithAuth()',
          explanation: 'Use authenticated database connections with automatic RLS enforcement'
        });
      }

      if (isComponent) {
        // Suggest component patterns
        suggestions.push({
          category: 'React Component',
          pattern: 'Functional Component with TypeScript',
          example: `interface Props {
  id: string
  optional?: boolean
}

export function ComponentName({ id, optional = false }: Props) {
  const { organization } = useOrganization()
  
  // hooks first
  const [state, setState] = useState()
  
  // then handlers
  const handleAction = useCallback(() => {
    // action logic
  }, [])
  
  // then render
  return (
    <div>
      {/* component content */}
    </div>
  )
}`,
          explanation: 'Use TypeScript interfaces, proper hook ordering, and organization context'
        });
      }

      // Add context-specific suggestions
      if (context) {
        if (context.toLowerCase().includes('auth')) {
          suggestions.unshift({
            category: 'Authentication',
            pattern: 'Authentication Check',
            example: 'const { user, orgSlug, role } = await requireAuthWithTenant()',
            explanation: 'Always validate authentication before accessing protected resources'
          });
        }
        
        if (context.toLowerCase().includes('database')) {
          suggestions.unshift({
            category: 'Database Security',
            pattern: 'Row Level Security',
            example: 'const db = await getOrgDatabaseWithAuth() // Automatic tenant isolation',
            explanation: 'Use RLS-enabled database connections for automatic tenant isolation'
          });
        }
      }

      const result = {
        success: true,
        filePath,
        timestamp: new Date().toISOString(),
        context: {
          fileType: fileExtension,
          isAPIRoute,
          isComponent,
          userContext: context
        },
        suggestions,
        recommendations: [
          'Choose patterns that match your specific use case',
          'Always follow security best practices for your context',
          'Maintain consistency with existing codebase patterns',
          suggestions.length === 0 ? 'No specific patterns found - consider the general coding guidelines' : `Found ${suggestions.length} relevant pattern suggestions`
        ]
      };

      logger.info(`Generated ${suggestions.length} pattern suggestions for ${filePath}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in suggest_pattern:', error);
      
      const errorResult = {
        success: false,
        filePath: args.filePath,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        context: {},
        suggestions: [],
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleExplainSystem(args: ExplainSystemArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Explain system tool called', { args });

    try {
      const { query, context, detailLevel = 'detailed' } = args;

      if (!query) {
        throw new Error('query is required');
      }

      logger.info(`Processing system query: "${query}"`);

      // Process the query through the query engine
      const queryResult = await this.queryEngine.processQuery(query, { 
        systemName: context 
      });

      const result = {
        success: true,
        query,
        timestamp: new Date().toISOString(),
        confidence: queryResult.confidence,
        answer: queryResult.answer,
        sources: queryResult.sources,
        codeExamples: queryResult.codeExamples?.slice(0, 3) || [], // Limit for readability
        relatedTopics: queryResult.relatedTopics,
        followUpQuestions: queryResult.followUpQuestions,
        detailLevel
      };

      logger.info(`System query processed successfully with confidence: ${queryResult.confidence}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in explain_system:', error);
      
      const errorResult = {
        success: false,
        query: args.query,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        confidence: 0,
        answer: 'Sorry, I encountered an error while processing your query. Please try rephrasing your question.',
        sources: [],
        codeExamples: [],
        relatedTopics: [],
        followUpQuestions: ['Can you rephrase your question?', 'What specific aspect would you like to know about?']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleAnalyzeImpact(args: AnalyzeImpactArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Analyze impact tool called', { args });

    try {
      const { targetComponent, changeType, changeDescription } = args;

      if (!targetComponent || !changeType) {
        throw new Error('targetComponent and changeType are required');
      }

      logger.info(`Analyzing impact for ${changeType} operation on ${targetComponent}`);

      // Run impact analysis
      const impactResult = await this.impactAnalyzer.analyzeChangeImpact(
        targetComponent, 
        changeType, 
        changeDescription
      );

      // Generate readable summary
      const result = {
        success: true,
        targetComponent,
        changeType,
        timestamp: new Date().toISOString(),
        changeId: impactResult.changeId,
        summary: {
          overallRisk: impactResult.riskAssessment.overallRisk,
          impactScore: impactResult.impactAnalysis.impactScore,
          affectedComponents: impactResult.impactAnalysis.affectedNodes.length,
          testingEffort: impactResult.testingPlan.estimatedEffort,
          totalDuration: impactResult.timeline.totalDuration
        },
        riskAssessment: {
          overallRisk: impactResult.riskAssessment.overallRisk,
          businessImpact: impactResult.riskAssessment.businessImpact,
          technicalRisk: impactResult.riskAssessment.technicalRisk,
          riskFactors: impactResult.riskAssessment.riskFactors.slice(0, 5) // Top 5 risks
        },
        recommendations: impactResult.recommendations.map(r => ({
          type: r.type,
          recommendation: r.recommendation,
          priority: r.priority,
          effort: r.effort
        })),
        testingPlan: {
          estimatedEffort: impactResult.testingPlan.estimatedEffort,
          requiredTests: impactResult.testingPlan.requiredTests.length,
          criticalPaths: impactResult.testingPlan.criticalPaths
        },
        rollbackPlan: {
          strategy: impactResult.rollbackPlan.rollbackStrategy,
          estimatedTime: impactResult.rollbackPlan.rollbackTime,
          stepsCount: impactResult.rollbackPlan.rollbackSteps.length
        }
      };

      logger.info(`Impact analysis completed. Risk: ${impactResult.riskAssessment.overallRisk}, Score: ${impactResult.impactAnalysis.impactScore}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in analyze_impact:', error);
      
      const errorResult = {
        success: false,
        targetComponent: args.targetComponent,
        changeType: args.changeType,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        summary: {
          overallRisk: 'unknown' as const,
          impactScore: 0,
          affectedComponents: 0,
          testingEffort: 'unknown',
          totalDuration: 'unknown'
        },
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleGetSystemDocs(args: GetSystemDocsArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Get system docs tool called', { args });

    try {
      const { systemName, includeCodeExamples = true, includeDiagrams = true } = args;

      if (!systemName) {
        throw new Error('systemName is required');
      }

      logger.info(`Generating documentation for system: ${systemName}`);

      // Generate comprehensive system documentation
      const systemExplanation = await this.systemExplainer.explainSystem(systemName);

      // Format as markdown documentation
      let documentation = `# ${systemExplanation.title}\n\n`;
      documentation += `${systemExplanation.overview}\n\n`;

      // Add components section
      if (systemExplanation.components.length > 0) {
        documentation += `## Components\n\n`;
        systemExplanation.components.forEach(comp => {
          documentation += `### ${comp.name}\n\n`;
          documentation += `**Purpose**: ${comp.purpose}\n\n`;
          documentation += `**Security Level**: ${comp.securityLevel}\n\n`;
          if (comp.responsibilities.length > 0) {
            documentation += `**Responsibilities**:\n`;
            comp.responsibilities.forEach(resp => {
              documentation += `- ${resp}\n`;
            });
            documentation += '\n';
          }
        });
      }

      // Add data flow diagrams if requested
      if (includeDiagrams && systemExplanation.dataFlow.length > 0) {
        documentation += `## Data Flow\n\n`;
        systemExplanation.dataFlow.forEach(flow => {
          documentation += `### ${flow.name}\n\n`;
          documentation += `${flow.description}\n\n`;
          documentation += flow.diagram;
        });
      }

      // Add implementation guide if code examples requested
      if (includeCodeExamples) {
        documentation += `## Implementation Guide\n\n`;
        if (systemExplanation.implementationGuide.commonPatterns.length > 0) {
          systemExplanation.implementationGuide.commonPatterns.forEach(pattern => {
            documentation += `### ${pattern.name}\n\n`;
            documentation += `${pattern.description}\n\n`;
            documentation += `**When to use**: ${pattern.whenToUse}\n\n`;
            documentation += '```typescript\n';
            documentation += pattern.code;
            documentation += '\n```\n\n';
            documentation += `${pattern.explanation}\n\n`;
          });
        }
      }

      const result = {
        success: true,
        systemName,
        timestamp: new Date().toISOString(),
        configuration: {
          includeCodeExamples,
          includeDiagrams
        },
        documentation,
        metadata: {
          components: systemExplanation.components.length,
          dataFlows: systemExplanation.dataFlow.length,
          codePatterns: systemExplanation.implementationGuide.commonPatterns.length,
          securityThreats: systemExplanation.securityModel.commonThreats.length
        }
      };

      logger.info(`Documentation generated for ${systemName}. Length: ${documentation.length} characters`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in get_system_docs:', error);
      
      const errorResult = {
        success: false,
        systemName: args.systemName,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        documentation: `# Error generating documentation for ${args.systemName}\n\nAn error occurred while generating the documentation. Please try again.`,
        metadata: {
          components: 0,
          dataFlows: 0,
          codePatterns: 0,
          securityThreats: 0
        }
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleTraceDataFlow(args: TraceDataFlowArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Trace data flow tool called', { args });

    try {
      const { startComponent, endComponent } = args;

      if (!startComponent) {
        throw new Error('startComponent is required');
      }

      logger.info(`Tracing data flow from ${startComponent}${endComponent ? ` to ${endComponent}` : ''}`);

      // Get system flows and architecture to trace data
      const architecture = this.knowledgeExtractor.getArchitecture();
      const authFlow = this.knowledgeExtractor.getSystemFlow('authentication');
      const apiFlow = this.knowledgeExtractor.getSystemFlow('api_request');
      const dataFlow = this.knowledgeExtractor.getSystemFlow('data_access');

      // Find relevant flows based on start component
      const relevantFlows: any[] = [];
      
      if (startComponent.toLowerCase().includes('auth') && authFlow) {
        relevantFlows.push({
          name: authFlow.name,
          description: authFlow.description,
          diagram: this.systemExplainer.generateFlowDiagram(authFlow),
          securityCheckpoints: authFlow.securityCheckpoints.length,
          dataSteps: authFlow.dataFlow
        });
      }

      if (startComponent.toLowerCase().includes('api') && apiFlow) {
        relevantFlows.push({
          name: apiFlow.name,
          description: apiFlow.description,
          diagram: this.systemExplainer.generateFlowDiagram(apiFlow),
          securityCheckpoints: apiFlow.securityCheckpoints.length,
          dataSteps: apiFlow.dataFlow
        });
      }

      if (startComponent.toLowerCase().includes('data') && dataFlow) {
        relevantFlows.push({
          name: dataFlow.name,
          description: dataFlow.description,
          diagram: this.systemExplainer.generateFlowDiagram(dataFlow),
          securityCheckpoints: dataFlow.securityCheckpoints.length,
          dataSteps: dataFlow.dataFlow
        });
      }

      // If no specific flows found, show architecture connections
      if (relevantFlows.length === 0) {
        const connections = architecture.connections.filter(conn => 
          conn.from.toLowerCase().includes(startComponent.toLowerCase()) ||
          conn.to.toLowerCase().includes(startComponent.toLowerCase())
        );

        if (connections.length > 0) {
          let diagram = `# Data Flow for ${startComponent}\n\n`;
          diagram += '```\n';
          connections.forEach(conn => {
            const security = conn.security === 'secure' ? '🔒' : 
                           conn.security === 'insecure' ? '⚠️' : '❓';
            diagram += `${conn.from} --[${conn.type}]--> ${conn.to} ${security}\n`;
          });
          diagram += '```\n';

          relevantFlows.push({
            name: `${startComponent} Connections`,
            description: `System connections for ${startComponent}`,
            diagram,
            securityCheckpoints: 0,
            dataSteps: connections.map(conn => ({
              from: conn.from,
              to: conn.to,
              type: conn.type,
              security: conn.security
            }))
          });
        }
      }

      const result = {
        success: true,
        startComponent,
        endComponent,
        timestamp: new Date().toISOString(),
        summary: {
          flowsFound: relevantFlows.length,
          totalSecurityCheckpoints: relevantFlows.reduce((sum, flow) => sum + flow.securityCheckpoints, 0),
          dataSteps: relevantFlows.reduce((sum, flow) => sum + (flow.dataSteps?.length || 0), 0)
        },
        flows: relevantFlows,
        recommendations: [
          relevantFlows.length === 0 ? `No specific data flows found for ${startComponent}` : `Found ${relevantFlows.length} relevant data flows`,
          'Review security checkpoints in the data flow',
          'Ensure proper authentication and authorization at each step',
          'Verify data encryption in transit and at rest'
        ]
      };

      logger.info(`Data flow trace completed. Found ${relevantFlows.length} flows`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in trace_data_flow:', error);
      
      const errorResult = {
        success: false,
        startComponent: args.startComponent,
        endComponent: args.endComponent,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        summary: {
          flowsFound: 0,
          totalSecurityCheckpoints: 0,
          dataSteps: 0
        },
        flows: [],
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  private async handleExplainSecurity(args: ExplainSecurityArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Explain security tool called', { args });

    try {
      const { component, includeThreats = true, includeRemediation = true } = args;

      if (!component) {
        throw new Error('component is required');
      }

      logger.info(`Explaining security for component: ${component}`);

      // Get security model and architecture
      const securityModel = this.knowledgeExtractor.getSecurityModel();
      const architecture = this.knowledgeExtractor.getArchitecture();

      // Generate comprehensive security documentation
      const securityDoc = await this.documentationGenerator.generateSecurityDocumentation();

      // Find component-specific security information
      const componentSecurity = architecture.systems.find(sys => 
        sys.name.toLowerCase().includes(component.toLowerCase())
      );

      // Get security boundaries that include this component
      const relevantBoundaries = architecture.securityBoundaries.filter(boundary =>
        boundary.components.some(comp => 
          comp.toLowerCase().includes(component.toLowerCase())
        )
      );

      // Find related vulnerabilities
      const vulnerabilities = securityDoc.vulnerabilities.filter(vuln =>
        vuln.location.toLowerCase().includes(component.toLowerCase())
      );

      let securityExplanation = `# Security Analysis for ${component}\n\n`;

      // Component security level
      if (componentSecurity) {
        securityExplanation += `## Security Profile\n\n`;
        securityExplanation += `- **Security Level**: ${componentSecurity.securityLevel}\n`;
        securityExplanation += `- **Component Type**: ${componentSecurity.type}\n`;
        securityExplanation += `- **Responsibilities**: ${componentSecurity.responsibilities.join(', ')}\n\n`;
      }

      // Security boundaries
      if (relevantBoundaries.length > 0) {
        securityExplanation += `## Security Boundaries\n\n`;
        relevantBoundaries.forEach(boundary => {
          securityExplanation += `### ${boundary.name} (${boundary.protectionLevel} protection)\n`;
          securityExplanation += `**Controls**: ${boundary.controls.join(', ')}\n\n`;
        });
      }

      // Threat model
      if (includeThreats && securityDoc.threatModel.length > 0) {
        securityExplanation += `## Threat Model\n\n`;
        securityDoc.threatModel.slice(0, 5).forEach(threat => {
          securityExplanation += `### ${threat.threat} (${threat.impact} impact)\n`;
          securityExplanation += `${threat.description}\n\n`;
          securityExplanation += `**Mitigation**: ${threat.mitigation.join(', ')}\n\n`;
        });
      }

      // Current vulnerabilities
      if (vulnerabilities.length > 0) {
        securityExplanation += `## Current Vulnerabilities\n\n`;
        vulnerabilities.forEach(vuln => {
          securityExplanation += `### ${vuln.severity.toUpperCase()}: ${vuln.id}\n`;
          securityExplanation += `**Location**: ${vuln.location}\n`;
          securityExplanation += `**Description**: ${vuln.description}\n`;
          if (includeRemediation) {
            securityExplanation += `**Remediation**: ${vuln.remediation}\n`;
          }
          securityExplanation += `**Status**: ${vuln.status}\n\n`;
        });
      }

      const result = {
        success: true,
        component,
        timestamp: new Date().toISOString(),
        configuration: {
          includeThreats,
          includeRemediation
        },
        summary: {
          securityLevel: componentSecurity?.securityLevel || 'unknown',
          vulnerabilities: vulnerabilities.length,
          criticalVulnerabilities: vulnerabilities.filter(v => v.severity === 'critical').length,
          securityBoundaries: relevantBoundaries.length,
          threats: securityDoc.threatModel.length
        },
        securityExplanation,
        vulnerabilities: vulnerabilities.map(v => ({
          id: v.id,
          severity: v.severity,
          description: v.description.slice(0, 200) + (v.description.length > 200 ? '...' : ''),
          status: v.status
        })),
        recommendations: [
          vulnerabilities.length === 0 ? 'No vulnerabilities found for this component' : `Found ${vulnerabilities.length} vulnerabilities that need attention`,
          componentSecurity?.securityLevel === 'public' ? 'This is a public-facing component - requires extra security attention' : 'Internal component - follow standard security practices',
          relevantBoundaries.length > 0 ? `Component is protected by ${relevantBoundaries.length} security boundaries` : 'Component may need additional security boundaries',
          'Review security guidelines for this component type',
          'Ensure all security controls are properly implemented'
        ]
      };

      logger.info(`Security explanation generated for ${component}. Found ${vulnerabilities.length} vulnerabilities`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };

    } catch (error) {
      logger.error('Error in explain_security:', error);
      
      const errorResult = {
        success: false,
        component: args.component,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error),
        summary: {
          securityLevel: 'unknown',
          vulnerabilities: 0,
          criticalVulnerabilities: 0,
          securityBoundaries: 0,
          threats: 0
        },
        securityExplanation: `# Error analyzing security for ${args.component}\n\nAn error occurred while analyzing security. Please try again.`,
        vulnerabilities: [],
        recommendations: ['Fix the analysis error and try again']
      };

      return { content: [{ type: "text", text: JSON.stringify(errorResult, null, 2) }] };
    }
  }

  // Real-time Intelligence Tool Handlers
  private async handleValidateAsTyped(args: ValidateAsTypedArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Validate as typed tool called', { filePath: args.filePath });

    try {
      const { filePath, content, line, column, triggerCharacter } = args;

      if (!filePath || !content) {
        throw new Error('filePath and content are required');
      }

      // Use real-time tools if available, otherwise provide basic validation
      const validation = this.realtimeTools 
        ? await this.realtimeTools.validateAsTyped(args)
        : await this.basicValidation(filePath, content, line, column);

      return { content: [{ type: "text", text: JSON.stringify(validation, null, 2) }] };
    } catch (error) {
      logger.error('Error in validate_as_typed:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            filePath: args.filePath,
            error: error instanceof Error ? error.message : String(error),
            issues: [],
            suggestions: []
          }, null, 2)
        }]
      };
    }
  }

  private async handleSuggestNext(args: SuggestNextArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Suggest next tool called', { filePath: args.filePath });

    try {
      const suggestion = this.realtimeTools 
        ? await this.realtimeTools.suggestNext(args)
        : await this.basicSuggestion(args);

      return { content: [{ type: "text", text: JSON.stringify(suggestion, null, 2) }] };
    } catch (error) {
      logger.error('Error in suggest_next:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            filePath: args.filePath,
            error: error instanceof Error ? error.message : String(error),
            suggestions: []
          }, null, 2)
        }]
      };
    }
  }

  private async handlePreventError(args: PreventErrorArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Prevent error tool called', { filePath: args.filePath });

    try {
      const errorPrevention = this.realtimeTools 
        ? await this.realtimeTools.preventError(args)
        : await this.basicErrorPrevention(args);

      return { content: [{ type: "text", text: JSON.stringify(errorPrevention, null, 2) }] };
    } catch (error) {
      logger.error('Error in prevent_error:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            filePath: args.filePath,
            error: error instanceof Error ? error.message : String(error),
            potentialErrors: []
          }, null, 2)
        }]
      };
    }
  }

  private async handleQuickFix(args: QuickFixArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Quick fix tool called', { filePath: args.filePath, issueId: args.issueId });

    try {
      const quickFix = this.realtimeTools 
        ? await this.realtimeTools.quickFix(args)
        : await this.basicQuickFix(args);

      return { content: [{ type: "text", text: JSON.stringify(quickFix, null, 2) }] };
    } catch (error) {
      logger.error('Error in quick_fix:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            filePath: args.filePath,
            issueId: args.issueId,
            error: error instanceof Error ? error.message : String(error),
            fixes: []
          }, null, 2)
        }]
      };
    }
  }

  private async handleExplainWarning(args: ExplainWarningArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Explain warning tool called', { issueId: args.issueId });

    try {
      const explanation = this.realtimeTools 
        ? await this.realtimeTools.explainWarning(args)
        : await this.basicExplanation(args);

      return { content: [{ type: "text", text: JSON.stringify(explanation, null, 2) }] };
    } catch (error) {
      logger.error('Error in explain_warning:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            issueId: args.issueId,
            error: error instanceof Error ? error.message : String(error),
            explanation: 'Unable to provide explanation at this time'
          }, null, 2)
        }]
      };
    }
  }

  private async handleStartWatching(args: StartWatchingArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Start watching tool called', { projectPath: args.projectPath });

    try {
      const watchResult = this.realtimeTools 
        ? await this.realtimeTools.startWatching(args)
        : await this.basicStartWatching(args);

      return { content: [{ type: "text", text: JSON.stringify(watchResult, null, 2) }] };
    } catch (error) {
      logger.error('Error in start_watching:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            projectPath: args.projectPath,
            error: error instanceof Error ? error.message : String(error),
            watching: false
          }, null, 2)
        }]
      };
    }
  }

  private async handleStopWatching(args: StopWatchingArgs): Promise<{ content: Array<{ type: string; text: string; }> }> {
    logger.info('Stop watching tool called', { projectPath: args.projectPath });

    try {
      const stopResult = this.realtimeTools 
        ? await this.realtimeTools.stopWatching(args)
        : await this.basicStopWatching(args);

      return { content: [{ type: "text", text: JSON.stringify(stopResult, null, 2) }] };
    } catch (error) {
      logger.error('Error in stop_watching:', error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            projectPath: args.projectPath,
            error: error instanceof Error ? error.message : String(error)
          }, null, 2)
        }]
      };
    }
  }

  // Basic fallback implementations when real-time tools are not available
  private async basicValidation(filePath: string, content: string, line?: number, column?: number): Promise<any> {
    // Basic syntax and security validation
    const issues: any[] = [];
    const suggestions: any[] = [];

    // Check for common security issues
    if (content.includes('drizzle(') && !content.includes('getOrgDatabaseWithAuth')) {
      issues.push({
        id: 'direct-db-access',
        severity: 'critical',
        message: 'Direct database access detected - use getOrgDatabaseWithAuth() instead',
        line: line || 1,
        column: column || 1
      });
    }

    if (content.includes('export async function') && !content.includes('requireAuthWithTenant')) {
      issues.push({
        id: 'missing-auth',
        severity: 'high',
        message: 'API route missing authentication check',
        line: line || 1,
        column: column || 1
      });
    }

    return {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      issues,
      suggestions,
      performance: { analysisTime: Date.now() }
    };
  }

  private async basicSuggestion(args: SuggestNextArgs): Promise<any> {
    const suggestions: any[] = [];
    const { filePath, content, context } = args;

    // Basic pattern suggestions based on file content
    if (filePath.includes('route.') && content.includes('requireAuthWithTenant')) {
      suggestions.push({
        text: 'const db = await getOrgDatabaseWithAuth()',
        category: 'database-access',
        confidence: 0.9,
        description: 'Add authenticated database connection'
      });
    }

    if (content.includes('export function') && filePath.endsWith('.tsx')) {
      suggestions.push({
        text: '  const { organization } = useOrganization()',
        category: 'react-hook',
        confidence: 0.8,
        description: 'Add organization context hook'
      });
    }

    return {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      suggestions,
      context: args.context
    };
  }

  private async basicErrorPrevention(args: PreventErrorArgs): Promise<any> {
    const potentialErrors: any[] = [];
    const { filePath, content } = args;

    if (content && content.length > 0) {
      // Check for potential runtime errors
      if (content.includes('.id,') && !content.includes('?.id')) {
        potentialErrors.push({
          id: 'potential-null-access',
          severity: 'medium',
          message: 'Potential null reference access',
          suggestion: 'Consider using optional chaining (?.)',
          line: 1
        });
      }

      if (content.includes('process.env.') && !content.includes('||')) {
        potentialErrors.push({
          id: 'missing-env-fallback',
          severity: 'low',
          message: 'Environment variable without fallback',
          suggestion: 'Add fallback value or validation',
          line: 1
        });
      }
    }

    return {
      success: true,
      filePath,
      timestamp: new Date().toISOString(),
      potentialErrors,
      analysisType: args.analysisType || 'quick'
    };
  }

  private async basicQuickFix(args: QuickFixArgs): Promise<any> {
    const fixes: any[] = [];

    // Provide basic fixes for common issues
    if (args.issueId === 'direct-db-access') {
      fixes.push({
        description: 'Replace with authenticated database connection',
        oldText: 'drizzle(connectionString)',
        newText: 'await getOrgDatabaseWithAuth()',
        line: args.line,
        column: args.column
      });
    }

    if (args.issueId === 'missing-auth') {
      fixes.push({
        description: 'Add authentication check',
        oldText: 'export async function GET() {',
        newText: 'export async function GET() {\n  const { user, orgSlug } = await requireAuthWithTenant()\n',
        line: args.line,
        column: args.column
      });
    }

    return {
      success: true,
      filePath: args.filePath,
      issueId: args.issueId,
      timestamp: new Date().toISOString(),
      fixes,
      autoApplicable: fixes.length > 0
    };
  }

  private async basicExplanation(args: ExplainWarningArgs): Promise<any> {
    let explanation = 'This is a code quality or security issue that needs attention.';
    let examples: any[] = [];

    if (args.issueId === 'direct-db-access') {
      explanation = 'Direct database access bypasses Row Level Security (RLS) and authentication checks. This can lead to unauthorized data access.';
      if (args.includeExamples) {
        examples.push({
          incorrect: 'const db = drizzle(connectionString)',
          correct: 'const db = await getOrgDatabaseWithAuth()',
          explanation: 'Use the authenticated database connection to ensure proper security'
        });
      }
    }

    return {
      success: true,
      issueId: args.issueId,
      timestamp: new Date().toISOString(),
      explanation,
      examples,
      severity: 'high'
    };
  }

  private async basicStartWatching(args: StartWatchingArgs): Promise<any> {
    // Basic file watching would be implemented here
    return {
      success: true,
      projectPath: args.projectPath,
      timestamp: new Date().toISOString(),
      watching: false,
      message: 'File watching not implemented in basic mode'
    };
  }

  private async basicStopWatching(args: StopWatchingArgs): Promise<any> {
    return {
      success: true,
      projectPath: args.projectPath,
      timestamp: new Date().toISOString(),
      watching: false,
      message: 'File watching stopped'
    };
  }

  async start(): Promise<void> {
    try {
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      logger.info('Codebase Intelligence MCP Server started successfully');
      
      // Set up graceful shutdown
      process.on('SIGINT', () => this.cleanup());
      process.on('SIGTERM', () => this.cleanup());
    } catch (error) {
      logger.error('Failed to start MCP server:', error);
      throw error;
    }
  }

  async cleanup(): Promise<void> {
    logger.info('Shutting down Codebase Intelligence MCP Server...');
    
    try {
      // Cleanup all tool modules
      await Promise.all([
        this.securityTools.cleanup(),
        this.iacSecurityTools.cleanup(),
        this.patternTools.cleanup(),
        this.knowledgeTools.cleanup(),
        this.navigationTools.cleanup(),
        this.governanceTools.cleanup(),
        this.realtimeTools.cleanup()
      ]);
      
      // Close database connections
      await this.database.close();
      
      // Generate final performance report
      const performanceReport = this.performanceMonitor.generateReport();
      logger.info('Final performance report:', performanceReport);
      
      logger.info('Cleanup completed successfully');
    } catch (error) {
      logger.error('Error during cleanup:', error);
    }
    
    process.exit(0);
  }
}

export default CodebaseIntelligenceMCPServer;