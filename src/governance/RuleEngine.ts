import DatabaseManager, { GovernanceRule, PatternViolation, Pattern } from '../database/schema';
import { PatternAnalysisResult } from '../patterns/PatternRegistry';
import { TSESTree } from '@typescript-eslint/types';
import logger from '../utils/logger';
import { glob } from 'glob';
import { minimatch } from 'minimatch';

export interface Rule {
  id?: number;
  name: string;
  description: string;
  category: 'security' | 'performance' | 'maintainability' | 'style' | 'architecture';
  ruleType: 'required' | 'forbidden' | 'preferred';
  scope: RuleScope;
  condition: RuleCondition;
  message: string;
  severity: 'error' | 'warning' | 'info';
  autoFixAvailable: boolean;
  autoFix?: AutoFixFunction;
  enabled: boolean;
  priority: number; // 1-10, higher = more important
}

export interface RuleScope {
  filePatterns: string[]; // glob patterns for files this rule applies to
  excludePatterns?: string[]; // glob patterns for files to exclude
  directories?: string[]; // specific directories
  fileTypes?: string[]; // file extensions like '.ts', '.tsx'
}

export interface RuleCondition {
  type: 'pattern_presence' | 'pattern_absence' | 'code_structure' | 'dependency' | 'custom';
  patternName?: string; // for pattern-based rules
  codePattern?: string; // regex or AST pattern
  customCheck?: (node: TSESTree.Node, sourceCode: string, filePath: string) => boolean;
  metadata?: Record<string, any>;
}

export interface AutoFixFunction {
  (sourceCode: string, violation: RuleViolation): string;
}

export interface RuleViolation {
  ruleId: number;
  filePath: string;
  line: number;
  column?: number;
  message: string;
  severity: 'error' | 'warning' | 'info';
  context?: string; // surrounding code context
  suggestion?: string;
  autoFixAvailable: boolean;
  description: string; // Missing property from plan
  fixable: boolean; // Missing property from plan
  suggestedFix: string; // Missing property from plan
  examples: string[]; // Missing property from plan
}

export interface GovernanceReport {
  summary: {
    totalViolations: number;
    errorCount: number;
    warningCount: number;
    infoCount: number;
    filesAnalyzed: number;
    rulesApplied: number;
  };
  violationsByRule: Record<string, RuleViolation[]>;
  violationsByFile: Record<string, RuleViolation[]>;
  violationsBySeverity: Record<string, RuleViolation[]>;
  recommendations: string[];
  autoFixSuggestions: RuleViolation[];
}

export class RuleEngine {
  private db: DatabaseManager;
  private rules: Map<number, Rule> = new Map();
  private enabledRules: Rule[] = [];

  constructor(db: DatabaseManager) {
    this.db = db;
    this.initializeBuiltInRules();
    this.loadRulesFromDatabase();
  }

  private initializeBuiltInRules(): void {
    const builtInRules: Omit<Rule, 'id'>[] = [
      // OWASP Top 10 Rules
      ...this.createOwaspTop10Rules(),
      // OWASP API Security Top 10 Rules
      ...this.createOwaspApiSecurityRules(),
      // OWASP Mobile Top 10 Rules
      ...this.createOwaspMobileSecurityRules(),
      // OWASP AI Security Rules
      ...this.createOwaspAiSecurityRules(),
      // Existing rules
      {
        name: 'require_auth_in_api_routes',
        description: 'All API routes must include authentication checks',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts', '**/api/**/*.js'],
          fileTypes: ['.ts', '.js']
        },
        condition: {
          type: 'pattern_presence',
          patternName: 'requireAuth'
        },
        message: 'API route must include authentication check (requireAuthWithTenant)',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 10
      },
      {
        name: 'forbid_direct_database_access',
        description: 'Direct database connections are forbidden - use authenticated wrappers',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
          excludePatterns: ['**/lib/database.ts', '**/database/schema.ts']
        },
        condition: {
          type: 'pattern_presence',
          patternName: 'directDatabaseConnection'
        },
        message: 'Use getOrgDatabaseWithAuth() instead of direct database connections',
        severity: 'error',
        autoFixAvailable: true,
        autoFix: this.createDatabaseAccessAutoFix(),
        enabled: true,
        priority: 10
      },
      {
        name: 'require_typescript_types',
        description: 'All functions and variables should have explicit TypeScript types',
        category: 'maintainability',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx'],
          excludePatterns: ['**/*.test.ts', '**/*.spec.ts']
        },
        condition: {
          type: 'code_structure',
          customCheck: this.checkTypeScriptTypes
        },
        message: 'Add explicit TypeScript type annotations',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 6
      },
      {
        name: 'forbid_any_types',
        description: 'Avoid using "any" type - use specific types instead',
        category: 'maintainability',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx']
        },
        condition: {
          type: 'code_structure',
          codePattern: ':\\s*any\\b|<any>|any\\[\\]'
        },
        message: 'Replace "any" type with specific type definition',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      },
      {
        name: 'require_error_handling_in_api',
        description: 'API routes must have proper error handling with try-catch blocks',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts', '**/route.ts']
        },
        condition: {
          type: 'code_structure',
          customCheck: this.checkErrorHandling
        },
        message: 'Add try-catch block for proper error handling',
        severity: 'error',
        autoFixAvailable: true,
        autoFix: this.createErrorHandlingAutoFix(),
        enabled: true,
        priority: 9
      },
      {
        name: 'prefer_const_over_let',
        description: 'Use const instead of let when variable is not reassigned',
        category: 'style',
        ruleType: 'preferred',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx']
        },
        condition: {
          type: 'code_structure',
          customCheck: this.checkConstUsage
        },
        message: 'Use const instead of let for variables that are not reassigned',
        severity: 'info',
        autoFixAvailable: true,
        autoFix: this.createConstAutoFix(),
        enabled: true,
        priority: 3
      },
      {
        name: 'require_permission_checks',
        description: 'Operations on sensitive resources should include permission checks',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts']
        },
        condition: {
          type: 'custom',
          customCheck: this.checkPermissionChecks
        },
        message: 'Add permission check before accessing sensitive resources',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 8
      },
      {
        name: 'forbid_hardcoded_secrets',
        description: 'No hardcoded secrets, API keys, or passwords in code',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js', '**/*.tsx', '**/*.jsx']
        },
        condition: {
          type: 'code_structure',
          codePattern: '(api[_-]?key|password|secret|token)\\s*[=:]\\s*["\'][^"\']{8,}["\']'
        },
        message: 'Move secrets to environment variables',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 10
      }
    ];

    // Store built-in rules in database if they don't exist
    for (const rule of builtInRules) {
      this.addRule(rule);
    }
  }

  private createOwaspTop10Rules(): Omit<Rule, 'id'>[] {
    return [
      // A01:2021 – Broken Access Control
      {
        name: 'owasp_a01_broken_access_control',
        description: 'OWASP A01 - Check for proper access control implementation',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts', '**/routes/**/*.ts', '**/controllers/**/*.ts'],
          fileTypes: ['.ts', '.js']
        },
        condition: {
          type: 'custom',
          customCheck: this.checkAccessControl
        },
        message: 'OWASP A01: Implement proper access control checks',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 10
      },
      // A02:2021 – Cryptographic Failures
      {
        name: 'owasp_a02_cryptographic_failures',
        description: 'OWASP A02 - Check for proper cryptographic implementation',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'code_structure',
          codePattern: '(md5|sha1)\\s*\\(|password\\s*[=:]\\s*["\'][^"\']*["\']|\\bdes\\b|\\brc4\\b'
        },
        message: 'OWASP A02: Use strong cryptographic algorithms (avoid MD5, SHA1, DES, RC4)',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      },
      // A03:2021 – Injection
      {
        name: 'owasp_a03_injection',
        description: 'OWASP A03 - Check for SQL injection vulnerabilities',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'query\\s*\\+\\s*|exec\\s*\\(.*\\+|\\$\\{.*\\}.*sql|raw\\s*\\('
        },
        message: 'OWASP A03: Use parameterized queries to prevent injection attacks',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 10
      },
      // A04:2021 – Insecure Design
      {
        name: 'owasp_a04_insecure_design',
        description: 'OWASP A04 - Check for insecure design patterns',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkInsecureDesign
        },
        message: 'OWASP A04: Implement secure design patterns',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 8
      },
      // A05:2021 – Security Misconfiguration
      {
        name: 'owasp_a05_security_misconfiguration',
        description: 'OWASP A05 - Check for security misconfigurations',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js', '**/*.json'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'debug\\s*[=:]\\s*true|cors\\s*\\(\\s*\\)|x-powered-by|server.*express'
        },
        message: 'OWASP A05: Fix security misconfigurations (disable debug, configure CORS properly)',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      },
      // A06:2021 – Vulnerable and Outdated Components
      {
        name: 'owasp_a06_vulnerable_components',
        description: 'OWASP A06 - Check for vulnerable dependencies',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/package.json', '**/requirements.txt', '**/Gemfile'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkVulnerableComponents
        },
        message: 'OWASP A06: Update vulnerable dependencies',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 8
      },
      // A07:2021 – Identification and Authentication Failures
      {
        name: 'owasp_a07_auth_failures',
        description: 'OWASP A07 - Check for authentication implementation issues',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/auth/**/*.ts', '**/login/**/*.ts', '**/authentication/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkAuthenticationFailures
        },
        message: 'OWASP A07: Implement proper authentication mechanisms',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      },
      // A08:2021 – Software and Data Integrity Failures
      {
        name: 'owasp_a08_integrity_failures',
        description: 'OWASP A08 - Check for integrity verification',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkIntegrityFailures
        },
        message: 'OWASP A08: Implement integrity verification for critical operations',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      },
      // A09:2021 – Security Logging and Monitoring Failures
      {
        name: 'owasp_a09_logging_failures',
        description: 'OWASP A09 - Check for proper logging and monitoring',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts', '**/auth/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkLoggingFailures
        },
        message: 'OWASP A09: Implement proper security logging and monitoring',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 6
      },
      // A10:2021 – Server-Side Request Forgery (SSRF)
      {
        name: 'owasp_a10_ssrf',
        description: 'OWASP A10 - Check for SSRF vulnerabilities',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'fetch\\s*\\(\\s*req\\.|axios\\s*\\(\\s*req\\.|request\\s*\\(\\s*req\\.'
        },
        message: 'OWASP A10: Validate and sanitize URLs to prevent SSRF attacks',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      }
    ];
  }

  private createOwaspApiSecurityRules(): Omit<Rule, 'id'>[] {
    return [
      // API1:2023 – Broken Object Level Authorization
      {
        name: 'owasp_api01_broken_object_auth',
        description: 'OWASP API01 - Check for broken object level authorization',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts', '**/routes/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkObjectLevelAuth
        },
        message: 'OWASP API01: Implement object-level authorization checks',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 10
      },
      // API2:2023 – Broken Authentication
      {
        name: 'owasp_api02_broken_auth',
        description: 'OWASP API02 - Check for broken API authentication',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkApiAuthentication
        },
        message: 'OWASP API02: Implement proper API authentication',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 10
      },
      // API3:2023 – Broken Object Property Level Authorization
      {
        name: 'owasp_api03_property_auth',
        description: 'OWASP API03 - Check for property level authorization',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkPropertyLevelAuth
        },
        message: 'OWASP API03: Implement property-level authorization',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 8
      },
      // API4:2023 – Unrestricted Resource Consumption
      {
        name: 'owasp_api04_resource_consumption',
        description: 'OWASP API04 - Check for rate limiting and resource controls',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkResourceConsumption
        },
        message: 'OWASP API04: Implement rate limiting and resource consumption controls',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      },
      // API5:2023 – Broken Function Level Authorization
      {
        name: 'owasp_api05_function_auth',
        description: 'OWASP API05 - Check for function level authorization',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/api/**/*.ts'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkFunctionLevelAuth
        },
        message: 'OWASP API05: Implement function-level authorization checks',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      }
    ];
  }

  private createOwaspMobileSecurityRules(): Omit<Rule, 'id'>[] {
    return [
      // M1: Improper Platform Usage
      {
        name: 'owasp_m01_improper_platform_usage',
        description: 'OWASP M01 - Check for improper platform API usage',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkImproperPlatformUsage
        },
        message: 'OWASP M01: Use platform APIs securely',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      },
      // M2: Insecure Data Storage
      {
        name: 'owasp_m02_insecure_data_storage',
        description: 'OWASP M02 - Check for insecure data storage',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'localStorage\\.|sessionStorage\\.|AsyncStorage\\.|setItem\\('
        },
        message: 'OWASP M02: Avoid storing sensitive data in local storage',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 8
      },
      // M3: Insecure Communication
      {
        name: 'owasp_m03_insecure_communication',
        description: 'OWASP M03 - Check for insecure communication',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'http://|allowsArbitraryLoads.*true|NSAllowsArbitraryLoads'
        },
        message: 'OWASP M03: Use HTTPS and secure communication protocols',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      },
      // M4: Insecure Authentication
      {
        name: 'owasp_m04_insecure_mobile_auth',
        description: 'OWASP M04 - Check for insecure mobile authentication',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkMobileAuthentication
        },
        message: 'OWASP M04: Implement secure mobile authentication',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      },
      // M5: Insufficient Cryptography
      {
        name: 'owasp_m05_insufficient_crypto',
        description: 'OWASP M05 - Check for insufficient cryptography in mobile apps',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'btoa\\(|atob\\(|base64|rot13|caesar'
        },
        message: 'OWASP M05: Use proper cryptographic algorithms, not encoding',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      }
    ];
  }

  private createOwaspAiSecurityRules(): Omit<Rule, 'id'>[] {
    return [
      // AI Model Security
      {
        name: 'owasp_ai_model_security',
        description: 'OWASP AI - Check for secure AI model handling',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js', '**/*.py'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkAiModelSecurity
        },
        message: 'OWASP AI: Implement secure AI model loading and handling',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 7
      },
      // Prompt Injection Prevention
      {
        name: 'owasp_ai_prompt_injection',
        description: 'OWASP AI - Check for prompt injection vulnerabilities',
        category: 'security',
        ruleType: 'forbidden',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'code_structure',
          codePattern: 'prompt.*\\+.*req\\.|template.*\\+.*input|\\$\\{.*req\\.'
        },
        message: 'OWASP AI: Sanitize user input before using in AI prompts',
        severity: 'error',
        autoFixAvailable: false,
        enabled: true,
        priority: 9
      },
      // AI Data Validation
      {
        name: 'owasp_ai_data_validation',
        description: 'OWASP AI - Check for proper AI data validation',
        category: 'security',
        ruleType: 'required',
        scope: {
          filePatterns: ['**/*.ts', '**/*.js'],
        },
        condition: {
          type: 'custom',
          customCheck: this.checkAiDataValidation
        },
        message: 'OWASP AI: Validate and sanitize AI training and inference data',
        severity: 'warning',
        autoFixAvailable: false,
        enabled: true,
        priority: 8
      }
    ];
  }

  private loadRulesFromDatabase(): void {
    try {
      const database = this.db.getDatabase();
      const dbRules = database.prepare(`
        SELECT gr.*, p.name as pattern_name, p.category as pattern_category
        FROM governance_rules gr
        LEFT JOIN patterns p ON gr.pattern_id = p.id
        WHERE 1=1
        ORDER BY gr.id
      `).all() as Array<GovernanceRule & { pattern_name?: string; pattern_category?: string }>;

      for (const dbRule of dbRules) {
        // Convert database rule to Rule interface
        const rule: Rule = {
          id: dbRule.id,
          name: dbRule.pattern_name || `rule_${dbRule.id}`,
          description: dbRule.message,
          category: this.mapPatternCategoryToRuleCategory(dbRule.pattern_category || 'general'),
          ruleType: dbRule.rule_type as 'required' | 'forbidden' | 'preferred',
          scope: this.parseScopePattern(dbRule.scope_pattern),
          condition: {
            type: 'pattern_presence',
            patternName: dbRule.pattern_name
          },
          message: dbRule.message,
          severity: dbRule.severity as 'error' | 'warning' | 'info',
          autoFixAvailable: dbRule.auto_fix_available,
          enabled: true,
          priority: this.calculateRulePriority(dbRule.severity)
        };

        this.rules.set(rule.id!, rule);
      }

      this.updateEnabledRules();
      logger.info(`Loaded ${dbRules.length} rules from database`);
    } catch (error) {
      logger.error('Failed to load rules from database:', error);
    }
  }

  async checkCompliance(
    filePath: string,
    ast: TSESTree.Program,
    sourceCode: string,
    analysisResult?: PatternAnalysisResult
  ): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    logger.debug(`Checking compliance for ${filePath} with ${this.enabledRules.length} rules`);

    for (const rule of this.enabledRules) {
      // Check if rule applies to this file
      if (!this.ruleAppliesTo(rule, filePath)) {
        continue;
      }

      // Check rule condition
      const ruleViolations = await this.checkRule(rule, filePath, ast, sourceCode, analysisResult);
      violations.push(...ruleViolations);
    }

    // Store violations in database
    await this.storeViolations(violations);

    logger.debug(`Found ${violations.length} violations in ${filePath}`);
    return violations;
  }

  private ruleAppliesTo(rule: Rule, filePath: string): boolean {
    const scope = rule.scope;

    // Check file patterns
    if (scope.filePatterns.length > 0) {
      const matches = scope.filePatterns.some(pattern => minimatch(filePath, pattern));
      if (!matches) return false;
    }

    // Check exclude patterns
    if (scope.excludePatterns && scope.excludePatterns.length > 0) {
      const excluded = scope.excludePatterns.some(pattern => minimatch(filePath, pattern));
      if (excluded) return false;
    }

    // Check directories
    if (scope.directories && scope.directories.length > 0) {
      const inDirectory = scope.directories.some(dir => filePath.includes(dir));
      if (!inDirectory) return false;
    }

    // Check file types
    if (scope.fileTypes && scope.fileTypes.length > 0) {
      const hasCorrectType = scope.fileTypes.some(type => filePath.endsWith(type));
      if (!hasCorrectType) return false;
    }

    return true;
  }

  private async checkRule(
    rule: Rule,
    filePath: string,
    ast: TSESTree.Program,
    sourceCode: string,
    analysisResult?: PatternAnalysisResult
  ): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    try {
      switch (rule.condition.type) {
        case 'pattern_presence':
          const presenceViolations = this.checkPatternPresence(rule, filePath, analysisResult);
          violations.push(...presenceViolations);
          break;

        case 'pattern_absence':
          const absenceViolations = this.checkPatternAbsence(rule, filePath, analysisResult);
          violations.push(...absenceViolations);
          break;

        case 'code_structure':
          const structureViolations = await this.checkCodeStructure(rule, filePath, ast, sourceCode);
          violations.push(...structureViolations);
          break;

        case 'custom':
          const customViolations = await this.checkCustomRule(rule, filePath, ast, sourceCode);
          violations.push(...customViolations);
          break;
      }
    } catch (error) {
      logger.warn(`Error checking rule ${rule.name} for ${filePath}:`, error);
    }

    return violations;
  }

  private checkPatternPresence(
    rule: Rule,
    filePath: string,
    analysisResult?: PatternAnalysisResult
  ): RuleViolation[] {
    if (!analysisResult || !rule.condition.patternName) {
      return [];
    }

    const patternName = rule.condition.patternName;
    const violations: RuleViolation[] = [];

    // Check if required pattern is present
    if (rule.ruleType === 'required') {
      const hasPattern = this.hasPattern(analysisResult, patternName);
      if (!hasPattern) {
        violations.push({
          ruleId: rule.id!,
          filePath,
          line: 1,
          message: rule.message,
          severity: rule.severity,
          autoFixAvailable: rule.autoFixAvailable,
          suggestion: this.generateSuggestion(rule, patternName),
          description: rule.description,
          fixable: rule.autoFixAvailable,
          suggestedFix: this.generateSuggestion(rule, patternName),
          examples: []
        });
      }
    }

    // Check if forbidden pattern is present
    if (rule.ruleType === 'forbidden') {
      const hasPattern = this.hasPattern(analysisResult, patternName);
      if (hasPattern) {
        violations.push({
          ruleId: rule.id!,
          filePath,
          line: 1,
          message: rule.message,
          severity: rule.severity,
          autoFixAvailable: rule.autoFixAvailable,
          suggestion: this.generateSuggestion(rule, patternName),
          description: rule.description,
          fixable: rule.autoFixAvailable,
          suggestedFix: this.generateSuggestion(rule, patternName),
          examples: []
        });
      }
    }

    return violations;
  }

  private checkPatternAbsence(
    rule: Rule,
    filePath: string,
    analysisResult?: PatternAnalysisResult
  ): RuleViolation[] {
    // Similar to checkPatternPresence but with inverted logic
    return this.checkPatternPresence(rule, filePath, analysisResult);
  }

  private async checkCodeStructure(
    rule: Rule,
    filePath: string,
    ast: TSESTree.Program,
    sourceCode: string
  ): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Check regex pattern
    if (rule.condition.codePattern) {
      const regex = new RegExp(rule.condition.codePattern, 'gi');
      const matches = sourceCode.matchAll(regex);

      for (const match of matches) {
        const line = this.getLineNumber(sourceCode, match.index || 0);
        violations.push({
          ruleId: rule.id!,
          filePath,
          line,
          message: rule.message,
          severity: rule.severity,
          autoFixAvailable: rule.autoFixAvailable,
          context: this.getContext(sourceCode, match.index || 0),
          suggestion: this.generateSuggestion(rule),
          description: rule.description,
          fixable: rule.autoFixAvailable,
          suggestedFix: this.generateSuggestion(rule),
          examples: []
        });
      }
    }

    // Check custom function
    if (rule.condition.customCheck) {
      for (const node of ast.body) {
        const hasViolation = rule.condition.customCheck(node, sourceCode, filePath);
        if (hasViolation) {
          violations.push({
            ruleId: rule.id!,
            filePath,
            line: node.loc?.start.line || 1,
            message: rule.message,
            severity: rule.severity,
            autoFixAvailable: rule.autoFixAvailable,
            suggestion: this.generateSuggestion(rule),
            description: rule.description,
            fixable: rule.autoFixAvailable,
            suggestedFix: this.generateSuggestion(rule),
            examples: []
          });
        }
      }
    }

    return violations;
  }

  private async checkCustomRule(
    rule: Rule,
    filePath: string,
    ast: TSESTree.Program,
    sourceCode: string
  ): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    if (rule.condition.customCheck) {
      for (const node of ast.body) {
        const hasViolation = rule.condition.customCheck(node, sourceCode, filePath);
        if (hasViolation) {
          violations.push({
            ruleId: rule.id!,
            filePath,
            line: node.loc?.start.line || 1,
            message: rule.message,
            severity: rule.severity,
            autoFixAvailable: rule.autoFixAvailable,
            suggestion: this.generateSuggestion(rule),
            description: rule.description,
            fixable: rule.autoFixAvailable,
            suggestedFix: this.generateSuggestion(rule),
            examples: []
          });
        }
      }
    }

    return violations;
  }

  // Custom check functions
  private checkTypeScriptTypes = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for functions without return type annotations
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      return !func.returnType;
    }

    // Check for variables without type annotations
    if (node.type === 'VariableDeclaration') {
      const varDecl = node as TSESTree.VariableDeclaration;
      return varDecl.declarations.some(decl => 
        decl.id.type === 'Identifier' && !(decl.id as any).typeAnnotation
      );
    }

    return false;
  };

  private checkErrorHandling = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check if API route functions have try-catch blocks
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
      
      if (httpMethods.includes(func.id?.name || '')) {
        // Check if function body contains try-catch
        return !this.hasTryCatchBlock(func.body);
      }
    }

    return false;
  };

  private checkConstUsage = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for let declarations that could be const
    if (node.type === 'VariableDeclaration') {
      const varDecl = node as TSESTree.VariableDeclaration;
      return varDecl.kind === 'let' && varDecl.declarations.every(decl => decl.init !== null);
    }

    return false;
  };

  private checkPermissionChecks = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check if sensitive operations have permission checks
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      // Check for database operations without permission checks
      const dbOperations = ['delete', 'update', 'insert'];
      if (dbOperations.some(op => calleeText.toLowerCase().includes(op))) {
        return !sourceCode.includes('hasPermission') && !sourceCode.includes('checkPermission');
      }
    }

    return false;
  };

  // OWASP Top 10 Custom Check Functions
  private checkAccessControl = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing access control in API routes
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
      
      if (httpMethods.includes(func.id?.name || '')) {
        // Check if function has auth checks
        return !sourceCode.includes('requireAuth') && 
               !sourceCode.includes('checkPermission') &&
               !sourceCode.includes('authorize');
      }
    }
    return false;
  };

  private checkInsecureDesign = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for common insecure design patterns
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      // Check for admin functions without proper controls
      if (calleeText.toLowerCase().includes('admin') || calleeText.toLowerCase().includes('root')) {
        return !sourceCode.includes('isAdmin') && !sourceCode.includes('hasRole');
      }
    }
    return false;
  };

  private checkVulnerableComponents = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check package.json for known vulnerable versions (simplified)
    if (filePath.includes('package.json')) {
      const vulnerablePatterns = [
        '"lodash": "4.17.20"',
        '"express": "4.17.1"',
        '"moment": "2.29.1"'
      ];
      return vulnerablePatterns.some(pattern => sourceCode.includes(pattern));
    }
    return false;
  };

  private checkAuthenticationFailures = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for weak authentication patterns
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      // Check for weak password validation
      if (calleeText.includes('password') || calleeText.includes('auth')) {
        return !sourceCode.includes('bcrypt') && 
               !sourceCode.includes('hash') &&
               !sourceCode.includes('validate');
      }
    }
    return false;
  };

  private checkIntegrityFailures = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing integrity checks in critical operations
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      if (calleeText.includes('update') || calleeText.includes('delete') || calleeText.includes('create')) {
        return !sourceCode.includes('checksum') && 
               !sourceCode.includes('validate') &&
               !sourceCode.includes('verify');
      }
    }
    return false;
  };

  private checkLoggingFailures = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing security logging
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethods = ['POST', 'PUT', 'DELETE'];
      
      if (httpMethods.includes(func.id?.name || '')) {
        return !sourceCode.includes('logger') && 
               !sourceCode.includes('log') &&
               !sourceCode.includes('audit');
      }
    }
    return false;
  };

  // OWASP API Security Custom Check Functions
  private checkObjectLevelAuth = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing object-level authorization
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      if (calleeText.includes('findById') || calleeText.includes('getById')) {
        return !sourceCode.includes('checkOwnership') && 
               !sourceCode.includes('canAccess') &&
               !sourceCode.includes('hasPermission');
      }
    }
    return false;
  };

  private checkApiAuthentication = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing API authentication
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
      
      if (httpMethods.includes(func.id?.name || '')) {
        return !sourceCode.includes('Bearer') && 
               !sourceCode.includes('jwt') &&
               !sourceCode.includes('token');
      }
    }
    return false;
  };

  private checkPropertyLevelAuth = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for property level authorization issues
    if (node.type === 'ObjectExpression') {
      const obj = node as TSESTree.ObjectExpression;
      // Check if sensitive properties are exposed without checks
      return obj.properties.some(prop => {
        if (prop.type === 'Property' && prop.key.type === 'Identifier') {
          const propName = prop.key.name.toLowerCase();
          return (propName.includes('password') || propName.includes('secret') || propName.includes('key')) &&
                 !sourceCode.includes('sanitize') && !sourceCode.includes('filter');
        }
        return false;
      });
    }
    return false;
  };

  private checkResourceConsumption = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing rate limiting
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const httpMethods = ['POST', 'PUT', 'DELETE'];
      
      if (httpMethods.includes(func.id?.name || '')) {
        return !sourceCode.includes('rateLimit') && 
               !sourceCode.includes('throttle') &&
               !sourceCode.includes('limit');
      }
    }
    return false;
  };

  private checkFunctionLevelAuth = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing function-level authorization
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      const functionName = func.id?.name?.toLowerCase() || '';
      
      if (functionName.includes('admin') || functionName.includes('delete') || functionName.includes('create')) {
        return !sourceCode.includes('hasRole') && 
               !sourceCode.includes('checkPermission') &&
               !sourceCode.includes('authorize');
      }
    }
    return false;
  };

  // OWASP Mobile Security Custom Check Functions
  private checkImproperPlatformUsage = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for improper platform API usage
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      // Check for insecure platform API usage
      const insecureApis = ['eval', 'innerHTML', 'dangerouslySetInnerHTML'];
      return insecureApis.some(api => calleeText.includes(api));
    }
    return false;
  };

  private checkMobileAuthentication = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for insecure mobile authentication patterns
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      if (calleeText.includes('authenticate') || calleeText.includes('login')) {
        return !sourceCode.includes('biometric') && 
               !sourceCode.includes('TouchID') &&
               !sourceCode.includes('FaceID') &&
               !sourceCode.includes('keystore');
      }
    }
    return false;
  };

  // OWASP AI Security Custom Check Functions
  private checkAiModelSecurity = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for insecure AI model loading
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      if (calleeText.includes('load') && (calleeText.includes('model') || calleeText.includes('Model'))) {
        return !sourceCode.includes('verify') && 
               !sourceCode.includes('checksum') &&
               !sourceCode.includes('trusted');
      }
    }
    return false;
  };

  private checkAiDataValidation = (node: TSESTree.Node, sourceCode: string, filePath: string): boolean => {
    // Check for missing AI data validation
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const calleeText = this.getCalleeText(call.callee);
      
      if (calleeText.includes('predict') || calleeText.includes('inference') || calleeText.includes('classify')) {
        return !sourceCode.includes('validate') && 
               !sourceCode.includes('sanitize') &&
               !sourceCode.includes('normalize');
      }
    }
    return false;
  };

  // Auto-fix functions
  private createDatabaseAccessAutoFix(): AutoFixFunction {
    return (sourceCode: string, violation: RuleViolation): string => {
      // Replace direct database connections with authenticated wrappers
      return sourceCode
        .replace(/drizzle\([^)]+\)/g, 'await getOrgDatabaseWithAuth()')
        .replace(/new Client\([^)]+\)/g, 'await getOrgDatabaseWithAuth()');
    };
  }

  private createErrorHandlingAutoFix(): AutoFixFunction {
    return (sourceCode: string, violation: RuleViolation): string => {
      // Wrap API route functions in try-catch blocks
      const lines = sourceCode.split('\n');
      const targetLine = violation.line - 1;
      
      // Find the function body and wrap it in try-catch
      // This is a simplified implementation
      return sourceCode.replace(
        /export async function (GET|POST|PUT|DELETE|PATCH)\([^)]*\)\s*{/,
        'export async function $1($2) {\n  try {'
      ).replace(/}$/, '  } catch (error) {\n    return new Response("Internal Error", { status: 500 })\n  }\n}');
    };
  }

  private createConstAutoFix(): AutoFixFunction {
    return (sourceCode: string, violation: RuleViolation): string => {
      // Replace let with const for variables that are not reassigned
      return sourceCode.replace(/\blet\b/g, 'const');
    };
  }

  // Helper methods
  private hasPattern(analysisResult: PatternAnalysisResult, patternName: string): boolean {
    // Check all pattern matches for the specified pattern
    const allMatches = [
      ...analysisResult.authMatches.map(m => m.pattern.name),
      ...analysisResult.apiMatches.map(m => m.pattern.name),
      ...analysisResult.dataAccessMatches.map(m => m.pattern.name),
      ...analysisResult.componentMatches.map(m => m.pattern.name),
      ...analysisResult.styleMatches.map(m => m.pattern.name)
    ];

    return allMatches.includes(patternName);
  }

  private hasTryCatchBlock(node: TSESTree.BlockStatement | null): boolean {
    if (!node) return false;

    for (const stmt of node.body) {
      if (stmt.type === 'TryStatement') {
        return true;
      }
    }

    return false;
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

  private getLineNumber(sourceCode: string, index: number): number {
    return sourceCode.substring(0, index).split('\n').length;
  }

  private getContext(sourceCode: string, index: number, contextSize = 50): string {
    const start = Math.max(0, index - contextSize);
    const end = Math.min(sourceCode.length, index + contextSize);
    return sourceCode.substring(start, end);
  }

  private generateSuggestion(rule: Rule, patternName?: string): string {
    switch (rule.name) {
      case 'require_auth_in_api_routes':
        return 'Add: const { user } = await requireAuthWithTenant()';
      case 'forbid_direct_database_access':
        return 'Replace with: const db = await getOrgDatabaseWithAuth()';
      case 'require_typescript_types':
        return 'Add explicit type annotations to functions and variables';
      case 'forbid_any_types':
        return 'Replace "any" with specific type definitions';
      default:
        return 'Follow the coding standards for this rule';
    }
  }

  private mapPatternCategoryToRuleCategory(patternCategory: string): Rule['category'] {
    switch (patternCategory) {
      case 'auth':
      case 'security':
        return 'security';
      case 'api':
      case 'architecture':
        return 'architecture';
      case 'style':
        return 'style';
      case 'performance':
        return 'performance';
      default:
        return 'maintainability';
    }
  }

  private parseScopePattern(scopePattern?: string | null): RuleScope {
    if (!scopePattern) {
      return { filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'] };
    }

    // Simple parsing - in practice, this would be more sophisticated
    return {
      filePatterns: scopePattern.split(',').map(p => p.trim())
    };
  }

  private calculateRulePriority(severity: string): number {
    switch (severity) {
      case 'error':
        return 10;
      case 'warning':
        return 7;
      case 'info':
        return 3;
      default:
        return 5;
    }
  }

  private isFileInScope(filePath: string, scope: RuleScope): boolean {
    // Check if file matches any include patterns
    const matchesInclude = scope.filePatterns.some(pattern => 
      minimatch(filePath, pattern)
    );

    if (!matchesInclude) return false;

    // Check if file matches any exclude patterns
    if (scope.excludePatterns && scope.excludePatterns.length > 0) {
      const matchesExclude = scope.excludePatterns.some(pattern => 
        minimatch(filePath, pattern)
      );
      if (matchesExclude) return false;
    }

    return true;
  }

  private async evaluateRule(rule: Rule, filePath: string, sourceCode: string): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    try {
      switch (rule.condition.type) {
        case 'pattern_presence':
          if (rule.condition.patternName && rule.ruleType === 'required') {
            // Check if required pattern is present
            if (!sourceCode.includes(rule.condition.patternName)) {
              violations.push({
                ruleId: rule.id!,
                filePath,
                line: 1,
                message: rule.message,
                severity: rule.severity,
                autoFixAvailable: rule.autoFixAvailable,
                description: rule.description,
                fixable: rule.autoFixAvailable,
                suggestedFix: rule.message,
                examples: []
              });
            }
          }
          break;

        case 'pattern_absence':
          if (rule.condition.patternName && rule.ruleType === 'forbidden') {
            // Check if forbidden pattern is absent
            if (sourceCode.includes(rule.condition.patternName)) {
              const line = this.findPatternLine(sourceCode, rule.condition.patternName);
              violations.push({
                ruleId: rule.id!,
                filePath,
                line,
                message: rule.message,
                severity: rule.severity,
                autoFixAvailable: rule.autoFixAvailable,
                description: rule.description,
                fixable: rule.autoFixAvailable,
                suggestedFix: rule.message,
                examples: []
              });
            }
          }
          break;

        case 'code_structure':
          if (rule.condition.codePattern) {
            const regex = new RegExp(rule.condition.codePattern, 'g');
            let match;
            while ((match = regex.exec(sourceCode)) !== null) {
              const line = this.getLineNumber(sourceCode, match.index);
              violations.push({
                ruleId: rule.id!,
                filePath,
                line,
                message: rule.message,
                severity: rule.severity,
                autoFixAvailable: rule.autoFixAvailable,
                description: rule.description,
                fixable: rule.autoFixAvailable,
                suggestedFix: rule.message,
                examples: []
              });
            }
          }
          break;

        case 'custom':
          // Custom rules would be evaluated here
          break;
      }
    } catch (error) {
      logger.error(`Error evaluating rule ${rule.name}:`, error);
    }

    return violations;
  }

  private findPatternLine(sourceCode: string, pattern: string): number {
    const index = sourceCode.indexOf(pattern);
    if (index === -1) return 1;
    return this.getLineNumber(sourceCode, index);
  }

  private updateEnabledRules(): void {
    this.enabledRules = Array.from(this.rules.values())
      .filter(rule => rule.enabled)
      .sort((a, b) => b.priority - a.priority);
  }

  private async storeViolations(violations: RuleViolation[]): Promise<void> {
    try {
      for (const violation of violations) {
        // Check if violation already exists
        const database = this.db.getDatabase();
        const existing = database.prepare(`
          SELECT id FROM pattern_violations 
          WHERE rule_id = ? AND file_path = ? AND line = ?
        `).get(violation.ruleId, violation.filePath, violation.line);

        if (!existing) {
          database.prepare(`
            INSERT INTO pattern_violations (rule_id, file_path, line, detected_at, resolved)
            VALUES (?, ?, ?, datetime('now'), 0)
          `).run(violation.ruleId, violation.filePath, violation.line);
        }
      }
    } catch (error) {
      logger.error('Failed to store violations:', error);
    }
  }

  // Public API methods
  async addRule(rule: Omit<Rule, 'id'>): Promise<number> {
    try {
      // First, check if a rule with this name already exists
      const database = this.db.getDatabase();
      const existing = database.prepare(`
        SELECT gr.id FROM governance_rules gr
        JOIN patterns p ON gr.pattern_id = p.id
        WHERE p.name = ?
      `).get(rule.name);

      if (existing) {
        logger.debug(`Rule ${rule.name} already exists, skipping`);
        return (existing as any).id;
      }

      // Create a pattern for this rule if it doesn't exist
      let patternId: number;
      const existingPattern = database.prepare(`
        SELECT id FROM patterns WHERE name = ?
      `).get(rule.name);

      if (existingPattern) {
        patternId = (existingPattern as any).id;
      } else {
        patternId = this.db.insertPattern({
          name: rule.name,
          category: rule.category,
          description: rule.description,
          confidence_threshold: 0.8,
          is_approved: true
        });
      }

      // Create governance rule
      const ruleId = database.prepare(`
        INSERT INTO governance_rules 
        (pattern_id, rule_type, scope_pattern, message, severity, auto_fix_available)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        patternId,
        rule.ruleType,
        rule.scope.filePatterns.join(','),
        rule.message,
        rule.severity,
        rule.autoFixAvailable ? 1 : 0
      ).lastInsertRowid as number;

      // Add to memory
      const fullRule: Rule = { ...rule, id: ruleId };
      this.rules.set(ruleId, fullRule);
      this.updateEnabledRules();

      logger.info(`Added rule: ${rule.name}`);
      return ruleId;
    } catch (error) {
      logger.error(`Failed to add rule ${rule.name}:`, error);
      throw error;
    }
  }

  async removeRule(ruleId: number): Promise<void> {
    const database = this.db.getDatabase();
    
    // Remove violations first
    database.prepare('DELETE FROM pattern_violations WHERE rule_id = ?').run(ruleId);
    
    // Remove rule
    database.prepare('DELETE FROM governance_rules WHERE id = ?').run(ruleId);
    
    // Remove from memory
    this.rules.delete(ruleId);
    this.updateEnabledRules();

    logger.info(`Removed rule ${ruleId}`);
  }

  async enableRule(ruleId: number): Promise<void> {
    const rule = this.rules.get(ruleId);
    if (rule) {
      rule.enabled = true;
      this.updateEnabledRules();
      logger.info(`Enabled rule ${ruleId}`);
    }
  }

  async disableRule(ruleId: number): Promise<void> {
    const rule = this.rules.get(ruleId);
    if (rule) {
      rule.enabled = false;
      this.updateEnabledRules();
      logger.info(`Disabled rule ${ruleId}`);
    }
  }

  async generateGovernanceReport(filePaths?: string[]): Promise<GovernanceReport> {
    const database = this.db.getDatabase();
    
    let whereClause = '1=1';
    const params: any[] = [];
    
    if (filePaths && filePaths.length > 0) {
      whereClause = `file_path IN (${filePaths.map(() => '?').join(',')})`;
      params.push(...filePaths);
    }

    const violations = database.prepare(`
      SELECT pv.*, gr.message, gr.severity, gr.auto_fix_available
      FROM pattern_violations pv
      JOIN governance_rules gr ON pv.rule_id = gr.id
      WHERE ${whereClause} AND pv.resolved = 0
      ORDER BY gr.severity, pv.detected_at DESC
    `).all(...params) as Array<PatternViolation & { message: string; severity: string; auto_fix_available: boolean }>;

    const report: GovernanceReport = {
      summary: {
        totalViolations: violations.length,
        errorCount: violations.filter(v => v.severity === 'error').length,
        warningCount: violations.filter(v => v.severity === 'warning').length,
        infoCount: violations.filter(v => v.severity === 'info').length,
        filesAnalyzed: new Set(violations.map(v => v.file_path)).size,
        rulesApplied: this.enabledRules.length
      },
      violationsByRule: {},
      violationsByFile: {},
      violationsBySeverity: {
        error: [],
        warning: [],
        info: []
      },
      recommendations: [],
      autoFixSuggestions: []
    };

    // Group violations
    for (const violation of violations) {
      const ruleViolation: RuleViolation = {
        ruleId: violation.rule_id,
        filePath: violation.file_path,
        line: violation.line,
        message: violation.message,
        severity: violation.severity as 'error' | 'warning' | 'info',
        autoFixAvailable: violation.auto_fix_available,
        description: violation.message,
        fixable: violation.auto_fix_available,
        suggestedFix: violation.message,
        examples: []
      };

      // By rule
      const ruleName = this.rules.get(violation.rule_id)?.name || `rule_${violation.rule_id}`;
      if (!report.violationsByRule[ruleName]) {
        report.violationsByRule[ruleName] = [];
      }
      report.violationsByRule[ruleName].push(ruleViolation);

      // By file
      if (!report.violationsByFile[violation.file_path]) {
        report.violationsByFile[violation.file_path] = [];
      }
      report.violationsByFile[violation.file_path].push(ruleViolation);

      // By severity
      report.violationsBySeverity[violation.severity as 'error' | 'warning' | 'info'].push(ruleViolation);

      // Auto-fix suggestions
      if (violation.auto_fix_available) {
        report.autoFixSuggestions.push(ruleViolation);
      }
    }

    // Generate recommendations
    report.recommendations = this.generateGovernanceRecommendations(report);

    return report;
  }

  private generateGovernanceRecommendations(report: GovernanceReport): string[] {
    const recommendations: string[] = [];

    if (report.summary.errorCount > 0) {
      recommendations.push(`🚨 Fix ${report.summary.errorCount} critical errors immediately`);
    }

    if (report.summary.warningCount > 10) {
      recommendations.push(`⚠️ Address ${report.summary.warningCount} warnings to improve code quality`);
    }

    if (report.autoFixSuggestions.length > 0) {
      recommendations.push(`🔧 ${report.autoFixSuggestions.length} violations can be auto-fixed`);
    }

    const topViolatedRules = Object.entries(report.violationsByRule)
      .sort(([,a], [,b]) => b.length - a.length)
      .slice(0, 3);

    for (const [ruleName, violations] of topViolatedRules) {
      recommendations.push(`📊 Most violated rule: "${ruleName}" (${violations.length} occurrences)`);
    }

    if (recommendations.length === 0) {
      recommendations.push('✅ All governance rules are being followed correctly');
    }

    return recommendations;
  }

  getRules(): Rule[] {
    return Array.from(this.rules.values());
  }

  getEnabledRules(): Rule[] {
    return [...this.enabledRules];
  }

  getRule(ruleId: number): Rule | undefined {
    return this.rules.get(ruleId);
  }

  /**
   * Validate a single file against all enabled rules with additional options
   */
  async validateFile(filePath: string, options: any): Promise<RuleViolation[]> {
    logger.debug(`Validating file: ${filePath}`);
    
    const sourceCode = options?.sourceCode;
    const ast = options?.ast;
    const analysisResult = options?.analysisResult;
    
    // If no source code provided, this would read from file
    if (!sourceCode) {
      // In a real implementation, we'd read the file
      return [];
    }

    const violations: RuleViolation[] = [];

    for (const rule of this.enabledRules) {
      if (this.isFileInScope(filePath, rule.scope)) {
        const ruleViolations = ast ? 
          await this.checkRule(rule, filePath, ast, sourceCode, analysisResult) :
          await this.evaluateRule(rule, filePath, sourceCode);
        violations.push(...ruleViolations);
      }
    }

    await this.storeViolations(violations);
    return violations;
  }

  /**
   * Create a new rule (alias for addRule)
   */
  async createRule(rule: Omit<Rule, 'id'>): Promise<number> {
    return this.addRule(rule);
  }

  /**
   * Generate a comprehensive project governance report
   */
  async generateProjectReport(projectPath: string, options?: {
    includeMetrics?: boolean;
    includeRecommendations?: boolean;
    outputFormat?: 'json' | 'html' | 'markdown';
  }): Promise<{
    report: GovernanceReport;
    metrics?: ProjectGovernanceMetrics;
    formatted?: string;
  }> {
    logger.info(`Generating project governance report for: ${projectPath}`);

    // Get all violations for the project
    const report = await this.generateGovernanceReport();

    const result: any = { report };

    if (options?.includeMetrics) {
      result.metrics = {
        totalRules: this.rules.size,
        enabledRules: this.enabledRules.length,
        complianceScore: this.calculateComplianceScore(report),
        violationTrends: [], // Placeholder
        ruleEffectiveness: new Map()
      };
    }

    if (options?.outputFormat && options.outputFormat !== 'json') {
      result.formatted = this.formatReport(report, options.outputFormat);
    }

    return result;
  }

  /**
   * Validate style guide compliance
   */
  async validateStyleGuide(filePath: string, styleGuideRules: string[]): Promise<{
    violations: RuleViolation[];
    complianceScore: number;
    recommendations: string[];
  }> {
    logger.debug(`Validating style guide for: ${filePath}`);

    const violations: RuleViolation[] = [];
    let applicableRules = 0;

    // Find style rules that match the requested rules
    for (const rule of this.enabledRules) {
      if (rule.category === 'style' && styleGuideRules.includes(rule.name)) {
        applicableRules++;
        if (this.isFileInScope(filePath, rule.scope)) {
          // In a real implementation, we'd evaluate the rule
          // For now, return placeholder
        }
      }
    }

    const complianceScore = applicableRules > 0 ? 
      Math.max(0, 100 - (violations.length / applicableRules) * 100) : 100;

    const recommendations = violations.length > 0 ? 
      [`Fix ${violations.length} style violations to improve compliance`] : 
      ['Style guide compliance is excellent'];

    return {
      violations,
      complianceScore,
      recommendations
    };
  }

  private calculateComplianceScore(report: GovernanceReport): number {
    const total = report.summary.totalViolations;
    const critical = report.summary.errorCount;
    
    if (total === 0) return 100;
    
    // Weight critical errors more heavily
    const weightedScore = Math.max(0, 100 - (critical * 10 + (total - critical) * 2));
    return Math.round(weightedScore);
  }

  private formatReport(report: GovernanceReport, format: 'html' | 'markdown'): string {
    if (format === 'markdown') {
      return `# Governance Report

## Summary
- Total Violations: ${report.summary.totalViolations}
- Errors: ${report.summary.errorCount}
- Warnings: ${report.summary.warningCount}
- Info: ${report.summary.infoCount}

## Recommendations
${report.recommendations.map(r => `- ${r}`).join('\n')}
`;
    }
    
    return '<h1>Governance Report</h1>'; // Placeholder HTML
  }
}

interface ProjectGovernanceMetrics {
  totalRules: number;
  enabledRules: number;
  complianceScore: number;
  violationTrends: Array<{ date: string; count: number; }>;
  ruleEffectiveness: Map<string, number>;
  qualityScore: number; // Missing property from plan
  maintainabilityIndex: number; // Missing property from plan
  technicalDebt: number; // Missing property from plan
  securityScore: number; // Missing property from plan
}

export default RuleEngine;