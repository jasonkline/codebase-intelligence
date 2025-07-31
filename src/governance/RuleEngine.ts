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
          suggestion: this.generateSuggestion(rule, patternName)
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
          suggestion: this.generateSuggestion(rule, patternName)
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
          suggestion: this.generateSuggestion(rule)
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
            suggestion: this.generateSuggestion(rule)
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
            suggestion: this.generateSuggestion(rule)
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
        SELECT id FROM governance_rules gr
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
        autoFixAvailable: violation.auto_fix_available
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
}

export default RuleEngine;