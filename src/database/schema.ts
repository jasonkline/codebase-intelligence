import Database from 'better-sqlite3';
import { join } from 'path';
import { mkdirSync, existsSync } from 'fs';
import logger from '../utils/logger';

export interface Symbol {
  id?: number;
  name: string;
  kind: string; // 'function', 'class', 'interface', 'variable', etc.
  file_path: string;
  line_start: number;
  line_end: number;
  column_start: number;
  column_end: number;
  parent_symbol_id?: number;
  signature?: string; // For functions: parameter types and return type
  doc_comment?: string;
  visibility?: string; // 'public', 'private', 'protected'
  is_exported: boolean;
}

export interface Reference {
  id?: number;
  symbol_id: number;
  file_path: string;
  line: number;
  column: number;
  reference_kind: string; // 'call', 'import', 'type', 'extend', etc.
}

export interface FileInfo {
  id?: number;
  path: string;
  last_indexed: string; // ISO timestamp
  hash: string; // To detect changes
  size: number;
  language: string;
}

export interface Pattern {
  id?: number;
  name: string; // 'auth_check', 'api_route', 'db_access', etc.
  category: string; // 'security', 'data_access', 'api', etc.
  description?: string;
  ast_signature?: string; // Serialized AST pattern for matching
  example_file?: string;
  example_line?: number;
  confidence_threshold: number;
  confidence?: number; // Pattern match confidence
  template?: string; // Code template for auto-fix
  tags?: string[]; // Pattern tags for categorization
  usageCount?: number; // Computed field, not stored in database
  is_approved: boolean;
}

export interface PatternInstance {
  id?: number;
  pattern_id: number;
  file_path: string;
  line_start: number;
  line_end: number;
  confidence: number; // 0.0 to 1.0
  metadata?: string; // JSON string with additional context
}

export interface GovernanceRule {
  id?: number;
  pattern_id: number;
  rule_type: string; // 'required', 'forbidden', 'preferred'
  scope_pattern?: string; // File path pattern where rule applies
  message: string; // Guidance message for violations
  severity: string; // 'error', 'warning', 'info'
  auto_fix_available: boolean;
}

export interface PatternViolation {
  id?: number;
  rule_id: number;
  file_path: string;
  line: number;
  detected_at: string; // ISO timestamp
  resolved: boolean;
}

export interface SystemKnowledge {
  id?: number;
  system_name: string; // 'auth', 'rbac', 'data_access', etc.
  component: string;
  description: string;
  implementation_details?: string;
  security_considerations?: string;
  related_files?: string; // JSON array of file paths
  related_patterns?: string; // JSON array of pattern IDs
  last_updated: string; // ISO timestamp
}

export interface SecurityIssue {
  id?: number;
  severity: string; // 'critical', 'high', 'medium', 'low', 'info'
  category: string; // 'auth', 'injection', 'xss', 'csrf', etc.
  file_path: string;
  line_start: number;
  line_end: number;
  description: string;
  remediation: string;
  cwe_id?: string; // Common Weakness Enumeration ID
  detected_at: string; // ISO timestamp
  resolved: boolean;
  false_positive: boolean;
}

export interface StylePattern {
  id?: number;
  name: string; // 'component_structure', 'import_order', etc.
  category: string; // 'react', 'typescript', 'imports', etc.
  ast_pattern?: string;
  example_code?: string;
  anti_pattern_example?: string;
  auto_fixable: boolean;
}

export interface RBACPattern {
  id?: number;
  role: string;
  permission: string;
  resource_pattern?: string;
  implementation_pattern?: string;
  file_references?: string; // JSON array
}

export interface SystemDependency {
  id?: number;
  from_system: string;
  to_system: string;
  dependency_type: string; // 'imports', 'calls', 'extends', etc.
  strength?: number; // 1-10 coupling strength
  description?: string;
}

// OWASP Standards and References
export interface OwaspStandard {
  id?: number;
  standard_name: string; // 'Top 10 2021', 'API Security Top 10', 'ASVS', 'Cheat Sheets', etc.
  version: string;
  description: string;
  category: string; // 'web', 'api', 'mobile', 'ai', 'verification'
  url: string;
  last_updated: string;
}

export interface OwaspControl {
  id?: number;
  standard_id: number;
  control_id: string; // 'A01:2021', 'API1:2023', 'V2.1.1', etc.
  title: string;
  description: string;
  level?: number; // For ASVS levels 1-3
  category: string;
  cwe_mapping?: string; // JSON array of CWE IDs
  references?: string; // JSON array of reference URLs
}

export interface ControlMapping {
  id?: number;
  finding_id: number; // References security_issues.id
  control_id: number; // References owasp_controls.id
  compliance_status: string; // 'compliant', 'non_compliant', 'not_applicable', 'manual_review'
  evidence?: string;
  assessed_at: string;
}

export interface CheatSheetPattern {
  id?: number;
  sheet_name: string;
  pattern_name: string;
  category: string;
  code_pattern: string; // RegExp pattern or string match
  severity: string;
  remediation: string;
  references?: string; // JSON array
  examples?: string; // JSON object with vulnerable/secure examples
  tags?: string; // JSON array
  context?: string; // JSON array of file types/contexts
}

export interface AsvsAssessment {
  id?: number;
  project_path: string;
  level: number; // 1, 2, or 3
  score: number; // 0-100 compliance score
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  not_applicable_controls: number;
  manual_review_controls: number;
  assessed_at: string;
}

export interface AsvsControlStatus {
  id?: number;
  assessment_id: number;
  control_id: number;
  status: string; // 'pass', 'fail', 'not_applicable', 'manual_review'
  confidence: number; // 0.0-1.0
  evidence?: string; // JSON array of evidence
  violations?: string; // JSON array of violations
  remediation?: string;
}

export interface ApiSecurityFinding {
  id?: number;
  api_id: string; // API1-API10
  endpoint_path?: string;
  http_method?: string;
  security_issue_id: number; // References security_issues.id
  platform: string; // 'REST', 'GraphQL', 'gRPC', etc.
  risk_score: number; // 1-10
}

export interface MobileSecurityFinding {
  id?: number;
  mobile_id: string; // M1-M10
  platform: string; // 'iOS', 'Android', 'Cross-Platform', 'Web'
  framework?: string;
  security_issue_id: number; // References security_issues.id
  risk_score: number; // 1-10
}

export interface AiSecurityFinding {
  id?: number;
  ai_category: string; // 'model_security', 'data_poisoning', 'prompt_injection', etc.
  model_type?: string;
  ai_library?: string;
  security_issue_id: number; // References security_issues.id
  ml_risk: string; // 'high', 'medium', 'low'
  impact_area?: string; // JSON array
}

export interface ComplianceReport {
  id?: number;
  project_path: string;
  standard_id: number;
  compliance_score: number; // 0-100
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  not_applicable_controls: number;
  generated_at: string;
  report_data?: string; // JSON with detailed findings
}

export interface OwaspComplianceReport {
  id?: number;
  report_id: string;
  project_path: string;
  report_date: string;
  overall_score: number;
  compliance_level: string;
  issue_count: number;
  critical_issue_count: number;
  standard_scores?: string; // JSON with individual standard scores
  report_data: string; // Full JSON report data
}

// IaC Security specific interfaces
export interface IaCSecurityFinding {
  id?: number;
  finding_id: string;
  check_type: string; // 'terraform', 'cloudformation', 'kubernetes', etc.
  resource_type: string;
  resource_name?: string;
  file_path: string;
  line_start: number;
  line_end: number;
  severity: string; // 'critical', 'high', 'medium', 'low', 'info'
  check_id: string; // Checkov check ID (e.g., CKV_AWS_23)
  description: string;
  remediation: string;
  cwe_id?: string;
  compliance_frameworks?: string; // JSON array of compliance frameworks
  detected_at: string;
  resolved: boolean;
  bc_check_id?: string; // Bridgecrew check ID
  guideline?: string;
  frameworks?: string; // JSON array of frameworks
  risk_score?: number; // 1-10 risk assessment
}

export interface IaCComplianceReport {
  id?: number;
  report_id: string;
  project_path: string;
  scan_type: string; // 'full', 'incremental', 'targeted'
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  skipped_checks: number;
  compliance_score: number; // 0-100
  frameworks_scanned?: string; // JSON array
  scan_duration?: number; // milliseconds
  generated_at: string;
  checkov_version?: string;
  scan_options?: string; // JSON with scan configuration
}

export interface IaCPolicyRule {
  id?: number;
  rule_id: string;
  name: string;
  category: string;
  severity: string;
  frameworks: string; // JSON array
  resource_types: string; // JSON array
  description: string;
  remediation: string;
  enabled: boolean;
  custom: boolean; // true for user-defined rules
  created_at: string;
  updated_at: string;
}

export class DatabaseManager {
  private db: Database.Database;
  private dbPath: string;

  constructor(dbPath?: string) {
    this.dbPath = dbPath || join(process.cwd(), '.codeintel', 'index.db');
    
    // Ensure directory exists
    const dbDir = join(this.dbPath, '..');
    if (!existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
    }

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('cache_size = 1000');
    this.db.pragma('temp_store = memory');
    
    this.initializeSchema();
    logger.info(`Database initialized at ${this.dbPath}`);
  }

  private initializeSchema(): void {
    // Create all tables
    this.db.exec(`
      -- Symbols table (functions, classes, variables, etc.)
      CREATE TABLE IF NOT EXISTS symbols (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          kind TEXT NOT NULL,
          file_path TEXT NOT NULL,
          line_start INTEGER NOT NULL,
          line_end INTEGER NOT NULL,
          column_start INTEGER NOT NULL,
          column_end INTEGER NOT NULL,
          parent_symbol_id INTEGER,
          signature TEXT,
          doc_comment TEXT,
          visibility TEXT,
          is_exported BOOLEAN DEFAULT FALSE,
          FOREIGN KEY (parent_symbol_id) REFERENCES symbols(id)
      );

      -- References table (where symbols are used)
      CREATE TABLE IF NOT EXISTS symbol_references (
          id INTEGER PRIMARY KEY,
          symbol_id INTEGER NOT NULL,
          file_path TEXT NOT NULL,
          line INTEGER NOT NULL,
          column INTEGER NOT NULL,
          reference_kind TEXT NOT NULL,
          FOREIGN KEY (symbol_id) REFERENCES symbols(id)
      );

      -- Files table (track file metadata)
      CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY,
          path TEXT UNIQUE NOT NULL,
          last_indexed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          hash TEXT NOT NULL,
          size INTEGER NOT NULL,
          language TEXT NOT NULL
      );

      -- Full-text search virtual table
      CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts USING fts5(
          name, 
          doc_comment,
          file_path,
          content=symbols
      );

      -- Patterns table (identified code patterns)
      CREATE TABLE IF NOT EXISTS patterns (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          description TEXT,
          ast_signature TEXT,
          example_file TEXT,
          example_line INTEGER,
          confidence_threshold REAL DEFAULT 0.8,
          is_approved BOOLEAN DEFAULT TRUE
      );

      -- Pattern instances (where patterns are found)
      CREATE TABLE IF NOT EXISTS pattern_instances (
          id INTEGER PRIMARY KEY,
          pattern_id INTEGER NOT NULL,
          file_path TEXT NOT NULL,
          line_start INTEGER NOT NULL,
          line_end INTEGER NOT NULL,
          confidence REAL NOT NULL,
          metadata TEXT,
          FOREIGN KEY (pattern_id) REFERENCES patterns(id)
      );

      -- Governance rules
      CREATE TABLE IF NOT EXISTS governance_rules (
          id INTEGER PRIMARY KEY,
          pattern_id INTEGER NOT NULL,
          rule_type TEXT NOT NULL,
          scope_pattern TEXT,
          message TEXT NOT NULL,
          severity TEXT DEFAULT 'warning',
          auto_fix_available BOOLEAN DEFAULT FALSE,
          FOREIGN KEY (pattern_id) REFERENCES patterns(id)
      );

      -- Pattern violations
      CREATE TABLE IF NOT EXISTS pattern_violations (
          id INTEGER PRIMARY KEY,
          rule_id INTEGER NOT NULL,
          file_path TEXT NOT NULL,
          line INTEGER NOT NULL,
          detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          resolved BOOLEAN DEFAULT FALSE,
          FOREIGN KEY (rule_id) REFERENCES governance_rules(id)
      );

      -- System knowledge base
      CREATE TABLE IF NOT EXISTS system_knowledge (
          id INTEGER PRIMARY KEY,
          system_name TEXT NOT NULL,
          component TEXT NOT NULL,
          description TEXT NOT NULL,
          implementation_details TEXT,
          security_considerations TEXT,
          related_files TEXT,
          related_patterns TEXT,
          last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Security vulnerabilities
      CREATE TABLE IF NOT EXISTS security_issues (
          id INTEGER PRIMARY KEY,
          severity TEXT NOT NULL,
          category TEXT NOT NULL,
          file_path TEXT NOT NULL,
          line_start INTEGER NOT NULL,
          line_end INTEGER NOT NULL,
          description TEXT NOT NULL,
          remediation TEXT NOT NULL,
          cwe_id TEXT,
          detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          resolved BOOLEAN DEFAULT FALSE,
          false_positive BOOLEAN DEFAULT FALSE
      );

      -- Code style patterns
      CREATE TABLE IF NOT EXISTS style_patterns (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          ast_pattern TEXT,
          example_code TEXT,
          anti_pattern_example TEXT,
          auto_fixable BOOLEAN DEFAULT FALSE
      );

      -- RBAC patterns
      CREATE TABLE IF NOT EXISTS rbac_patterns (
          id INTEGER PRIMARY KEY,
          role TEXT NOT NULL,
          permission TEXT NOT NULL,
          resource_pattern TEXT,
          implementation_pattern TEXT,
          file_references TEXT
      );

      -- System dependencies
      CREATE TABLE IF NOT EXISTS system_dependencies (
          id INTEGER PRIMARY KEY,
          from_system TEXT NOT NULL,
          to_system TEXT NOT NULL,
          dependency_type TEXT NOT NULL,
          strength INTEGER,
          description TEXT
      );

      -- OWASP Standards
      CREATE TABLE IF NOT EXISTS owasp_standards (
          id INTEGER PRIMARY KEY,
          standard_name TEXT NOT NULL,
          version TEXT NOT NULL,
          description TEXT NOT NULL,
          category TEXT NOT NULL,
          url TEXT NOT NULL,
          last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- OWASP Controls
      CREATE TABLE IF NOT EXISTS owasp_controls (
          id INTEGER PRIMARY KEY,
          standard_id INTEGER NOT NULL,
          control_id TEXT NOT NULL,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          level INTEGER,
          category TEXT NOT NULL,
          cwe_mapping TEXT,
          "references" TEXT,
          FOREIGN KEY (standard_id) REFERENCES owasp_standards(id)
      );

      -- Control Mappings (link security findings to OWASP controls)
      CREATE TABLE IF NOT EXISTS control_mappings (
          id INTEGER PRIMARY KEY,
          finding_id INTEGER NOT NULL,
          control_id INTEGER NOT NULL,
          compliance_status TEXT NOT NULL,
          evidence TEXT,
          assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (finding_id) REFERENCES security_issues(id),
          FOREIGN KEY (control_id) REFERENCES owasp_controls(id)
      );

      -- OWASP Cheat Sheet Patterns
      CREATE TABLE IF NOT EXISTS cheat_sheet_patterns (
          id INTEGER PRIMARY KEY,
          sheet_name TEXT NOT NULL,
          pattern_name TEXT NOT NULL,
          category TEXT NOT NULL,
          code_pattern TEXT NOT NULL,
          severity TEXT NOT NULL,
          remediation TEXT NOT NULL,
          "references" TEXT,
          examples TEXT,
          tags TEXT,
          context TEXT
      );

      -- ASVS Assessments
      CREATE TABLE IF NOT EXISTS asvs_assessments (
          id INTEGER PRIMARY KEY,
          project_path TEXT NOT NULL,
          level INTEGER NOT NULL,
          score INTEGER NOT NULL,
          total_controls INTEGER NOT NULL,
          passed_controls INTEGER NOT NULL,
          failed_controls INTEGER NOT NULL,
          not_applicable_controls INTEGER NOT NULL,
          manual_review_controls INTEGER NOT NULL,
          assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- ASVS Control Status
      CREATE TABLE IF NOT EXISTS asvs_control_status (
          id INTEGER PRIMARY KEY,
          assessment_id INTEGER NOT NULL,
          control_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          confidence REAL NOT NULL,
          evidence TEXT,
          violations TEXT,
          remediation TEXT,
          FOREIGN KEY (assessment_id) REFERENCES asvs_assessments(id),
          FOREIGN KEY (control_id) REFERENCES owasp_controls(id)
      );

      -- API Security Findings (OWASP API Security Top 10)
      CREATE TABLE IF NOT EXISTS api_security_findings (
          id INTEGER PRIMARY KEY,
          api_id TEXT NOT NULL,
          endpoint_path TEXT,
          http_method TEXT,
          security_issue_id INTEGER NOT NULL,
          platform TEXT NOT NULL,
          risk_score INTEGER NOT NULL,
          FOREIGN KEY (security_issue_id) REFERENCES security_issues(id)
      );

      -- Mobile Security Findings (OWASP Mobile Top 10)
      CREATE TABLE IF NOT EXISTS mobile_security_findings (
          id INTEGER PRIMARY KEY,
          mobile_id TEXT NOT NULL,
          platform TEXT NOT NULL,
          framework TEXT,
          security_issue_id INTEGER NOT NULL,
          risk_score INTEGER NOT NULL,
          FOREIGN KEY (security_issue_id) REFERENCES security_issues(id)
      );

      -- AI Security Findings (OWASP AI Security Guide)
      CREATE TABLE IF NOT EXISTS ai_security_findings (
          id INTEGER PRIMARY KEY,
          ai_category TEXT NOT NULL,
          model_type TEXT,
          ai_library TEXT,
          security_issue_id INTEGER NOT NULL,
          ml_risk TEXT NOT NULL,
          impact_area TEXT,
          FOREIGN KEY (security_issue_id) REFERENCES security_issues(id)
      );

      -- Compliance Reports
      CREATE TABLE IF NOT EXISTS compliance_reports (
          id INTEGER PRIMARY KEY,
          project_path TEXT NOT NULL,
          standard_id INTEGER NOT NULL,
          compliance_score INTEGER NOT NULL,
          total_controls INTEGER NOT NULL,
          compliant_controls INTEGER NOT NULL,
          non_compliant_controls INTEGER NOT NULL,
          not_applicable_controls INTEGER NOT NULL,
          generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          report_data TEXT,
          FOREIGN KEY (standard_id) REFERENCES owasp_standards(id)
      );

      -- OWASP Compliance Reports (Enhanced)
      CREATE TABLE IF NOT EXISTS owasp_compliance_reports (
          id INTEGER PRIMARY KEY,
          report_id TEXT NOT NULL UNIQUE,
          project_path TEXT NOT NULL,
          report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          overall_score INTEGER NOT NULL,
          compliance_level TEXT NOT NULL,
          issue_count INTEGER NOT NULL,
          critical_issue_count INTEGER NOT NULL,
          standard_scores TEXT, -- JSON with individual standard scores
          report_data TEXT NOT NULL -- Full JSON report data
      );

      -- IaC Security Findings (Checkov scan results)
      CREATE TABLE IF NOT EXISTS iac_security_findings (
        id INTEGER PRIMARY KEY,
        finding_id TEXT UNIQUE NOT NULL,
        check_type TEXT NOT NULL, -- 'terraform', 'cloudformation', 'kubernetes', etc.
        resource_type TEXT NOT NULL,
        resource_name TEXT,
        file_path TEXT NOT NULL,
        line_start INTEGER NOT NULL,
        line_end INTEGER NOT NULL,
        severity TEXT NOT NULL,
        check_id TEXT NOT NULL, -- Checkov check ID (e.g., CKV_AWS_23)
        description TEXT NOT NULL,
        remediation TEXT NOT NULL,
        cwe_id TEXT,
        compliance_frameworks TEXT, -- JSON array of compliance frameworks
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved BOOLEAN DEFAULT FALSE,
        bc_check_id TEXT, -- Bridgecrew check ID
        guideline TEXT,
        frameworks TEXT, -- JSON array of frameworks
        risk_score INTEGER -- 1-10 risk assessment
      );

      -- IaC Compliance Reports
      CREATE TABLE IF NOT EXISTS iac_compliance_reports (
        id INTEGER PRIMARY KEY,
        report_id TEXT UNIQUE NOT NULL,
        project_path TEXT NOT NULL,
        scan_type TEXT NOT NULL, -- 'full', 'incremental', 'targeted'
        total_checks INTEGER NOT NULL,
        passed_checks INTEGER NOT NULL,
        failed_checks INTEGER NOT NULL,
        skipped_checks INTEGER NOT NULL,
        compliance_score INTEGER NOT NULL, -- 0-100
        frameworks_scanned TEXT, -- JSON array
        scan_duration INTEGER, -- milliseconds
        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        checkov_version TEXT,
        scan_options TEXT -- JSON with scan configuration
      );

      -- IaC Policy Rules (Custom and standard security policies)
      CREATE TABLE IF NOT EXISTS iac_policy_rules (
        id INTEGER PRIMARY KEY,
        rule_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        frameworks TEXT NOT NULL, -- JSON array
        resource_types TEXT NOT NULL, -- JSON array
        description TEXT NOT NULL,
        remediation TEXT NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        custom BOOLEAN DEFAULT FALSE, -- true for user-defined rules
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create indexes for better performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
      CREATE INDEX IF NOT EXISTS idx_symbols_file_path ON symbols(file_path);
      CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
      CREATE INDEX IF NOT EXISTS idx_references_symbol_id ON symbol_references(symbol_id);
      CREATE INDEX IF NOT EXISTS idx_references_file_path ON symbol_references(file_path);
      CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
      CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);
      CREATE INDEX IF NOT EXISTS idx_pattern_instances_pattern_id ON pattern_instances(pattern_id);
      CREATE INDEX IF NOT EXISTS idx_pattern_instances_file_path ON pattern_instances(file_path);
      CREATE INDEX IF NOT EXISTS idx_security_issues_severity ON security_issues(severity);
      CREATE INDEX IF NOT EXISTS idx_security_issues_file_path ON security_issues(file_path);
      CREATE INDEX IF NOT EXISTS idx_owasp_compliance_reports_project_path ON owasp_compliance_reports(project_path);
      CREATE INDEX IF NOT EXISTS idx_owasp_compliance_reports_date ON owasp_compliance_reports(report_date);
      
      -- OWASP table indexes
      CREATE INDEX IF NOT EXISTS idx_owasp_standards_category ON owasp_standards(category);
      CREATE INDEX IF NOT EXISTS idx_owasp_controls_standard_id ON owasp_controls(standard_id);
      CREATE INDEX IF NOT EXISTS idx_owasp_controls_control_id ON owasp_controls(control_id);
      CREATE INDEX IF NOT EXISTS idx_control_mappings_finding_id ON control_mappings(finding_id);
      CREATE INDEX IF NOT EXISTS idx_control_mappings_control_id ON control_mappings(control_id);
      CREATE INDEX IF NOT EXISTS idx_cheat_sheet_patterns_category ON cheat_sheet_patterns(category);
      CREATE INDEX IF NOT EXISTS idx_asvs_assessments_project_path ON asvs_assessments(project_path);
      CREATE INDEX IF NOT EXISTS idx_asvs_control_status_assessment_id ON asvs_control_status(assessment_id);
      CREATE INDEX IF NOT EXISTS idx_api_security_findings_api_id ON api_security_findings(api_id);
      CREATE INDEX IF NOT EXISTS idx_mobile_security_findings_mobile_id ON mobile_security_findings(mobile_id);
      CREATE INDEX IF NOT EXISTS idx_ai_security_findings_category ON ai_security_findings(ai_category);
      CREATE INDEX IF NOT EXISTS idx_compliance_reports_project_path ON compliance_reports(project_path);
      CREATE INDEX IF NOT EXISTS idx_compliance_reports_standard_id ON compliance_reports(standard_id);
      
      -- IaC table indexes
      CREATE INDEX IF NOT EXISTS idx_iac_security_findings_file_path ON iac_security_findings(file_path);
      CREATE INDEX IF NOT EXISTS idx_iac_security_findings_check_id ON iac_security_findings(check_id);
      CREATE INDEX IF NOT EXISTS idx_iac_security_findings_severity ON iac_security_findings(severity);
      CREATE INDEX IF NOT EXISTS idx_iac_security_findings_check_type ON iac_security_findings(check_type);
      CREATE INDEX IF NOT EXISTS idx_iac_security_findings_resource_type ON iac_security_findings(resource_type);
      CREATE INDEX IF NOT EXISTS idx_iac_compliance_reports_project_path ON iac_compliance_reports(project_path);
      CREATE INDEX IF NOT EXISTS idx_iac_compliance_reports_generated_at ON iac_compliance_reports(generated_at);
      CREATE INDEX IF NOT EXISTS idx_iac_policy_rules_category ON iac_policy_rules(category);
      CREATE INDEX IF NOT EXISTS idx_iac_policy_rules_enabled ON iac_policy_rules(enabled);
    `);

    logger.info('Database schema initialized successfully');
  }

  // Symbol operations
  insertSymbol(symbol: Symbol): number {
    const stmt = this.db.prepare(`
      INSERT INTO symbols (name, kind, file_path, line_start, line_end, column_start, column_end, 
                          parent_symbol_id, signature, doc_comment, visibility, is_exported)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      symbol.name,
      symbol.kind,
      symbol.file_path,
      symbol.line_start,
      symbol.line_end,
      symbol.column_start,
      symbol.column_end,
      symbol.parent_symbol_id || null,
      symbol.signature || null,
      symbol.doc_comment || null,
      symbol.visibility || null,
      symbol.is_exported ? 1 : 0
    );
    
    return result.lastInsertRowid as number;
  }

  getSymbolsByFile(filePath: string): Symbol[] {
    const stmt = this.db.prepare('SELECT * FROM symbols WHERE file_path = ?');
    return stmt.all(filePath) as Symbol[];
  }

  // File operations
  insertFile(file: FileInfo): number {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO files (path, last_indexed, hash, size, language)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      file.path,
      file.last_indexed,
      file.hash,
      file.size,
      file.language
    );
    
    return result.lastInsertRowid as number;
  }

  getFileByPath(path: string): FileInfo | undefined {
    const stmt = this.db.prepare('SELECT * FROM files WHERE path = ?');
    return stmt.get(path) as FileInfo | undefined;
  }

  // Pattern operations
  insertPattern(pattern: Pattern): number {
    const stmt = this.db.prepare(`
      INSERT INTO patterns (name, category, description, ast_signature, example_file, 
                           example_line, confidence_threshold, is_approved)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      pattern.name,
      pattern.category,
      pattern.description || null,
      pattern.ast_signature || null,
      pattern.example_file || null,
      pattern.example_line || null,
      pattern.confidence_threshold,
      pattern.is_approved ? 1 : 0
    );
    
    return result.lastInsertRowid as number;
  }

  insertPatternInstance(instance: PatternInstance): number {
    const stmt = this.db.prepare(`
      INSERT INTO pattern_instances (pattern_id, file_path, line_start, line_end, confidence, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      instance.pattern_id,
      instance.file_path,
      instance.line_start,
      instance.line_end,
      instance.confidence,
      instance.metadata || null
    );
    
    return result.lastInsertRowid as number;
  }

  // Knowledge operations
  insertSystemKnowledge(knowledge: SystemKnowledge): number {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO system_knowledge 
      (system_name, component, description, implementation_details, security_considerations, 
       related_files, related_patterns, last_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      knowledge.system_name,
      knowledge.component,
      knowledge.description,
      knowledge.implementation_details || null,
      knowledge.security_considerations || null,
      knowledge.related_files || null,
      knowledge.related_patterns || null,
      knowledge.last_updated
    );
    
    return result.lastInsertRowid as number;
  }

  // Security operations
  insertSecurityIssue(issue: SecurityIssue): number {
    const stmt = this.db.prepare(`
      INSERT INTO security_issues 
      (severity, category, file_path, line_start, line_end, description, remediation, 
       cwe_id, detected_at, resolved, false_positive)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      issue.severity,
      issue.category,
      issue.file_path,
      issue.line_start,
      issue.line_end,
      issue.description,
      issue.remediation,
      issue.cwe_id || null,
      issue.detected_at,
      issue.resolved,
      issue.false_positive
    );
    
    return result.lastInsertRowid as number;
  }

  // Search operations
  searchSymbols(query: string): Symbol[] {
    const stmt = this.db.prepare(`
      SELECT symbols.* FROM symbols
      JOIN symbols_fts ON symbols.rowid = symbols_fts.rowid
      WHERE symbols_fts MATCH ?
      ORDER BY rank
    `);
    return stmt.all(query) as Symbol[];
  }

  // Clear operations (for re-indexing)
  clearFileData(filePath: string): void {
    const transaction = this.db.transaction(() => {
      this.db.prepare('DELETE FROM symbols WHERE file_path = ?').run(filePath);
      this.db.prepare('DELETE FROM symbol_references WHERE file_path = ?').run(filePath);
      this.db.prepare('DELETE FROM pattern_instances WHERE file_path = ?').run(filePath);
      this.db.prepare('DELETE FROM security_issues WHERE file_path = ?').run(filePath);
    });
    transaction();
  }

  // Utility methods
  close(): void {
    this.db.close();
  }

  getDatabase(): Database.Database {
    return this.db;
  }

  getDb(): Database.Database {
    return this.db;
  }

  // Transaction support
  transaction<T>(fn: () => T): T {
    const transaction = this.db.transaction(fn);
    return transaction();
  }

  // OWASP Standards operations
  insertOwaspStandard(standard: OwaspStandard): number {
    const stmt = this.db.prepare(`
      INSERT INTO owasp_standards (standard_name, version, description, category, url, last_updated)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      standard.standard_name,
      standard.version,
      standard.description,
      standard.category,
      standard.url,
      standard.last_updated
    );
    
    return result.lastInsertRowid as number;
  }

  getOwaspStandards(): OwaspStandard[] {
    const stmt = this.db.prepare('SELECT * FROM owasp_standards ORDER BY category, standard_name');
    return stmt.all() as OwaspStandard[];
  }

  // OWASP Controls operations
  insertOwaspControl(control: OwaspControl): number {
    const stmt = this.db.prepare(`
      INSERT INTO owasp_controls (standard_id, control_id, title, description, level, category, cwe_mapping, "references")
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      control.standard_id,
      control.control_id,
      control.title,
      control.description,
      control.level || null,
      control.category,
      control.cwe_mapping || null,
      control.references || null
    );
    
    return result.lastInsertRowid as number;
  }

  getOwaspControlsByStandard(standardId: number): OwaspControl[] {
    const stmt = this.db.prepare('SELECT * FROM owasp_controls WHERE standard_id = ? ORDER BY control_id');
    return stmt.all(standardId) as OwaspControl[];
  }

  // Control Mapping operations
  insertControlMapping(mapping: ControlMapping): number {
    const stmt = this.db.prepare(`
      INSERT INTO control_mappings (finding_id, control_id, compliance_status, evidence, assessed_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      mapping.finding_id,
      mapping.control_id,
      mapping.compliance_status,
      mapping.evidence || null,
      mapping.assessed_at
    );
    
    return result.lastInsertRowid as number;
  }

  getControlMappingsByFinding(findingId: number): ControlMapping[] {
    const stmt = this.db.prepare('SELECT * FROM control_mappings WHERE finding_id = ?');
    return stmt.all(findingId) as ControlMapping[];
  }

  // Cheat Sheet Pattern operations
  insertCheatSheetPattern(pattern: CheatSheetPattern): number {
    const stmt = this.db.prepare(`
      INSERT INTO cheat_sheet_patterns (sheet_name, pattern_name, category, code_pattern, severity, 
                                      remediation, "references", examples, tags, context)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      pattern.sheet_name,
      pattern.pattern_name,
      pattern.category,
      pattern.code_pattern,
      pattern.severity,
      pattern.remediation,
      pattern.references || null,
      pattern.examples || null,
      pattern.tags || null,
      pattern.context || null
    );
    
    return result.lastInsertRowid as number;
  }

  getCheatSheetPatternsByCategory(category: string): CheatSheetPattern[] {
    const stmt = this.db.prepare('SELECT * FROM cheat_sheet_patterns WHERE category = ?');
    return stmt.all(category) as CheatSheetPattern[];
  }

  // ASVS Assessment operations
  insertAsvsAssessment(assessment: AsvsAssessment): number {
    const stmt = this.db.prepare(`
      INSERT INTO asvs_assessments (project_path, level, score, total_controls, passed_controls, 
                                  failed_controls, not_applicable_controls, manual_review_controls, assessed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      assessment.project_path,
      assessment.level,
      assessment.score,
      assessment.total_controls,
      assessment.passed_controls,
      assessment.failed_controls,
      assessment.not_applicable_controls,
      assessment.manual_review_controls,
      assessment.assessed_at
    );
    
    return result.lastInsertRowid as number;
  }

  getAsvsAssessmentsByProject(projectPath: string): AsvsAssessment[] {
    const stmt = this.db.prepare('SELECT * FROM asvs_assessments WHERE project_path = ? ORDER BY assessed_at DESC');
    return stmt.all(projectPath) as AsvsAssessment[];
  }

  // ASVS Control Status operations
  insertAsvsControlStatus(status: AsvsControlStatus): number {
    const stmt = this.db.prepare(`
      INSERT INTO asvs_control_status (assessment_id, control_id, status, confidence, evidence, violations, remediation)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      status.assessment_id,
      status.control_id,
      status.status,
      status.confidence,
      status.evidence || null,
      status.violations || null,
      status.remediation || null
    );
    
    return result.lastInsertRowid as number;
  }

  getAsvsControlStatusByAssessment(assessmentId: number): AsvsControlStatus[] {
    const stmt = this.db.prepare('SELECT * FROM asvs_control_status WHERE assessment_id = ?');
    return stmt.all(assessmentId) as AsvsControlStatus[];
  }

  // API Security Finding operations
  insertApiSecurityFinding(finding: ApiSecurityFinding): number {
    const stmt = this.db.prepare(`
      INSERT INTO api_security_findings (api_id, endpoint_path, http_method, security_issue_id, platform, risk_score)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      finding.api_id,
      finding.endpoint_path || null,
      finding.http_method || null,
      finding.security_issue_id,
      finding.platform,
      finding.risk_score
    );
    
    return result.lastInsertRowid as number;
  }

  getApiSecurityFindingsByProject(projectPath: string): ApiSecurityFinding[] {
    const stmt = this.db.prepare(`
      SELECT asf.*, si.file_path 
      FROM api_security_findings asf
      JOIN security_issues si ON asf.security_issue_id = si.id
      WHERE si.file_path LIKE ?
      ORDER BY asf.risk_score DESC
    `);
    return stmt.all(`${projectPath}%`) as ApiSecurityFinding[];
  }

  // Mobile Security Finding operations
  insertMobileSecurityFinding(finding: MobileSecurityFinding): number {
    const stmt = this.db.prepare(`
      INSERT INTO mobile_security_findings (mobile_id, platform, framework, security_issue_id, risk_score)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      finding.mobile_id,
      finding.platform,
      finding.framework || null,
      finding.security_issue_id,
      finding.risk_score
    );
    
    return result.lastInsertRowid as number;
  }

  getMobileSecurityFindingsByProject(projectPath: string): MobileSecurityFinding[] {
    const stmt = this.db.prepare(`
      SELECT msf.*, si.file_path 
      FROM mobile_security_findings msf
      JOIN security_issues si ON msf.security_issue_id = si.id
      WHERE si.file_path LIKE ?
      ORDER BY msf.risk_score DESC
    `);
    return stmt.all(`${projectPath}%`) as MobileSecurityFinding[];
  }

  // AI Security Finding operations
  insertAiSecurityFinding(finding: AiSecurityFinding): number {
    const stmt = this.db.prepare(`
      INSERT INTO ai_security_findings (ai_category, model_type, ai_library, security_issue_id, ml_risk, impact_area)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      finding.ai_category,
      finding.model_type || null,
      finding.ai_library || null,
      finding.security_issue_id,
      finding.ml_risk,
      finding.impact_area || null
    );
    
    return result.lastInsertRowid as number;
  }

  getAiSecurityFindingsByProject(projectPath: string): AiSecurityFinding[] {
    const stmt = this.db.prepare(`
      SELECT aisf.*, si.file_path 
      FROM ai_security_findings aisf
      JOIN security_issues si ON aisf.security_issue_id = si.id
      WHERE si.file_path LIKE ?
      ORDER BY aisf.ml_risk DESC
    `);
    return stmt.all(`${projectPath}%`) as AiSecurityFinding[];
  }

  // Compliance Report operations
  insertComplianceReport(report: ComplianceReport): number {
    const stmt = this.db.prepare(`
      INSERT INTO compliance_reports (project_path, standard_id, compliance_score, total_controls, 
                                    compliant_controls, non_compliant_controls, not_applicable_controls, 
                                    generated_at, report_data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      report.project_path,
      report.standard_id,
      report.compliance_score,
      report.total_controls,
      report.compliant_controls,
      report.non_compliant_controls,
      report.not_applicable_controls,
      report.generated_at,
      report.report_data || null
    );
    
    return result.lastInsertRowid as number;
  }

  getComplianceReportsByProject(projectPath: string): ComplianceReport[] {
    const stmt = this.db.prepare(`
      SELECT cr.*, os.standard_name, os.version
      FROM compliance_reports cr
      JOIN owasp_standards os ON cr.standard_id = os.id
      WHERE cr.project_path = ?
      ORDER BY cr.generated_at DESC
    `);
    return stmt.all(projectPath) as (ComplianceReport & { standard_name: string; version: string })[];
  }

  // Utility methods for OWASP data initialization
  initializeOwaspData(): void {
    const transaction = this.db.transaction(() => {
      // Initialize OWASP standards
      const standards = [
        {
          standard_name: 'OWASP Top 10',
          version: '2021',
          description: 'The OWASP Top 10 is a standard awareness document for developers and web application security',
          category: 'web',
          url: 'https://owasp.org/Top10/',
          last_updated: new Date().toISOString()
        },
        {
          standard_name: 'OWASP API Security Top 10',
          version: '2023',
          description: 'The OWASP API Security Top 10 focuses on strategies and solutions for API security',
          category: 'api',
          url: 'https://owasp.org/API-Security/editions/2023/en/0x00-header/',
          last_updated: new Date().toISOString()
        },
        {
          standard_name: 'OWASP ASVS',
          version: '4.0',
          description: 'Application Security Verification Standard - comprehensive framework for security requirements',
          category: 'verification',
          url: 'https://owasp.org/www-project-application-security-verification-standard/',
          last_updated: new Date().toISOString()
        },
        {
          standard_name: 'OWASP Mobile Top 10',
          version: '2016',
          description: 'The OWASP Mobile Top 10 provides guidance for mobile application security',
          category: 'mobile',  
          url: 'https://owasp.org/www-project-mobile-top-10/',
          last_updated: new Date().toISOString()
        },
        {
          standard_name: 'OWASP Cheat Sheets',
          version: '4.0',
          description: 'Concise collection of high value information on specific application security topics',
          category: 'guidance',
          url: 'https://cheatsheetseries.owasp.org/',
          last_updated: new Date().toISOString()
        }
      ];

      standards.forEach(standard => {
        try {
          this.insertOwaspStandard(standard);
        } catch (error: any) {
          if (!error.message.includes('UNIQUE constraint failed')) {
            logger.error('Error inserting OWASP standard:', error);
          }
        }
      });

      logger.info('OWASP standards initialized');
    });

    transaction();
  }

  // IaC Security Finding operations
  insertIaCSecurityFinding(finding: IaCSecurityFinding): number {
    const stmt = this.db.prepare(`
      INSERT INTO iac_security_findings (
        finding_id, check_type, resource_type, resource_name, file_path, line_start, line_end,
        severity, check_id, description, remediation, cwe_id, compliance_frameworks,
        detected_at, resolved, bc_check_id, guideline, frameworks, risk_score
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      finding.finding_id,
      finding.check_type,
      finding.resource_type,
      finding.resource_name || null,
      finding.file_path,
      finding.line_start,
      finding.line_end,
      finding.severity,
      finding.check_id,
      finding.description,
      finding.remediation,
      finding.cwe_id || null,
      finding.compliance_frameworks || null,
      finding.detected_at,
      finding.resolved,
      finding.bc_check_id || null,
      finding.guideline || null,
      finding.frameworks || null,
      finding.risk_score || null
    );
    
    return result.lastInsertRowid as number;
  }

  getIaCSecurityFindingsByProject(projectPath: string): IaCSecurityFinding[] {
    const stmt = this.db.prepare(`
      SELECT * FROM iac_security_findings 
      WHERE file_path LIKE ? 
      ORDER BY severity, risk_score DESC, detected_at DESC
    `);
    return stmt.all(`${projectPath}%`) as IaCSecurityFinding[];
  }

  getIaCSecurityFindingsByFile(filePath: string): IaCSecurityFinding[] {
    const stmt = this.db.prepare('SELECT * FROM iac_security_findings WHERE file_path = ? ORDER BY line_start');
    return stmt.all(filePath) as IaCSecurityFinding[];
  }

  updateIaCFindingStatus(findingId: string, resolved: boolean): void {
    const stmt = this.db.prepare('UPDATE iac_security_findings SET resolved = ? WHERE finding_id = ?');
    stmt.run(resolved, findingId);
  }

  // IaC Compliance Report operations
  insertIaCComplianceReport(report: IaCComplianceReport): number {
    const stmt = this.db.prepare(`
      INSERT INTO iac_compliance_reports (
        report_id, project_path, scan_type, total_checks, passed_checks, failed_checks,
        skipped_checks, compliance_score, frameworks_scanned, scan_duration,
        generated_at, checkov_version, scan_options
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      report.report_id,
      report.project_path,
      report.scan_type,
      report.total_checks,
      report.passed_checks,
      report.failed_checks,
      report.skipped_checks,
      report.compliance_score,
      report.frameworks_scanned || null,
      report.scan_duration || null,
      report.generated_at,
      report.checkov_version || null,
      report.scan_options || null
    );
    
    return result.lastInsertRowid as number;
  }

  getIaCComplianceReportsByProject(projectPath: string): IaCComplianceReport[] {
    const stmt = this.db.prepare(`
      SELECT * FROM iac_compliance_reports 
      WHERE project_path = ? 
      ORDER BY generated_at DESC
    `);
    return stmt.all(projectPath) as IaCComplianceReport[];
  }

  getLatestIaCComplianceReport(projectPath: string): IaCComplianceReport | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM iac_compliance_reports 
      WHERE project_path = ? 
      ORDER BY generated_at DESC 
      LIMIT 1
    `);
    return stmt.get(projectPath) as IaCComplianceReport | undefined;
  }

  // IaC Policy Rule operations
  insertIaCPolicyRule(rule: IaCPolicyRule): number {
    const stmt = this.db.prepare(`
      INSERT INTO iac_policy_rules (
        rule_id, name, category, severity, frameworks, resource_types,
        description, remediation, enabled, custom, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      rule.rule_id,
      rule.name,
      rule.category,
      rule.severity,
      rule.frameworks,
      rule.resource_types,
      rule.description,
      rule.remediation,
      rule.enabled,
      rule.custom,
      rule.created_at,
      rule.updated_at
    );
    
    return result.lastInsertRowid as number;
  }

  getIaCPolicyRules(category?: string, enabled?: boolean): IaCPolicyRule[] {
    let query = 'SELECT * FROM iac_policy_rules WHERE 1=1';
    const params: any[] = [];
    
    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }
    
    if (enabled !== undefined) {
      query += ' AND enabled = ?';
      params.push(enabled);
    }
    
    query += ' ORDER BY category, name';
    
    const stmt = this.db.prepare(query);
    return stmt.all(...params) as IaCPolicyRule[];
  }

  updateIaCPolicyRule(ruleId: string, updates: Partial<IaCPolicyRule>): void {
    const setClause = Object.keys(updates)
      .filter(key => key !== 'id' && key !== 'rule_id')
      .map(key => `${key} = ?`)
      .join(', ');
    
    if (!setClause) return;
    
    const values = Object.keys(updates)
      .filter(key => key !== 'id' && key !== 'rule_id')
      .map(key => updates[key as keyof IaCPolicyRule]);
    
    values.push(ruleId);
    
    const stmt = this.db.prepare(`
      UPDATE iac_policy_rules 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
      WHERE rule_id = ?
    `);
    
    stmt.run(...values);
  }

  deleteIaCPolicyRule(ruleId: string): void {
    const stmt = this.db.prepare('DELETE FROM iac_policy_rules WHERE rule_id = ?');
    stmt.run(ruleId);
  }

  // IaC Statistics and Analytics
  getIaCSecurityStatsByProject(projectPath: string): {
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    findingsByCheckType: Record<string, number>;
    complianceScore: number;
  } {
    const findings = this.getIaCSecurityFindingsByProject(projectPath);
    
    const findingsBySeverity: Record<string, number> = {};
    const findingsByCheckType: Record<string, number> = {};
    
    findings.forEach(finding => {
      findingsBySeverity[finding.severity] = (findingsBySeverity[finding.severity] || 0) + 1;
      findingsByCheckType[finding.check_type] = (findingsByCheckType[finding.check_type] || 0) + 1;
    });
    
    const latestReport = this.getLatestIaCComplianceReport(projectPath);
    const complianceScore = latestReport?.compliance_score || 0;
    
    return {
      totalFindings: findings.length,
      findingsBySeverity,
      findingsByCheckType,
      complianceScore
    };
  }
}

export default DatabaseManager;