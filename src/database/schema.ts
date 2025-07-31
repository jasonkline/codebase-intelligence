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
      pattern.is_approved
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
      this.db.prepare('DELETE FROM references WHERE file_path = ?').run(filePath);
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

  // Transaction support
  transaction<T>(fn: () => T): T {
    const transaction = this.db.transaction(fn);
    return transaction();
  }
}

export default DatabaseManager;