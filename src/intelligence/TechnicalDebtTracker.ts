import { ParsedSymbol } from '../parser/ASTParser';
import { logger } from '../utils/logger';
import Database from 'better-sqlite3';
import * as fs from 'fs';

export interface CodeSmell {
  id: string;
  type: 'long_method' | 'large_class' | 'duplicate_code' | 'complex_conditional' | 
        'feature_envy' | 'data_clumps' | 'primitive_obsession' | 'dead_code' |
        'god_class' | 'shotgun_surgery' | 'divergent_change' | 'lazy_class';
  filePath: string;
  location: {
    lineStart: number;
    lineEnd: number;
    function?: string;
    class?: string;
  };
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  impact: string;
  effortToFix: 'trivial' | 'small' | 'medium' | 'large' | 'huge';
  priority: number; // 1-10
  detectedAt: number;
  codeSnippet: string;
  suggestions: string[];
  metrics: {
    complexity?: number;
    lineCount?: number;
    duplicateCount?: number;
    cohesion?: number;
    coupling?: number;
  };
}

export interface ComplexityMetrics {
  filePath: string;
  cyclomaticComplexity: number;
  cognitiveComplexity: number;
  maintainabilityIndex: number;
  linesOfCode: number;
  commentRatio: number;
  functionCount: number;
  classCount: number;
  duplicateLines: number;
  testCoverage?: number;
  dependencies: number;
  fanIn: number; // Number of classes that depend on this
  fanOut: number; // Number of classes this depends on
  instability: number; // fanOut / (fanIn + fanOut)
  abstractness: number; // abstract classes / total classes
  distance: number; // |abstractness + instability - 1|
}

export interface DebtItem {
  id: string;
  category: 'code_quality' | 'architecture' | 'documentation' | 'testing' | 'security' | 'performance';
  title: string;
  description: string;
  filePath?: string;
  location?: {
    lineStart?: number;
    lineEnd?: number;
  };
  severity: 'low' | 'medium' | 'high' | 'critical';
  estimatedEffort: number; // hours
  businessImpact: 'low' | 'medium' | 'high';
  technicalImpact: 'low' | 'medium' | 'high';
  priority: number; // calculated based on impacts and effort
  tags: string[];
  createdAt: number;
  resolvedAt?: number;
  resolution?: string;
  relatedItems: string[]; // IDs of related debt items
}

export interface DebtReport {
  summary: {
    totalDebt: number; // estimated hours
    totalItems: number;
    averagePriority: number;
    categories: Record<string, number>;
    severities: Record<string, number>;
    trend: 'improving' | 'stable' | 'worsening';
  };
  topPriorities: DebtItem[];
  quickWins: DebtItem[]; // high impact, low effort
  criticalIssues: DebtItem[];
  recommendations: string[];
  metrics: {
    codeQualityScore: number; // 0-100
    maintainabilityScore: number; // 0-100
    testabilityScore: number; // 0-100
    architecturalHealth: number; // 0-100
  };
}

export interface QualityTrend {
  date: number;
  metrics: ComplexityMetrics;
  debtCount: number;
  totalDebt: number;
  qualityScore: number;
}

export class TechnicalDebtTracker {
  private db: Database.Database;
  private codeSmells: Map<string, CodeSmell> = new Map();
  private debtItems: Map<string, DebtItem> = new Map();
  private qualityTrends: QualityTrend[] = [];

  constructor(private databasePath: string) {
    this.db = new Database(databasePath);
    this.initializeDatabase();
    this.loadExistingData();
  }

  private initializeDatabase(): void {
    // Code smells table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS code_smells (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_start INTEGER NOT NULL,
        line_end INTEGER NOT NULL,
        function_name TEXT,
        class_name TEXT,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        impact TEXT NOT NULL,
        effort_to_fix TEXT NOT NULL,
        priority INTEGER NOT NULL,
        detected_at INTEGER NOT NULL,
        code_snippet TEXT,
        suggestions TEXT, -- JSON array
        metrics TEXT -- JSON object
      )
    `);

    // Complexity metrics table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS complexity_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        cyclomatic_complexity INTEGER NOT NULL,
        cognitive_complexity INTEGER NOT NULL,
        maintainability_index REAL NOT NULL,
        lines_of_code INTEGER NOT NULL,
        comment_ratio REAL NOT NULL,
        function_count INTEGER NOT NULL,
        class_count INTEGER NOT NULL,
        duplicate_lines INTEGER NOT NULL,
        test_coverage REAL,
        dependencies INTEGER NOT NULL,
        fan_in INTEGER NOT NULL,
        fan_out INTEGER NOT NULL,
        instability REAL NOT NULL,
        abstractness REAL NOT NULL,
        distance REAL NOT NULL
      )
    `);

    // Technical debt items table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS debt_items (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        file_path TEXT,
        line_start INTEGER,
        line_end INTEGER,
        severity TEXT NOT NULL,
        estimated_effort REAL NOT NULL,
        business_impact TEXT NOT NULL,
        technical_impact TEXT NOT NULL,
        priority INTEGER NOT NULL,
        tags TEXT, -- JSON array
        created_at INTEGER NOT NULL,
        resolved_at INTEGER,
        resolution TEXT,
        related_items TEXT -- JSON array
      )
    `);

    // Quality trends table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS quality_trends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        debt_count INTEGER NOT NULL,
        total_debt REAL NOT NULL,
        quality_score REAL NOT NULL,
        metrics TEXT -- JSON object
      )
    `);

    // Indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_code_smells_file 
      ON code_smells(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_code_smells_type 
      ON code_smells(type);
      
      CREATE INDEX IF NOT EXISTS idx_code_smells_severity 
      ON code_smells(severity);
      
      CREATE INDEX IF NOT EXISTS idx_complexity_file_time 
      ON complexity_metrics(file_path, timestamp);
      
      CREATE INDEX IF NOT EXISTS idx_debt_category 
      ON debt_items(category);
      
      CREATE INDEX IF NOT EXISTS idx_debt_priority 
      ON debt_items(priority);
      
      CREATE INDEX IF NOT EXISTS idx_trends_time 
      ON quality_trends(timestamp);
    `);
  }

  private loadExistingData(): void {
    // Load code smells
    const smellStmt = this.db.prepare('SELECT * FROM code_smells ORDER BY priority DESC');
    const smells = smellStmt.all() as any[];
    
    for (const smell of smells) {
      this.codeSmells.set(smell.id, {
        id: smell.id,
        type: smell.type,
        filePath: smell.file_path,
        location: {
          lineStart: smell.line_start,
          lineEnd: smell.line_end,
          function: smell.function_name,
          class: smell.class_name
        },
        severity: smell.severity,
        description: smell.description,
        impact: smell.impact,
        effortToFix: smell.effort_to_fix,
        priority: smell.priority,
        detectedAt: smell.detected_at,
        codeSnippet: smell.code_snippet,
        suggestions: JSON.parse(smell.suggestions || '[]'),
        metrics: JSON.parse(smell.metrics || '{}')
      });
    }

    // Load debt items
    const debtStmt = this.db.prepare('SELECT * FROM debt_items ORDER BY priority DESC');
    const debts = debtStmt.all() as any[];
    
    for (const debt of debts) {
      this.debtItems.set(debt.id, {
        id: debt.id,
        category: debt.category,
        title: debt.title,
        description: debt.description,
        filePath: debt.file_path,
        location: debt.line_start ? {
          lineStart: debt.line_start,
          lineEnd: debt.line_end
        } : undefined,
        severity: debt.severity,
        estimatedEffort: debt.estimated_effort,
        businessImpact: debt.business_impact,
        technicalImpact: debt.technical_impact,
        priority: debt.priority,
        tags: JSON.parse(debt.tags || '[]'),
        createdAt: debt.created_at,
        resolvedAt: debt.resolved_at,
        resolution: debt.resolution,
        relatedItems: JSON.parse(debt.related_items || '[]')
      });
    }

    // Load quality trends
    const trendStmt = this.db.prepare(`
      SELECT * FROM quality_trends 
      ORDER BY timestamp DESC 
      LIMIT 100
    `);
    const trends = trendStmt.all() as any[];
    
    this.qualityTrends = trends.map(trend => ({
      date: trend.timestamp,
      metrics: JSON.parse(trend.metrics),
      debtCount: trend.debt_count,
      totalDebt: trend.total_debt,
      qualityScore: trend.quality_score
    }));

    logger.info(`Loaded ${smells.length} code smells, ${debts.length} debt items, ${trends.length} quality trends`);
  }

  async analyzeFile(filePath: string, symbols: ParsedSymbol[]): Promise<{
    smells: CodeSmell[];
    metrics: ComplexityMetrics;
    debtItems: DebtItem[];
  }> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Calculate complexity metrics
      const metrics = this.calculateComplexityMetrics(filePath, lines, symbols);

      // Detect code smells
      const smells = await this.detectCodeSmells(filePath, lines, symbols, metrics);

      // Identify debt items
      const debtItems = await this.identifyDebtItems(filePath, lines, symbols, metrics, smells);

      // Store results
      await this.storeComplexityMetrics(metrics);
      await this.storeCodeSmells(smells);
      await this.storeDebtItems(debtItems);

      return { smells, metrics, debtItems };
    } catch (error) {
      logger.error(`Error analyzing file ${filePath}:`, error);
      return { smells: [], metrics: this.getDefaultMetrics(filePath), debtItems: [] };
    }
  }

  private calculateComplexityMetrics(
    filePath: string, 
    lines: string[], 
    symbols: ParsedSymbol[]
  ): ComplexityMetrics {
    const functions = symbols.filter(s => s.kind === 'function');
    const classes = symbols.filter(s => s.kind === 'class');
    
    // Calculate cyclomatic complexity
    let totalCyclomatic = 0;
    for (const func of functions) {
      totalCyclomatic += this.calculateCyclomaticComplexity(func, lines);
    }

    // Calculate cognitive complexity
    const cognitiveComplexity = this.calculateCognitiveComplexity(lines);

    // Count lines of code (excluding comments and empty lines)
    const codeLines = lines.filter(line => {
      const trimmed = line.trim();
      return trimmed.length > 0 && 
             !trimmed.startsWith('//') && 
             !trimmed.startsWith('/*') && 
             !trimmed.startsWith('*') &&
             trimmed !== '*/';
    });

    // Calculate comment ratio
    const commentLines = lines.filter(line => {
      const trimmed = line.trim();
      return trimmed.startsWith('//') || 
             trimmed.startsWith('/*') || 
             trimmed.startsWith('*') ||
             trimmed === '*/';
    });
    const commentRatio = commentLines.length / Math.max(lines.length, 1);

    // Count duplicate lines (simple heuristic)
    const lineMap = new Map<string, number>();
    let duplicateLines = 0;
    for (const line of codeLines) {
      const normalized = line.trim();
      if (normalized.length > 10) { // Only count substantial lines
        const count = lineMap.get(normalized) || 0;
        lineMap.set(normalized, count + 1);
        if (count === 1) duplicateLines++;
      }
    }

    // Calculate dependencies (imports)
    const imports = symbols.filter(s => s.kind === 'import');
    
    // Simple fan-in/fan-out calculation
    const fanOut = imports.length;
    const fanIn = this.calculateFanIn(filePath); // Would need cross-file analysis
    
    const instability = fanOut / Math.max(fanIn + fanOut, 1);
    const abstractness = this.calculateAbstractness(classes);
    const distance = Math.abs(abstractness + instability - 1);

    // Calculate maintainability index
    const maintainabilityIndex = this.calculateMaintainabilityIndex(
      totalCyclomatic,
      codeLines.length,
      commentRatio
    );

    return {
      filePath,
      cyclomaticComplexity: totalCyclomatic,
      cognitiveComplexity,
      maintainabilityIndex,
      linesOfCode: codeLines.length,
      commentRatio,
      functionCount: functions.length,
      classCount: classes.length,
      duplicateLines,
      dependencies: imports.length,
      fanIn,
      fanOut,
      instability,
      abstractness,
      distance
    };
  }

  private async detectCodeSmells(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[],
    metrics: ComplexityMetrics
  ): Promise<CodeSmell[]> {
    const smells: CodeSmell[] = [];

    // Long method smell
    const longMethods = this.detectLongMethods(symbols, lines);
    smells.push(...longMethods);

    // Large class smell
    const largeClasses = this.detectLargeClasses(symbols, lines);
    smells.push(...largeClasses);

    // Duplicate code smell
    const duplicateCode = this.detectDuplicateCode(filePath, lines);
    smells.push(...duplicateCode);

    // Complex conditional smell
    const complexConditionals = this.detectComplexConditionals(filePath, lines);
    smells.push(...complexConditionals);

    // God class smell
    const godClasses = this.detectGodClasses(symbols, metrics);
    smells.push(...godClasses);

    // Dead code smell
    const deadCode = this.detectDeadCode(symbols);
    smells.push(...deadCode);

    // Feature envy smell
    const featureEnvy = this.detectFeatureEnvy(symbols);
    smells.push(...featureEnvy);

    // Data clumps smell
    const dataClumps = this.detectDataClumps(symbols);
    smells.push(...dataClumps);

    return smells;
  }

  private async identifyDebtItems(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[],
    metrics: ComplexityMetrics,
    smells: CodeSmell[]
  ): Promise<DebtItem[]> {
    const debtItems: DebtItem[] = [];

    // High complexity debt
    if (metrics.cyclomaticComplexity > 20) {
      debtItems.push({
        id: `complexity-${filePath}-${Date.now()}`,
        category: 'code_quality',
        title: 'High cyclomatic complexity',
        description: `File has cyclomatic complexity of ${metrics.cyclomaticComplexity}`,
        filePath,
        severity: metrics.cyclomaticComplexity > 50 ? 'critical' : 
                 metrics.cyclomaticComplexity > 30 ? 'high' : 'medium',
        estimatedEffort: Math.min(metrics.cyclomaticComplexity / 5, 40),
        businessImpact: 'medium',
        technicalImpact: 'high',
        priority: this.calculateDebtPriority('medium', 'high', Math.min(metrics.cyclomaticComplexity / 5, 40)),
        tags: ['complexity', 'maintainability'],
        createdAt: Date.now(),
        relatedItems: []
      });
    }

    // Low maintainability debt
    if (metrics.maintainabilityIndex < 50) {
      debtItems.push({
        id: `maintainability-${filePath}-${Date.now()}`,
        category: 'code_quality',
        title: 'Low maintainability index',
        description: `File has maintainability index of ${metrics.maintainabilityIndex.toFixed(1)}`,
        filePath,
        severity: metrics.maintainabilityIndex < 20 ? 'critical' : 
                 metrics.maintainabilityIndex < 35 ? 'high' : 'medium',
        estimatedEffort: 8,
        businessImpact: 'medium',
        technicalImpact: 'high',
        priority: this.calculateDebtPriority('medium', 'high', 8),
        tags: ['maintainability', 'quality'],
        createdAt: Date.now(),
        relatedItems: []
      });
    }

    // Poor test coverage debt (if available)
    if (metrics.testCoverage !== undefined && metrics.testCoverage < 60) {
      debtItems.push({
        id: `coverage-${filePath}-${Date.now()}`,
        category: 'testing',
        title: 'Low test coverage',
        description: `File has test coverage of ${metrics.testCoverage.toFixed(1)}%`,
        filePath,
        severity: metrics.testCoverage < 30 ? 'high' : 'medium',
        estimatedEffort: (100 - metrics.testCoverage) * 0.2,
        businessImpact: 'high',
        technicalImpact: 'medium',
        priority: this.calculateDebtPriority('high', 'medium', (100 - metrics.testCoverage) * 0.2),
        tags: ['testing', 'coverage'],
        createdAt: Date.now(),
        relatedItems: []
      });
    }

    // Documentation debt
    if (metrics.commentRatio < 0.1) {
      debtItems.push({
        id: `documentation-${filePath}-${Date.now()}`,
        category: 'documentation',
        title: 'Insufficient documentation',
        description: `File has comment ratio of ${(metrics.commentRatio * 100).toFixed(1)}%`,
        filePath,
        severity: 'medium',
        estimatedEffort: metrics.linesOfCode * 0.05,
        businessImpact: 'low',
        technicalImpact: 'medium',
        priority: this.calculateDebtPriority('low', 'medium', metrics.linesOfCode * 0.05),
        tags: ['documentation', 'maintainability'],
        createdAt: Date.now(),
        relatedItems: []
      });
    }

    // Architecture debt from high coupling
    if (metrics.instability > 0.8) {
      debtItems.push({
        id: `coupling-${filePath}-${Date.now()}`,
        category: 'architecture',
        title: 'High instability (coupling)',
        description: `File has instability metric of ${metrics.instability.toFixed(2)}`,
        filePath,
        severity: 'medium',
        estimatedEffort: 12,
        businessImpact: 'medium',
        technicalImpact: 'high',
        priority: this.calculateDebtPriority('medium', 'high', 12),
        tags: ['architecture', 'coupling'],
        createdAt: Date.now(),
        relatedItems: []
      });
    }

    // Convert critical code smells to debt items
    for (const smell of smells) {
      if (smell.severity === 'critical' || smell.severity === 'high') {
        debtItems.push({
          id: `smell-${smell.id}`,
          category: 'code_quality',
          title: `Code smell: ${smell.type.replace('_', ' ')}`,
          description: smell.description,
          filePath: smell.filePath,
          location: {
            lineStart: smell.location.lineStart,
            lineEnd: smell.location.lineEnd
          },
          severity: smell.severity,
          estimatedEffort: this.effortToHours(smell.effortToFix),
          businessImpact: 'medium',
          technicalImpact: smell.severity === 'critical' ? 'high' : 'medium',
          priority: smell.priority,
          tags: [smell.type, 'code_smell'],
          createdAt: Date.now(),
          relatedItems: []
        });
      }
    }

    return debtItems;
  }

  async generateDebtReport(): Promise<DebtReport> {
    const allDebtItems = Array.from(this.debtItems.values()).filter(item => !item.resolvedAt);
    
    const totalDebt = allDebtItems.reduce((sum, item) => sum + item.estimatedEffort, 0);
    const averagePriority = allDebtItems.reduce((sum, item) => sum + item.priority, 0) / allDebtItems.length;

    // Categorize debt
    const categories = allDebtItems.reduce((acc, item) => {
      acc[item.category] = (acc[item.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const severities = allDebtItems.reduce((acc, item) => {
      acc[item.severity] = (acc[item.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Get top priorities
    const topPriorities = allDebtItems
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 10);

    // Get quick wins (high impact, low effort)
    const quickWins = allDebtItems
      .filter(item => 
        (item.businessImpact === 'high' || item.technicalImpact === 'high') &&
        item.estimatedEffort <= 4
      )
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 5);

    // Get critical issues
    const criticalIssues = allDebtItems
      .filter(item => item.severity === 'critical')
      .sort((a, b) => b.priority - a.priority);

    // Calculate quality scores
    const codeQualityScore = this.calculateCodeQualityScore();
    const maintainabilityScore = this.calculateMaintainabilityScore();
    const testabilityScore = this.calculateTestabilityScore();
    const architecturalHealth = this.calculateArchitecturalHealth();

    // Determine trend
    const trend = this.calculateTrend();

    return {
      summary: {
        totalDebt,
        totalItems: allDebtItems.length,
        averagePriority,
        categories,
        severities,
        trend
      },
      topPriorities,
      quickWins,
      criticalIssues,
      recommendations: this.generateRecommendations(allDebtItems),
      metrics: {
        codeQualityScore,
        maintainabilityScore,
        testabilityScore,
        architecturalHealth
      }
    };
  }

  async recordQualityTrend(): Promise<void> {
    const allDebtItems = Array.from(this.debtItems.values()).filter(item => !item.resolvedAt);
    const totalDebt = allDebtItems.reduce((sum, item) => sum + item.estimatedEffort, 0);
    const qualityScore = this.calculateOverallQualityScore();

    const trend: QualityTrend = {
      date: Date.now(),
      metrics: this.getAverageMetrics(),
      debtCount: allDebtItems.length,
      totalDebt,
      qualityScore
    };

    this.qualityTrends.unshift(trend);
    if (this.qualityTrends.length > 100) {
      this.qualityTrends = this.qualityTrends.slice(0, 100);
    }

    // Store in database
    const stmt = this.db.prepare(`
      INSERT INTO quality_trends (timestamp, debt_count, total_debt, quality_score, metrics)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      trend.date,
      trend.debtCount,
      trend.totalDebt,
      trend.qualityScore,
      JSON.stringify(trend.metrics)
    );
  }

  async resolveDebtItem(id: string, resolution: string): Promise<void> {
    const item = this.debtItems.get(id);
    if (item) {
      item.resolvedAt = Date.now();
      item.resolution = resolution;

      const stmt = this.db.prepare(`
        UPDATE debt_items 
        SET resolved_at = ?, resolution = ?
        WHERE id = ?
      `);
      stmt.run(item.resolvedAt, resolution, id);
    }
  }

  getQualityTrends(days: number = 30): QualityTrend[] {
    const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
    return this.qualityTrends.filter(trend => trend.date >= cutoff);
  }

  // Private helper methods

  private detectLongMethods(symbols: ParsedSymbol[], lines: string[]): CodeSmell[] {
    const smells: CodeSmell[] = [];
    const functions = symbols.filter(s => s.kind === 'function');

    for (const func of functions) {
      const lineCount = func.lineEnd - func.lineStart + 1;
      
      if (lineCount > 30) {
        smells.push({
          id: `long-method-${func.name}-${func.lineStart}`,
          type: 'long_method',
          filePath: func.filePath,
          location: {
            lineStart: func.lineStart,
            lineEnd: func.lineEnd,
            function: func.name
          },
          severity: lineCount > 100 ? 'critical' : lineCount > 60 ? 'high' : 'medium',
          description: `Method ${func.name} has ${lineCount} lines`,
          impact: 'Reduces readability and maintainability',
          effortToFix: lineCount > 100 ? 'large' : lineCount > 60 ? 'medium' : 'small',
          priority: Math.min(Math.floor(lineCount / 10), 10),
          detectedAt: Date.now(),
          codeSnippet: lines.slice(func.lineStart - 1, Math.min(func.lineStart + 4, func.lineEnd)).join('\n') + '...',
          suggestions: [
            'Break down into smaller methods',
            'Extract helper functions',
            'Use the Extract Method refactoring'
          ],
          metrics: { lineCount }
        });
      }
    }

    return smells;
  }

  private detectLargeClasses(symbols: ParsedSymbol[], lines: string[]): CodeSmell[] {
    const smells: CodeSmell[] = [];
    const classes = symbols.filter(s => s.kind === 'class');

    for (const cls of classes) {
      const lineCount = cls.lineEnd - cls.lineStart + 1;
      const methods = symbols.filter(s => s.kind === 'method' && s.parentSymbolId === cls.id);
      
      if (lineCount > 200 || methods.length > 15) {
        smells.push({
          id: `large-class-${cls.name}-${cls.lineStart}`,
          type: 'large_class',
          filePath: cls.filePath,
          location: {
            lineStart: cls.lineStart,
            lineEnd: cls.lineEnd,
            class: cls.name
          },
          severity: lineCount > 500 || methods.length > 25 ? 'critical' : 'high',
          description: `Class ${cls.name} has ${lineCount} lines and ${methods.length} methods`,
          impact: 'Violates Single Responsibility Principle, hard to maintain',
          effortToFix: 'large',
          priority: Math.min(Math.floor((lineCount + methods.length * 10) / 50), 10),
          detectedAt: Date.now(),
          codeSnippet: lines.slice(cls.lineStart - 1, Math.min(cls.lineStart + 4, cls.lineEnd)).join('\n') + '...',
          suggestions: [
            'Extract classes for separate responsibilities',
            'Move methods to appropriate classes',
            'Apply the Single Responsibility Principle'
          ],
          metrics: { lineCount, complexity: methods.length }
        });
      }
    }

    return smells;
  }

  private detectDuplicateCode(filePath: string, lines: string[]): CodeSmell[] {
    const smells: CodeSmell[] = [];
    const blockSize = 6;
    const duplicates = new Map<string, number[]>();

    // Find duplicate blocks
    for (let i = 0; i <= lines.length - blockSize; i++) {
      const block = lines.slice(i, i + blockSize)
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith('//'))
        .join('\n');
      
      if (block.length > 100) { // Only consider substantial blocks
        const hash = this.hashCode(block);
        if (!duplicates.has(hash)) {
          duplicates.set(hash, []);
        }
        duplicates.get(hash)!.push(i);
      }
    }

    // Create smells for duplicates
    for (const [hash, positions] of duplicates) {
      if (positions.length > 1) {
        smells.push({
          id: `duplicate-${hash}-${positions[0]}`,
          type: 'duplicate_code',
          filePath,
          location: {
            lineStart: positions[0] + 1,
            lineEnd: positions[0] + blockSize
          },
          severity: positions.length > 3 ? 'high' : 'medium',
          description: `Duplicate code block found in ${positions.length} locations`,
          impact: 'Increases maintenance burden and bug risk',
          effortToFix: 'medium',
          priority: positions.length * 2,
          detectedAt: Date.now(),
          codeSnippet: lines.slice(positions[0], positions[0] + blockSize).join('\n'),
          suggestions: [
            'Extract common code into a function',
            'Use parameterization to handle variations',
            'Consider using inheritance or composition'
          ],
          metrics: { duplicateCount: positions.length }
        });
      }
    }

    return smells;
  }

  private detectComplexConditionals(filePath: string, lines: string[]): CodeSmell[] {
    const smells: CodeSmell[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      if (line.includes('if') || line.includes('while') || line.includes('for')) {
        const complexity = this.countLogicalOperators(line);
        
        if (complexity > 4) {
          smells.push({
            id: `complex-conditional-${i}-${Date.now()}`,
            type: 'complex_conditional',
            filePath,
            location: {
              lineStart: i + 1,
              lineEnd: i + 1
            },
            severity: complexity > 8 ? 'high' : 'medium',
            description: `Complex conditional with ${complexity} logical operators`,
            impact: 'Reduces readability and increases bug risk',
            effortToFix: 'small',
            priority: complexity,
            detectedAt: Date.now(),
            codeSnippet: line,
            suggestions: [
              'Break down into multiple conditions',
              'Extract to well-named methods',
              'Use guard clauses'
            ],
            metrics: { complexity }
          });
        }
      }
    }

    return smells;
  }

  private detectGodClasses(symbols: ParsedSymbol[], metrics: ComplexityMetrics): CodeSmell[] {
    const smells: CodeSmell[] = [];
    const classes = symbols.filter(s => s.kind === 'class');

    for (const cls of classes) {
      const methods = symbols.filter(s => s.kind === 'method' && s.parentSymbolId === cls.id);
      const lineCount = cls.lineEnd - cls.lineStart + 1;
      
      // God class heuristic: large class with many responsibilities
      if (methods.length > 20 && lineCount > 400) {
        smells.push({
          id: `god-class-${cls.name}`,
          type: 'god_class',
          filePath: cls.filePath,
          location: {
            lineStart: cls.lineStart,
            lineEnd: cls.lineEnd,
            class: cls.name
          },
          severity: 'critical',
          description: `God class ${cls.name} with ${methods.length} methods and ${lineCount} lines`,
          impact: 'Violates Single Responsibility, hard to test and maintain',
          effortToFix: 'huge',
          priority: 10,
          detectedAt: Date.now(),
          codeSnippet: `class ${cls.name} { /* ${methods.length} methods, ${lineCount} lines */ }`,
          suggestions: [
            'Break down into multiple focused classes',
            'Apply the Single Responsibility Principle',
            'Use composition over inheritance'
          ],
          metrics: { lineCount, complexity: methods.length }
        });
      }
    }

    return smells;
  }

  private detectDeadCode(symbols: ParsedSymbol[]): CodeSmell[] {
    const smells: CodeSmell[] = [];
    
    // Simple dead code detection - private methods not referenced
    const privateMethods = symbols.filter(s => 
      (s.kind === 'function' || s.kind === 'method') && 
      s.visibility === 'private'
    );
    
    const references = symbols.filter(s => s.kind === 'reference');
    
    for (const method of privateMethods) {
      const isReferenced = references.some(ref => ref.name === method.name);
      
      if (!isReferenced) {
        smells.push({
          id: `dead-code-${method.name}-${method.lineStart}`,
          type: 'dead_code',
          filePath: method.filePath,
          location: {
            lineStart: method.lineStart,
            lineEnd: method.lineEnd,
            function: method.name
          },
          severity: 'medium',
          description: `Unused private method ${method.name}`,
          impact: 'Clutters codebase and increases maintenance',
          effortToFix: 'trivial',
          priority: 2,
          detectedAt: Date.now(),
          codeSnippet: method.signature || method.name,
          suggestions: [
            'Remove unused method',
            'Verify it\'s truly unused with deeper analysis'
          ],
          metrics: {}
        });
      }
    }

    return smells;
  }

  private detectFeatureEnvy(symbols: ParsedSymbol[]): CodeSmell[] {
    // Simplified implementation - would need deeper analysis
    return [];
  }

  private detectDataClumps(symbols: ParsedSymbol[]): CodeSmell[] {
    // Simplified implementation - would need parameter analysis
    return [];
  }

  private calculateCyclomaticComplexity(func: ParsedSymbol, lines: string[]): number {
    let complexity = 1; // Base complexity
    
    const funcLines = lines.slice(func.lineStart - 1, func.lineEnd);
    const content = funcLines.join(' ');
    
    // Count decision points
    const decisions = (content.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
    complexity += decisions;
    
    return complexity;
  }

  private calculateCognitiveComplexity(lines: string[]): number {
    let complexity = 0;
    let nestingLevel = 0;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Increase nesting for blocks
      if (trimmed.includes('{')) nestingLevel++;
      if (trimmed.includes('}')) nestingLevel = Math.max(0, nestingLevel - 1);
      
      // Add complexity for control structures
      if (trimmed.includes('if') || trimmed.includes('while') || trimmed.includes('for')) {
        complexity += 1 + nestingLevel;
      }
      
      // Add complexity for logical operators
      const logicalOps = (trimmed.match(/&&|\|\|/g) || []).length;
      complexity += logicalOps;
    }
    
    return complexity;
  }

  private calculateMaintainabilityIndex(
    cyclomaticComplexity: number,
    linesOfCode: number,
    commentRatio: number
  ): number {
    // Simplified maintainability index calculation
    const volume = linesOfCode * Math.log2(Math.max(cyclomaticComplexity, 1));
    const commentWeight = commentRatio * 100;
    
    return Math.max(0, 171 - 5.2 * Math.log(volume) - 0.23 * cyclomaticComplexity - 16.2 * Math.log(linesOfCode) + commentWeight);
  }

  private calculateFanIn(filePath: string): number {
    // Would need cross-file analysis to implement properly
    return 1;
  }

  private calculateAbstractness(classes: ParsedSymbol[]): number {
    if (classes.length === 0) return 0;
    
    const abstractClasses = classes.filter(cls => 
      cls.signature?.includes('abstract') || cls.name.includes('Abstract')
    );
    
    return abstractClasses.length / classes.length;
  }

  private calculateDebtPriority(
    businessImpact: string,
    technicalImpact: string,
    effort: number
  ): number {
    const businessWeight = { low: 1, medium: 2, high: 3 };
    const technicalWeight = { low: 1, medium: 2, high: 3 };
    
    const impact = businessWeight[businessImpact as keyof typeof businessWeight] + 
                  technicalWeight[technicalImpact as keyof typeof technicalWeight];
    
    // Priority = impact / effort (with bounds)
    return Math.min(Math.max(Math.round(impact * 10 / Math.max(effort, 1)), 1), 10);
  }

  private effortToHours(effort: string): number {
    const mapping = {
      trivial: 0.5,
      small: 2,
      medium: 8,
      large: 24,
      huge: 80
    };
    return mapping[effort as keyof typeof mapping] || 8;
  }

  private calculateCodeQualityScore(): number {
    const smells = Array.from(this.codeSmells.values());
    if (smells.length === 0) return 100;
    
    const severityWeights = { low: 1, medium: 2, high: 4, critical: 8 };
    const totalWeight = smells.reduce((sum, smell) => 
      sum + severityWeights[smell.severity], 0);
    
    return Math.max(0, 100 - totalWeight);
  }

  private calculateMaintainabilityScore(): number {
    // Average maintainability index from recent metrics
    const stmt = this.db.prepare(`
      SELECT AVG(maintainability_index) as avg_maintainability 
      FROM complexity_metrics 
      WHERE timestamp > ?
    `);
    
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const result = stmt.get(oneWeekAgo) as any;
    
    return result?.avg_maintainability || 75;
  }

  private calculateTestabilityScore(): number {
    // Based on test coverage and testability smells
    const stmt = this.db.prepare(`
      SELECT AVG(test_coverage) as avg_coverage 
      FROM complexity_metrics 
      WHERE test_coverage IS NOT NULL AND timestamp > ?
    `);
    
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const result = stmt.get(oneWeekAgo) as any;
    
    return result?.avg_coverage || 60;
  }

  private calculateArchitecturalHealth(): number {
    // Based on coupling, cohesion, and architectural smells
    const stmt = this.db.prepare(`
      SELECT AVG(distance) as avg_distance 
      FROM complexity_metrics 
      WHERE timestamp > ?
    `);
    
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const result = stmt.get(oneWeekAgo) as any;
    
    const distance = result?.avg_distance || 0.5;
    return Math.max(0, 100 - (distance * 100));
  }

  private calculateTrend(): 'improving' | 'stable' | 'worsening' {
    if (this.qualityTrends.length < 2) return 'stable';
    
    const recent = this.qualityTrends.slice(0, 5);
    const older = this.qualityTrends.slice(5, 10);
    
    if (recent.length === 0 || older.length === 0) return 'stable';
    
    const recentAvg = recent.reduce((sum, t) => sum + t.qualityScore, 0) / recent.length;
    const olderAvg = older.reduce((sum, t) => sum + t.qualityScore, 0) / older.length;
    
    const diff = recentAvg - olderAvg;
    
    if (diff > 2) return 'improving';
    if (diff < -2) return 'worsening';
    return 'stable';
  }

  private calculateOverallQualityScore(): number {
    const codeQuality = this.calculateCodeQualityScore();
    const maintainability = this.calculateMaintainabilityScore();
    const testability = this.calculateTestabilityScore();
    const architecture = this.calculateArchitecturalHealth();
    
    return (codeQuality + maintainability + testability + architecture) / 4;
  }

  private getDefaultMetrics(filePath: string): ComplexityMetrics {
    return {
      filePath,
      cyclomaticComplexity: 0,
      cognitiveComplexity: 0,
      maintainabilityIndex: 100,
      linesOfCode: 0,
      commentRatio: 0,
      functionCount: 0,
      classCount: 0,
      duplicateLines: 0,
      dependencies: 0,
      fanIn: 0,
      fanOut: 0,
      instability: 0,
      abstractness: 0,
      distance: 0
    };
  }

  private getAverageMetrics(): ComplexityMetrics {
    const stmt = this.db.prepare(`
      SELECT 
        AVG(cyclomatic_complexity) as avg_cyclomatic,
        AVG(cognitive_complexity) as avg_cognitive,
        AVG(maintainability_index) as avg_maintainability,
        AVG(lines_of_code) as avg_loc,
        AVG(comment_ratio) as avg_comments,
        AVG(dependencies) as avg_deps,
        AVG(instability) as avg_instability,
        AVG(abstractness) as avg_abstractness,
        AVG(distance) as avg_distance
      FROM complexity_metrics 
      WHERE timestamp > ?
    `);
    
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const result = stmt.get(oneWeekAgo) as any;
    
    return {
      filePath: 'average',
      cyclomaticComplexity: result?.avg_cyclomatic || 0,
      cognitiveComplexity: result?.avg_cognitive || 0,
      maintainabilityIndex: result?.avg_maintainability || 100,
      linesOfCode: result?.avg_loc || 0,
      commentRatio: result?.avg_comments || 0,
      functionCount: 0,
      classCount: 0,
      duplicateLines: 0,
      dependencies: result?.avg_deps || 0,
      fanIn: 0,
      fanOut: 0,
      instability: result?.avg_instability || 0,
      abstractness: result?.avg_abstractness || 0,
      distance: result?.avg_distance || 0
    };
  }

  private generateRecommendations(debtItems: DebtItem[]): string[] {
    const recommendations: string[] = [];
    
    const categories = debtItems.reduce((acc, item) => {
      acc[item.category] = (acc[item.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    const topCategory = Object.entries(categories)
      .sort(([,a], [,b]) => b - a)[0];
    
    if (topCategory) {
      const [category, count] = topCategory;
      recommendations.push(`Focus on ${category} improvements - ${count} items need attention`);
    }
    
    const quickWins = debtItems.filter(item => item.estimatedEffort <= 4);
    if (quickWins.length > 0) {
      recommendations.push(`Address ${quickWins.length} quick wins first for immediate impact`);
    }
    
    const criticalItems = debtItems.filter(item => item.severity === 'critical');
    if (criticalItems.length > 0) {
      recommendations.push(`${criticalItems.length} critical issues require immediate attention`);
    }
    
    return recommendations;
  }

  private countLogicalOperators(line: string): number {
    return (line.match(/&&|\|\||!=/g) || []).length + 1;
  }

  private hashCode(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString();
  }

  private async storeComplexityMetrics(metrics: ComplexityMetrics): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO complexity_metrics (
        file_path, timestamp, cyclomatic_complexity, cognitive_complexity,
        maintainability_index, lines_of_code, comment_ratio, function_count,
        class_count, duplicate_lines, test_coverage, dependencies,
        fan_in, fan_out, instability, abstractness, distance
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      metrics.filePath,
      Date.now(),
      metrics.cyclomaticComplexity,
      metrics.cognitiveComplexity,
      metrics.maintainabilityIndex,
      metrics.linesOfCode,
      metrics.commentRatio,
      metrics.functionCount,
      metrics.classCount,
      metrics.duplicateLines,
      metrics.testCoverage,
      metrics.dependencies,
      metrics.fanIn,
      metrics.fanOut,
      metrics.instability,
      metrics.abstractness,
      metrics.distance
    );
  }

  private async storeCodeSmells(smells: CodeSmell[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO code_smells (
        id, type, file_path, line_start, line_end, function_name,
        class_name, severity, description, impact, effort_to_fix,
        priority, detected_at, code_snippet, suggestions, metrics
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const smell of smells) {
      this.codeSmells.set(smell.id, smell);
      
      stmt.run(
        smell.id,
        smell.type,
        smell.filePath,
        smell.location.lineStart,
        smell.location.lineEnd,
        smell.location.function,
        smell.location.class,
        smell.severity,
        smell.description,
        smell.impact,
        smell.effortToFix,
        smell.priority,
        smell.detectedAt,
        smell.codeSnippet,
        JSON.stringify(smell.suggestions),
        JSON.stringify(smell.metrics)
      );
    }
  }

  private async storeDebtItems(debtItems: DebtItem[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO debt_items (
        id, category, title, description, file_path, line_start,
        line_end, severity, estimated_effort, business_impact,
        technical_impact, priority, tags, created_at, related_items
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const item of debtItems) {
      this.debtItems.set(item.id, item);
      
      stmt.run(
        item.id,
        item.category,
        item.title,
        item.description,
        item.filePath,
        item.location?.lineStart,
        item.location?.lineEnd,
        item.severity,
        item.estimatedEffort,
        item.businessImpact,
        item.technicalImpact,
        item.priority,
        JSON.stringify(item.tags),
        item.createdAt,
        JSON.stringify(item.relatedItems)
      );
    }
  }
}