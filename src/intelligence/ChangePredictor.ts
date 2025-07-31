import { ParsedSymbol } from '../parser/ASTParser';
import { PatternRegistry, Pattern } from '../patterns/PatternRegistry';
import { logger } from '../utils/logger';
import Database from 'better-sqlite3';
import * as fs from 'fs';

export interface ChangeHistory {
  id?: number;
  filePath: string;
  timestamp: number;
  changeType: 'create' | 'modify' | 'delete' | 'rename';
  linesAdded: number;
  linesRemoved: number;
  changeDescription: string;
  affectedSymbols: string[];
  patterns: string[];
  author?: string;
  commit?: string;
  metadata?: any;
}

export interface ChangePrediction {
  id: string;
  filePath: string;
  probability: number; // 0-1
  predictedChangeType: 'refactor' | 'feature' | 'bugfix' | 'optimization' | 'security';
  description: string;
  suggestedChanges: SuggestedChange[];
  reasoning: string[];
  confidence: number;
  timeframe: 'immediate' | 'short' | 'medium' | 'long'; // within hours, days, weeks, months
  priority: 'critical' | 'high' | 'medium' | 'low';
  relatedFiles: string[];
  patterns: string[];
}

export interface SuggestedChange {
  description: string;
  type: 'add' | 'modify' | 'remove' | 'extract' | 'merge';
  location: {
    line?: number;
    function?: string;
    class?: string;
  };
  impact: 'low' | 'medium' | 'high';
  effort: 'trivial' | 'small' | 'medium' | 'large';
  benefits: string[];
  risks: string[];
  codeExample?: string;
}

export interface RefactoringOpportunity {
  id: string;
  type: 'extract_function' | 'extract_class' | 'inline_method' | 'move_method' | 
        'rename_symbol' | 'simplify_conditional' | 'remove_duplication' | 'decompose_complex';
  filePath: string;
  location: {
    lineStart: number;
    lineEnd: number;
    column?: number;
  };
  description: string;
  benefits: string[];
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
  priority: number; // 1-10
  codeSnippet: string;
  suggestedRefactoring: string;
  preservesSemantics: boolean;
  breakingChange: boolean;
  testingRequired: boolean;
}

export interface CodeImprovement {
  id: string;
  category: 'performance' | 'readability' | 'maintainability' | 'security' | 'testability';
  description: string;
  filePath: string;
  lineNumber: number;
  severity: 'info' | 'warning' | 'error';
  currentCode: string;
  improvedCode: string;
  justification: string;
  benefits: string[];
  prerequisites: string[];
}

export interface HistoricalPattern {
  pattern: string;
  frequency: number;
  contexts: string[];
  outcomes: 'positive' | 'neutral' | 'negative';
  timeSpan: number; // days
  confidence: number;
}

export class ChangePredictor {
  private db: Database.Database;
  private changeHistory: ChangeHistory[] = [];
  private patterns: Map<string, HistoricalPattern> = new Map();
  private learningThreshold = 10; // Minimum changes to learn from

  constructor(
    private databasePath: string,
    private patternRegistry: PatternRegistry
  ) {
    this.db = new Database(databasePath);
    this.initializeDatabase();
    this.loadChangeHistory();
    this.analyzeHistoricalPatterns();
  }

  private initializeDatabase(): void {
    // Create change history table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS change_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        change_type TEXT NOT NULL,
        lines_added INTEGER DEFAULT 0,
        lines_removed INTEGER DEFAULT 0,
        change_description TEXT,
        affected_symbols TEXT, -- JSON array
        patterns TEXT, -- JSON array
        author TEXT,
        commit TEXT,
        metadata TEXT -- JSON
      )
    `);

    // Create predictions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS change_predictions (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        probability REAL NOT NULL,
        predicted_change_type TEXT NOT NULL,
        description TEXT NOT NULL,
        reasoning TEXT, -- JSON array
        confidence REAL NOT NULL,
        timeframe TEXT NOT NULL,
        priority TEXT NOT NULL,
        related_files TEXT, -- JSON array
        patterns TEXT, -- JSON array
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        validated BOOLEAN DEFAULT FALSE,
        outcome TEXT -- 'correct', 'incorrect', 'partially_correct', 'unknown'
      )
    `);

    // Create refactoring opportunities table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS refactoring_opportunities (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_start INTEGER NOT NULL,
        line_end INTEGER NOT NULL,
        description TEXT NOT NULL,
        benefits TEXT, -- JSON array
        effort TEXT NOT NULL,
        impact TEXT NOT NULL,
        priority INTEGER NOT NULL,
        code_snippet TEXT,
        suggested_refactoring TEXT,
        preserves_semantics BOOLEAN DEFAULT TRUE,
        breaking_change BOOLEAN DEFAULT FALSE,
        testing_required BOOLEAN DEFAULT TRUE,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        applied BOOLEAN DEFAULT FALSE
      )
    `);

    // Indexes for performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_change_history_file_time 
      ON change_history(file_path, timestamp);
      
      CREATE INDEX IF NOT EXISTS idx_change_history_type 
      ON change_history(change_type);
      
      CREATE INDEX IF NOT EXISTS idx_predictions_file 
      ON change_predictions(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_refactoring_file 
      ON refactoring_opportunities(file_path);
    `);
  }

  private loadChangeHistory(): void {
    const stmt = this.db.prepare(`
      SELECT * FROM change_history 
      ORDER BY timestamp DESC 
      LIMIT 1000
    `);
    
    const rows = stmt.all() as any[];
    this.changeHistory = rows.map(row => ({
      id: row.id,
      filePath: row.file_path,
      timestamp: row.timestamp,
      changeType: row.change_type,
      linesAdded: row.lines_added,
      linesRemoved: row.lines_removed,
      changeDescription: row.change_description,
      affectedSymbols: JSON.parse(row.affected_symbols || '[]'),
      patterns: JSON.parse(row.patterns || '[]'),
      author: row.author,
      commit: row.commit,
      metadata: JSON.parse(row.metadata || '{}')
    }));

    logger.info(`Loaded ${this.changeHistory.length} change history records`);
  }

  private analyzeHistoricalPatterns(): void {
    if (this.changeHistory.length < this.learningThreshold) {
      logger.info('Insufficient history for pattern analysis');
      return;
    }

    const patternMap = new Map<string, { count: number; contexts: Set<string>; outcomes: string[] }>();

    // Analyze patterns in historical changes
    for (const change of this.changeHistory) {
      for (const pattern of change.patterns) {
        if (!patternMap.has(pattern)) {
          patternMap.set(pattern, { count: 0, contexts: new Set(), outcomes: [] });
        }
        
        const data = patternMap.get(pattern)!;
        data.count++;
        data.contexts.add(change.changeType);
        
        // Simple heuristic for outcome assessment
        const outcome = this.assessChangeOutcome(change);
        data.outcomes.push(outcome);
      }
    }

    // Convert to historical patterns
    for (const [pattern, data] of patternMap) {
      const frequency = data.count / this.changeHistory.length;
      const positiveOutcomes = data.outcomes.filter(o => o === 'positive').length;
      const neutralOutcomes = data.outcomes.filter(o => o === 'neutral').length;
      const negativeOutcomes = data.outcomes.filter(o => o === 'negative').length;
      
      let overallOutcome: 'positive' | 'neutral' | 'negative' = 'neutral';
      if (positiveOutcomes > negativeOutcomes && positiveOutcomes > neutralOutcomes) {
        overallOutcome = 'positive';
      } else if (negativeOutcomes > positiveOutcomes) {
        overallOutcome = 'negative';
      }

      this.patterns.set(pattern, {
        pattern,
        frequency,
        contexts: Array.from(data.contexts),
        outcomes: overallOutcome,
        timeSpan: this.calculateTimeSpan(pattern),
        confidence: Math.min(data.count / 10, 1.0)
      });
    }

    logger.info(`Analyzed ${this.patterns.size} historical patterns`);
  }

  async recordChange(change: Omit<ChangeHistory, 'id'>): Promise<number> {
    const stmt = this.db.prepare(`
      INSERT INTO change_history (
        file_path, timestamp, change_type, lines_added, lines_removed,
        change_description, affected_symbols, patterns, author, commit, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      change.filePath,
      change.timestamp,
      change.changeType,
      change.linesAdded,
      change.linesRemoved,
      change.changeDescription,
      JSON.stringify(change.affectedSymbols),
      JSON.stringify(change.patterns),
      change.author,
      change.commit,
      JSON.stringify(change.metadata || {})
    );

    // Add to in-memory history
    this.changeHistory.unshift({ ...change, id: result.lastInsertRowid as number });
    
    // Keep only recent history in memory
    if (this.changeHistory.length > 1000) {
      this.changeHistory = this.changeHistory.slice(0, 500);
    }

    // Re-analyze patterns if we have enough data
    if (this.changeHistory.length > this.learningThreshold && 
        this.changeHistory.length % 10 === 0) {
      this.analyzeHistoricalPatterns();
    }

    return result.lastInsertRowid as number;
  }

  async predictChanges(filePath: string, symbols: ParsedSymbol[]): Promise<ChangePrediction[]> {
    const predictions: ChangePrediction[] = [];

    try {
      // Get file history
      const fileHistory = this.getFileHistory(filePath);
      
      // Analyze patterns in current file
      const currentPatterns = await this.identifyCurrentPatterns(filePath, symbols);
      
      // Predict based on historical patterns
      const historicalPredictions = this.predictFromHistory(filePath, fileHistory, currentPatterns);
      predictions.push(...historicalPredictions);

      // Predict based on code complexity
      const complexityPredictions = this.predictFromComplexity(filePath, symbols);
      predictions.push(...complexityPredictions);

      // Predict based on change frequency
      const frequencyPredictions = this.predictFromFrequency(filePath, fileHistory);
      predictions.push(...frequencyPredictions);

      // Predict based on code age and staleness
      const stalnessPredictions = this.predictFromStaleness(filePath, fileHistory);
      predictions.push(...stalnessPredictions);

      // Store predictions
      await this.storePredictions(predictions);

      return predictions.sort((a, b) => b.probability - a.probability);
    } catch (error) {
      logger.error('Error predicting changes:', error);
      return [];
    }
  }

  async identifyRefactoringOpportunities(
    filePath: string, 
    symbols: ParsedSymbol[]
  ): Promise<RefactoringOpportunity[]> {
    const opportunities: RefactoringOpportunity[] = [];

    try {
      // Read file content
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Detect long functions
      const longFunctions = this.detectLongFunctions(symbols, lines);
      opportunities.push(...longFunctions);

      // Detect duplicated code
      const duplications = this.detectDuplicatedCode(filePath, lines);
      opportunities.push(...duplications);

      // Detect complex conditionals
      const complexConditionals = this.detectComplexConditionals(filePath, lines);
      opportunities.push(...complexConditionals);

      // Detect large classes
      const largeClasses = this.detectLargeClasses(symbols, lines);
      opportunities.push(...largeClasses);

      // Detect feature envy (methods using external data more than own)
      const featureEnvy = this.detectFeatureEnvy(symbols);
      opportunities.push(...featureEnvy);

      // Detect dead code
      const deadCode = this.detectDeadCode(symbols);
      opportunities.push(...deadCode);

      // Store opportunities
      await this.storeRefactoringOpportunities(opportunities);

      return opportunities.sort((a, b) => b.priority - a.priority);
    } catch (error) {
      logger.error('Error identifying refactoring opportunities:', error);
      return [];
    }
  }

  async suggestImprovements(
    filePath: string, 
    symbols: ParsedSymbol[]
  ): Promise<CodeImprovement[]> {
    const improvements: CodeImprovement[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Performance improvements
      improvements.push(...this.suggestPerformanceImprovements(filePath, lines, symbols));

      // Readability improvements
      improvements.push(...this.suggestReadabilityImprovements(filePath, lines, symbols));

      // Security improvements
      improvements.push(...this.suggestSecurityImprovements(filePath, lines, symbols));

      // Maintainability improvements
      improvements.push(...this.suggestMaintainabilityImprovements(filePath, lines, symbols));

      // Testability improvements
      improvements.push(...this.suggestTestabilityImprovements(filePath, lines, symbols));

      return improvements.sort((a, b) => {
        const severityOrder = { error: 3, warning: 2, info: 1 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      });
    } catch (error) {
      logger.error('Error suggesting improvements:', error);
      return [];
    }
  }

  async learnFromOutcome(predictionId: string, outcome: 'correct' | 'incorrect' | 'partially_correct'): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE change_predictions 
      SET validated = TRUE, outcome = ?
      WHERE id = ?
    `);
    
    stmt.run(outcome, predictionId);

    // Use this feedback to improve future predictions
    await this.adjustPredictionModels(predictionId, outcome);
  }

  // Private helper methods

  private getFileHistory(filePath: string): ChangeHistory[] {
    return this.changeHistory.filter(change => change.filePath === filePath);
  }

  private async identifyCurrentPatterns(filePath: string, symbols: ParsedSymbol[]): Promise<string[]> {
    try {
      const patterns = await this.patternRegistry.getPatternsByFile(filePath);
      return patterns.map(p => p.name);
    } catch (error) {
      logger.debug('Error identifying current patterns:', error);
      return [];
    }
  }

  private predictFromHistory(
    filePath: string, 
    history: ChangeHistory[], 
    patterns: string[]
  ): ChangePrediction[] {
    const predictions: ChangePrediction[] = [];

    if (history.length === 0) return predictions;

    // Analyze change frequency
    const now = Date.now();
    const recentChanges = history.filter(h => now - h.timestamp < 30 * 24 * 60 * 60 * 1000); // 30 days
    
    if (recentChanges.length > 5) {
      predictions.push({
        id: `freq-${filePath}-${Date.now()}`,
        filePath,
        probability: Math.min(recentChanges.length / 10, 0.9),
        predictedChangeType: 'refactor',
        description: 'File shows high change frequency, likely needs refactoring',
        suggestedChanges: [{
          description: 'Consider breaking down this file into smaller modules',
          type: 'extract',
          location: {},
          impact: 'medium',
          effort: 'medium',
          benefits: ['Improved maintainability', 'Reduced change frequency'],
          risks: ['Initial complexity increase']
        }],
        reasoning: [
          `File has ${recentChanges.length} changes in the last 30 days`,
          'High change frequency indicates complexity or instability'
        ],
        confidence: 0.7,
        timeframe: 'short',
        priority: 'medium',
        relatedFiles: [],
        patterns
      });
    }

    return predictions;
  }

  private predictFromComplexity(filePath: string, symbols: ParsedSymbol[]): ChangePrediction[] {
    const predictions: ChangePrediction[] = [];

    // Calculate complexity metrics
    const functions = symbols.filter(s => s.kind === 'function');
    const complexFunctions = functions.filter(f => this.calculateCyclomaticComplexity(f) > 10);

    if (complexFunctions.length > 0) {
      predictions.push({
        id: `complexity-${filePath}-${Date.now()}`,
        filePath,
        probability: Math.min(complexFunctions.length / functions.length, 0.8),
        predictedChangeType: 'refactor',
        description: 'File contains complex functions that need simplification',
        suggestedChanges: complexFunctions.map(f => ({
          description: `Simplify function ${f.name}`,
          type: 'modify',
          location: { function: f.name, line: f.lineStart },
          impact: 'medium',
          effort: 'medium',
          benefits: ['Improved readability', 'Easier testing', 'Reduced bugs'],
          risks: ['Potential behavior changes']
        })),
        reasoning: [
          `${complexFunctions.length} functions exceed complexity threshold`,
          'Complex functions are harder to maintain and test'
        ],
        confidence: 0.8,
        timeframe: 'medium',
        priority: 'high',
        relatedFiles: [],
        patterns: []
      });
    }

    return predictions;
  }

  private predictFromFrequency(filePath: string, history: ChangeHistory[]): ChangePrediction[] {
    const predictions: ChangePrediction[] = [];

    if (history.length < 3) return predictions;

    // Analyze change patterns
    const intervals = [];
    for (let i = 1; i < history.length; i++) {
      intervals.push(history[i-1].timestamp - history[i].timestamp);
    }

    const averageInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const lastChange = history[0].timestamp;
    const timeSinceLastChange = Date.now() - lastChange;

    if (timeSinceLastChange > averageInterval * 1.5) {
      const probability = Math.min(timeSinceLastChange / (averageInterval * 2), 0.7);
      
      predictions.push({
        id: `schedule-${filePath}-${Date.now()}`,
        filePath,
        probability,
        predictedChangeType: 'feature',
        description: 'File is due for changes based on historical pattern',
        suggestedChanges: [{
          description: 'Review file for potential updates or improvements',
          type: 'modify',
          location: {},
          impact: 'low',
          effort: 'small',
          benefits: ['Stay ahead of technical debt'],
          risks: ['Unnecessary changes']
        }],
        reasoning: [
          `Average change interval: ${Math.round(averageInterval / (24 * 60 * 60 * 1000))} days`,
          `Time since last change: ${Math.round(timeSinceLastChange / (24 * 60 * 60 * 1000))} days`
        ],
        confidence: 0.6,
        timeframe: 'short',
        priority: 'low',
        relatedFiles: [],
        patterns: []
      });
    }

    return predictions;
  }

  private predictFromStaleness(filePath: string, history: ChangeHistory[]): ChangePrediction[] {
    const predictions: ChangePrediction[] = [];

    if (history.length === 0) return predictions;

    const lastChange = history[0].timestamp;
    const daysSinceChange = (Date.now() - lastChange) / (24 * 60 * 60 * 1000);

    // If file hasn't been changed in 6+ months, it might need review
    if (daysSinceChange > 180) {
      predictions.push({
        id: `stale-${filePath}-${Date.now()}`,
        filePath,
        probability: Math.min(daysSinceChange / 365, 0.6),
        predictedChangeType: 'optimization',
        description: 'File may be stale and need modernization',
        suggestedChanges: [{
          description: 'Review for outdated patterns and dependencies',
          type: 'modify',
          location: {},
          impact: 'low',
          effort: 'small',
          benefits: ['Modern best practices', 'Updated dependencies'],
          risks: ['Introducing bugs in stable code']
        }],
        reasoning: [
          `File hasn't been modified in ${Math.round(daysSinceChange)} days`,
          'Long-unchanged files may use outdated patterns'
        ],
        confidence: 0.4,
        timeframe: 'long',
        priority: 'low',
        relatedFiles: [],
        patterns: []
      });
    }

    return predictions;
  }

  private detectLongFunctions(symbols: ParsedSymbol[], lines: string[]): RefactoringOpportunity[] {
    const opportunities: RefactoringOpportunity[] = [];

    const functions = symbols.filter(s => s.kind === 'function');
    
    for (const func of functions) {
      const lineCount = func.lineEnd - func.lineStart + 1;
      
      if (lineCount > 50) { // Functions longer than 50 lines
        opportunities.push({
          id: `long-function-${func.name}-${Date.now()}`,
          type: 'extract_function',
          filePath: func.filePath,
          location: {
            lineStart: func.lineStart,
            lineEnd: func.lineEnd
          },
          description: `Function ${func.name} is ${lineCount} lines long and should be broken down`,
          benefits: [
            'Improved readability',
            'Easier testing',
            'Better separation of concerns',
            'Reduced complexity'
          ],
          effort: lineCount > 100 ? 'high' : 'medium',
          impact: 'medium',
          priority: Math.min(Math.floor(lineCount / 10), 10),
          codeSnippet: lines.slice(func.lineStart - 1, func.lineEnd).join('\n'),
          suggestedRefactoring: `Break down ${func.name} into smaller, focused functions`,
          preservesSemantics: true,
          breakingChange: false,
          testingRequired: true
        });
      }
    }

    return opportunities;
  }

  private detectDuplicatedCode(filePath: string, lines: string[]): RefactoringOpportunity[] {
    const opportunities: RefactoringOpportunity[] = [];

    // Simple duplication detection - look for identical consecutive blocks
    const blockSize = 5;
    const duplicates = new Map<string, number[]>();

    for (let i = 0; i <= lines.length - blockSize; i++) {
      const block = lines.slice(i, i + blockSize)
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith('//'))
        .join('\n');
      
      if (block.length > 50) { // Only consider substantial blocks
        if (!duplicates.has(block)) {
          duplicates.set(block, []);
        }
        duplicates.get(block)!.push(i);
      }
    }

    for (const [block, positions] of duplicates) {
      if (positions.length > 1) {
        opportunities.push({
          id: `duplicate-${positions[0]}-${Date.now()}`,
          type: 'extract_function',
          filePath,
          location: {
            lineStart: positions[0] + 1,
            lineEnd: positions[0] + blockSize
          },
          description: `Duplicated code block found in ${positions.length} locations`,
          benefits: [
            'Eliminate code duplication',
            'Single point of maintenance',
            'Improved consistency'
          ],
          effort: 'medium',
          impact: 'medium',
          priority: positions.length * 2,
          codeSnippet: block,
          suggestedRefactoring: 'Extract common code into a reusable function',
          preservesSemantics: true,
          breakingChange: false,
          testingRequired: true
        });
      }
    }

    return opportunities;
  }

  private detectComplexConditionals(filePath: string, lines: string[]): RefactoringOpportunity[] {
    const opportunities: RefactoringOpportunity[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Look for complex if statements
      if (line.startsWith('if') || line.includes(' if ')) {
        const complexity = this.measureConditionalComplexity(line);
        
        if (complexity > 3) {
          opportunities.push({
            id: `complex-conditional-${i}-${Date.now()}`,
            type: 'simplify_conditional',
            filePath,
            location: {
              lineStart: i + 1,
              lineEnd: i + 1
            },
            description: `Complex conditional with ${complexity} logical operators`,
            benefits: [
              'Improved readability',
              'Easier debugging',
              'Better testability'
            ],
            effort: 'low',
            impact: 'low',
            priority: complexity,
            codeSnippet: line,
            suggestedRefactoring: 'Break down into multiple conditions or extract to well-named functions',
            preservesSemantics: true,
            breakingChange: false,
            testingRequired: true
          });
        }
      }
    }

    return opportunities;
  }

  private detectLargeClasses(symbols: ParsedSymbol[], lines: string[]): RefactoringOpportunity[] {
    const opportunities: RefactoringOpportunity[] = [];

    const classes = symbols.filter(s => s.kind === 'class');
    
    for (const cls of classes) {
      const lineCount = cls.lineEnd - cls.lineStart + 1;
      const methods = symbols.filter(s => 
        s.kind === 'method' && 
        s.parentSymbolId === Number(cls.id)
      ).length;

      if (lineCount > 200 || methods > 20) {
        opportunities.push({
          id: `large-class-${cls.name}-${Date.now()}`,
          type: 'extract_class',
          filePath: cls.filePath,
          location: {
            lineStart: cls.lineStart,
            lineEnd: cls.lineEnd
          },
          description: `Class ${cls.name} has ${lineCount} lines and ${methods} methods`,
          benefits: [
            'Better separation of concerns',
            'Improved maintainability',
            'Easier testing',
            'Reduced complexity'
          ],
          effort: 'high',
          impact: 'high',
          priority: Math.min(Math.floor((lineCount + methods * 10) / 50), 10),
          codeSnippet: lines.slice(cls.lineStart - 1, Math.min(cls.lineStart + 9, cls.lineEnd)).join('\n') + '...',
          suggestedRefactoring: `Break down ${cls.name} into smaller, focused classes`,
          preservesSemantics: true,
          breakingChange: true,
          testingRequired: true
        });
      }
    }

    return opportunities;
  }

  private detectFeatureEnvy(symbols: ParsedSymbol[]): RefactoringOpportunity[] {
    // Simplified feature envy detection
    // In a real implementation, this would analyze method dependencies
    return [];
  }

  private detectDeadCode(symbols: ParsedSymbol[]): RefactoringOpportunity[] {
    const opportunities: RefactoringOpportunity[] = [];

    // Look for private methods/functions that are never called
    const privateMethods = symbols.filter(s => 
      (s.kind === 'function' || s.kind === 'method') && 
      s.visibility === 'private'
    );

    const allReferences = symbols.filter(s => s.kind === 'reference');

    for (const method of privateMethods) {
      const isReferenced = allReferences.some(ref => ref.name === method.name);
      
      if (!isReferenced) {
        opportunities.push({
          id: `dead-code-${method.name}-${Date.now()}`,
          type: 'move_method',
          filePath: method.filePath,
          location: {
            lineStart: method.lineStart,
            lineEnd: method.lineEnd
          },
          description: `Private method ${method.name} appears to be unused`,
          benefits: [
            'Reduced code complexity',
            'Improved maintainability',
            'Smaller bundle size'
          ],
          effort: 'low',
          impact: 'low',
          priority: 3,
          codeSnippet: `${method.signature || method.name}`,
          suggestedRefactoring: 'Consider removing unused method after thorough verification',
          preservesSemantics: true,
          breakingChange: false,
          testingRequired: true
        });
      }
    }

    return opportunities;
  }

  private suggestPerformanceImprovements(
    filePath: string, 
    lines: string[], 
    symbols: ParsedSymbol[]
  ): CodeImprovement[] {
    const improvements: CodeImprovement[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Suggest useMemo for expensive computations
      if (line.includes('expensive') && !line.includes('useMemo')) {
        improvements.push({
          id: `perf-memo-${i}-${Date.now()}`,
          category: 'performance',
          description: 'Consider using useMemo for expensive computations',
          filePath,
          lineNumber: i + 1,
          severity: 'info',
          currentCode: line.trim(),
          improvedCode: 'const result = useMemo(() => expensiveComputation(), [dependencies])',
          justification: 'Memoization prevents unnecessary recalculations',
          benefits: ['Improved performance', 'Reduced CPU usage'],
          prerequisites: ['React hooks available']
        });
      }

      // Suggest useCallback for event handlers
      if (line.includes('onClick') && !line.includes('useCallback')) {
        improvements.push({
          id: `perf-callback-${i}-${Date.now()}`,
          category: 'performance',
          description: 'Consider using useCallback for event handlers',
          filePath,
          lineNumber: i + 1,
          severity: 'info',
          currentCode: line.trim(),
          improvedCode: 'const handleClick = useCallback(() => { /* handler */ }, [dependencies])',
          justification: 'Prevents unnecessary re-renders of child components',
          benefits: ['Reduced re-renders', 'Better performance'],
          prerequisites: ['React hooks available']
        });
      }
    }

    return improvements;
  }

  private suggestReadabilityImprovements(
    filePath: string, 
    lines: string[], 
    symbols: ParsedSymbol[]
  ): CodeImprovement[] {
    const improvements: CodeImprovement[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Suggest meaningful variable names
      if (/\b[a-z]\b/.test(line) && line.includes('=')) {
        improvements.push({
          id: `read-naming-${i}-${Date.now()}`,
          category: 'readability',
          description: 'Consider using more descriptive variable names',
          filePath,
          lineNumber: i + 1,
          severity: 'info',
          currentCode: line.trim(),
          improvedCode: line.replace(/\b[a-z]\b/, 'meaningfulName'),
          justification: 'Descriptive names improve code readability',
          benefits: ['Better code understanding', 'Easier maintenance'],
          prerequisites: []
        });
      }

      // Suggest extracting magic numbers
      if (/\b\d{2,}\b/.test(line) && !line.includes('const')) {
        const match = line.match(/\b(\d{2,})\b/);
        if (match) {
          improvements.push({
            id: `read-magic-${i}-${Date.now()}`,
            category: 'readability',
            description: 'Consider extracting magic number to named constant',
            filePath,
            lineNumber: i + 1,
            severity: 'warning',
            currentCode: line.trim(),
            improvedCode: `const MEANINGFUL_CONSTANT = ${match[1]};\n${line.replace(match[1], 'MEANINGFUL_CONSTANT')}`,
            justification: 'Named constants are more maintainable than magic numbers',
            benefits: ['Better maintainability', 'Self-documenting code'],
            prerequisites: []
          });
        }
      }
    }

    return improvements;
  }

  private suggestSecurityImprovements(
    filePath: string, 
    lines: string[], 
    symbols: ParsedSymbol[]
  ): CodeImprovement[] {
    const improvements: CodeImprovement[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Suggest input validation
      if (line.includes('req.body') && !line.includes('validate')) {
        improvements.push({
          id: `sec-validation-${i}-${Date.now()}`,
          category: 'security',
          description: 'Add input validation for request body',
          filePath,
          lineNumber: i + 1,
          severity: 'warning',
          currentCode: line.trim(),
          improvedCode: 'const validatedBody = validateInput(req.body)',
          justification: 'Input validation prevents injection attacks',
          benefits: ['Improved security', 'Data integrity'],
          prerequisites: ['Validation library available']
        });
      }

      // Suggest authentication checks
      if (filePath.includes('/api/') && line.includes('export async function') && 
          !lines.slice(i, i + 5).some(l => l.includes('requireAuth'))) {
        improvements.push({
          id: `sec-auth-${i}-${Date.now()}`,
          category: 'security',
          description: 'Add authentication check to API endpoint',
          filePath,
          lineNumber: i + 2,
          severity: 'error',
          currentCode: line.trim(),
          improvedCode: 'const { user } = await requireAuthWithTenant()',
          justification: 'API endpoints should verify authentication',
          benefits: ['Improved security', 'Access control'],
          prerequisites: ['Authentication system available']
        });
      }
    }

    return improvements;
  }

  private suggestMaintainabilityImprovements(
    filePath: string, 
    lines: string[], 
    symbols: ParsedSymbol[]
  ): CodeImprovement[] {
    const improvements: CodeImprovement[] = [];

    // Look for functions without documentation
    const functions = symbols.filter(s => s.kind === 'function');
    
    for (const func of functions) {
      if (!func.docComment || func.docComment.trim() === '') {
        improvements.push({
          id: `maint-doc-${func.name}-${Date.now()}`,
          category: 'maintainability',
          description: `Add documentation for function ${func.name}`,
          filePath,
          lineNumber: func.lineStart,
          severity: 'info',
          currentCode: `function ${func.name}`,
          improvedCode: `/**\n * Description of what this function does\n */\nfunction ${func.name}`,
          justification: 'Documentation improves code maintainability',
          benefits: ['Better understanding', 'Easier maintenance'],
          prerequisites: []
        });
      }
    }

    return improvements;
  }

  private suggestTestabilityImprovements(
    filePath: string, 
    lines: string[], 
    symbols: ParsedSymbol[]
  ): CodeImprovement[] {
    const improvements: CodeImprovement[] = [];

    // Look for hard-to-test patterns
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Suggest dependency injection for new Date()
      if (line.includes('new Date()')) {
        improvements.push({
          id: `test-date-${i}-${Date.now()}`,
          category: 'testability',
          description: 'Consider injecting date dependency for better testability',
          filePath,
          lineNumber: i + 1,
          severity: 'info',
          currentCode: line.trim(),
          improvedCode: 'const now = dateProvider.now() // or pass date as parameter',
          justification: 'Dependency injection makes time-dependent code testable',
          benefits: ['Better testability', 'Deterministic tests'],
          prerequisites: ['Date provider or parameter']
        });
      }

      // Suggest mocking for external dependencies
      if (line.includes('fetch(') || line.includes('axios.')) {
        improvements.push({
          id: `test-external-${i}-${Date.now()}`,
          category: 'testability',
          description: 'Consider abstracting external HTTP calls for testing',
          filePath,
          lineNumber: i + 1,
          severity: 'info',
          currentCode: line.trim(),
          improvedCode: 'const response = await httpClient.get(url) // injectable client',
          justification: 'Abstracted HTTP clients can be mocked in tests',
          benefits: ['Better testability', 'Isolated testing'],
          prerequisites: ['HTTP client abstraction']
        });
      }
    }

    return improvements;
  }

  private async storePredictions(predictions: ChangePrediction[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO change_predictions (
        id, file_path, probability, predicted_change_type, description,
        reasoning, confidence, timeframe, priority, related_files, patterns
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const prediction of predictions) {
      stmt.run(
        prediction.id,
        prediction.filePath,
        prediction.probability,
        prediction.predictedChangeType,
        prediction.description,
        JSON.stringify(prediction.reasoning),
        prediction.confidence,
        prediction.timeframe,
        prediction.priority,
        JSON.stringify(prediction.relatedFiles),
        JSON.stringify(prediction.patterns)
      );
    }
  }

  private async storeRefactoringOpportunities(opportunities: RefactoringOpportunity[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO refactoring_opportunities (
        id, type, file_path, line_start, line_end, description,
        benefits, effort, impact, priority, code_snippet,
        suggested_refactoring, preserves_semantics, breaking_change, testing_required
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const opp of opportunities) {
      stmt.run(
        opp.id,
        opp.type,
        opp.filePath,
        opp.location.lineStart,
        opp.location.lineEnd,
        opp.description,
        JSON.stringify(opp.benefits),
        opp.effort,
        opp.impact,
        opp.priority,
        opp.codeSnippet,
        opp.suggestedRefactoring,
        opp.preservesSemantics,
        opp.breakingChange,
        opp.testingRequired
      );
    }
  }

  private assessChangeOutcome(change: ChangeHistory): 'positive' | 'neutral' | 'negative' {
    // Simple heuristic based on change characteristics
    if (change.changeDescription.toLowerCase().includes('fix') || 
        change.changeDescription.toLowerCase().includes('security')) {
      return 'positive';
    }
    
    if (change.linesRemoved > change.linesAdded * 2) { // Significant code removal
      return 'positive';
    }
    
    if (change.linesAdded > 500) { // Very large additions might indicate problems
      return 'negative';
    }
    
    return 'neutral';
  }

  private calculateTimeSpan(pattern: string): number {
    const patternChanges = this.changeHistory.filter(h => h.patterns.includes(pattern));
    if (patternChanges.length < 2) return 0;
    
    const earliest = Math.min(...patternChanges.map(h => h.timestamp));
    const latest = Math.max(...patternChanges.map(h => h.timestamp));
    
    return (latest - earliest) / (24 * 60 * 60 * 1000); // days
  }

  private calculateCyclomaticComplexity(symbol: ParsedSymbol): number {
    // Simplified complexity calculation
    // In a real implementation, this would parse the function body
    const signature = symbol.signature || '';
    
    // Count decision points
    let complexity = 1; // Base complexity
    complexity += (signature.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
    
    return complexity;
  }

  private measureConditionalComplexity(line: string): number {
    const operators = (line.match(/&&|\|\||!=/g) || []).length;
    return operators + 1;
  }

  private async adjustPredictionModels(predictionId: string, outcome: string): Promise<void> {
    // In a real implementation, this would adjust ML models based on feedback
    logger.info(`Adjusting prediction models based on outcome: ${outcome} for prediction ${predictionId}`);
  }

  async getStatistics(): Promise<any> {
    const totalChanges = this.changeHistory.length;
    const recentChanges = this.changeHistory.filter(h => 
      Date.now() - h.timestamp < 30 * 24 * 60 * 60 * 1000
    ).length;

    const changeTypes = this.changeHistory.reduce((acc, change) => {
      acc[change.changeType] = (acc[change.changeType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM change_predictions');
    const predictionCount = (stmt.get() as any).count;

    return {
      totalChanges,
      recentChanges,
      changeTypes,
      predictionCount,
      patternsLearned: this.patterns.size,
      averageChangeInterval: totalChanges > 1 ? 
        (this.changeHistory[0].timestamp - this.changeHistory[totalChanges - 1].timestamp) / (totalChanges - 1) : 0
    };
  }
}