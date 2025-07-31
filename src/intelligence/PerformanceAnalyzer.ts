import { ParsedSymbol } from '../parser/ASTParser';
import { logger } from '../utils/logger';
import Database from 'better-sqlite3';
import * as fs from 'fs';

export interface PerformanceIssue {
  id: string;
  type: 'n_plus_one' | 'memory_leak' | 'inefficient_loop' | 'blocking_operation' |
        'large_object_creation' | 'unnecessary_rerender' | 'inefficient_algorithm' |
        'resource_not_closed' | 'synchronous_io' | 'deep_recursion' | 'expensive_computation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  filePath: string;
  location: {
    lineStart: number;
    lineEnd: number;
    function?: string;
    class?: string;
  };
  title: string;
  description: string;
  impact: {
    performance: 'low' | 'medium' | 'high';
    memory: 'low' | 'medium' | 'high';
    scalability: 'low' | 'medium' | 'high';
    userExperience: 'low' | 'medium' | 'high';
  };
  estimatedSlowdown: number; // multiplier (e.g., 2.5x slower)
  suggestedFix: string;
  codeExample: string;
  detectedAt: number;
  confidence: number; // 0-1
  metrics: {
    complexity?: number;
    memoryUsage?: number;
    cpuIntensive?: boolean;
    ioOperations?: number;
  };
}

export interface OptimizationSuggestion {
  id: string;
  category: 'algorithm' | 'caching' | 'async' | 'memory' | 'database' | 'ui' | 'bundle';
  priority: 'low' | 'medium' | 'high' | 'critical';
  filePath: string;
  title: string;
  description: string;
  currentApproach: string;
  optimizedApproach: string;
  expectedImprovement: {
    performance: number; // percentage improvement
    memory: number;
    userExperience: number;
  };
  implementationEffort: 'trivial' | 'small' | 'medium' | 'large' | 'huge';
  riskLevel: 'low' | 'medium' | 'high';
  prerequisites: string[];
  codeExample: {
    before: string;
    after: string;
  };
  relatedIssues: string[]; // IDs of related performance issues
}

export interface CachingOpportunity {
  id: string;
  filePath: string;
  function: string;
  type: 'memoization' | 'result_cache' | 'computed_property' | 'api_cache' | 'asset_cache';
  description: string;
  cachingStrategy: string;
  estimatedHitRate: number; // 0-1
  memoryFootprint: 'small' | 'medium' | 'large';
  implementation: string;
  benefits: string[];
  considerations: string[];
}

export interface AsyncOpportunity {
  id: string;
  filePath: string;
  function: string;
  type: 'promise' | 'async_await' | 'web_worker' | 'lazy_loading' | 'streaming';
  description: string;
  currentBlocking: boolean;
  estimatedTimeReduction: number; // milliseconds
  implementation: string;
  dependencies: string[];
  compatibility: {
    browsers: string[];
    nodeVersion?: string;
  };
}

export interface MemoryAnalysis {
  filePath: string;
  potentialLeaks: MemoryLeak[];
  heavyObjects: HeavyObject[];
  unnecessaryAllocations: UnnecessaryAllocation[];
  optimizationOpportunities: MemoryOptimization[];
  totalEstimatedSaving: number; // MB
}

export interface MemoryLeak {
  type: 'event_listener' | 'timer' | 'closure' | 'dom_reference' | 'global_variable';
  location: {
    lineStart: number;
    lineEnd: number;
    function?: string;
  };
  description: string;
  leakRate: 'slow' | 'medium' | 'fast';
  fix: string;
}

export interface HeavyObject {
  type: 'large_array' | 'complex_object' | 'dom_collection' | 'image_data' | 'buffer';
  location: {
    lineStart: number;
    lineEnd: number;
  };
  estimatedSize: number; // KB
  usage: 'frequently_used' | 'occasionally_used' | 'rarely_used';
  optimization: string;
}

export interface UnnecessaryAllocation {
  type: 'object_in_loop' | 'string_concatenation' | 'array_copying' | 'function_recreation';
  location: {
    lineStart: number;
    lineEnd: number;
  };
  frequency: 'per_call' | 'per_iteration' | 'per_render';
  impact: number; // allocations per second
  fix: string;
}

export interface MemoryOptimization {
  type: 'object_pooling' | 'lazy_initialization' | 'weak_references' | 'memory_recycling';
  description: string;
  implementation: string;
  estimatedSaving: number; // MB
}

export interface BundleAnalysis {
  filePath: string;
  bundleSize: number; // KB
  unusedCode: UnusedCode[];
  heavyDependencies: HeavyDependency[];
  duplicatedModules: DuplicatedModule[];
  splitOpportunities: SplitOpportunity[];
  compressionOpportunities: CompressionOpportunity[];
}

export interface UnusedCode {
  type: 'unused_export' | 'unused_import' | 'dead_code' | 'unreachable_code';
  location: {
    lineStart: number;
    lineEnd: number;
  };
  size: number; // bytes
  confidence: number; // 0-1
}

export interface HeavyDependency {
  name: string;
  size: number; // KB
  usage: 'full' | 'partial' | 'minimal';
  alternatives: string[];
  optimization: string;
}

export interface DuplicatedModule {
  name: string;
  locations: string[];
  size: number; // KB
  consolidationStrategy: string;
}

export interface SplitOpportunity {
  type: 'route_based' | 'feature_based' | 'vendor_based' | 'dynamic_import';
  modules: string[];
  estimatedSaving: number; // KB on initial load
  implementation: string;
}

export interface CompressionOpportunity {
  type: 'gzip' | 'brotli' | 'minification' | 'tree_shaking';
  estimatedSaving: number; // percentage
  implementation: string;
}

export class PerformanceAnalyzer {
  private db: Database.Database;
  private performanceIssues: Map<string, PerformanceIssue[]> = new Map();
  private optimizationSuggestions: Map<string, OptimizationSuggestion[]> = new Map();

  constructor(private databasePath: string) {
    this.db = new Database(databasePath);
    this.initializeDatabase();
    this.loadExistingData();
  }

  private initializeDatabase(): void {
    // Performance issues table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS performance_issues (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_start INTEGER NOT NULL,
        line_end INTEGER NOT NULL,
        function_name TEXT,
        class_name TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        performance_impact TEXT NOT NULL,
        memory_impact TEXT NOT NULL,
        scalability_impact TEXT NOT NULL,
        ux_impact TEXT NOT NULL,
        estimated_slowdown REAL NOT NULL,
        suggested_fix TEXT NOT NULL,
        code_example TEXT,
        detected_at INTEGER NOT NULL,
        confidence REAL NOT NULL,
        metrics TEXT -- JSON
      )
    `);

    // Optimization suggestions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS optimization_suggestions (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        priority TEXT NOT NULL,
        file_path TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        current_approach TEXT NOT NULL,
        optimized_approach TEXT NOT NULL,
        performance_improvement REAL NOT NULL,
        memory_improvement REAL NOT NULL,
        ux_improvement REAL NOT NULL,
        implementation_effort TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        prerequisites TEXT, -- JSON array
        code_before TEXT,
        code_after TEXT,
        related_issues TEXT, -- JSON array
        created_at INTEGER NOT NULL
      )
    `);

    // Caching opportunities table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS caching_opportunities (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        function_name TEXT NOT NULL,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        caching_strategy TEXT NOT NULL,
        estimated_hit_rate REAL NOT NULL,
        memory_footprint TEXT NOT NULL,
        implementation TEXT NOT NULL,
        benefits TEXT, -- JSON array
        considerations TEXT, -- JSON array
        detected_at INTEGER NOT NULL
      )
    `);

    // Async opportunities table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS async_opportunities (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        function_name TEXT NOT NULL,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        currently_blocking BOOLEAN NOT NULL,
        estimated_time_reduction INTEGER NOT NULL,
        implementation TEXT NOT NULL,
        dependencies TEXT, -- JSON array
        browser_support TEXT, -- JSON array
        node_version TEXT,
        detected_at INTEGER NOT NULL
      )
    `);

    // Memory analysis table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memory_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        potential_leaks TEXT, -- JSON array
        heavy_objects TEXT, -- JSON array
        unnecessary_allocations TEXT, -- JSON array
        optimization_opportunities TEXT, -- JSON array
        total_estimated_saving REAL NOT NULL,
        analyzed_at INTEGER NOT NULL
      )
    `);

    // Bundle analysis table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS bundle_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        bundle_size INTEGER NOT NULL,
        unused_code TEXT, -- JSON array
        heavy_dependencies TEXT, -- JSON array
        duplicated_modules TEXT, -- JSON array
        split_opportunities TEXT, -- JSON array
        compression_opportunities TEXT, -- JSON array
        analyzed_at INTEGER NOT NULL
      )
    `);

    // Indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_perf_issues_file_severity 
      ON performance_issues(file_path, severity);
      
      CREATE INDEX IF NOT EXISTS idx_perf_issues_type 
      ON performance_issues(type);
      
      CREATE INDEX IF NOT EXISTS idx_optimization_priority 
      ON optimization_suggestions(priority, file_path);
      
      CREATE INDEX IF NOT EXISTS idx_caching_file 
      ON caching_opportunities(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_async_file 
      ON async_opportunities(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_memory_file 
      ON memory_analysis(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_bundle_file 
      ON bundle_analysis(file_path);
    `);
  }

  private loadExistingData(): void {
    // Load performance issues
    const issueStmt = this.db.prepare('SELECT * FROM performance_issues ORDER BY severity DESC, confidence DESC');
    const issues = issueStmt.all() as any[];
    
    for (const issue of issues) {
      const filePath = issue.file_path;
      if (!this.performanceIssues.has(filePath)) {
        this.performanceIssues.set(filePath, []);
      }
      
      this.performanceIssues.get(filePath)!.push({
        id: issue.id,
        type: issue.type,
        severity: issue.severity,
        filePath: issue.file_path,
        location: {
          lineStart: issue.line_start,
          lineEnd: issue.line_end,
          function: issue.function_name,
          class: issue.class_name
        },
        title: issue.title,
        description: issue.description,
        impact: {
          performance: issue.performance_impact,
          memory: issue.memory_impact,
          scalability: issue.scalability_impact,
          userExperience: issue.ux_impact
        },
        estimatedSlowdown: issue.estimated_slowdown,
        suggestedFix: issue.suggested_fix,
        codeExample: issue.code_example,
        detectedAt: issue.detected_at,
        confidence: issue.confidence,
        metrics: JSON.parse(issue.metrics || '{}')
      });
    }

    // Load optimization suggestions
    const optimStmt = this.db.prepare('SELECT * FROM optimization_suggestions ORDER BY priority DESC');
    const optimizations = optimStmt.all() as any[];
    
    for (const opt of optimizations) {
      const filePath = opt.file_path;
      if (!this.optimizationSuggestions.has(filePath)) {
        this.optimizationSuggestions.set(filePath, []);
      }
      
      this.optimizationSuggestions.get(filePath)!.push({
        id: opt.id,
        category: opt.category,
        priority: opt.priority,
        filePath: opt.file_path,
        title: opt.title,
        description: opt.description,
        currentApproach: opt.current_approach,
        optimizedApproach: opt.optimized_approach,
        expectedImprovement: {
          performance: opt.performance_improvement,
          memory: opt.memory_improvement,
          userExperience: opt.ux_improvement
        },
        implementationEffort: opt.implementation_effort,
        riskLevel: opt.risk_level,
        prerequisites: JSON.parse(opt.prerequisites || '[]'),
        codeExample: {
          before: opt.code_before,
          after: opt.code_after
        },
        relatedIssues: JSON.parse(opt.related_issues || '[]')
      });
    }

    logger.info(`Loaded ${issues.length} performance issues, ${optimizations.length} optimization suggestions`);
  }

  async analyzePerformance(filePath: string, symbols: ParsedSymbol[]): Promise<{
    issues: PerformanceIssue[];
    suggestions: OptimizationSuggestion[];
    cachingOpportunities: CachingOpportunity[];
    asyncOpportunities: AsyncOpportunity[];
  }> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Detect performance issues
      const issues = await this.detectPerformanceIssues(filePath, lines, symbols);

      // Generate optimization suggestions
      const suggestions = await this.generateOptimizationSuggestions(filePath, lines, symbols, issues);

      // Identify caching opportunities
      const cachingOpportunities = await this.identifyCachingOpportunities(filePath, lines, symbols);

      // Identify async opportunities
      const asyncOpportunities = await this.identifyAsyncOpportunities(filePath, lines, symbols);

      // Store results
      await this.storePerformanceIssues(issues);
      await this.storeOptimizationSuggestions(suggestions);
      await this.storeCachingOpportunities(cachingOpportunities);
      await this.storeAsyncOpportunities(asyncOpportunities);

      // Update in-memory cache
      this.performanceIssues.set(filePath, issues);
      this.optimizationSuggestions.set(filePath, suggestions);

      return { issues, suggestions, cachingOpportunities, asyncOpportunities };
    } catch (error) {
      logger.error(`Error analyzing performance for ${filePath}:`, error);
      return { issues: [], suggestions: [], cachingOpportunities: [], asyncOpportunities: [] };
    }
  }

  async analyzeMemory(filePath: string, symbols: ParsedSymbol[]): Promise<MemoryAnalysis> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      const potentialLeaks = this.detectMemoryLeaks(lines, symbols);
      const heavyObjects = this.detectHeavyObjects(lines, symbols);
      const unnecessaryAllocations = this.detectUnnecessaryAllocations(lines, symbols);
      const optimizationOpportunities = this.identifyMemoryOptimizations(lines, symbols);

      const totalEstimatedSaving = heavyObjects.reduce((sum, obj) => sum + obj.estimatedSize / 1024, 0) +
                                  optimizationOpportunities.reduce((sum, opt) => sum + opt.estimatedSaving, 0);

      const analysis: MemoryAnalysis = {
        filePath,
        potentialLeaks,
        heavyObjects,
        unnecessaryAllocations,
        optimizationOpportunities,
        totalEstimatedSaving
      };

      await this.storeMemoryAnalysis(analysis);
      return analysis;
    } catch (error) {
      logger.error(`Error analyzing memory for ${filePath}:`, error);
      return {
        filePath,
        potentialLeaks: [],
        heavyObjects: [],
        unnecessaryAllocations: [],
        optimizationOpportunities: [],
        totalEstimatedSaving: 0
      };
    }
  }

  async analyzeBundle(filePath: string): Promise<BundleAnalysis> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const bundleSize = Buffer.byteLength(content, 'utf8') / 1024; // KB

      const unusedCode = this.detectUnusedCode(content);
      const heavyDependencies = this.detectHeavyDependencies(content);
      const duplicatedModules = this.detectDuplicatedModules(content);
      const splitOpportunities = this.identifySplitOpportunities(content);
      const compressionOpportunities = this.identifyCompressionOpportunities(content);

      const analysis: BundleAnalysis = {
        filePath,
        bundleSize,
        unusedCode,
        heavyDependencies,
        duplicatedModules,
        splitOpportunities,
        compressionOpportunities
      };

      await this.storeBundleAnalysis(analysis);
      return analysis;
    } catch (error) {
      logger.error(`Error analyzing bundle for ${filePath}:`, error);
      return {
        filePath,
        bundleSize: 0,
        unusedCode: [],
        heavyDependencies: [],
        duplicatedModules: [],
        splitOpportunities: [],
        compressionOpportunities: []
      };
    }
  }

  // Performance issue detection methods

  private async detectPerformanceIssues(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): Promise<PerformanceIssue[]> {
    const issues: PerformanceIssue[] = [];

    // Detect N+1 queries
    issues.push(...this.detectNPlusOneQueries(filePath, lines));

    // Detect inefficient loops
    issues.push(...this.detectInefficientLoops(filePath, lines));

    // Detect blocking operations
    issues.push(...this.detectBlockingOperations(filePath, lines));

    // Detect unnecessary re-renders (React)
    issues.push(...this.detectUnnecessaryRerenders(filePath, lines));

    // Detect inefficient algorithms
    issues.push(...this.detectInefficientAlgorithms(filePath, lines, symbols));

    // Detect memory leaks
    issues.push(...this.detectPerformanceMemoryLeaks(filePath, lines));

    // Detect deep recursion
    issues.push(...this.detectDeepRecursion(filePath, lines, symbols));

    // Detect expensive computations
    issues.push(...this.detectExpensiveComputations(filePath, lines));

    return issues.sort((a, b) => this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity));
  }

  private detectNPlusOneQueries(filePath: string, lines: string[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for loops with database queries
      if (line.includes('for(') || line.includes('forEach') || line.includes('map(')) {
        let j = i + 1;
        let foundQuery = false;
        let braceCount = 0;
        
        while (j < lines.length && (braceCount > 0 || j === i + 1)) {
          const innerLine = lines[j];
          
          if (innerLine.includes('{')) braceCount++;
          if (innerLine.includes('}')) braceCount--;
          
          // Look for database operations
          if (innerLine.includes('await db.') || innerLine.includes('query(') || 
              innerLine.includes('findOne') || innerLine.includes('findById')) {
            foundQuery = true;
            break;
          }
          
          j++;
        }
        
        if (foundQuery) {
          issues.push({
            id: `n-plus-one-${i}-${Date.now()}`,
            type: 'n_plus_one',
            severity: 'high',
            filePath,
            location: { lineStart: i + 1, lineEnd: j + 1 },
            title: 'Potential N+1 Query Problem',
            description: 'Database query inside a loop can cause performance issues',
            impact: {
              performance: 'high',
              memory: 'medium',
              scalability: 'high',
              userExperience: 'high'
            },
            estimatedSlowdown: 5.0,
            suggestedFix: 'Use batch queries, joins, or eager loading instead',
            codeExample: lines.slice(i, j + 1).join('\n'),
            detectedAt: Date.now(),
            confidence: 0.8,
            metrics: { ioOperations: 1 }
          });
        }
      }
    }

    return issues;
  }

  private detectInefficientLoops(filePath: string, lines: string[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Nested loops
      if (line.includes('for(') || line.includes('while(')) {
        let nestedLoops = 0;
        let j = i + 1;
        let braceCount = 0;
        
        while (j < lines.length && (braceCount > 0 || j === i + 1)) {
          const innerLine = lines[j].trim();
          
          if (innerLine.includes('{')) braceCount++;
          if (innerLine.includes('}')) braceCount--;
          
          if ((innerLine.includes('for(') || innerLine.includes('while(')) && j !== i) {
            nestedLoops++;
          }
          
          j++;
        }
        
        if (nestedLoops >= 2) {
          issues.push({
            id: `nested-loops-${i}-${Date.now()}`,
            type: 'inefficient_algorithm',
            severity: 'medium',
            filePath,
            location: { lineStart: i + 1, lineEnd: j },
            title: 'Nested Loops Performance Issue',
            description: `${nestedLoops + 1} nested loops detected`,
            impact: {
              performance: 'high',
              memory: 'low',
              scalability: 'high',
              userExperience: 'medium'
            },
            estimatedSlowdown: Math.pow(2, nestedLoops),
            suggestedFix: 'Consider using more efficient algorithms or data structures',
            codeExample: lines.slice(i, i + 5).join('\n') + '...',
            detectedAt: Date.now(),
            confidence: 0.9,
            metrics: { complexity: nestedLoops + 1 }
          });
        }
      }

      // Array operations in loops
      if (line.includes('indexOf') || line.includes('includes') || line.includes('find(')) {
        let inLoop = false;
        for (let k = Math.max(0, i - 10); k < i; k++) {
          if (lines[k].includes('for(') || lines[k].includes('forEach') || lines[k].includes('map(')) {
            inLoop = true;
            break;
          }
        }
        
        if (inLoop) {
          issues.push({
            id: `inefficient-search-${i}-${Date.now()}`,
            type: 'inefficient_loop',
            severity: 'medium',
            filePath,
            location: { lineStart: i + 1, lineEnd: i + 1 },
            title: 'Inefficient Array Search in Loop',
            description: 'Linear search operations inside loops can be slow',
            impact: {
              performance: 'medium',
              memory: 'low',
              scalability: 'medium',
              userExperience: 'medium'
            },
            estimatedSlowdown: 2.0,
            suggestedFix: 'Use Set, Map, or pre-computed lookup tables',
            codeExample: line,
            detectedAt: Date.now(),
            confidence: 0.7,
            metrics: { complexity: 2 }
          });
        }
      }
    }

    return issues;
  }

  private detectBlockingOperations(filePath: string, lines: string[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    const blockingPatterns = [
      { pattern: /fs\.readFileSync/, name: 'Synchronous File Read' },
      { pattern: /fs\.writeFileSync/, name: 'Synchronous File Write' },
      { pattern: /JSON\.parse.*large/, name: 'Large JSON Parsing' },
      { pattern: /\.sort\(\).*large/, name: 'Large Array Sorting' },
      { pattern: /while\(true\)/, name: 'Infinite Loop' },
      { pattern: /sleep\(/, name: 'Blocking Sleep' }
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const { pattern, name } of blockingPatterns) {
        if (pattern.test(line)) {
          issues.push({
            id: `blocking-op-${i}-${Date.now()}`,
            type: 'blocking_operation',
            severity: 'medium',
            filePath,
            location: { lineStart: i + 1, lineEnd: i + 1 },
            title: `Blocking Operation: ${name}`,
            description: `${name} can block the event loop`,
            impact: {
              performance: 'high',
              memory: 'low',
              scalability: 'medium',
              userExperience: 'high'
            },
            estimatedSlowdown: 3.0,
            suggestedFix: 'Use async alternatives or move to worker thread',
            codeExample: line.trim(),
            detectedAt: Date.now(),
            confidence: 0.9,
            metrics: { cpuIntensive: true }
          });
        }
      }
    }

    return issues;
  }

  private detectUnnecessaryRerenders(filePath: string, lines: string[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    // React-specific patterns
    if (!filePath.endsWith('.tsx') && !filePath.endsWith('.jsx')) {
      return issues;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Object/array creation in render
      if (line.includes('return') && (line.includes('= {}') || line.includes('= []'))) {
        issues.push({
          id: `rerender-object-${i}-${Date.now()}`,
          type: 'unnecessary_rerender',
          severity: 'low',
          filePath,
          location: { lineStart: i + 1, lineEnd: i + 1 },
          title: 'Object Creation in Render',
          description: 'Creating objects/arrays in render causes unnecessary re-renders',
          impact: {
            performance: 'medium',
            memory: 'low',
            scalability: 'low',
            userExperience: 'low'
          },
          estimatedSlowdown: 1.2,
          suggestedFix: 'Move object creation outside render or use useMemo',
          codeExample: line.trim(),
          detectedAt: Date.now(),
          confidence: 0.6,
          metrics: {}
        });
      }

      // Inline functions
      if (line.includes('onClick={() =>') || line.includes('onChange={() =>')) {
        issues.push({
          id: `inline-function-${i}-${Date.now()}`,
          type: 'unnecessary_rerender',
          severity: 'low',
          filePath,
          location: { lineStart: i + 1, lineEnd: i + 1 },
          title: 'Inline Function in JSX',
          description: 'Inline functions cause child components to re-render',
          impact: {
            performance: 'low',
            memory: 'low',
            scalability: 'low',
            userExperience: 'low'
          },
          estimatedSlowdown: 1.1,
          suggestedFix: 'Use useCallback or define function outside render',
          codeExample: line.trim(),
          detectedAt: Date.now(),
          confidence: 0.8,
          metrics: {}
        });
      }
    }

    return issues;
  }

  private detectInefficientAlgorithms(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Bubble sort pattern
      if (line.includes('for(') && i + 5 < lines.length) {
        const block = lines.slice(i, i + 6).join(' ');
        if (block.includes('for(') && block.includes('[j]') && block.includes('[j+1]')) {
          issues.push({
            id: `bubble-sort-${i}-${Date.now()}`,
            type: 'inefficient_algorithm',
            severity: 'medium',
            filePath,
            location: { lineStart: i + 1, lineEnd: i + 6 },
            title: 'Inefficient Sorting Algorithm',
            description: 'Bubble sort has O(n²) complexity',
            impact: {
              performance: 'high',
              memory: 'low',
              scalability: 'high',
              userExperience: 'medium'
            },
            estimatedSlowdown: 10.0,
            suggestedFix: 'Use Array.sort() or efficient sorting algorithms',
            codeExample: lines.slice(i, i + 6).join('\n'),
            detectedAt: Date.now(),
            confidence: 0.85,
            metrics: { complexity: 2 }
          });
        }
      }

      // Linear search in sorted array
      if (line.includes('indexOf') || line.includes('find(')) {
        // Check if working with potentially sorted data
        const context = lines.slice(Math.max(0, i - 3), i + 3).join(' ');
        if (context.includes('sort') || context.includes('sorted')) {
          issues.push({
            id: `linear-search-sorted-${i}-${Date.now()}`,
            type: 'inefficient_algorithm',
            severity: 'low',
            filePath,
            location: { lineStart: i + 1, lineEnd: i + 1 },
            title: 'Linear Search on Sorted Data',
            description: 'Binary search would be more efficient on sorted data',
            impact: {
              performance: 'medium',
              memory: 'low',
              scalability: 'medium',
              userExperience: 'low'
            },
            estimatedSlowdown: 2.0,
            suggestedFix: 'Use binary search for sorted arrays',
            codeExample: line.trim(),
            detectedAt: Date.now(),
            confidence: 0.6,
            metrics: { complexity: 1 }
          });
        }
      }
    }

    return issues;
  }

  private detectPerformanceMemoryLeaks(filePath: string, lines: string[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Event listeners without cleanup
      if (line.includes('addEventListener') && !line.includes('removeEventListener')) {
        let hasCleanup = false;
        // Look for cleanup in the next 20 lines
        for (let j = i + 1; j < Math.min(lines.length, i + 20); j++) {
          if (lines[j].includes('removeEventListener')) {
            hasCleanup = true;
            break;
          }
        }
        
        if (!hasCleanup) {
          issues.push({
            id: `memory-leak-listener-${i}-${Date.now()}`,
            type: 'memory_leak',
            severity: 'medium',
            filePath,
            location: { lineStart: i + 1, lineEnd: i + 1 },
            title: 'Potential Memory Leak: Event Listener',
            description: 'Event listener added without cleanup',
            impact: {
              performance: 'medium',
              memory: 'high',
              scalability: 'medium',
              userExperience: 'medium'
            },
            estimatedSlowdown: 1.5,
            suggestedFix: 'Add removeEventListener in cleanup/unmount',
            codeExample: line.trim(),
            detectedAt: Date.now(),
            confidence: 0.7,
            metrics: { memoryUsage: 1 }
          });
        }
      }

      // Timers without cleanup
      if ((line.includes('setInterval') || line.includes('setTimeout')) && 
          !line.includes('clearInterval') && !line.includes('clearTimeout')) {
        issues.push({
          id: `memory-leak-timer-${i}-${Date.now()}`,
          type: 'memory_leak',
          severity: 'medium',
          filePath,
          location: { lineStart: i + 1, lineEnd: i + 1 },
          title: 'Potential Memory Leak: Timer',
          description: 'Timer created without cleanup',
          impact: {
            performance: 'medium',
            memory: 'high',
            scalability: 'medium',
            userExperience: 'medium'
          },
          estimatedSlowdown: 1.3,
          suggestedFix: 'Clear timers in cleanup/unmount',
          codeExample: line.trim(),
          detectedAt: Date.now(),
          confidence: 0.8,
          metrics: { memoryUsage: 1 }
        });
      }
    }

    return issues;
  }

  private detectDeepRecursion(filePath: string, lines: string[], symbols: ParsedSymbol[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    const functions = symbols.filter(s => s.kind === 'function');
    
    for (const func of functions) {
      const funcLines = lines.slice(func.lineStart - 1, func.lineEnd);
      const funcContent = funcLines.join('\n');
      
      // Check if function calls itself
      if (funcContent.includes(func.name + '(')) {
        // Check for base case
        const hasBaseCase = funcContent.includes('return') && 
                           (funcContent.includes('if') || funcContent.includes('?'));
        
        if (!hasBaseCase) {
          issues.push({
            id: `deep-recursion-${func.name}-${Date.now()}`,
            type: 'deep_recursion',
            severity: 'high',
            filePath,
            location: { lineStart: func.lineStart, lineEnd: func.lineEnd, function: func.name },
            title: 'Potential Stack Overflow: Deep Recursion',
            description: `Function ${func.name} may cause stack overflow`,
            impact: {
              performance: 'high',
              memory: 'high',
              scalability: 'low',
              userExperience: 'high'
            },
            estimatedSlowdown: 1.0, // Could crash
            suggestedFix: 'Add proper base case or use iterative approach',
            codeExample: funcLines.slice(0, 5).join('\n') + '...',
            detectedAt: Date.now(),
            confidence: 0.9,
            metrics: { complexity: 3 }
          });
        }
      }
    }

    return issues;
  }

  private detectExpensiveComputations(filePath: string, lines: string[]): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    const expensivePatterns = [
      { pattern: /Math\.pow/, name: 'Power computation' },
      { pattern: /Math\.sqrt/, name: 'Square root computation' }, 
      { pattern: /JSON\.stringify.*large/, name: 'Large JSON serialization' },
      { pattern: /RegExp.*complex/, name: 'Complex regex' },
      { pattern: /sort\(\).*large/, name: 'Large array sorting' }
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const { pattern, name } of expensivePatterns) {
        if (pattern.test(line)) {
          // Check if it's in a loop or called frequently
          let inLoop = false;
          for (let k = Math.max(0, i - 5); k < i; k++) {
            if (lines[k].includes('for(') || lines[k].includes('forEach')) {
              inLoop = true;
              break;
            }
          }
          
          if (inLoop) {
            issues.push({
              id: `expensive-computation-${i}-${Date.now()}`,
              type: 'expensive_computation',
              severity: 'medium',
              filePath,
              location: { lineStart: i + 1, lineEnd: i + 1 },
              title: `Expensive Computation in Loop: ${name}`,
              description: `${name} inside loop can be slow`,
              impact: {
                performance: 'high',
                memory: 'low',
                scalability: 'medium',
                userExperience: 'medium'
              },
              estimatedSlowdown: 2.5,
              suggestedFix: 'Move computation outside loop or use memoization',
              codeExample: line.trim(),
              detectedAt: Date.now(),
              confidence: 0.8,
              metrics: { cpuIntensive: true }
            });
          }
        }
      }
    }

    return issues;
  }

  // Optimization suggestion methods

  private async generateOptimizationSuggestions(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[],
    issues: PerformanceIssue[]
  ): Promise<OptimizationSuggestion[]> {
    const suggestions: OptimizationSuggestion[] = [];

    // Generate suggestions based on detected issues
    for (const issue of issues) {
      const suggestion = this.createOptimizationFromIssue(issue);
      if (suggestion) {
        suggestions.push(suggestion);
      }
    }

    // Generate proactive optimization suggestions
    suggestions.push(...this.generateAlgorithmOptimizations(filePath, lines, symbols));
    suggestions.push(...this.generateUIOptimizations(filePath, lines));
    suggestions.push(...this.generateBundleOptimizations(filePath, lines));

    return suggestions.sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority));
  }

  private createOptimizationFromIssue(issue: PerformanceIssue): OptimizationSuggestion | null {
    const optimizationMap: Record<string, Partial<OptimizationSuggestion>> = {
      'n_plus_one': {
        category: 'database',
        title: 'Optimize Database Queries',
        currentApproach: 'Individual queries in loop',
        optimizedApproach: 'Batch queries or joins',
        expectedImprovement: { performance: 80, memory: 20, userExperience: 70 },
        implementationEffort: 'medium',
        riskLevel: 'low'
      },
      'inefficient_loop': {
        category: 'algorithm',
        title: 'Optimize Loop Performance',
        currentApproach: 'O(n²) or inefficient operations',
        optimizedApproach: 'Use efficient data structures and algorithms',
        expectedImprovement: { performance: 60, memory: 10, userExperience: 40 },
        implementationEffort: 'small',
        riskLevel: 'low'
      },
      'blocking_operation': {
        category: 'async',
        title: 'Make Operations Asynchronous',
        currentApproach: 'Synchronous blocking operations',
        optimizedApproach: 'Async/await or worker threads',
        expectedImprovement: { performance: 70, memory: 0, userExperience: 80 },
        implementationEffort: 'medium',
        riskLevel: 'medium'
      }
    };

    const template = optimizationMap[issue.type];
    if (!template) return null;

    return {
      id: `opt-${issue.id}`,
      category: template.category!,
      priority: issue.severity === 'critical' ? 'critical' : 
               issue.severity === 'high' ? 'high' : 'medium',
      filePath: issue.filePath,
      title: template.title!,
      description: issue.description,
      currentApproach: template.currentApproach!,
      optimizedApproach: template.optimizedApproach!,
      expectedImprovement: template.expectedImprovement!,
      implementationEffort: template.implementationEffort!,
      riskLevel: template.riskLevel!,
      prerequisites: [],
      codeExample: {
        before: issue.codeExample,
        after: this.generateOptimizedCode(issue)
      },
      relatedIssues: [issue.id]
    };
  }

  private generateOptimizedCode(issue: PerformanceIssue): string {
    switch (issue.type) {
      case 'n_plus_one':
        return '// Use batch query or join instead\nconst results = await db.select().from(table).where(conditions);';
      
      case 'inefficient_loop':
        return '// Use efficient data structures\nconst lookup = new Map();\nconst result = items.map(item => lookup.get(item.id));';
      
      case 'blocking_operation':
        return '// Use async operations\nconst result = await fs.promises.readFile(filename);';
      
      default:
        return '// Optimized implementation';
    }
  }

  private generateAlgorithmOptimizations(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Look for sorting opportunities
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes('sort()') && line.includes('large')) {
        suggestions.push({
          id: `algo-sort-${i}-${Date.now()}`,
          category: 'algorithm',
          priority: 'medium',
          filePath,
          title: 'Optimize Large Array Sorting',
          description: 'Use efficient sorting for large datasets',
          currentApproach: 'Default array sort',
          optimizedApproach: 'Timsort or external sorting for very large datasets',
          expectedImprovement: { performance: 40, memory: 20, userExperience: 30 },
          implementationEffort: 'small',
          riskLevel: 'low',
          prerequisites: [],
          codeExample: {
            before: line.trim(),
            after: 'largeArray.sort((a, b) => a - b); // Ensure stable sort'
          },
          relatedIssues: []
        });
      }
    }

    return suggestions;
  }

  private generateUIOptimizations(filePath: string, lines: string[]): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    if (!filePath.endsWith('.tsx') && !filePath.endsWith('.jsx')) {
      return suggestions;
    }

    // Look for virtualization opportunities
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes('.map(') && (line.includes('items') || line.includes('data'))) {
        suggestions.push({
          id: `ui-virtualization-${i}-${Date.now()}`,
          category: 'ui',
          priority: 'medium',
          filePath,
          title: 'Consider Virtual Scrolling',
          description: 'Large lists can benefit from virtualization',
          currentApproach: 'Render all list items',
          optimizedApproach: 'Use virtual scrolling (react-window, react-virtualized)',
          expectedImprovement: { performance: 60, memory: 70, userExperience: 50 },
          implementationEffort: 'medium',
          riskLevel: 'low',
          prerequisites: ['react-window or similar library'],
          codeExample: {
            before: line.trim(),
            after: '<FixedSizeList height={600} itemCount={items.length} itemSize={35}>{Row}</FixedSizeList>'
          },
          relatedIssues: []
        });
      }
    }

    return suggestions;
  }

  private generateBundleOptimizations(filePath: string, lines: string[]): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Look for large imports
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes('import') && (line.includes('lodash') || line.includes('moment'))) {
        suggestions.push({
          id: `bundle-tree-shaking-${i}-${Date.now()}`,
          category: 'bundle',
          priority: 'low',
          filePath,
          title: 'Optimize Import for Bundle Size',
          description: 'Use tree-shaking friendly imports',
          currentApproach: 'Import entire library',
          optimizedApproach: 'Import only needed functions',
          expectedImprovement: { performance: 20, memory: 30, userExperience: 15 },
          implementationEffort: 'trivial',
          riskLevel: 'low',
          prerequisites: [],
          codeExample: {
            before: line.trim(),
            after: "import { debounce } from 'lodash-es';"
          },
          relatedIssues: []
        });
      }
    }

    return suggestions;
  }

  // Caching and async opportunity methods

  private async identifyCachingOpportunities(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): Promise<CachingOpportunity[]> {
    const opportunities: CachingOpportunity[] = [];

    const functions = symbols.filter(s => s.kind === 'function');
    
    for (const func of functions) {
      // Look for pure functions that could be memoized
      if (this.isPureFunction(func, lines)) {
        opportunities.push({
          id: `cache-memo-${func.name}-${Date.now()}`,
          filePath,
          function: func.name,
          type: 'memoization',
          description: `Function ${func.name} appears to be pure and could be memoized`,
          cachingStrategy: 'Memoization with LRU cache',
          estimatedHitRate: 0.6,
          memoryFootprint: 'small',
          implementation: `const memoized${func.name} = useMemo(() => ${func.name}, [dependencies]);`,
          benefits: ['Reduced computation time', 'Better performance for repeated calls'],
          considerations: ['Memory usage', 'Cache invalidation']
        });
      }

      // Look for API calls that could be cached
      const funcContent = lines.slice(func.lineStart - 1, func.lineEnd).join('\n');
      if (funcContent.includes('fetch(') || funcContent.includes('axios.')) {
        opportunities.push({
          id: `cache-api-${func.name}-${Date.now()}`,
          filePath,
          function: func.name,
          type: 'api_cache',
          description: `API calls in ${func.name} could be cached`,
          cachingStrategy: 'HTTP cache with TTL',
          estimatedHitRate: 0.8,
          memoryFootprint: 'medium',
          implementation: 'Use SWR, React Query, or custom cache layer',
          benefits: ['Reduced network requests', 'Faster response times', 'Better UX'],
          considerations: ['Data freshness', 'Cache size limits']
        });
      }
    }

    return opportunities;
  }

  private async identifyAsyncOpportunities(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): Promise<AsyncOpportunity[]> {
    const opportunities: AsyncOpportunity[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Synchronous file operations
      if (line.includes('fs.readFileSync') || line.includes('fs.writeFileSync')) {
        opportunities.push({
          id: `async-fs-${i}-${Date.now()}`,
          filePath,
          function: this.findContainingFunction(i, symbols)?.name || 'unknown',
          type: 'async_await',
          description: 'Convert synchronous file operations to async',
          currentBlocking: true,
          estimatedTimeReduction: 100,
          implementation: 'Use fs.promises or util.promisify',
          dependencies: ['fs.promises'],
          compatibility: {
            browsers: ['Node.js'],
            nodeVersion: '10+'
          }
        });
      }

      // Heavy computations that could use web workers
      if (line.includes('heavy') || line.includes('compute') || line.includes('process')) {
        const context = lines.slice(Math.max(0, i - 2), i + 3).join(' ');
        if (context.includes('for(') || context.includes('while(')) {
          opportunities.push({
            id: `async-worker-${i}-${Date.now()}`,
            filePath,
            function: this.findContainingFunction(i, symbols)?.name || 'unknown',
            type: 'web_worker',
            description: 'Move heavy computation to web worker',
            currentBlocking: true,
            estimatedTimeReduction: 500,
            implementation: 'Create web worker for background processing',
            dependencies: ['Web Workers API'],
            compatibility: {
              browsers: ['Modern browsers'],
              nodeVersion: 'N/A'
            }
          });
        }
      }
    }

    return opportunities;
  }

  // Memory analysis methods

  private detectMemoryLeaks(lines: string[], symbols: ParsedSymbol[]): MemoryLeak[] {
    const leaks: MemoryLeak[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Event listeners
      if (line.includes('addEventListener')) {
        leaks.push({
          type: 'event_listener',
          location: { lineStart: i + 1, lineEnd: i + 1 },
          description: 'Event listener may not be cleaned up',
          leakRate: 'slow',
          fix: 'Add removeEventListener in cleanup'
        });
      }

      // Global variables
      if (line.includes('window.') && line.includes('=')) {
        leaks.push({
          type: 'global_variable',
          location: { lineStart: i + 1, lineEnd: i + 1 },
          description: 'Global variable assignment',
          leakRate: 'slow',
          fix: 'Use local scope or cleanup when done'
        });
      }
    }

    return leaks;
  }

  private detectHeavyObjects(lines: string[], symbols: ParsedSymbol[]): HeavyObject[] {
    const heavyObjects: HeavyObject[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Large arrays
      if (line.includes('new Array(') || line.includes('Array(')) {
        const match = line.match(/Array\((\d+)\)/);
        if (match && parseInt(match[1]) > 1000) {
          heavyObjects.push({
            type: 'large_array',
            location: { lineStart: i + 1, lineEnd: i + 1 },
            estimatedSize: parseInt(match[1]) * 8 / 1024, // Rough estimate in KB
            usage: 'frequently_used', // Would need more analysis
            optimization: 'Use typed arrays or lazy loading'
          });
        }
      }

      // Buffer allocations
      if (line.includes('Buffer.alloc') || line.includes('new Buffer')) {
        heavyObjects.push({
          type: 'buffer',
          location: { lineStart: i + 1, lineEnd: i + 1 },
          estimatedSize: 100, // Default estimate
          usage: 'frequently_used',
          optimization: 'Reuse buffers or use buffer pools'
        });
      }
    }

    return heavyObjects;
  }

  private detectUnnecessaryAllocations(lines: string[], symbols: ParsedSymbol[]): UnnecessaryAllocation[] {
    const allocations: UnnecessaryAllocation[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Object creation in loops
      if (line.includes('= {}') || line.includes('= []')) {
        let inLoop = false;
        for (let k = Math.max(0, i - 5); k < i; k++) {
          if (lines[k].includes('for(') || lines[k].includes('while(')) {
            inLoop = true;
            break;
          }
        }
        
        if (inLoop) {
          allocations.push({
            type: 'object_in_loop',
            location: { lineStart: i + 1, lineEnd: i + 1 },
            frequency: 'per_iteration',
            impact: 100, // Rough estimate
            fix: 'Move object creation outside loop or reuse objects'
          });
        }
      }

      // String concatenation in loops
      if (line.includes('+=') && line.includes('"')) {
        let inLoop = false;
        for (let k = Math.max(0, i - 5); k < i; k++) {
          if (lines[k].includes('for(') || lines[k].includes('while(')) {
            inLoop = true;
            break;
          }
        }
        
        if (inLoop) {
          allocations.push({
            type: 'string_concatenation',
            location: { lineStart: i + 1, lineEnd: i + 1 },
            frequency: 'per_iteration',
            impact: 50,
            fix: 'Use array join or template literals'
          });
        }
      }
    }

    return allocations;
  }

  private identifyMemoryOptimizations(lines: string[], symbols: ParsedSymbol[]): MemoryOptimization[] {
    const optimizations: MemoryOptimization[] = [];

    // Look for repeated object creation patterns
    const objectCreationPattern = /new \w+\(/g;
    let matches = 0;
    
    for (const line of lines) {
      if (objectCreationPattern.test(line)) {
        matches++;
      }
    }

    if (matches > 10) {
      optimizations.push({
        type: 'object_pooling',
        description: 'High frequency of object creation detected',
        implementation: 'Implement object pooling pattern',
        estimatedSaving: matches * 0.1 // Rough estimate in MB
      });
    }

    return optimizations;
  }

  // Bundle analysis methods

  private detectUnusedCode(content: string): UnusedCode[] {
    const unusedCode: UnusedCode[] = [];
    const lines = content.split('\n');

    // Simple heuristic: exports that are never imported
    const exports = new Set<string>();
    const imports = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes('export')) {
        const match = line.match(/export.*\{([^}]+)\}/);
        if (match) {
          match[1].split(',').forEach(name => exports.add(name.trim()));
        }
      }

      if (line.includes('import')) {
        const match = line.match(/import.*\{([^}]+)\}/);
        if (match) {
          match[1].split(',').forEach(name => imports.add(name.trim()));
        }
      }
    }

    for (const exp of exports) {
      if (!imports.has(exp)) {
        unusedCode.push({
          type: 'unused_export',
          location: { lineStart: 1, lineEnd: 1 }, // Would need more precise location
          size: exp.length * 10, // Rough estimate
          confidence: 0.6
        });
      }
    }

    return unusedCode;
  }

  private detectHeavyDependencies(content: string): HeavyDependency[] {
    const heavyDeps: HeavyDependency[] = [];
    
    const knownHeavyDeps = [
      { name: 'lodash', size: 70, alternatives: ['lodash-es', 'ramda'] },
      { name: 'moment', size: 67, alternatives: ['date-fns', 'dayjs'] },
      { name: 'axios', size: 15, alternatives: ['fetch', 'ky'] }
    ];

    for (const dep of knownHeavyDeps) {
      if (content.includes(`'${dep.name}'`) || content.includes(`"${dep.name}"`)) {
        heavyDeps.push({
          name: dep.name,
          size: dep.size,
          usage: content.split(dep.name).length > 3 ? 'full' : 'partial',
          alternatives: dep.alternatives,
          optimization: `Consider replacing with ${dep.alternatives[0]}`
        });
      }
    }

    return heavyDeps;
  }

  private detectDuplicatedModules(content: string): DuplicatedModule[] {
    // Simplified implementation
    return [];
  }

  private identifySplitOpportunities(content: string): SplitOpportunity[] {
    const opportunities: SplitOpportunity[] = [];

    // Look for route-based splitting opportunities
    if (content.includes('Route') || content.includes('router')) {
      opportunities.push({
        type: 'route_based',
        modules: ['routes'],
        estimatedSaving: 30,
        implementation: 'Use React.lazy() or dynamic imports'
      });
    }

    return opportunities;
  }

  private identifyCompressionOpportunities(content: string): CompressionOpportunity[] {
    const opportunities: CompressionOpportunity[] = [];

    // Always suggest compression if not already present
    opportunities.push({
      type: 'gzip',
      estimatedSaving: 70,
      implementation: 'Enable gzip compression on server'
    });

    return opportunities;
  }

  // Helper methods

  private getSeverityWeight(severity: PerformanceIssue['severity']): number {
    const weights = { critical: 4, high: 3, medium: 2, low: 1 };
    return weights[severity];
  }

  private getPriorityWeight(priority: OptimizationSuggestion['priority']): number {
    const weights = { critical: 4, high: 3, medium: 2, low: 1 };
    return weights[priority];
  }

  private isPureFunction(func: ParsedSymbol, lines: string[]): boolean {
    const funcContent = lines.slice(func.lineStart - 1, func.lineEnd).join('\n');
    
    // Simple heuristics for pure functions
    const hasSideEffects = funcContent.includes('console.') ||
                          funcContent.includes('document.') ||
                          funcContent.includes('window.') ||
                          funcContent.includes('Math.random') ||
                          funcContent.includes('Date.now');
    
    const hasReturn = funcContent.includes('return');
    
    return hasReturn && !hasSideEffects;
  }

  private findContainingFunction(lineIndex: number, symbols: ParsedSymbol[]): ParsedSymbol | null {
    const functions = symbols.filter(s => s.kind === 'function');
    
    for (const func of functions) {
      if (lineIndex >= func.lineStart - 1 && lineIndex <= func.lineEnd - 1) {
        return func;
      }
    }
    
    return null;
  }

  // Database storage methods

  private async storePerformanceIssues(issues: PerformanceIssue[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO performance_issues (
        id, type, severity, file_path, line_start, line_end, function_name,
        class_name, title, description, performance_impact, memory_impact,
        scalability_impact, ux_impact, estimated_slowdown, suggested_fix,
        code_example, detected_at, confidence, metrics
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const issue of issues) {
      stmt.run(
        issue.id,
        issue.type,
        issue.severity,
        issue.filePath,
        issue.location.lineStart,
        issue.location.lineEnd,
        issue.location.function,
        issue.location.class,
        issue.title,
        issue.description,
        issue.impact.performance,
        issue.impact.memory,
        issue.impact.scalability,
        issue.impact.userExperience,
        issue.estimatedSlowdown,
        issue.suggestedFix,
        issue.codeExample,
        issue.detectedAt,
        issue.confidence,
        JSON.stringify(issue.metrics)
      );
    }
  }

  private async storeOptimizationSuggestions(suggestions: OptimizationSuggestion[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO optimization_suggestions (
        id, category, priority, file_path, title, description,
        current_approach, optimized_approach, performance_improvement,
        memory_improvement, ux_improvement, implementation_effort,
        risk_level, prerequisites, code_before, code_after,
        related_issues, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const suggestion of suggestions) {
      stmt.run(
        suggestion.id,
        suggestion.category,
        suggestion.priority,
        suggestion.filePath,
        suggestion.title,
        suggestion.description,
        suggestion.currentApproach,
        suggestion.optimizedApproach,
        suggestion.expectedImprovement.performance,
        suggestion.expectedImprovement.memory,
        suggestion.expectedImprovement.userExperience,
        suggestion.implementationEffort,
        suggestion.riskLevel,
        JSON.stringify(suggestion.prerequisites),
        suggestion.codeExample.before,
        suggestion.codeExample.after,
        JSON.stringify(suggestion.relatedIssues),
        Date.now()
      );
    }
  }

  private async storeCachingOpportunities(opportunities: CachingOpportunity[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO caching_opportunities (
        id, file_path, function_name, type, description, caching_strategy,
        estimated_hit_rate, memory_footprint, implementation, benefits,
        considerations, detected_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const opp of opportunities) {
      stmt.run(
        opp.id,
        opp.filePath,
        opp.function,
        opp.type,
        opp.description,
        opp.cachingStrategy,
        opp.estimatedHitRate,
        opp.memoryFootprint,
        opp.implementation,
        JSON.stringify(opp.benefits),
        JSON.stringify(opp.considerations),
        Date.now()
      );
    }
  }

  private async storeAsyncOpportunities(opportunities: AsyncOpportunity[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO async_opportunities (
        id, file_path, function_name, type, description, currently_blocking,
        estimated_time_reduction, implementation, dependencies,
        browser_support, node_version, detected_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const opp of opportunities) {
      stmt.run(
        opp.id,
        opp.filePath,
        opp.function,
        opp.type,
        opp.description,
        opp.currentBlocking,
        opp.estimatedTimeReduction,
        opp.implementation,
        JSON.stringify(opp.dependencies),
        JSON.stringify(opp.compatibility.browsers),
        opp.compatibility.nodeVersion,
        Date.now()
      );
    }
  }

  private async storeMemoryAnalysis(analysis: MemoryAnalysis): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO memory_analysis (
        file_path, potential_leaks, heavy_objects, unnecessary_allocations,
        optimization_opportunities, total_estimated_saving, analyzed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      analysis.filePath,
      JSON.stringify(analysis.potentialLeaks),
      JSON.stringify(analysis.heavyObjects),
      JSON.stringify(analysis.unnecessaryAllocations),
      JSON.stringify(analysis.optimizationOpportunities),
      analysis.totalEstimatedSaving,
      Date.now()
    );
  }

  private async storeBundleAnalysis(analysis: BundleAnalysis): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO bundle_analysis (
        file_path, bundle_size, unused_code, heavy_dependencies,
        duplicated_modules, split_opportunities, compression_opportunities, analyzed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      analysis.filePath,
      analysis.bundleSize,
      JSON.stringify(analysis.unusedCode),
      JSON.stringify(analysis.heavyDependencies),
      JSON.stringify(analysis.duplicatedModules),
      JSON.stringify(analysis.splitOpportunities),
      JSON.stringify(analysis.compressionOpportunities),
      Date.now()
    );
  }
}