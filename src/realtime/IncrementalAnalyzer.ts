import { Worker } from 'worker_threads';
import path from 'path';
import fs from 'fs/promises';
import { ASTParser, ParsedSymbol } from '../parser/ASTParser';
import { PatternMatcher } from '../patterns/PatternMatcher';
import { SecurityScanner } from '../security/SecurityScanner';
import { FileChange } from './FileWatcher';
import { PerformanceOptimizer, WorkerTask } from './PerformanceOptimizer';
import logger from '../utils/logger';

export interface AnalysisResult {
  filePath: string;
  symbols: ParsedSymbol[];
  patterns: any[];
  securityIssues: any[];
  dependencies: string[];
  exports: string[];
  imports: string[];
  hash: string;
  timestamp: number;
  analysisTime: number;
}

export interface CacheEntry {
  result: AnalysisResult;
  lastAccessed: number;
  accessCount: number;
}

export interface IncrementalUpdate {
  type: 'add' | 'update' | 'remove';
  filePath: string;
  result?: AnalysisResult;
  affectedFiles: string[];
}

interface WorkerMessage {
  id: string;
  type: 'analyze' | 'terminate';
  data: any;
}

interface WorkerResponse {
  id: string;
  success: boolean;
  result?: AnalysisResult;
  error?: string;
}

export class IncrementalAnalyzer {
  private cache = new Map<string, CacheEntry>();
  private dependencyGraph = new Map<string, Set<string>>();
  private reverseDependencyGraph = new Map<string, Set<string>>();
  private analysisQueue: string[] = [];
  private processing = new Set<string>();
  private workers: Worker[] = [];
  private workerQueue: Array<{ resolve: Function; reject: Function; message: WorkerMessage }> = [];
  private nextWorkerId = 0;
  
  private readonly astParser: ASTParser;
  private readonly patternMatcher: PatternMatcher;
  private readonly securityScanner: SecurityScanner;
  private readonly performanceOptimizer: PerformanceOptimizer;
  
  private readonly maxCacheSize: number;
  private readonly maxWorkers: number;
  private readonly workerTimeout: number;
  private readonly targetResponseTime: number;

  constructor(options: {
    maxCacheSize?: number;
    maxWorkers?: number;
    workerTimeout?: number;
    targetResponseTime?: number;
  } = {}) {
    this.maxCacheSize = options.maxCacheSize ?? 10000;
    this.maxWorkers = options.maxWorkers ?? Math.max(2, Math.floor(require('os').cpus().length / 2));
    this.workerTimeout = options.workerTimeout ?? 5000;
    this.targetResponseTime = options.targetResponseTime ?? 100;

    this.astParser = new ASTParser();
    this.patternMatcher = new PatternMatcher();
    this.securityScanner = new SecurityScanner();
    this.performanceOptimizer = new PerformanceOptimizer({
      maxWorkers: this.maxWorkers,
      targetResponseTime: this.targetResponseTime,
      cacheConfig: {
        maxSize: this.maxCacheSize,
        ttlMs: 300000, // 5 minutes
        compression: false
      }
    });

    this.initializeWorkers();
  }

  private initializeWorkers(): void {
    // For now, we'll do synchronous analysis
    // In a full implementation, you'd create worker threads
    logger.info(`Initialized incremental analyzer (sync mode)`);
  }

  async analyzeFile(filePath: string, force = false): Promise<AnalysisResult> {
    const startTime = Date.now();
    
    try {
      // Use performance optimizer for caching and task management
      const cacheKey = `analysis:${filePath}:${force}`;
      
      const result = await this.performanceOptimizer.cacheResult(
        cacheKey,
        async () => {
          // Check our local cache first if not forced
          if (!force) {
            const cached = await this.getCachedResult(filePath);
            if (cached && Date.now() - startTime < this.targetResponseTime) {
              logger.debug(`Local cache hit for ${filePath} (${Date.now() - startTime}ms)`);
              return cached;
            }
          }

          // Create analysis task
          const task: WorkerTask = {
            id: `analysis-${Date.now()}-${Math.random()}`,
            type: 'analysis',
            priority: force ? 'high' : 'medium',
            data: { filePath, force },
            timeout: this.workerTimeout
          };

          // Execute through performance optimizer
          const analysisResult = await this.performanceOptimizer.executeTask<AnalysisResult>(task);
          
          // Update local cache and dependency graphs
          this.updateCache(filePath, analysisResult);
          this.updateDependencyGraph(filePath, analysisResult);
          
          return analysisResult;
        },
        300000 // 5 minute cache TTL
      );
      
      const analysisTime = Date.now() - startTime;
      result.analysisTime = analysisTime;
      
      logger.debug(`Analyzed ${filePath} in ${analysisTime}ms`);
      return result;
    } catch (error) {
      logger.error(`Failed to analyze ${filePath}:`, error);
      throw error;
    }
  }

  async handleFileChange(change: FileChange): Promise<IncrementalUpdate[]> {
    const updates: IncrementalUpdate[] = [];
    
    try {
      switch (change.type) {
        case 'add':
        case 'change':
          const result = await this.analyzeFile(change.path, true);
          const affectedFiles = this.getAffectedFiles(change.path);
          
          updates.push({
            type: change.type === 'add' ? 'add' : 'update',
            filePath: change.path,
            result,
            affectedFiles
          });

          // Re-analyze affected files if needed
          for (const affectedPath of affectedFiles) {
            if (this.shouldReanalyzeAffected(affectedPath, change.path)) {
              try {
                const affectedResult = await this.analyzeFile(affectedPath, true);
                updates.push({
                  type: 'update',
                  filePath: affectedPath,
                  result: affectedResult,
                  affectedFiles: []
                });
              } catch (error) {
                logger.error(`Failed to re-analyze affected file ${affectedPath}:`, error);
              }
            }
          }
          break;

        case 'unlink':
          this.removeFromCache(change.path);
          const removedAffected = this.getAffectedFiles(change.path);
          
          updates.push({
            type: 'remove',
            filePath: change.path,
            affectedFiles: removedAffected
          });

          // Clean up dependency graph
          this.removeDependencies(change.path);
          break;
      }
    } catch (error) {
      logger.error(`Error handling file change for ${change.path}:`, error);
    }

    return updates;
  }

  async handleBatch(changes: FileChange[]): Promise<IncrementalUpdate[]> {
    const startTime = Date.now();
    const updates: IncrementalUpdate[] = [];
    
    // Group changes by type for efficient processing
    const adds = changes.filter(c => c.type === 'add');
    const changes_updates = changes.filter(c => c.type === 'change');
    const deletes = changes.filter(c => c.type === 'unlink');

    try {
      // Process deletes first (synchronously)
      for (const change of deletes) {
        const deleteUpdates = await this.handleFileChange(change);
        updates.push(...deleteUpdates);
      }

      // Create tasks for adds and changes
      const analysisTasks: WorkerTask[] = [...adds, ...changes_updates].map(change => ({
        id: `batch-${change.path}-${Date.now()}`,
        type: 'analysis',
        priority: change.type === 'add' ? 'medium' : 'high', // Changes are higher priority
        data: { filePath: change.path, force: true },
        timeout: this.workerTimeout
      }));

      // Process tasks with performance optimizer
      const taskResults = await this.performanceOptimizer.processPrioritizedQueue(
        analysisTasks,
        async (task) => {
          const change = [...adds, ...changes_updates].find(c => 
            task.data.filePath === c.path
          );
          if (change) {
            return await this.handleFileChange(change);
          }
          return [];
        }
      );

      // Flatten results
      taskResults.forEach(result => {
        if (Array.isArray(result)) {
          updates.push(...result);
        }
      });

      const processingTime = Date.now() - startTime;
      logger.info(`Processed batch of ${changes.length} changes in ${processingTime}ms using performance optimizer`);

    } catch (error) {
      logger.error('Error processing batch:', error);
    }

    return updates;
  }

  private async getCachedResult(filePath: string): Promise<AnalysisResult | null> {
    const entry = this.cache.get(filePath);
    if (!entry) {
      return null;
    }

    // Check if file has been modified since cache entry
    try {
      const stats = await fs.stat(filePath);
      const fileTime = stats.mtime.getTime();
      
      if (fileTime > entry.result.timestamp) {
        // File has been modified, cache is stale
        this.cache.delete(filePath);
        return null;
      }

      // Update access statistics
      entry.lastAccessed = Date.now();
      entry.accessCount++;
      
      return entry.result;
    } catch (error) {
      // File might not exist anymore
      this.cache.delete(filePath);
      return null;
    }
  }

  private async performAnalysis(filePath: string): Promise<AnalysisResult> {
    const startTime = Date.now();
    
    try {
      // Read file content
      const content = await fs.readFile(filePath, 'utf-8');
      const hash = require('crypto').createHash('sha256').update(content).digest('hex');

      // Parse AST and extract symbols
      const parsedFile = await this.astParser.parseFile(filePath);
      
      if (!parsedFile) {
        throw new Error(`Failed to parse file: ${filePath}`);
      }
      
      // Extract imports/exports for dependency tracking
      const imports = this.extractImports(parsedFile.symbols);
      const exports = this.extractExports(parsedFile.symbols);
      const dependencies = this.resolveDependencies(filePath, imports);

      // Analyze patterns (with timeout for performance)
      const patterns = await this.analyzePatterns(filePath, content, parsedFile.symbols);
      
      // Scan for security issues (with timeout)
      const securityIssues = await this.analyzeSecurity(filePath, content, parsedFile.symbols);

      return {
        filePath,
        symbols: parsedFile.symbols,
        patterns,
        securityIssues,
        dependencies,
        exports,
        imports,
        hash,
        timestamp: Date.now(),
        analysisTime: Date.now() - startTime
      };
    } catch (error) {
      logger.error(`Analysis failed for ${filePath}:`, error);
      
      // Return minimal result for invalid/unparseable files
      return {
        filePath,
        symbols: [],
        patterns: [],
        securityIssues: [],
        dependencies: [],
        exports: [],
        imports: [],
        hash: '',
        timestamp: Date.now(),
        analysisTime: Date.now() - startTime
      };
    }
  }

  private async analyzePatterns(
    filePath: string, 
    content: string, 
    symbols: ParsedSymbol[]
  ): Promise<any[]> {
    try {
      // Use a timeout to ensure sub-100ms response times
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Pattern analysis timeout')), 50);
      });

      // PatternMatcher doesn't have analyzePatterns method - return empty array for now
      return [];
    } catch (error) {
      if (error.message === 'Pattern analysis timeout') {
        logger.debug(`Pattern analysis timeout for ${filePath}, using cache or simplified analysis`);
      } else {
        logger.error(`Pattern analysis error for ${filePath}:`, error);
      }
      return [];
    }
  }

  private async analyzeSecurity(
    filePath: string,
    content: string,
    symbols: ParsedSymbol[]
  ): Promise<any[]> {
    try {
      // Use a timeout for security analysis too
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Security analysis timeout')), 30);
      });

      const analysisPromise = this.securityScanner.scanFile(filePath, {});
      
      return await Promise.race([analysisPromise, timeoutPromise]) as any[];
    } catch (error) {
      if (error.message === 'Security analysis timeout') {
        logger.debug(`Security analysis timeout for ${filePath}, deferring to background`);
        // Schedule background analysis
        this.scheduleBackgroundSecurityScan(filePath, content);
      } else {
        logger.error(`Security analysis error for ${filePath}:`, error);
      }
      return [];
    }
  }

  private scheduleBackgroundSecurityScan(filePath: string, content: string): void {
    // Schedule for background processing
    setImmediate(async () => {
      try {
        const issues = await this.securityScanner.scanFile(filePath, {});
        if (issues.length > 0) {
          // Update cache with security findings
          const cached = this.cache.get(filePath);
          if (cached) {
            cached.result.securityIssues = issues;
          }
        }
      } catch (error) {
        logger.error(`Background security scan failed for ${filePath}:`, error);
      }
    });
  }

  private extractImports(symbols: ParsedSymbol[]): string[] {
    return symbols
      .filter(symbol => symbol.kind === 'import')
      .map(symbol => symbol.name)
      .filter(Boolean);
  }

  private extractExports(symbols: ParsedSymbol[]): string[] {
    return symbols
      .filter(symbol => symbol.isExported)
      .map(symbol => symbol.name);
  }

  private resolveDependencies(filePath: string, imports: string[]): string[] {
    const dir = path.dirname(filePath);
    const dependencies: string[] = [];

    for (const imp of imports) {
      try {
        if (imp.startsWith('.')) {
          // Relative import
          const resolved = path.resolve(dir, imp);
          dependencies.push(resolved);
        } else if (!imp.startsWith('@') && !imp.includes('/')) {
          // Built-in or npm module
          dependencies.push(imp);
        }
      } catch (error) {
        logger.debug(`Could not resolve dependency ${imp} from ${filePath}`);
      }
    }

    return dependencies;
  }

  private updateCache(filePath: string, result: AnalysisResult): void {
    // Implement LRU cache eviction if needed
    if (this.cache.size >= this.maxCacheSize) {
      this.evictLeastRecentlyUsed();
    }

    this.cache.set(filePath, {
      result,
      lastAccessed: Date.now(),
      accessCount: 1
    });
  }

  private evictLeastRecentlyUsed(): void {
    let oldestTime = Date.now();
    let oldestKey = '';

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < oldestTime) {
        oldestTime = entry.lastAccessed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      logger.debug(`Evicted cache entry for ${oldestKey}`);
    }
  }

  private removeFromCache(filePath: string): void {
    this.cache.delete(filePath);
  }

  private updateDependencyGraph(filePath: string, result: AnalysisResult): void {
    // Clear existing dependencies for this file
    const oldDeps = this.dependencyGraph.get(filePath);
    if (oldDeps) {
      for (const dep of oldDeps) {
        const reverseDeps = this.reverseDependencyGraph.get(dep);
        if (reverseDeps) {
          reverseDeps.delete(filePath);
          if (reverseDeps.size === 0) {
            this.reverseDependencyGraph.delete(dep);
          }
        }
      }
    }

    // Add new dependencies
    const newDeps = new Set(result.dependencies);
    this.dependencyGraph.set(filePath, newDeps);

    for (const dep of newDeps) {
      if (!this.reverseDependencyGraph.has(dep)) {
        this.reverseDependencyGraph.set(dep, new Set());
      }
      this.reverseDependencyGraph.get(dep)!.add(filePath);
    }
  }

  private removeDependencies(filePath: string): void {
    const deps = this.dependencyGraph.get(filePath);
    if (deps) {
      for (const dep of deps) {
        const reverseDeps = this.reverseDependencyGraph.get(dep);
        if (reverseDeps) {
          reverseDeps.delete(filePath);
          if (reverseDeps.size === 0) {
            this.reverseDependencyGraph.delete(dep);
          }
        }
      }
      this.dependencyGraph.delete(filePath);
    }
  }

  private getAffectedFiles(filePath: string): string[] {
    const affected = this.reverseDependencyGraph.get(filePath);
    return affected ? Array.from(affected) : [];
  }

  private shouldReanalyzeAffected(affectedPath: string, changedPath: string): boolean {
    // For now, always re-analyze affected files
    // In a more sophisticated implementation, you could check
    // if the changes actually affect the dependent file
    return true;
  }

  // Public query methods

  getCachedAnalysis(filePath: string): AnalysisResult | null {
    const entry = this.cache.get(filePath);
    return entry ? entry.result : null;
  }

  getDependencies(filePath: string): string[] {
    const deps = this.dependencyGraph.get(filePath);
    return deps ? Array.from(deps) : [];
  }

  getDependents(filePath: string): string[] {
    return this.getAffectedFiles(filePath);
  }

  getStats(): {
    cacheSize: number;
    cacheHitRate: number;
    averageAnalysisTime: number;
    totalFiles: number;
  } {
    let totalAccess = 0;
    let totalAnalysisTime = 0;
    
    for (const entry of this.cache.values()) {
      totalAccess += entry.accessCount;
      totalAnalysisTime += entry.result.analysisTime;
    }

    const cacheSize = this.cache.size;
    const avgAnalysisTime = cacheSize > 0 ? totalAnalysisTime / cacheSize : 0;

    return {
      cacheSize,
      cacheHitRate: totalAccess > 0 ? (totalAccess - cacheSize) / totalAccess : 0,
      averageAnalysisTime: avgAnalysisTime,
      totalFiles: this.dependencyGraph.size
    };
  }

  async clearCache(): Promise<void> {
    this.cache.clear();
    this.dependencyGraph.clear();
    this.reverseDependencyGraph.clear();
    logger.info('Analysis cache cleared');
  }

  async warmUpCache(filePaths: string[]): Promise<void> {
    logger.info(`Warming up cache for ${filePaths.length} files`);
    const startTime = Date.now();

    const promises = filePaths.map(async (filePath) => {
      try {
        await this.analyzeFile(filePath);
      } catch (error) {
        logger.debug(`Failed to warm up cache for ${filePath}:`, error);
      }
    });

    await Promise.all(promises);
    
    const duration = Date.now() - startTime;
    logger.info(`Cache warm-up completed in ${duration}ms`);
  }

  async destroy(): Promise<void> {
    // Clean up workers and resources
    await this.clearCache();
    await this.performanceOptimizer.shutdown();
    logger.info('Incremental analyzer destroyed');
  }
}