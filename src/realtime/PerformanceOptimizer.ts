import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { EventEmitter } from 'events';
import os from 'os';
import { logger } from '../utils/logger';

export interface PerformanceMetrics {
  responseTime: number;
  memoryUsage: number;
  cpuUsage: number;
  cacheHitRate: number;
  queueSize: number;
  activeWorkers: number;
  timestamp: number;
}

export interface WorkerTask {
  id: string;
  type: 'analysis' | 'validation' | 'pattern_matching' | 'security_scan';
  priority: 'high' | 'medium' | 'low';
  data: any;
  timeout?: number;
}

export interface WorkerResult {
  id: string;
  success: boolean;
  result?: any;
  error?: string;
  processingTime: number;
}

export interface CacheConfig {
  maxSize: number;
  ttlMs: number;
  compression: boolean;
}

export interface OptimizationConfig {
  maxWorkers: number;
  queueSize: number;
  batchSize: number;
  targetResponseTime: number;
  cacheConfig: CacheConfig;
  enablePrioritization: boolean;
  memoryThreshold: number; // MB
  cpuThreshold: number; // percentage
}

export class PerformanceOptimizer extends EventEmitter {
  private workers: Worker[] = [];
  private workerQueue: Array<{ task: WorkerTask; resolve: Function; reject: Function }> = [];
  private activeWorkers = 0;
  private nextWorkerId = 0;
  private cache = new Map<string, { data: any; timestamp: number; hits: number }>();
  private metrics: PerformanceMetrics[] = [];
  private config: OptimizationConfig;
  private isShuttingDown = false;

  constructor(config: Partial<OptimizationConfig> = {}) {
    super();
    
    this.config = {
      maxWorkers: config.maxWorkers ?? Math.max(2, Math.floor(os.cpus().length / 2)),
      queueSize: config.queueSize ?? 1000,
      batchSize: config.batchSize ?? 10,
      targetResponseTime: config.targetResponseTime ?? 100, // ms
      cacheConfig: {
        maxSize: config.cacheConfig?.maxSize ?? 10000,
        ttlMs: config.cacheConfig?.ttlMs ?? 300000, // 5 minutes
        compression: config.cacheConfig?.compression ?? false
      },
      enablePrioritization: config.enablePrioritization ?? true,
      memoryThreshold: config.memoryThreshold ?? 1024, // 1GB
      cpuThreshold: config.cpuThreshold ?? 80
    };

    this.initializeWorkers();
    this.startMetricsCollection();
    this.startCacheCleanup();
  }

  private initializeWorkers(): void {
    logger.info(`Initializing ${this.config.maxWorkers} worker threads`);
    
    for (let i = 0; i < this.config.maxWorkers; i++) {
      this.createWorker();
    }
  }

  private createWorker(): void {
    try {
      // In a real implementation, you'd create actual worker threads
      // For now, we'll simulate workers with async processing
      logger.debug(`Worker ${this.nextWorkerId} created`);
      this.nextWorkerId++;
    } catch (error) {
      logger.error('Failed to create worker:', error);
    }
  }

  async executeTask<T>(task: WorkerTask): Promise<T> {
    const startTime = Date.now();
    
    try {
      // Check cache first
      const cacheKey = this.getCacheKey(task);
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        const responseTime = Date.now() - startTime;
        this.recordMetrics(responseTime, true);
        return cached as T;
      }

      // Execute task
      const result = await this.processTask(task);
      
      // Cache result if appropriate
      if (this.shouldCache(task)) {
        this.setCache(cacheKey, result);
      }

      const responseTime = Date.now() - startTime;
      this.recordMetrics(responseTime, false);
      
      return result as T;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      this.recordMetrics(responseTime, false);
      throw error;
    }
  }

  async executeBatch<T>(tasks: WorkerTask[]): Promise<Array<WorkerResult & { result: T }>> {
    const startTime = Date.now();
    
    try {
      // Sort by priority if enabled
      if (this.config.enablePrioritization) {
        tasks.sort((a, b) => this.getPriorityValue(b.priority) - this.getPriorityValue(a.priority));
      }

      // Process in batches
      const results: Array<WorkerResult & { result: T }> = [];
      const batchSize = this.config.batchSize;
      
      for (let i = 0; i < tasks.length; i += batchSize) {
        const batch = tasks.slice(i, i + batchSize);
        const batchPromises = batch.map(task => this.processTaskWithResult(task));
        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults as Array<WorkerResult & { result: T }>);
        
        // Check system resources and adjust if needed
        await this.adaptiveThrottling();
      }

      const totalTime = Date.now() - startTime;
      logger.debug(`Batch of ${tasks.length} tasks completed in ${totalTime}ms`);
      
      return results;
    } catch (error) {
      logger.error('Batch execution failed:', error);
      throw error;
    }
  }

  private async processTask(task: WorkerTask): Promise<any> {
    // Simulate worker processing based on task type
    const processingTime = this.getEstimatedProcessingTime(task.type);
    
    return new Promise((resolve, reject) => {
      const timeout = task.timeout || 5000;
      
      const timer = setTimeout(() => {
        reject(new Error(`Task ${task.id} timed out after ${timeout}ms`));
      }, timeout);
      
      // Simulate async processing
      setTimeout(() => {
        clearTimeout(timer);
        
        try {
          const result = this.simulateTaskProcessing(task);
          resolve(result);
        } catch (error) {
          reject(error);
        }
      }, processingTime);
    });
  }

  private async processTaskWithResult(task: WorkerTask): Promise<WorkerResult> {
    const startTime = Date.now();
    
    try {
      const result = await this.processTask(task);
      
      return {
        id: task.id,
        success: true,
        result,
        processingTime: Date.now() - startTime
      };
    } catch (error) {
      return {
        id: task.id,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        processingTime: Date.now() - startTime
      };
    }
  }

  private simulateTaskProcessing(task: WorkerTask): any {
    // Simulate different types of processing
    switch (task.type) {
      case 'analysis':
        return {
          type: 'analysis',
          symbols: Math.floor(Math.random() * 100),
          patterns: Math.floor(Math.random() * 20),
          issues: Math.floor(Math.random() * 5)
        };
      
      case 'validation':
        return {
          type: 'validation',
          errors: Math.floor(Math.random() * 3),
          warnings: Math.floor(Math.random() * 5),
          suggestions: Math.floor(Math.random() * 10)
        };
      
      case 'pattern_matching':
        return {
          type: 'pattern_matching',
          matches: Math.floor(Math.random() * 15),
          confidence: Math.random()
        };
      
      case 'security_scan':
        return {
          type: 'security_scan',
          vulnerabilities: Math.floor(Math.random() * 2),
          severity: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)]
        };
      
      default:
        return { type: 'unknown', processed: true };
    }
  }

  private getEstimatedProcessingTime(taskType: WorkerTask['type']): number {
    // Estimated processing times (in milliseconds)
    const times = {
      analysis: 50 + Math.random() * 100,
      validation: 10 + Math.random() * 40,
      pattern_matching: 20 + Math.random() * 60,
      security_scan: 30 + Math.random() * 80
    };
    
    return Math.floor(times[taskType]);
  }

  private getPriorityValue(priority: WorkerTask['priority']): number {
    const values = { high: 3, medium: 2, low: 1 };
    return values[priority];
  }

  private getCacheKey(task: WorkerTask): string {
    // Create a cache key based on task type and data
    const dataStr = JSON.stringify(task.data);
    const hash = require('crypto').createHash('md5').update(dataStr).digest('hex');
    return `${task.type}:${hash}`;
  }

  private shouldCache(task: WorkerTask): boolean {
    // Cache analysis and pattern matching results, but not real-time validations
    return task.type === 'analysis' || task.type === 'pattern_matching';
  }

  private getFromCache(key: string): any | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    // Check TTL
    if (Date.now() - entry.timestamp > this.config.cacheConfig.ttlMs) {
      this.cache.delete(key);
      return null;
    }
    
    // Update hit count
    entry.hits++;
    return entry.data;
  }

  private setCache(key: string, data: any): void {
    // Check cache size limit
    if (this.cache.size >= this.config.cacheConfig.maxSize) {
      // Remove oldest entries (LRU)
      const entries = Array.from(this.cache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
      
      // Remove 10% of oldest entries
      const toRemove = Math.floor(entries.length * 0.1);
      for (let i = 0; i < toRemove; i++) {
        this.cache.delete(entries[i][0]);
      }
    }
    
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      hits: 0
    });
  }

  private async adaptiveThrottling(): Promise<void> {
    const currentMetrics = this.getCurrentSystemMetrics();
    
    // If system is under stress, add small delay
    if (currentMetrics.memoryUsage > this.config.memoryThreshold ||
        currentMetrics.cpuUsage > this.config.cpuThreshold) {
      
      logger.debug('System under stress, applying adaptive throttling');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  private getCurrentSystemMetrics(): { memoryUsage: number; cpuUsage: number } {
    const memoryUsage = process.memoryUsage();
    const memoryMB = memoryUsage.heapUsed / 1024 / 1024;
    
    // CPU usage estimation (simplified)
    const cpuUsage = Math.min(this.activeWorkers / this.config.maxWorkers * 100, 100);
    
    return {
      memoryUsage: memoryMB,
      cpuUsage
    };
  }

  private recordMetrics(responseTime: number, fromCache: boolean): void {
    const systemMetrics = this.getCurrentSystemMetrics();
    const cacheHitRate = this.calculateCacheHitRate();
    
    const metrics: PerformanceMetrics = {
      responseTime,
      memoryUsage: systemMetrics.memoryUsage,
      cpuUsage: systemMetrics.cpuUsage,
      cacheHitRate,
      queueSize: this.workerQueue.length,
      activeWorkers: this.activeWorkers,
      timestamp: Date.now()
    };
    
    this.metrics.push(metrics);
    
    // Keep only recent metrics
    if (this.metrics.length > 1000) {
      this.metrics = this.metrics.slice(-500);
    }
    
    // Emit performance event for monitoring
    this.emit('metrics', metrics);
    
    // Check if performance is degrading
    if (responseTime > this.config.targetResponseTime * 2) {
      this.emit('performance-warning', {
        message: 'Response time exceeding target',
        responseTime,
        target: this.config.targetResponseTime
      });
    }
  }

  private calculateCacheHitRate(): number {
    const totalEntries = this.cache.size;
    if (totalEntries === 0) return 0;
    
    let totalHits = 0;
    for (const entry of this.cache.values()) {
      totalHits += entry.hits;
    }
    
    return totalHits / (totalHits + totalEntries);
  }

  private startMetricsCollection(): void {
    // Collect metrics every 30 seconds
    const metricsInterval = setInterval(() => {
      if (this.isShuttingDown) {
        clearInterval(metricsInterval);
        return;
      }
      
      const systemMetrics = this.getCurrentSystemMetrics();
      this.recordMetrics(0, false); // Baseline metrics
    }, 30000);
  }

  private startCacheCleanup(): void {
    // Clean up expired cache entries every 5 minutes
    const cleanupInterval = setInterval(() => {
      if (this.isShuttingDown) {
        clearInterval(cleanupInterval);
        return;
      }
      
      const now = Date.now();
      const expiredKeys: string[] = [];
      
      for (const [key, entry] of this.cache.entries()) {
        if (now - entry.timestamp > this.config.cacheConfig.ttlMs) {
          expiredKeys.push(key);
        }
      }
      
      expiredKeys.forEach(key => this.cache.delete(key));
      
      if (expiredKeys.length > 0) {
        logger.debug(`Cleaned up ${expiredKeys.length} expired cache entries`);
      }
    }, 300000);
  }

  // Public methods for monitoring and control
  getPerformanceStats(): {
    averageResponseTime: number;
    cacheHitRate: number;
    memoryUsage: number;
    cpuUsage: number;
    queueSize: number;
    cacheSize: number;
    recentMetrics: PerformanceMetrics[];
  } {
    const recentMetrics = this.metrics.slice(-10);
    const avgResponseTime = recentMetrics.length > 0
      ? recentMetrics.reduce((sum, m) => sum + m.responseTime, 0) / recentMetrics.length
      : 0;
    
    const systemMetrics = this.getCurrentSystemMetrics();
    
    return {
      averageResponseTime: avgResponseTime,
      cacheHitRate: this.calculateCacheHitRate(),
      memoryUsage: systemMetrics.memoryUsage,
      cpuUsage: systemMetrics.cpuUsage,
      queueSize: this.workerQueue.length,
      cacheSize: this.cache.size,
      recentMetrics
    };
  }

  clearCache(): void {
    this.cache.clear();
    logger.info('Performance cache cleared');
  }

  updateConfig(newConfig: Partial<OptimizationConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('Performance optimizer configuration updated');
  }

  // Caching utilities for external use
  async cacheResult<T>(key: string, computation: () => Promise<T>, ttl?: number): Promise<T> {
    const cached = this.getFromCache(key);
    if (cached) {
      return cached as T;
    }
    
    const result = await computation();
    
    // Temporarily override TTL if specified
    const originalTtl = this.config.cacheConfig.ttlMs;
    if (ttl) {
      this.config.cacheConfig.ttlMs = ttl;
    }
    
    this.setCache(key, result);
    
    if (ttl) {
      this.config.cacheConfig.ttlMs = originalTtl;
    }
    
    return result;
  }

  // Batch processing utilities
  async processPrioritizedQueue<T>(
    tasks: WorkerTask[],
    processFunction: (task: WorkerTask) => Promise<T>
  ): Promise<T[]> {
    // Sort by priority
    tasks.sort((a, b) => this.getPriorityValue(b.priority) - this.getPriorityValue(a.priority));
    
    const results: T[] = [];
    const concurrency = Math.min(tasks.length, this.config.maxWorkers);
    
    // Process with controlled concurrency
    for (let i = 0; i < tasks.length; i += concurrency) {
      const batch = tasks.slice(i, i + concurrency);
      const batchPromises = batch.map(processFunction);
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Adaptive throttling between batches
      await this.adaptiveThrottling();
    }
    
    return results;
  }

  async shutdown(): Promise<void> {
    logger.info('Shutting down performance optimizer...');
    this.isShuttingDown = true;
    
    // Wait for pending tasks to complete or timeout
    const shutdownTimeout = 5000; // 5 seconds
    const startTime = Date.now();
    
    while (this.workerQueue.length > 0 && Date.now() - startTime < shutdownTimeout) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    // Cleanup workers
    for (const worker of this.workers) {
      try {
        // In a real implementation, you'd terminate worker threads
        logger.debug('Worker terminated');
      } catch (error) {
        logger.error('Error terminating worker:', error);
      }
    }
    
    this.workers = [];
    this.cache.clear();
    
    logger.info('Performance optimizer shutdown completed');
  }
}