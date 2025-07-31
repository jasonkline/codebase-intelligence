import { EventEmitter } from 'events';
import logger from '../utils/logger';

export interface MemoryThresholds {
  warning: number;    // Memory usage percentage to trigger warning
  critical: number;   // Memory usage percentage to trigger critical actions
  maximum: number;    // Maximum memory usage before forcing cleanup
}

export interface MemoryMetrics {
  heapUsed: number;
  heapTotal: number;
  external: number;
  rss: number;
  arrayBuffers: number;
  timestamp: number;
  gcCount: number;
  gcDuration: number;
}

export interface CacheCleaner {
  name: string;
  priority: number;
  estimatedSavings: number; // Estimated memory savings in bytes
  cleaner: () => Promise<number>; // Returns actual bytes freed
}

export class MemoryManager extends EventEmitter {
  private thresholds: MemoryThresholds;
  private cleaners: CacheCleaner[] = [];
  private metrics: MemoryMetrics[] = [];
  private monitoringInterval: NodeJS.Timeout | null = null;
  private gcMetrics = { count: 0, totalDuration: 0 };
  private readonly maxMetricsHistory = 100;
  private readonly monitoringIntervalMs = 30000; // 30 seconds

  constructor(thresholds: Partial<MemoryThresholds> = {}) {
    super();
    
    this.thresholds = {
      warning: thresholds.warning ?? 75,
      critical: thresholds.critical ?? 85,
      maximum: thresholds.maximum ?? 95
    };

    this.startMonitoring();
    this.setupGCMetrics();
  }

  addCacheCleaner(cleaner: CacheCleaner): void {
    this.cleaners.push(cleaner);
    // Sort by priority (higher priority = cleaned first)
    this.cleaners.sort((a, b) => b.priority - a.priority);
    logger.info(`Added cache cleaner: ${cleaner.name} (priority: ${cleaner.priority})`);
  }

  removeCacheCleaner(name: string): void {
    const index = this.cleaners.findIndex(c => c.name === name);
    if (index !== -1) {
      this.cleaners.splice(index, 1);
      logger.info(`Removed cache cleaner: ${name}`);
    }
  }

  getCurrentMetrics(): MemoryMetrics {
    const memUsage = process.memoryUsage();
    return {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      external: memUsage.external,
      rss: memUsage.rss,
      arrayBuffers: memUsage.arrayBuffers,
      timestamp: Date.now(),
      gcCount: this.gcMetrics.count,
      gcDuration: this.gcMetrics.totalDuration
    };
  }

  getMemoryUsagePercentage(): number {
    const metrics = this.getCurrentMetrics();
    const totalSystemMemory = require('os').totalmem();
    return (metrics.rss / totalSystemMemory) * 100;
  }

  getHeapUsagePercentage(): number {
    const metrics = this.getCurrentMetrics();
    return (metrics.heapUsed / metrics.heapTotal) * 100;
  }

  getMetricsHistory(): MemoryMetrics[] {
    return [...this.metrics];
  }

  async forceGarbageCollection(): Promise<void> {
    if (global.gc) {
      logger.info('Forcing garbage collection...');
      const start = Date.now();
      global.gc();
      const duration = Date.now() - start;
      logger.info(`Garbage collection completed in ${duration}ms`);
      this.emit('gc:forced', { duration });
    } else {
      logger.warn('Garbage collection not available. Run with --expose-gc flag.');
    }
  }

  async cleanupCaches(targetReduction?: number): Promise<number> {
    logger.info('Starting cache cleanup...');
    let totalFreed = 0;
    const beforeMetrics = this.getCurrentMetrics();

    // Calculate how much memory we want to free
    const targetBytes = targetReduction || Math.floor(beforeMetrics.heapUsed * 0.2); // Default: 20%

    for (const cleaner of this.cleaners) {
      if (totalFreed >= targetBytes) {
        break;
      }

      try {
        logger.info(`Running cache cleaner: ${cleaner.name}`);
        const freed = await cleaner.cleaner();
        totalFreed += freed;
        logger.info(`Cache cleaner ${cleaner.name} freed ${this.formatBytes(freed)}`);
        
        this.emit('cache:cleaned', {
          cleaner: cleaner.name,
          freed,
          totalFreed
        });
      } catch (error) {
        logger.error(`Cache cleaner ${cleaner.name} failed:`, error);
        this.emit('cache:error', {
          cleaner: cleaner.name,
          error
        });
      }
    }

    // Force GC after cleanup
    await this.forceGarbageCollection();

    const afterMetrics = this.getCurrentMetrics();
    const actualFreed = beforeMetrics.heapUsed - afterMetrics.heapUsed;

    logger.info(`Cache cleanup completed. Freed ${this.formatBytes(actualFreed)} (${this.formatBytes(totalFreed)} reported by cleaners)`);
    
    this.emit('cleanup:complete', {
      targetBytes,
      reportedFreed: totalFreed,
      actualFreed,
      beforeMetrics,
      afterMetrics
    });

    return actualFreed;
  }

  async handleMemoryPressure(): Promise<void> {
    const usage = this.getMemoryUsagePercentage();
    const heapUsage = this.getHeapUsagePercentage();
    
    logger.warn(`Memory pressure detected: ${usage.toFixed(1)}% system, ${heapUsage.toFixed(1)}% heap`);
    
    if (usage >= this.thresholds.critical || heapUsage >= this.thresholds.critical) {
      this.emit('memory:critical', { usage, heapUsage });
      
      // Aggressive cleanup
      await this.cleanupCaches();
      
      // Check if we're still in critical state
      const newUsage = this.getMemoryUsagePercentage();
      if (newUsage >= this.thresholds.maximum) {
        logger.error(`Memory usage still critical after cleanup: ${newUsage.toFixed(1)}%`);
        this.emit('memory:maximum', { usage: newUsage });
        
        // Consider more drastic measures
        await this.emergencyCleanup();
      }
    } else if (usage >= this.thresholds.warning || heapUsage >= this.thresholds.warning) {
      this.emit('memory:warning', { usage, heapUsage });
      
      // Light cleanup
      await this.cleanupCaches(Math.floor(this.getCurrentMetrics().heapUsed * 0.1)); // 10%
    }
  }

  private async emergencyCleanup(): Promise<void> {
    logger.error('Performing emergency memory cleanup');
    
    // Run all cleaners regardless of estimated savings
    for (const cleaner of this.cleaners) {
      try {
        await cleaner.cleaner();
      } catch (error) {
        logger.error(`Emergency cleaner ${cleaner.name} failed:`, error);
      }
    }

    // Multiple GC cycles
    for (let i = 0; i < 3; i++) {
      await this.forceGarbageCollection();
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.emit('memory:emergency', {
      usage: this.getMemoryUsagePercentage(),
      heapUsage: this.getHeapUsagePercentage()
    });
  }

  private startMonitoring(): void {
    this.monitoringInterval = setInterval(() => {
      const metrics = this.getCurrentMetrics();
      this.metrics.push(metrics);
      
      // Keep only recent metrics
      if (this.metrics.length > this.maxMetricsHistory) {
        this.metrics.shift();
      }

      // Check for memory pressure
      const usage = this.getMemoryUsagePercentage();
      const heapUsage = this.getHeapUsagePercentage();

      if (usage >= this.thresholds.warning || heapUsage >= this.thresholds.warning) {
        this.handleMemoryPressure().catch(error => {
          logger.error('Error handling memory pressure:', error);
        });
      }

      this.emit('metrics:update', metrics);
    }, this.monitoringIntervalMs);
  }

  private setupGCMetrics(): void {
    if (process.env.NODE_ENV === 'development') {
      // In development, we can track GC more aggressively
      const originalGC = global.gc;
      if (originalGC) {
        global.gc = async () => {
          const start = Date.now();
          originalGC();
          const duration = Date.now() - start;
          this.gcMetrics.count++;
          this.gcMetrics.totalDuration += duration;
          this.emit('gc:completed', { duration, count: this.gcMetrics.count });
        };
      }
    }
  }

  private formatBytes(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }

  getHealthStatus() {
    const usage = this.getMemoryUsagePercentage();
    const heapUsage = this.getHeapUsagePercentage();
    const metrics = this.getCurrentMetrics();
    
    const healthy = {
      memoryUsageOk: usage < this.thresholds.warning,
      heapUsageOk: heapUsage < this.thresholds.warning,
      recentGCOk: this.gcMetrics.count === 0 || this.gcMetrics.totalDuration / this.gcMetrics.count < 100
    };

    return {
      healthy: Object.values(healthy).every(Boolean),
      checks: healthy,
      metrics: {
        systemUsage: usage,
        heapUsage,
        rss: this.formatBytes(metrics.rss),
        heapUsed: this.formatBytes(metrics.heapUsed),
        heapTotal: this.formatBytes(metrics.heapTotal),
        external: this.formatBytes(metrics.external),
        gcCount: this.gcMetrics.count,
        averageGCDuration: this.gcMetrics.count > 0 ? this.gcMetrics.totalDuration / this.gcMetrics.count : 0
      }
    };
  }

  stop(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
    logger.info('Memory monitoring stopped');
  }
}

// Create singleton instance
let memoryManager: MemoryManager | null = null;

export function getMemoryManager(thresholds?: Partial<MemoryThresholds>): MemoryManager {
  if (!memoryManager) {
    memoryManager = new MemoryManager(thresholds);
  }
  return memoryManager;
}

export function stopMemoryManager(): void {
  if (memoryManager) {
    memoryManager.stop();
    memoryManager = null;
  }
}

// Common cache cleaners for the codebase intelligence system
export const defaultCacheCleaners: CacheCleaner[] = [
  {
    name: 'ast-cache',
    priority: 90,
    estimatedSavings: 50 * 1024 * 1024, // 50MB
    cleaner: async () => {
      // Clear AST parsing cache
      let freed = 0;
      try {
        // This would integrate with the actual AST parser cache
        freed = 0; // Placeholder
      } catch (error) {
        logger.error('Error cleaning AST cache:', error);
      }
      return freed;
    }
  },
  {
    name: 'pattern-registry-cache',
    priority: 80,
    estimatedSavings: 30 * 1024 * 1024, // 30MB
    cleaner: async () => {
      // Clear pattern matching cache
      let freed = 0;
      try {
        // This would integrate with the pattern registry
        freed = 0; // Placeholder
      } catch (error) {
        logger.error('Error cleaning pattern cache:', error);
      }
      return freed;
    }
  },
  {
    name: 'security-scan-cache',
    priority: 70,
    estimatedSavings: 20 * 1024 * 1024, // 20MB
    cleaner: async () => {
      // Clear security scan results cache
      let freed = 0;
      try {
        // This would integrate with the security scanner
        freed = 0; // Placeholder
      } catch (error) {
        logger.error('Error cleaning security cache:', error);
      }
      return freed;
    }
  },
  {
    name: 'knowledge-cache',
    priority: 60,
    estimatedSavings: 40 * 1024 * 1024, // 40MB
    cleaner: async () => {
      // Clear knowledge extraction cache
      let freed = 0;
      try {
        // This would integrate with the knowledge system
        freed = 0; // Placeholder
      } catch (error) {
        logger.error('Error cleaning knowledge cache:', error);
      }
      return freed;
    }
  }
];

// Auto-register default cleaners if memory manager is created
export function setupDefaultMemoryManagement(thresholds?: Partial<MemoryThresholds>): MemoryManager {
  const manager = getMemoryManager(thresholds);
  
  // Add default cache cleaners
  defaultCacheCleaners.forEach(cleaner => {
    manager.addCacheCleaner(cleaner);
  });

  return manager;
}