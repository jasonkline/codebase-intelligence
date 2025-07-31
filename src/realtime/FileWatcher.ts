import chokidar from 'chokidar';
import { EventEmitter } from 'events';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import logger from '../utils/logger';

import { Stats } from 'fs';

export interface FileChange {
  type: 'add' | 'change' | 'unlink' | 'addDir' | 'unlinkDir';
  path: string;
  stats?: Stats;
  hash?: string;
  timestamp: number;
}

export interface FileHistory {
  path: string;
  changes: FileChange[];
  maxHistory: number;
}

export interface WatcherOptions {
  debounceMs?: number;
  batchSize?: number;
  maxBatchWaitMs?: number;
  historySize?: number;
  patterns?: string[];
  ignored?: string[];
}

interface PendingChange {
  change: FileChange;
  timeout: NodeJS.Timeout;
}

export class FileWatcher extends EventEmitter {
  private watcher: ReturnType<typeof chokidar.watch> | null = null;
  private pendingChanges = new Map<string, PendingChange>();
  private batchTimer: NodeJS.Timeout | null = null;
  private fileHistory = new Map<string, FileHistory>();
  private fileHashes = new Map<string, string>();
  
  private readonly options: Required<WatcherOptions>;
  private isWatching = false;
  private changeBuffer: FileChange[] = [];

  constructor(options: WatcherOptions = {}) {
    super();
    this.options = {
      debounceMs: options.debounceMs ?? 300,
      batchSize: options.batchSize ?? 50,
      maxBatchWaitMs: options.maxBatchWaitMs ?? 1000,
      historySize: options.historySize ?? 100,
      patterns: options.patterns ?? ['**/*.{ts,tsx,js,jsx,json}'],
      ignored: options.ignored ?? [
        '**/node_modules/**',
        '**/dist/**',
        '**/build/**',
        '**/.git/**',
        '**/.next/**',
        '**/coverage/**'
      ]
    };
  }

  async start(watchPath: string): Promise<void> {
    if (this.isWatching) {
      logger.warn('FileWatcher is already watching');
      return;
    }

    logger.info(`Starting file watcher for: ${watchPath}`);
    
    try {
      // Initialize file hashes for existing files
      await this.initializeFileHashes(watchPath);

      this.watcher = chokidar.watch(this.options.patterns, {
        cwd: watchPath,
        ignored: this.options.ignored,
        persistent: true,
        ignoreInitial: false,
        followSymlinks: false,
        depth: 99,
        awaitWriteFinish: {
          stabilityThreshold: 100,
          pollInterval: 50
        }
      });

      this.setupEventHandlers();
      this.isWatching = true;
      
      await new Promise<void>((resolve, reject) => {
        this.watcher!.on('ready', () => {
          logger.info('File watcher is ready');
          resolve();
        });
        
        this.watcher!.on('error', (error) => {
          logger.error('File watcher error:', error);
          reject(error);
        });
      });
    } catch (error) {
      logger.error('Failed to start file watcher:', error);
      throw error;
    }
  }

  async stop(): Promise<void> {
    if (!this.isWatching) {
      return;
    }

    logger.info('Stopping file watcher');
    
    // Clear all pending operations
    this.clearAllPendingChanges();
    
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }

    this.isWatching = false;
    logger.info('File watcher stopped');
  }

  private async initializeFileHashes(watchPath: string): Promise<void> {
    logger.info('Initializing file hashes...');
    const startTime = Date.now();
    let fileCount = 0;

    try {
      const files = await this.getAllFiles(watchPath);
      
      await Promise.all(
        files.map(async (filePath) => {
          try {
            const hash = await this.calculateFileHash(filePath);
            this.fileHashes.set(filePath, hash);
            fileCount++;
          } catch (error) {
            // File might have been deleted or inaccessible
            logger.debug(`Could not hash file ${filePath}:`, error);
          }
        })
      );

      const duration = Date.now() - startTime;
      logger.info(`Initialized ${fileCount} file hashes in ${duration}ms`);
    } catch (error) {
      logger.error('Failed to initialize file hashes:', error);
      throw error;
    }
  }

  private async getAllFiles(dir: string): Promise<string[]> {
    const files: string[] = [];
    
    const processDir = async (currentDir: string) => {
      try {
        const entries = await fs.readdir(currentDir, { withFileTypes: true });
        
        await Promise.all(
          entries.map(async (entry) => {
            const fullPath = path.join(currentDir, entry.name);
            
            if (entry.isDirectory()) {
              // Check if directory should be ignored
              const relativePath = path.relative(dir, fullPath);
              if (!this.shouldIgnore(relativePath)) {
                await processDir(fullPath);
              }
            } else if (entry.isFile()) {
              const relativePath = path.relative(dir, fullPath);
              if (this.shouldWatch(relativePath)) {
                files.push(fullPath);
              }
            }
          })
        );
      } catch (error) {
        logger.debug(`Could not read directory ${currentDir}:`, error);
      }
    };

    await processDir(dir);
    return files;
  }

  private shouldWatch(filePath: string): boolean {
    // Check if file matches any of the watch patterns
    return this.options.patterns.some(pattern => {
      const regex = this.globToRegex(pattern);
      return regex.test(filePath);
    });
  }

  private shouldIgnore(filePath: string): boolean {
    // Check if file matches any of the ignore patterns
    return this.options.ignored.some(pattern => {
      const regex = this.globToRegex(pattern);
      return regex.test(filePath);
    });
  }

  private globToRegex(glob: string): RegExp {
    const regexStr = glob
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/]')
      .replace(/\./g, '\\.');
    
    return new RegExp(`^${regexStr}$`);
  }

  private setupEventHandlers(): void {
    if (!this.watcher) return;

    this.watcher.on('add', (filePath, stats) => {
      this.handleFileChange('add', filePath, stats);
    });

    this.watcher.on('change', (filePath, stats) => {
      this.handleFileChange('change', filePath, stats);
    });

    this.watcher.on('unlink', (filePath) => {
      this.handleFileChange('unlink', filePath);
    });

    this.watcher.on('addDir', (dirPath, stats) => {
      this.handleFileChange('addDir', dirPath, stats);
    });

    this.watcher.on('unlinkDir', (dirPath) => {
      this.handleFileChange('unlinkDir', dirPath);
    });

    this.watcher.on('error', (error) => {
      logger.error('File watcher error:', error);
      this.emit('error', error);
    });
  }

  private async handleFileChange(
    type: FileChange['type'],
    filePath: string,
    stats?: Stats
  ): Promise<void> {
    try {
      const absolutePath = path.resolve(filePath);
      const hash = type !== 'unlink' && type !== 'unlinkDir' 
        ? await this.calculateFileHash(absolutePath)
        : undefined;

      // Check if file actually changed (for 'change' events)
      if (type === 'change' && hash) {
        const previousHash = this.fileHashes.get(absolutePath);
        if (previousHash === hash) {
          // File content hasn't actually changed, ignore
          return;
        }
        this.fileHashes.set(absolutePath, hash);
      } else if (type === 'add' && hash) {
        this.fileHashes.set(absolutePath, hash);
      } else if (type === 'unlink') {
        this.fileHashes.delete(absolutePath);
      }

      const change: FileChange = {
        type,
        path: absolutePath,
        stats,
        hash,
        timestamp: Date.now()
      };

      this.addFileHistory(absolutePath, change);
      this.debounceChange(change);
    } catch (error) {
      logger.error(`Error handling file change for ${filePath}:`, error);
    }
  }

  private async calculateFileHash(filePath: string): Promise<string> {
    try {
      const content = await fs.readFile(filePath);
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch (error) {
      logger.debug(`Could not calculate hash for ${filePath}:`, error);
      return '';
    }
  }

  private debounceChange(change: FileChange): void {
    const key = change.path;
    
    // Clear existing timeout for this file
    const existing = this.pendingChanges.get(key);
    if (existing) {
      clearTimeout(existing.timeout);
    }

    // Set new timeout
    const timeout = setTimeout(() => {
      this.pendingChanges.delete(key);
      this.addToBatch(change);
    }, this.options.debounceMs);

    this.pendingChanges.set(key, { change, timeout });
  }

  private addToBatch(change: FileChange): void {
    this.changeBuffer.push(change);

    // Process batch if it's full
    if (this.changeBuffer.length >= this.options.batchSize) {
      this.processBatch();
      return;
    }

    // Set timer for batch processing if not already set
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(() => {
        this.processBatch();
      }, this.options.maxBatchWaitMs);
    }
  }

  private processBatch(): void {
    if (this.changeBuffer.length === 0) {
      return;
    }

    const batch = [...this.changeBuffer];
    this.changeBuffer = [];
    
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    logger.debug(`Processing batch of ${batch.length} file changes`);
    this.emit('batch', batch);

    // Emit individual change events for compatibility
    batch.forEach(change => {
      this.emit('change', change);
    });
  }

  private addFileHistory(filePath: string, change: FileChange): void {
    let history = this.fileHistory.get(filePath);
    
    if (!history) {
      history = {
        path: filePath,
        changes: [],
        maxHistory: this.options.historySize
      };
      this.fileHistory.set(filePath, history);
    }

    history.changes.push(change);
    
    // Trim history if it exceeds max size
    if (history.changes.length > history.maxHistory) {
      history.changes = history.changes.slice(-history.maxHistory);
    }
  }

  private clearAllPendingChanges(): void {
    this.pendingChanges.forEach(({ timeout }) => {
      clearTimeout(timeout);
    });
    this.pendingChanges.clear();
  }

  // Public methods for querying state

  getFileHistory(filePath: string): FileHistory | undefined {
    return this.fileHistory.get(path.resolve(filePath));
  }

  getAllFileHistory(): Map<string, FileHistory> {
    return new Map(this.fileHistory);
  }

  getRecentChanges(sinceMs?: number): FileChange[] {
    const since = sinceMs ?? Date.now() - 60000; // Default to last minute
    const changes: FileChange[] = [];

    this.fileHistory.forEach(history => {
      const recentChanges = history.changes.filter(
        change => change.timestamp >= since
      );
      changes.push(...recentChanges);
    });

    return changes.sort((a, b) => b.timestamp - a.timestamp);
  }

  isFileWatched(filePath: string): boolean {
    return this.fileHashes.has(path.resolve(filePath));
  }

  getWatchedFileCount(): number {
    return this.fileHashes.size;
  }

  getStats(): {
    watchedFiles: number;
    pendingChanges: number;
    historyEntries: number;
    isWatching: boolean;
  } {
    return {
      watchedFiles: this.fileHashes.size,
      pendingChanges: this.pendingChanges.size,
      historyEntries: this.fileHistory.size,
      isWatching: this.isWatching
    };
  }

  // Rollback functionality
  async rollbackFile(filePath: string, toTimestamp: number): Promise<boolean> {
    const history = this.getFileHistory(filePath);
    if (!history) {
      return false;
    }

    // Find the change closest to the target timestamp
    const targetChange = history.changes
      .filter(change => change.timestamp <= toTimestamp)
      .sort((a, b) => b.timestamp - a.timestamp)[0];

    if (!targetChange || !targetChange.hash) {
      return false;
    }

    try {
      // This is a simplified rollback - in a real implementation,
      // you'd need to store file contents or use a VCS
      logger.info(`Rollback requested for ${filePath} to ${targetChange.timestamp}`);
      this.emit('rollback', { filePath, targetChange });
      return true;
    } catch (error) {
      logger.error(`Failed to rollback ${filePath}:`, error);
      return false;
    }
  }
}