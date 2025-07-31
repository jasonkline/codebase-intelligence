import { EventEmitter } from 'events';
import logger from '../utils/logger';
import { closeConnectionPool } from './ConnectionPoolManager';

export interface ShutdownHandler {
  name: string;
  priority: number; // Lower numbers run first
  timeout?: number; // Max time to wait for this handler
  handler: () => Promise<void>;
}

export class GracefulShutdown extends EventEmitter {
  private handlers: ShutdownHandler[] = [];
  private shutdownInProgress = false;
  private forceShutdownTimeout: NodeJS.Timeout | null = null;
  private readonly defaultTimeout = 30000; // 30 seconds
  private readonly forceTimeout = 60000; // 1 minute

  constructor() {
    super();
    this.setupSignalHandlers();
  }

  addHandler(handler: ShutdownHandler): void {
    this.handlers.push(handler);
    // Sort by priority (lower numbers first)
    this.handlers.sort((a, b) => a.priority - b.priority);
    logger.info(`Added shutdown handler: ${handler.name} (priority: ${handler.priority})`);
  }

  removeHandler(name: string): void {
    const index = this.handlers.findIndex(h => h.name === name);
    if (index !== -1) {
      this.handlers.splice(index, 1);
      logger.info(`Removed shutdown handler: ${name}`);
    }
  }

  async shutdown(reason: string = 'unknown'): Promise<void> {
    if (this.shutdownInProgress) {
      logger.warn('Shutdown already in progress, ignoring duplicate request');
      return;
    }

    this.shutdownInProgress = true;
    logger.info(`Starting graceful shutdown: ${reason}`);

    // Set a force shutdown timer
    this.forceShutdownTimeout = setTimeout(() => {
      logger.error(`Force shutdown after ${this.forceTimeout}ms timeout`);
      process.exit(1);
    }, this.forceTimeout);

    try {
      // Emit shutdown start event
      this.emit('shutdown:start', reason);

      // Execute handlers in priority order
      for (const handler of this.handlers) {
        await this.executeHandler(handler);
      }

      // Clear the force shutdown timer
      if (this.forceShutdownTimeout) {
        clearTimeout(this.forceShutdownTimeout);
        this.forceShutdownTimeout = null;
      }

      // Emit shutdown complete event
      this.emit('shutdown:complete', reason);
      
      logger.info('Graceful shutdown completed successfully');
      process.exit(0);
    } catch (error) {
      logger.error('Error during graceful shutdown:', error);
      
      // Clear the force shutdown timer
      if (this.forceShutdownTimeout) {
        clearTimeout(this.forceShutdownTimeout);
        this.forceShutdownTimeout = null;
      }

      // Emit shutdown error event
      this.emit('shutdown:error', error);
      
      process.exit(1);
    }
  }

  private async executeHandler(handler: ShutdownHandler): Promise<void> {
    const timeout = handler.timeout || this.defaultTimeout;
    logger.info(`Executing shutdown handler: ${handler.name} (timeout: ${timeout}ms)`);

    try {
      await Promise.race([
        handler.handler(),
        new Promise<never>((_, reject) => {
          setTimeout(() => {
            reject(new Error(`Handler ${handler.name} timed out after ${timeout}ms`));
          }, timeout);
        })
      ]);

      logger.info(`Shutdown handler completed: ${handler.name}`);
    } catch (error) {
      logger.error(`Shutdown handler failed: ${handler.name}`, error);
      
      // Emit handler error event but continue with other handlers
      this.emit('shutdown:handler:error', handler.name, error);
    }
  }

  private setupSignalHandlers(): void {
    // Handle various shutdown signals
    const signals = ['SIGTERM', 'SIGINT', 'SIGQUIT'] as const;
    
    signals.forEach(signal => {
      process.on(signal, () => {
        logger.info(`Received ${signal}, initiating graceful shutdown`);
        this.shutdown(`${signal} signal`);
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception:', error);
      this.shutdown('uncaught exception');
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled rejection at:', promise, 'reason:', reason);
      this.shutdown('unhandled rejection');
    });

    // Handle beforeExit event
    process.on('beforeExit', (code) => {
      if (!this.shutdownInProgress && code === 0) {
        logger.info('Process about to exit, initiating graceful shutdown');
        this.shutdown('process exit');
      }
    });
  }
}

// Create and configure the global shutdown manager
const shutdownManager = new GracefulShutdown();

// Add default handlers for common cleanup tasks
shutdownManager.addHandler({
  name: 'database-connections',
  priority: 10,
  timeout: 15000,
  handler: async () => {
    logger.info('Closing database connections...');
    await closeConnectionPool();
  }
});

shutdownManager.addHandler({
  name: 'file-watchers',
  priority: 20,
  timeout: 5000,
  handler: async () => {
    logger.info('Stopping file watchers...');
    // File watchers will be closed by their respective cleanup methods
  }
});

shutdownManager.addHandler({
  name: 'flush-logs',
  priority: 90,
  timeout: 3000,
  handler: async () => {
    logger.info('Flushing logs...');
    // Ensure all logs are written before shutdown
    return new Promise<void>((resolve) => {
      logger.on('finish', resolve);
      logger.end();
    });
  }
});

shutdownManager.addHandler({
  name: 'cleanup-temp-files',
  priority: 80,
  timeout: 5000,
  handler: async () => {
    logger.info('Cleaning up temporary files...');
    const fs = await import('fs/promises');
    const os = await import('os');
    const path = await import('path');
    
    try {
      const tempDir = path.join(os.tmpdir(), 'codebase-intelligence');
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch (error) {
      // Ignore errors during temp cleanup
      logger.debug('Error cleaning temp files:', error);
    }
  }
});

// Export the singleton instance
export default shutdownManager;

// Utility functions for common shutdown patterns
export function onShutdown(
  name: string, 
  handler: () => Promise<void>, 
  priority: number = 50,
  timeout?: number
): void {
  shutdownManager.addHandler({
    name,
    priority,
    timeout,
    handler
  });
}

export function removeShutdownHandler(name: string): void {
  shutdownManager.removeHandler(name);
}

// Health check function
export function getShutdownStatus() {
  return {
    shutdownInProgress: shutdownManager['shutdownInProgress'],
    handlersCount: shutdownManager['handlers'].length,
    handlers: shutdownManager['handlers'].map(h => ({
      name: h.name,
      priority: h.priority,
      timeout: h.timeout
    }))
  };
}