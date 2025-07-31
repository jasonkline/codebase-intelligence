import { Database } from 'better-sqlite3';
import logger from '../utils/logger';

export interface ConnectionPoolOptions {
  maxConnections: number;
  minConnections: number;
  connectionTimeout: number;
  idleTimeout: number;
  acquireTimeout: number;
  maxRetries: number;
}

export interface PooledConnection {
  id: string;
  database: Database;
  lastUsed: number;
  inUse: boolean;
  queries: number;
  errors: number;
}

export class ConnectionPoolManager {
  private connections: Map<string, PooledConnection> = new Map();
  private waitingQueue: Array<{ resolve: Function; reject: Function; timeout: NodeJS.Timeout }> = [];
  private options: ConnectionPoolOptions;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private metrics = {
    totalConnections: 0,
    activeConnections: 0,
    queuedRequests: 0,
    totalQueries: 0,
    totalErrors: 0,
    averageWaitTime: 0
  };

  constructor(options: Partial<ConnectionPoolOptions> = {}) {
    this.options = {
      maxConnections: options.maxConnections ?? 10,
      minConnections: options.minConnections ?? 2,
      connectionTimeout: options.connectionTimeout ?? 30000,
      idleTimeout: options.idleTimeout ?? 300000, // 5 minutes
      acquireTimeout: options.acquireTimeout ?? 10000,
      maxRetries: options.maxRetries ?? 3
    };

    this.startCleanupTimer();
    this.ensureMinConnections();
  }

  async acquireConnection(databasePath: string): Promise<PooledConnection> {
    const startTime = Date.now();
    this.metrics.queuedRequests++;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.metrics.queuedRequests--;
        reject(new Error(`Connection acquire timeout after ${this.options.acquireTimeout}ms`));
      }, this.options.acquireTimeout);

      // Try to get an available connection immediately
      const available = this.findAvailableConnection(databasePath);
      if (available) {
        clearTimeout(timeout);
        this.metrics.queuedRequests--;
        this.metrics.averageWaitTime = this.updateAverageWaitTime(Date.now() - startTime);
        resolve(this.markConnectionInUse(available));
        return;
      }

      // If we can create more connections, do so
      if (this.connections.size < this.options.maxConnections) {
        try {
          const newConnection = this.createConnection(databasePath);
          clearTimeout(timeout);
          this.metrics.queuedRequests--;
          this.metrics.averageWaitTime = this.updateAverageWaitTime(Date.now() - startTime);
          resolve(this.markConnectionInUse(newConnection));
          return;
        } catch (error) {
          logger.error('Failed to create new connection:', error);
        }
      }

      // Queue the request
      this.waitingQueue.push({
        resolve: (connection: PooledConnection) => {
          clearTimeout(timeout);
          this.metrics.queuedRequests--;
          this.metrics.averageWaitTime = this.updateAverageWaitTime(Date.now() - startTime);
          resolve(connection);
        },
        reject,
        timeout
      });
    });
  }

  releaseConnection(connection: PooledConnection): void {
    connection.inUse = false;
    connection.lastUsed = Date.now();
    this.metrics.activeConnections--;

    // Process waiting queue
    if (this.waitingQueue.length > 0) {
      const waiting = this.waitingQueue.shift();
      if (waiting) {
        waiting.resolve(this.markConnectionInUse(connection));
      }
    }
  }

  async closeConnection(connectionId: string): Promise<void> {
    const connection = this.connections.get(connectionId);
    if (!connection) {
      return;
    }

    try {
      connection.database.close();
      this.connections.delete(connectionId);
      this.metrics.totalConnections--;
      
      if (connection.inUse) {
        this.metrics.activeConnections--;
      }

      logger.info(`Closed database connection ${connectionId}`);
    } catch (error) {
      logger.error(`Error closing connection ${connectionId}:`, error);
    }
  }

  async closeAllConnections(): Promise<void> {
    const closePromises = Array.from(this.connections.keys()).map(id => 
      this.closeConnection(id)
    );

    await Promise.allSettled(closePromises);

    // Clear waiting queue
    while (this.waitingQueue.length > 0) {
      const waiting = this.waitingQueue.shift();
      if (waiting) {
        clearTimeout(waiting.timeout);
        waiting.reject(new Error('Connection pool shutting down'));
      }
    }

    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    logger.info('All database connections closed');
  }

  getMetrics() {
    return {
      ...this.metrics,
      poolSize: this.connections.size,
      availableConnections: Array.from(this.connections.values()).filter(c => !c.inUse).length,
      queuedRequests: this.waitingQueue.length
    };
  }

  getHealthStatus() {
    const metrics = this.getMetrics();
    const healthy = {
      poolNotOverloaded: metrics.queuedRequests < this.options.maxConnections,
      connectionsHealthy: metrics.totalErrors / Math.max(metrics.totalQueries, 1) < 0.1,
      responseTimeGood: metrics.averageWaitTime < 1000
    };

    return {
      healthy: Object.values(healthy).every(Boolean),
      checks: healthy,
      metrics
    };
  }

  private findAvailableConnection(databasePath: string): PooledConnection | null {
    for (const connection of this.connections.values()) {
      if (!connection.inUse && this.isConnectionValid(connection)) {
        return connection;
      }
    }
    return null;
  }

  private createConnection(databasePath: string): PooledConnection {
    const Database = require('better-sqlite3');
    const id = `conn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      const database = new Database(databasePath, {
        timeout: this.options.connectionTimeout,
        verbose: process.env.NODE_ENV === 'development' ? logger.debug : undefined
      });

      // Set pragmas for better performance
      database.pragma('journal_mode = WAL');
      database.pragma('synchronous = NORMAL');
      database.pragma('cache_size = 10000');
      database.pragma('temp_store = MEMORY');

      const connection: PooledConnection = {
        id,
        database,
        lastUsed: Date.now(),
        inUse: false,
        queries: 0,
        errors: 0
      };

      this.connections.set(id, connection);
      this.metrics.totalConnections++;

      logger.info(`Created new database connection ${id} for ${databasePath}`);
      return connection;
    } catch (error) {
      logger.error(`Failed to create database connection for ${databasePath}:`, error);
      throw error;
    }
  }

  private markConnectionInUse(connection: PooledConnection): PooledConnection {
    connection.inUse = true;
    connection.lastUsed = Date.now();
    this.metrics.activeConnections++;
    return connection;
  }

  private isConnectionValid(connection: PooledConnection): boolean {
    try {
      // Simple health check query
      connection.database.prepare('SELECT 1').get();
      return true;
    } catch (error) {
      logger.warn(`Connection ${connection.id} failed health check:`, error);
      connection.errors++;
      return false;
    }
  }

  private startCleanupTimer(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupIdleConnections();
    }, 60000); // Run cleanup every minute
  }

  private cleanupIdleConnections(): void {
    const now = Date.now();
    const connectionsToClose: string[] = [];

    for (const [id, connection] of this.connections.entries()) {
      if (!connection.inUse && 
          now - connection.lastUsed > this.options.idleTimeout &&
          this.connections.size > this.options.minConnections) {
        connectionsToClose.push(id);
      }
    }

    // Close idle connections
    connectionsToClose.forEach(id => {
      this.closeConnection(id);
    });

    if (connectionsToClose.length > 0) {
      logger.info(`Cleaned up ${connectionsToClose.length} idle connections`);
    }
  }

  private ensureMinConnections(): void {
    // This would need to be implemented if we want to maintain minimum connections
    // For now, connections are created on demand
  }

  private updateAverageWaitTime(waitTime: number): number {
    if (this.metrics.totalQueries === 0) {
      return waitTime;
    }
    
    // Simple moving average
    const alpha = 0.1;
    return this.metrics.averageWaitTime * (1 - alpha) + waitTime * alpha;
  }

  // Wrapper methods for common database operations with automatic connection management
  async executeQuery<T = any>(
    databasePath: string, 
    query: string, 
    params: any[] = []
  ): Promise<T[]> {
    let connection: PooledConnection | null = null;
    
    try {
      connection = await this.acquireConnection(databasePath);
      connection.queries++;
      this.metrics.totalQueries++;
      
      const stmt = connection.database.prepare(query);
      const result = stmt.all(...params);
      
      return result as T[];
    } catch (error) {
      if (connection) {
        connection.errors++;
      }
      this.metrics.totalErrors++;
      logger.error('Database query error:', error);
      throw error;
    } finally {
      if (connection) {
        this.releaseConnection(connection);
      }
    }
  }

  async executeStatement(
    databasePath: string, 
    query: string, 
    params: any[] = []
  ): Promise<{ changes: number; lastInsertRowid: number }> {
    let connection: PooledConnection | null = null;
    
    try {
      connection = await this.acquireConnection(databasePath);
      connection.queries++;
      this.metrics.totalQueries++;
      
      const stmt = connection.database.prepare(query);
      const result = stmt.run(...params);
      
      return {
        changes: result.changes,
        lastInsertRowid: Number(result.lastInsertRowid)
      };
    } catch (error) {
      if (connection) {
        connection.errors++;
      }
      this.metrics.totalErrors++;
      logger.error('Database statement error:', error);
      throw error;
    } finally {
      if (connection) {
        this.releaseConnection(connection);
      }
    }
  }

  async executeTransaction<T>(
    databasePath: string, 
    callback: (db: Database) => T
  ): Promise<T> {
    let connection: PooledConnection | null = null;
    
    try {
      connection = await this.acquireConnection(databasePath);
      connection.queries++;
      this.metrics.totalQueries++;
      
      return connection.database.transaction(callback)();
    } catch (error) {
      if (connection) {
        connection.errors++;
      }
      this.metrics.totalErrors++;
      logger.error('Database transaction error:', error);
      throw error;
    } finally {
      if (connection) {
        this.releaseConnection(connection);
      }
    }
  }
}

// Singleton instance
let connectionPoolManager: ConnectionPoolManager | null = null;

export function getConnectionPool(options?: Partial<ConnectionPoolOptions>): ConnectionPoolManager {
  if (!connectionPoolManager) {
    connectionPoolManager = new ConnectionPoolManager(options);
  }
  return connectionPoolManager;
}

export async function closeConnectionPool(): Promise<void> {
  if (connectionPoolManager) {
    await connectionPoolManager.closeAllConnections();
    connectionPoolManager = null;
  }
}