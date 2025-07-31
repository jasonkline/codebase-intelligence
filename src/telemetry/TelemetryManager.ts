import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';
import logger from '../utils/logger';

export interface TelemetryEvent {
  id: string;
  timestamp: number;
  sessionId: string;
  userId?: string;
  projectId?: string;
  eventType: string;
  category: 'usage' | 'performance' | 'error' | 'security' | 'system';
  properties: Record<string, any>;
  metrics?: Record<string, number>;
}

export interface SessionInfo {
  sessionId: string;
  startTime: number;
  userId?: string;
  projectPath?: string;
  version: string;
  platform: string;
  nodeVersion: string;
}

export interface TelemetryConfig {
  enabled: boolean;
  endpoint?: string;
  apiKey?: string;
  batchSize: number;
  flushInterval: number;
  retryAttempts: number;
  anonymize: boolean;
  includeSystemMetrics: boolean;
  includePerformanceMetrics: boolean;
  excludePatterns: string[];
}

export class TelemetryManager extends EventEmitter {
  private config: TelemetryConfig;
  private events: TelemetryEvent[] = [];
  private session: SessionInfo;
  private flushTimer: NodeJS.Timeout | null = null;
  private isShuttingDown = false;

  constructor(config: Partial<TelemetryConfig> = {}) {
    super();
    
    this.config = {
      enabled: config.enabled ?? true,
      endpoint: config.endpoint ?? null, // No default telemetry endpoint
      batchSize: config.batchSize ?? 50,
      flushInterval: config.flushInterval ?? 60000, // 1 minute
      retryAttempts: config.retryAttempts ?? 3,
      anonymize: config.anonymize ?? true,
      includeSystemMetrics: config.includeSystemMetrics ?? true,
      includePerformanceMetrics: config.includePerformanceMetrics ?? true,
      excludePatterns: config.excludePatterns ?? []
    };

    // Don't enable telemetry in test environment
    if (process.env.NODE_ENV === 'test') {
      this.config.enabled = false;
    }

    this.session = this.createSession();
    this.startFlushTimer();
    this.trackSystemMetrics();
    
    logger.info(`Telemetry initialized: ${this.config.enabled ? 'enabled' : 'disabled'}`);
  }

  track(
    eventType: string,
    category: TelemetryEvent['category'],
    properties: Record<string, any> = {},
    metrics: Record<string, number> = {}
  ): void {
    if (!this.config.enabled || this.isShuttingDown) {
      return;
    }

    // Check if event should be excluded
    if (this.shouldExcludeEvent(eventType, properties)) {
      return;
    }

    const event: TelemetryEvent = {
      id: randomUUID(),
      timestamp: Date.now(),
      sessionId: this.session.sessionId,
      userId: this.session.userId,
      projectId: this.getProjectId(),
      eventType,
      category,
      properties: this.sanitizeProperties(properties),
      metrics: Object.keys(metrics).length > 0 ? metrics : undefined
    };

    this.events.push(event);
    this.emit('event:tracked', event);

    // Auto-flush if batch size reached
    if (this.events.length >= this.config.batchSize) {
      this.flush().catch(error => {
        logger.error('Auto-flush failed:', error);
      });
    }
  }

  // Convenience methods for common event types
  trackUsage(action: string, properties: Record<string, any> = {}): void {
    this.track(`usage.${action}`, 'usage', properties);
  }

  trackPerformance(operation: string, duration: number, properties: Record<string, any> = {}): void {
    this.track(`performance.${operation}`, 'performance', properties, { duration });
  }

  trackError(error: Error | string, context: Record<string, any> = {}): void {
    const errorInfo = error instanceof Error ? {
      message: error.message,
      stack: error.stack,
      name: error.name
    } : { message: String(error) };

    this.track('error.occurred', 'error', {
      ...context,
      ...errorInfo
    });
  }

  trackSecurity(finding: string, severity: string, properties: Record<string, any> = {}): void {
    this.track(`security.${finding}`, 'security', {
      ...properties,
      severity
    });
  }

  trackAnalysis(type: string, duration: number, results: Record<string, any> = {}): void {
    this.track(`analysis.${type}`, 'performance', {
      analysisType: type,
      ...results
    }, { duration });
  }

  async flush(): Promise<void> {
    if (!this.config.enabled || this.events.length === 0) {
      return;
    }

    const eventsToSend = [...this.events];
    this.events = [];

    try {
      await this.sendEvents(eventsToSend);
      this.emit('events:sent', eventsToSend.length);
      logger.debug(`Sent ${eventsToSend.length} telemetry events`);
    } catch (error) {
      // Put events back in queue for retry
      this.events.unshift(...eventsToSend);
      logger.error('Failed to send telemetry events:', error);
      this.emit('events:failed', error);
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    this.isShuttingDown = true;
    
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }

    // Send any remaining events
    try {
      await this.flush();
      logger.info('Telemetry shutdown completed');
    } catch (error) {
      logger.error('Error during telemetry shutdown:', error);
    }
  }

  getSessionInfo(): SessionInfo {
    return { ...this.session };
  }

  updateConfig(config: Partial<TelemetryConfig>): void {
    this.config = { ...this.config, ...config };
    
    // Restart flush timer if interval changed
    if (config.flushInterval && this.flushTimer) {
      clearInterval(this.flushTimer);
      this.startFlushTimer();
    }

    logger.info('Telemetry configuration updated');
  }

  getMetrics(): Record<string, any> {
    return {
      session: this.session,
      config: {
        enabled: this.config.enabled,
        anonymize: this.config.anonymize,
        batchSize: this.config.batchSize,
        flushInterval: this.config.flushInterval
      },
      stats: {
        queuedEvents: this.events.length,
        sessionDuration: Date.now() - this.session.startTime
      }
    };
  }

  private createSession(): SessionInfo {
    const os = require('os');
    
    return {
      sessionId: randomUUID(),
      startTime: Date.now(),
      userId: this.config.anonymize ? this.hashUserId() : os.userInfo().username,
      projectPath: this.config.anonymize ? undefined : process.env.CI_PROJECT_PATH,
      version: require('../../package.json').version,
      platform: `${os.platform()}-${os.arch()}`,
      nodeVersion: process.version
    };
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch(error => {
        logger.error('Scheduled flush failed:', error);
      });
    }, this.config.flushInterval);
  }

  private async sendEvents(events: TelemetryEvent[]): Promise<void> {
    if (!this.config.endpoint) {
      logger.debug('No telemetry endpoint configured, events not sent');
      return;
    }

    const payload = {
      session: this.session,
      events,
      timestamp: Date.now()
    };

    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        const fetch = (await import('node-fetch')).default;
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        
        const response = await fetch(this.config.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': `codebase-intelligence/${this.session.version}`,
            ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` })
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return; // Success
      } catch (error) {
        lastError = error as Error;
        logger.debug(`Telemetry send attempt ${attempt} failed:`, error);
        
        if (attempt < this.config.retryAttempts) {
          await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
      }
    }

    throw lastError;
  }

  private shouldExcludeEvent(eventType: string, properties: Record<string, any>): boolean {
    return this.config.excludePatterns.some(pattern => {
      return eventType.includes(pattern) || 
             Object.keys(properties).some(key => key.includes(pattern)) ||
             Object.values(properties).some(value => 
               typeof value === 'string' && value.includes(pattern)
             );
    });
  }

  private sanitizeProperties(properties: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(properties)) {
      // Remove sensitive information
      if (this.isSensitiveKey(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'string' && this.containsSensitiveData(value)) {
        sanitized[key] = this.redactSensitiveData(value);
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(item => 
          typeof item === 'string' && this.containsSensitiveData(item) 
            ? this.redactSensitiveData(item) 
            : item
        );
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  private isSensitiveKey(key: string): boolean {
    const sensitiveKeys = [
      'password', 'token', 'key', 'secret', 'auth', 'credential',
      'username', 'email', 'phone', 'ssn', 'credit', 'card'
    ];
    
    return sensitiveKeys.some(sensitive => 
      key.toLowerCase().includes(sensitive)
    );
  }

  private containsSensitiveData(value: string): boolean {
    // Check for common patterns of sensitive data
    const patterns = [
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, // Credit card
      /(?:password|token|key|secret)[:=]\s*[\w\-\.]+/i // Key-value pairs
    ];

    return patterns.some(pattern => pattern.test(value));
  }

  private redactSensitiveData(value: string): string {
    return value
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]')
      .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]')
      .replace(/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, '[CARD]')
      .replace(/(?:password|token|key|secret)[:=]\s*[\w\-\.]+/gi, '$1=[REDACTED]');
  }

  private hashUserId(): string {
    const crypto = require('crypto');
    const os = require('os');
    
    // Create a consistent but anonymous identifier
    const userInfo = os.userInfo().username + os.homedir();
    return crypto.createHash('sha256').update(userInfo).digest('hex').substring(0, 16);
  }

  private getProjectId(): string | undefined {
    if (!this.config.anonymize && process.env.CI_PROJECT_PATH) {
      return process.env.CI_PROJECT_PATH;
    }
    
    if (process.env.CI_PROJECT_PATH) {
      const crypto = require('crypto');
      return crypto.createHash('sha256')
        .update(process.env.CI_PROJECT_PATH)
        .digest('hex')
        .substring(0, 16);
    }
    
    return undefined;
  }

  private trackSystemMetrics(): void {
    if (!this.config.includeSystemMetrics) {
      return;
    }

    // Track system info on startup
    const os = require('os');
    this.track('system.startup', 'system', {
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      cpuCount: os.cpus().length,
      totalMemory: os.totalmem(),
      loadAverage: os.loadavg()
    });

    // Track periodic system metrics
    if (this.config.includePerformanceMetrics) {
      setInterval(() => {
        if (this.isShuttingDown) return;
        
        const memUsage = process.memoryUsage();
        this.track('system.metrics', 'performance', {
          freeMemory: os.freemem(),
          loadAverage: os.loadavg()
        }, {
          heapUsed: memUsage.heapUsed,
          heapTotal: memUsage.heapTotal,
          external: memUsage.external,
          rss: memUsage.rss
        });
      }, 300000); // Every 5 minutes
    }
  }
}

// Singleton instance
let telemetryManager: TelemetryManager | null = null;

export function getTelemetryManager(config?: Partial<TelemetryConfig>): TelemetryManager {
  if (!telemetryManager) {
    telemetryManager = new TelemetryManager(config);
  }
  return telemetryManager;
}

export async function shutdownTelemetry(): Promise<void> {
  if (telemetryManager) {
    await telemetryManager.shutdown();
    telemetryManager = null;
  }
}

// Convenience functions for common tracking patterns
export function trackMCPToolCall(toolName: string, duration: number, success: boolean, properties: Record<string, any> = {}): void {
  const telemetry = getTelemetryManager();
  telemetry.trackUsage('mcp.tool.call', {
    toolName,
    success,
    ...properties
  });
  
  if (duration > 0) {
    telemetry.trackPerformance('mcp.tool.duration', duration, { toolName });
  }
}

export function trackAnalysisOperation(operation: string, duration: number, results: Record<string, any> = {}): void {
  const telemetry = getTelemetryManager();
  telemetry.trackAnalysis(operation, duration, results);
}

export function trackSecurityFinding(severity: string, category: string, properties: Record<string, any> = {}): void {
  const telemetry = getTelemetryManager();
  telemetry.trackSecurity('finding', severity, {
    category,
    ...properties
  });
}

export function trackError(error: Error | string, context: Record<string, any> = {}): void {
  const telemetry = getTelemetryManager();
  telemetry.trackError(error, context);
}

// Helper for timing operations
export function withTelemetryTiming<T>(
  operation: string,
  category: TelemetryEvent['category'],
  fn: () => Promise<T>,
  properties: Record<string, any> = {}
): Promise<T> {
  const telemetry = getTelemetryManager();
  const startTime = Date.now();
  
  return fn()
    .then(result => {
      const duration = Date.now() - startTime;
      telemetry.trackPerformance(operation, duration, properties);
      return result;
    })
    .catch(error => {
      const duration = Date.now() - startTime;
      telemetry.trackError(error, { operation, duration, ...properties });
      throw error;
    });
}