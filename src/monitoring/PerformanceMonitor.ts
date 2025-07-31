import logger from '../utils/logger';

export interface PerformanceMetrics {
  toolCalls: {
    total: number;
    successful: number;
    failed: number;
    averageTime: number;
    slowestCall: { tool: string; duration: number };
    fastestCall: { tool: string; duration: number };
    byTool: Record<string, {
      count: number;
      totalTime: number;
      averageTime: number;
      successRate: number;
    }>;
  };
  securityScans: {
    total: number;
    averageTime: number;
    vulnerabilitiesFound: number;
    falsePositives: number;
  };
  patternAnalysis: {
    total: number;
    averageTime: number;
    patternsLearned: number;
    complianceChecks: number;
  };
  knowledgeQueries: {
    total: number;
    averageTime: number;
    averageConfidence: number;
    cacheHitRate: number;
  };
  navigationQueries: {
    total: number;
    averageTime: number;
    searchesPerformed: number;
    symbolsFound: number;
  };
  governanceChecks: {
    total: number;
    averageTime: number;
    violationsFound: number;
    rulesEvaluated: number;
  };
  system: {
    memoryUsage: NodeJS.MemoryUsage;
    uptime: number;
    cpuUsage: number;
    requestsPerMinute: number;
  };
}

export interface AlertRule {
  name: string;
  condition: (metrics: PerformanceMetrics) => boolean;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  cooldown: number; // Minutes before same alert can fire again
}

export class PerformanceMonitor {
  private metrics: PerformanceMetrics;
  private startTime: number;
  private recentRequests: number[] = [];
  private alertRules: AlertRule[] = [];
  private lastAlerts: Map<string, number> = new Map();
  private enableProfiling: boolean = false;

  constructor() {
    this.startTime = Date.now();
    this.metrics = this.initializeMetrics();
    this.setupDefaultAlertRules();
    
    // Start periodic collection of system metrics
    this.startSystemMetricsCollection();
  }

  recordToolCall(toolName: string, duration: number, success: boolean): void {
    this.metrics.toolCalls.total++;
    
    if (success) {
      this.metrics.toolCalls.successful++;
    } else {
      this.metrics.toolCalls.failed++;
    }

    // Update tool-specific metrics
    if (!this.metrics.toolCalls.byTool[toolName]) {
      this.metrics.toolCalls.byTool[toolName] = {
        count: 0,
        totalTime: 0,
        averageTime: 0,
        successRate: 0
      };
    }

    const toolMetrics = this.metrics.toolCalls.byTool[toolName];
    toolMetrics.count++;
    toolMetrics.totalTime += duration;
    toolMetrics.averageTime = toolMetrics.totalTime / toolMetrics.count;
    toolMetrics.successRate = success ? 
      (toolMetrics.successRate * (toolMetrics.count - 1) + 1) / toolMetrics.count :
      (toolMetrics.successRate * (toolMetrics.count - 1)) / toolMetrics.count;

    // Update overall averages
    this.updateOverallAverages();

    // Update slowest/fastest calls
    if (!this.metrics.toolCalls.slowestCall || duration > this.metrics.toolCalls.slowestCall.duration) {
      this.metrics.toolCalls.slowestCall = { tool: toolName, duration };
    }
    
    if (!this.metrics.toolCalls.fastestCall || duration < this.metrics.toolCalls.fastestCall.duration) {
      this.metrics.toolCalls.fastestCall = { tool: toolName, duration };
    }

    // Track requests per minute
    this.recentRequests.push(Date.now());
    this.cleanupOldRequests();

    // Check alert conditions
    this.checkAlerts();

    if (this.enableProfiling) {
      logger.debug(`Tool call performance: ${toolName} - ${duration}ms (${success ? 'success' : 'failed'})`);
    }
  }

  recordSecurityScan(scanType: string, duration: number, vulnerabilitiesFound: number = 0): void {
    this.metrics.securityScans.total++;
    this.metrics.securityScans.averageTime = this.calculateNewAverage(
      this.metrics.securityScans.averageTime,
      duration,
      this.metrics.securityScans.total
    );
    this.metrics.securityScans.vulnerabilitiesFound += vulnerabilitiesFound;

    logger.debug(`Security scan: ${scanType} - ${duration}ms, found ${vulnerabilitiesFound} issues`);
  }

  recordPatternAnalysis(analysisType: string, duration: number, patternsLearned: number = 0): void {
    this.metrics.patternAnalysis.total++;
    this.metrics.patternAnalysis.averageTime = this.calculateNewAverage(
      this.metrics.patternAnalysis.averageTime,
      duration,
      this.metrics.patternAnalysis.total
    );
    
    if (patternsLearned > 0) {
      this.metrics.patternAnalysis.patternsLearned += patternsLearned;
    } else {
      this.metrics.patternAnalysis.complianceChecks++;
    }

    logger.debug(`Pattern analysis: ${analysisType} - ${duration}ms, learned ${patternsLearned} patterns`);
  }

  recordKnowledgeQuery(queryType: string, duration: number, confidence: number = 1.0, cacheHit: boolean = false): void {
    this.metrics.knowledgeQueries.total++;
    this.metrics.knowledgeQueries.averageTime = this.calculateNewAverage(
      this.metrics.knowledgeQueries.averageTime,
      duration,
      this.metrics.knowledgeQueries.total
    );
    
    this.metrics.knowledgeQueries.averageConfidence = this.calculateNewAverage(
      this.metrics.knowledgeQueries.averageConfidence,
      confidence,
      this.metrics.knowledgeQueries.total
    );

    if (cacheHit) {
      const totalQueries = this.metrics.knowledgeQueries.total;
      const currentHitRate = this.metrics.knowledgeQueries.cacheHitRate;
      this.metrics.knowledgeQueries.cacheHitRate = ((currentHitRate * (totalQueries - 1)) + 1) / totalQueries;
    }

    logger.debug(`Knowledge query: ${queryType} - ${duration}ms, confidence: ${confidence}, cache: ${cacheHit ? 'hit' : 'miss'}`);
  }

  recordNavigationQuery(queryType: string, duration: number, resultsFound: number = 0): void {
    this.metrics.navigationQueries.total++;
    this.metrics.navigationQueries.averageTime = this.calculateNewAverage(
      this.metrics.navigationQueries.averageTime,
      duration,
      this.metrics.navigationQueries.total
    );
    
    this.metrics.navigationQueries.searchesPerformed++;
    this.metrics.navigationQueries.symbolsFound += resultsFound;

    logger.debug(`Navigation query: ${queryType} - ${duration}ms, found ${resultsFound} results`);
  }

  recordGovernanceCheck(checkType: string, duration: number, violationsFound: number = 0, rulesEvaluated: number = 0): void {
    this.metrics.governanceChecks.total++;
    this.metrics.governanceChecks.averageTime = this.calculateNewAverage(
      this.metrics.governanceChecks.averageTime,
      duration,
      this.metrics.governanceChecks.total
    );
    
    this.metrics.governanceChecks.violationsFound += violationsFound;
    this.metrics.governanceChecks.rulesEvaluated += rulesEvaluated;

    logger.debug(`Governance check: ${checkType} - ${duration}ms, ${violationsFound} violations, ${rulesEvaluated} rules`);
  }

  getMetrics(): PerformanceMetrics {
    this.updateSystemMetrics();
    return { ...this.metrics };
  }

  generateReport(): any {
    const metrics = this.getMetrics();
    const uptime = Date.now() - this.startTime;

    return {
      timestamp: new Date().toISOString(),
      uptime: this.formatDuration(uptime),
      summary: {
        totalRequests: metrics.toolCalls.total,
        successRate: metrics.toolCalls.total > 0 ? 
          (metrics.toolCalls.successful / metrics.toolCalls.total * 100).toFixed(1) + '%' : 'N/A',
        averageResponseTime: Math.round(metrics.toolCalls.averageTime) + 'ms',
        requestsPerMinute: Math.round(metrics.system.requestsPerMinute),
        memoryUsage: this.formatBytes(metrics.system.memoryUsage.heapUsed),
        topPerformingTools: this.getTopPerformingTools(),
        slowestTools: this.getSlowestTools()
      },
      detailed: {
        toolCalls: metrics.toolCalls,
        securityScans: metrics.securityScans,
        patternAnalysis: metrics.patternAnalysis,
        knowledgeQueries: metrics.knowledgeQueries,
        navigationQueries: metrics.navigationQueries,
        governanceChecks: metrics.governanceChecks
      },
      system: {
        memory: {
          used: this.formatBytes(metrics.system.memoryUsage.heapUsed),
          total: this.formatBytes(metrics.system.memoryUsage.heapTotal),
          external: this.formatBytes(metrics.system.memoryUsage.external),
          rss: this.formatBytes(metrics.system.memoryUsage.rss)
        },
        uptime: this.formatDuration(metrics.system.uptime),
        cpuUsage: metrics.system.cpuUsage.toFixed(1) + '%'
      },
      recommendations: this.generateRecommendations(metrics)
    };
  }

  addAlertRule(rule: AlertRule): void {
    this.alertRules.push(rule);
    logger.info(`Added alert rule: ${rule.name}`);
  }

  removeAlertRule(ruleName: string): void {
    this.alertRules = this.alertRules.filter(rule => rule.name !== ruleName);
    logger.info(`Removed alert rule: ${ruleName}`);
  }

  enableProfiling(): void {
    this.enableProfiling = true;
    logger.info('Performance profiling enabled');
  }

  disableProfiling(): void {
    this.enableProfiling = false;
    logger.info('Performance profiling disabled');
  }

  reset(): void {
    this.metrics = this.initializeMetrics();
    this.startTime = Date.now();
    this.recentRequests = [];
    this.lastAlerts.clear();
    logger.info('Performance metrics reset');
  }

  private initializeMetrics(): PerformanceMetrics {
    return {
      toolCalls: {
        total: 0,
        successful: 0,
        failed: 0,
        averageTime: 0,
        slowestCall: { tool: '', duration: 0 },
        fastestCall: { tool: '', duration: Infinity },
        byTool: {}
      },
      securityScans: {
        total: 0,
        averageTime: 0,
        vulnerabilitiesFound: 0,
        falsePositives: 0
      },
      patternAnalysis: {
        total: 0,
        averageTime: 0,
        patternsLearned: 0,
        complianceChecks: 0
      },
      knowledgeQueries: {
        total: 0,
        averageTime: 0,
        averageConfidence: 0,
        cacheHitRate: 0
      },
      navigationQueries: {
        total: 0,
        averageTime: 0,
        searchesPerformed: 0,
        symbolsFound: 0
      },
      governanceChecks: {
        total: 0,
        averageTime: 0,
        violationsFound: 0,
        rulesEvaluated: 0
      },
      system: {
        memoryUsage: process.memoryUsage(),
        uptime: 0,
        cpuUsage: 0,
        requestsPerMinute: 0
      }
    };
  }

  private updateOverallAverages(): void {
    const totalTime = Object.values(this.metrics.toolCalls.byTool)
      .reduce((sum, tool) => sum + tool.totalTime, 0);
    
    this.metrics.toolCalls.averageTime = this.metrics.toolCalls.total > 0 ? 
      totalTime / this.metrics.toolCalls.total : 0;
  }

  private calculateNewAverage(currentAverage: number, newValue: number, count: number): number {
    return ((currentAverage * (count - 1)) + newValue) / count;
  }

  private cleanupOldRequests(): void {
    const oneMinuteAgo = Date.now() - 60000;
    this.recentRequests = this.recentRequests.filter(timestamp => timestamp > oneMinuteAgo);
  }

  private updateSystemMetrics(): void {
    this.metrics.system.memoryUsage = process.memoryUsage();
    this.metrics.system.uptime = Date.now() - this.startTime;
    this.metrics.system.requestsPerMinute = this.recentRequests.length;
    
    // Simple CPU usage estimation (not completely accurate)
    const usage = process.cpuUsage();
    this.metrics.system.cpuUsage = (usage.user + usage.system) / 1000000; // Convert to seconds
  }

  private startSystemMetricsCollection(): void {
    setInterval(() => {
      this.updateSystemMetrics();
      this.cleanupOldRequests();
    }, 30000); // Every 30 seconds
  }

  private setupDefaultAlertRules(): void {
    this.alertRules = [
      {
        name: 'high_response_time',
        condition: (metrics) => metrics.toolCalls.averageTime > 5000, // 5 seconds
        severity: 'warning',
        message: 'Average response time is high',
        cooldown: 10
      },
      {
        name: 'high_failure_rate',
        condition: (metrics) => {
          const failureRate = metrics.toolCalls.total > 0 ? 
            metrics.toolCalls.failed / metrics.toolCalls.total : 0;
          return failureRate > 0.1; // 10% failure rate
        },
        severity: 'error',
        message: 'Tool call failure rate is high',
        cooldown: 5
      },
      {
        name: 'high_memory_usage',
        condition: (metrics) => metrics.system.memoryUsage.heapUsed > 1024 * 1024 * 1024, // 1GB
        severity: 'warning',
        message: 'Memory usage is high',
        cooldown: 15
      },
      {
        name: 'low_confidence',
        condition: (metrics) => metrics.knowledgeQueries.averageConfidence < 0.5,
        severity: 'info',
        message: 'Knowledge query confidence is low',
        cooldown: 30
      }
    ];
  }

  private checkAlerts(): void {
    const now = Date.now();
    
    this.alertRules.forEach(rule => {
      const lastAlert = this.lastAlerts.get(rule.name) || 0;
      const cooldownMs = rule.cooldown * 60 * 1000;
      
      if (now - lastAlert < cooldownMs) {
        return; // Still in cooldown
      }

      if (rule.condition(this.metrics)) {
        this.fireAlert(rule);
        this.lastAlerts.set(rule.name, now);
      }
    });
  }

  private fireAlert(rule: AlertRule): void {
    const alertMessage = `[${rule.severity.toUpperCase()}] ${rule.message}`;
    
    switch (rule.severity) {
      case 'critical':
      case 'error':
        logger.error(`Performance Alert: ${alertMessage}`);
        break;
      case 'warning':
        logger.warn(`Performance Alert: ${alertMessage}`);
        break;
      case 'info':
        logger.info(`Performance Alert: ${alertMessage}`);
        break;
    }

    // Could extend this to send notifications to external systems
  }

  private getTopPerformingTools(): any[] {
    return Object.entries(this.metrics.toolCalls.byTool)
      .sort(([, a], [, b]) => b.successRate - a.successRate)
      .slice(0, 5)
      .map(([tool, metrics]) => ({
        tool,
        successRate: (metrics.successRate * 100).toFixed(1) + '%',
        averageTime: Math.round(metrics.averageTime) + 'ms',
        calls: metrics.count
      }));
  }

  private getSlowestTools(): any[] {
    return Object.entries(this.metrics.toolCalls.byTool)
      .sort(([, a], [, b]) => b.averageTime - a.averageTime)
      .slice(0, 5)
      .map(([tool, metrics]) => ({
        tool,
        averageTime: Math.round(metrics.averageTime) + 'ms',
        calls: metrics.count,
        successRate: (metrics.successRate * 100).toFixed(1) + '%'
      }));
  }

  private generateRecommendations(metrics: PerformanceMetrics): string[] {
    const recommendations = [];

    if (metrics.toolCalls.averageTime > 3000) {
      recommendations.push('Consider optimizing slow-performing tools or increasing timeout values');
    }

    if (metrics.system.memoryUsage.heapUsed > 512 * 1024 * 1024) { // 512MB
      recommendations.push('Memory usage is elevated - consider implementing garbage collection or reducing cache sizes');
    }

    const failureRate = metrics.toolCalls.total > 0 ? 
      metrics.toolCalls.failed / metrics.toolCalls.total : 0;
    
    if (failureRate > 0.05) { // 5% failure rate
      recommendations.push('Tool failure rate is above normal - check error logs and input validation');
    }

    if (metrics.knowledgeQueries.cacheHitRate < 0.3) {
      recommendations.push('Knowledge query cache hit rate is low - consider adjusting cache strategy or size');
    }

    if (metrics.system.requestsPerMinute > 100) {
      recommendations.push('High request volume detected - consider implementing rate limiting or scaling');
    }

    if (recommendations.length === 0) {
      recommendations.push('System performance is within normal parameters');
    }

    return recommendations;
  }

  private formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}