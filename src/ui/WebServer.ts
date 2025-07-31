import { createServer, IncomingMessage, ServerResponse } from 'http';
import { parse } from 'url';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { ConfigurationManager } from '../config/ConfigurationManager';
import { PerformanceMonitor } from '../monitoring/PerformanceMonitor';
import DatabaseManager from '../database/schema';
import logger from '../utils/logger';

export interface WebServerOptions {
  port: number;
  host?: string;
  enableCORS?: boolean;
  staticDir?: string;
}

export class WebServer {
  private server: any;
  private configManager: ConfigurationManager;
  private performanceMonitor: PerformanceMonitor;
  private database: DatabaseManager;
  private options: WebServerOptions;
  private isRunning: boolean = false;

  constructor(
    configManager: ConfigurationManager,
    performanceMonitor: PerformanceMonitor,
    database: DatabaseManager,
    options: WebServerOptions
  ) {
    this.configManager = configManager;
    this.performanceMonitor = performanceMonitor;
    this.database = database;
    this.options = {
      host: '127.0.0.1',
      enableCORS: true,
      staticDir: join(__dirname, '../../ui/static'),
      ...options
    };
  }

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Web server is already running');
    }

    this.server = createServer((req, res) => {
      this.handleRequest(req, res).catch(error => {
        logger.error('Error handling web request:', error);
        this.sendError(res, 500, 'Internal Server Error');
      });
    });

    return new Promise((resolve, reject) => {
      this.server.listen(this.options.port, this.options.host, (error: any) => {
        if (error) {
          reject(error);
        } else {
          this.isRunning = true;
          logger.info(`Web UI server started on http://${this.options.host}:${this.options.port}`);
          resolve();
        }
      });
    });
  }

  async stop(): Promise<void> {
    if (!this.isRunning || !this.server) {
      return;
    }

    return new Promise((resolve) => {
      this.server.close(() => {
        this.isRunning = false;
        logger.info('Web UI server stopped');
        resolve();
      });
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const parsedUrl = parse(req.url || '', true);
    const pathname = parsedUrl.pathname || '/';
    const method = req.method || 'GET';

    // Enable CORS if configured
    if (this.options.enableCORS) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      
      if (method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }
    }

    try {
      // Route handling
      if (pathname.startsWith('/api/')) {
        await this.handleApiRequest(pathname, method, req, res);
      } else {
        await this.handleStaticRequest(pathname, res);
      }
    } catch (error) {
      logger.error('Request handling error:', error);
      this.sendError(res, 500, 'Internal Server Error');
    }
  }

  private async handleApiRequest(pathname: string, method: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const apiPath = pathname.substring(4); // Remove '/api' prefix

    switch (apiPath) {
      case '/health':
        await this.handleHealthCheck(res);
        break;
      
      case '/metrics':
        await this.handleMetrics(res);
        break;
      
      case '/performance':
        await this.handlePerformanceReport(res);
        break;
      
      case '/config':
        if (method === 'GET') {
          await this.handleGetConfig(res);
        } else if (method === 'PUT') {
          await this.handleUpdateConfig(req, res);
        } else {
          this.sendError(res, 405, 'Method Not Allowed');
        }
        break;
      
      case '/patterns':
        await this.handlePatterns(res);
        break;
      
      case '/security':
        await this.handleSecurityOverview(res);
        break;
      
      case '/governance':
        await this.handleGovernanceStatus(res);
        break;
      
      case '/tools':
        await this.handleToolsStatus(res);
        break;
      
      case '/search':
        await this.handleSearch(req, res);
        break;
      
      default:
        this.sendError(res, 404, 'API endpoint not found');
    }
  }

  private async handleStaticRequest(pathname: string, res: ServerResponse): Promise<void> {
    // Serve static files or default to dashboard
    let filePath: string;
    
    if (pathname === '/' || pathname === '/dashboard') {
      filePath = join(this.options.staticDir || '', 'index.html');
    } else {
      filePath = join(this.options.staticDir || '', pathname);
    }

    // Security check - prevent directory traversal
    if (!filePath.startsWith(this.options.staticDir || '')) {
      this.sendError(res, 403, 'Forbidden');
      return;
    }

    if (existsSync(filePath)) {
      try {
        const content = readFileSync(filePath);
        const contentType = this.getContentType(filePath);
        
        res.setHeader('Content-Type', contentType);
        res.writeHead(200);
        res.end(content);
      } catch (error) {
        logger.error('Error serving static file:', error);
        this.sendError(res, 500, 'Error serving file');
      }
    } else {
      // If file doesn't exist, check if we have built-in UI
      this.serveBuiltInUI(pathname, res);
    }
  }

  private async handleHealthCheck(res: ServerResponse): Promise<void> {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: this.configManager.getConfig().version || '1.0.0',
      services: {
        database: await this.checkDatabaseHealth(),
        patterns: true, // Could add actual health checks
        security: true,
        knowledge: true
      }
    };

    this.sendJson(res, health);
  }

  private async handleMetrics(res: ServerResponse): Promise<void> {
    const metrics = this.performanceMonitor.getMetrics();
    this.sendJson(res, metrics);
  }

  private async handlePerformanceReport(res: ServerResponse): Promise<void> {
    const report = this.performanceMonitor.generateReport();
    this.sendJson(res, report);
  }

  private async handleGetConfig(res: ServerResponse): Promise<void> {
    const config = this.configManager.getConfig();
    // Remove sensitive information
    const safeConfig = {
      ...config,
      integrations: undefined // Don't expose integration secrets
    };
    this.sendJson(res, safeConfig);
  }

  private async handleUpdateConfig(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const body = await this.readRequestBody(req);
      const updates = JSON.parse(body);
      
      // Validate and sanitize updates
      const validatedUpdates = this.validateConfigUpdates(updates);
      
      this.configManager.updateConfig(validatedUpdates);
      
      this.sendJson(res, { 
        success: true, 
        message: 'Configuration updated successfully' 
      });
    } catch (error) {
      logger.error('Error updating configuration:', error);
      this.sendError(res, 400, 'Invalid configuration update');
    }
  }

  private async handlePatterns(res: ServerResponse): Promise<void> {
    try {
      const db = this.database.getDb();
      
      // Get pattern statistics
      const patternStats = db.prepare(`
        SELECT 
          category,
          COUNT(*) as count,
          AVG(confidence_threshold) as avg_confidence,
          COUNT(CASE WHEN is_approved = 1 THEN 1 END) as approved_count
        FROM patterns
        GROUP BY category
      `).all();

      // Get recent pattern instances
      const recentInstances = db.prepare(`
        SELECT p.name, p.category, pi.file_path, pi.confidence, pi.line_start
        FROM pattern_instances pi
        JOIN patterns p ON pi.pattern_id = p.id
        ORDER BY pi.id DESC
        LIMIT 20
      `).all();

      const response = {
        statistics: patternStats,
        recentInstances,
        totalPatterns: patternStats.reduce((sum: number, stat: any) => sum + stat.count, 0),
        categories: patternStats.map((stat: any) => stat.category)
      };

      this.sendJson(res, response);
    } catch (error) {
      logger.error('Error fetching patterns:', error);
      this.sendError(res, 500, 'Error fetching pattern data');
    }
  }

  private async handleSecurityOverview(res: ServerResponse): Promise<void> {
    try {
      const db = this.database.getDb();
      
      // Get security issue statistics
      const securityStats = db.prepare(`
        SELECT 
          severity,
          category,
          COUNT(*) as count,
          COUNT(CASE WHEN resolved = 0 THEN 1 END) as unresolved_count
        FROM security_issues
        GROUP BY severity, category
        ORDER BY 
          CASE severity 
            WHEN 'critical' THEN 1 
            WHEN 'high' THEN 2 
            WHEN 'medium' THEN 3 
            WHEN 'low' THEN 4 
            ELSE 5 
          END
      `).all();

      // Get recent security issues
      const recentIssues = db.prepare(`
        SELECT severity, category, file_path, line_start, description, detected_at
        FROM security_issues
        WHERE resolved = 0
        ORDER BY detected_at DESC
        LIMIT 15
      `).all();

      const response = {
        statistics: securityStats,
        recentIssues,
        summary: {
          total: securityStats.reduce((sum: number, stat: any) => sum + stat.count, 0),
          unresolved: securityStats.reduce((sum: number, stat: any) => sum + stat.unresolved_count, 0),
          critical: securityStats.filter((s: any) => s.severity === 'critical').reduce((sum: number, stat: any) => sum + stat.unresolved_count, 0)
        }
      };

      this.sendJson(res, response);
    } catch (error) {
      logger.error('Error fetching security data:', error);
      this.sendError(res, 500, 'Error fetching security data');
    }
  }

  private async handleGovernanceStatus(res: ServerResponse): Promise<void> {
    try {
      const db = this.database.getDb();
      
      // Get governance violation statistics
      const violations = db.prepare(`
        SELECT 
          gr.rule_type,
          gr.severity,
          COUNT(pv.id) as violation_count,
          COUNT(CASE WHEN pv.resolved = 0 THEN 1 END) as unresolved_count
        FROM governance_rules gr
        LEFT JOIN pattern_violations pv ON gr.id = pv.rule_id
        GROUP BY gr.rule_type, gr.severity
        ORDER BY violation_count DESC
      `).all();

      const response = {
        violations,
        summary: {
          totalViolations: violations.reduce((sum: number, v: any) => sum + v.violation_count, 0),
          unresolvedViolations: violations.reduce((sum: number, v: any) => sum + v.unresolved_count, 0),
          ruleTypes: [...new Set(violations.map((v: any) => v.rule_type))]
        }
      };

      this.sendJson(res, response);
    } catch (error) {
      logger.error('Error fetching governance data:', error);
      this.sendError(res, 500, 'Error fetching governance data');
    }
  }

  private async handleToolsStatus(res: ServerResponse): Promise<void> {
    const metrics = this.performanceMonitor.getMetrics();
    const config = this.configManager.getConfig();

    const response = {
      enabledTools: config.tools.enabled,
      disabledTools: config.tools.disabled,
      performance: metrics.toolCalls.byTool,
      summary: {
        totalCalls: metrics.toolCalls.total,
        successRate: metrics.toolCalls.total > 0 ? 
          (metrics.toolCalls.successful / metrics.toolCalls.total * 100).toFixed(1) + '%' : 'N/A',
        averageTime: Math.round(metrics.toolCalls.averageTime) + 'ms'
      }
    };

    this.sendJson(res, response);
  }

  private async handleSearch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const url = parse(req.url || '', true);
      const query = url.query.q as string;
      
      if (!query) {
        this.sendError(res, 400, 'Search query is required');
        return;
      }

      const db = this.database.getDb();
      
      // Search symbols using FTS
      const results = db.prepare(`
        SELECT s.name, s.kind, s.file_path, s.line_start, s.doc_comment,
               snippet(symbols_fts, 0, '<mark>', '</mark>', '...', 32) as snippet
        FROM symbols_fts
        JOIN symbols s ON symbols_fts.rowid = s.id
        WHERE symbols_fts MATCH ?
        ORDER BY bm25(symbols_fts)
        LIMIT 25
      `).all(query);

      this.sendJson(res, {
        query,
        results,
        count: results.length
      });
    } catch (error) {
      logger.error('Error performing search:', error);
      this.sendError(res, 500, 'Search error');
    }
  }

  private serveBuiltInUI(pathname: string, res: ServerResponse): void {
    // Serve a simple built-in dashboard if no static files are available
    const html = this.generateDashboardHTML();
    
    res.setHeader('Content-Type', 'text/html');
    res.writeHead(200);
    res.end(html);
  }

  private generateDashboardHTML(): string {
    const config = this.configManager.getConfig();
    const metrics = this.performanceMonitor.getMetrics();

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Codebase Intelligence Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .header h1 { color: #333; margin-bottom: 10px; }
            .header p { color: #666; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .card h2 { color: #333; margin-bottom: 15px; font-size: 18px; }
            .metric { display: flex; justify-content: space-between; margin-bottom: 10px; }
            .metric .label { color: #666; }
            .metric .value { font-weight: 600; color: #333; }
            .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
            .status.healthy { background: #d4edda; color: #155724; }
            .status.warning { background: #fff3cd; color: #856404; }
            .status.error { background: #f8d7da; color: #721c24; }
            .api-endpoints { margin-top: 20px; }
            .api-endpoints h3 { margin-bottom: 10px; }
            .api-endpoints ul { list-style: none; }
            .api-endpoints li { margin-bottom: 5px; }
            .api-endpoints a { color: #007bff; text-decoration: none; }
            .api-endpoints a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🧠 Codebase Intelligence Dashboard</h1>
                <p>Real-time insights into your codebase patterns, security, and governance</p>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h2>System Status</h2>
                    <div class="metric">
                        <span class="label">Status</span>
                        <span class="status healthy">Healthy</span>
                    </div>
                    <div class="metric">
                        <span class="label">Uptime</span>
                        <span class="value">${this.formatUptime(Date.now() - Date.now())}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Memory Usage</span>
                        <span class="value">${this.formatBytes(metrics.system.memoryUsage.heapUsed)}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Requests/min</span>
                        <span class="value">${Math.round(metrics.system.requestsPerMinute)}</span>
                    </div>
                </div>

                <div class="card">
                    <h2>Tool Performance</h2>
                    <div class="metric">
                        <span class="label">Total Calls</span>
                        <span class="value">${metrics.toolCalls.total}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Success Rate</span>
                        <span class="value">${metrics.toolCalls.total > 0 ? 
                          (metrics.toolCalls.successful / metrics.toolCalls.total * 100).toFixed(1) + '%' : 'N/A'}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Avg Response</span>
                        <span class="value">${Math.round(metrics.toolCalls.averageTime)}ms</span>
                    </div>
                    <div class="metric">
                        <span class="label">Active Tools</span>
                        <span class="value">${Object.keys(metrics.toolCalls.byTool).length}</span>
                    </div>
                </div>

                <div class="card">
                    <h2>Security Analysis</h2>
                    <div class="metric">
                        <span class="label">Scans Performed</span>
                        <span class="value">${metrics.securityScans.total}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Vulnerabilities Found</span>
                        <span class="value">${metrics.securityScans.vulnerabilitiesFound}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Avg Scan Time</span>
                        <span class="value">${Math.round(metrics.securityScans.averageTime)}ms</span>
                    </div>
                    <div class="metric">
                        <span class="label">Security Enabled</span>
                        <span class="status ${config.security.enabled ? 'healthy' : 'warning'}">
                            ${config.security.enabled ? 'Yes' : 'No'}
                        </span>
                    </div>
                </div>

                <div class="card">
                    <h2>Pattern Analysis</h2>
                    <div class="metric">
                        <span class="label">Analyses Run</span>
                        <span class="value">${metrics.patternAnalysis.total}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Patterns Learned</span>
                        <span class="value">${metrics.patternAnalysis.patternsLearned}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Compliance Checks</span>
                        <span class="value">${metrics.patternAnalysis.complianceChecks}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Learning Mode</span>
                        <span class="value">${config.patterns.learningMode}</span>
                    </div>
                </div>

                <div class="card">
                    <h2>Knowledge Queries</h2>
                    <div class="metric">
                        <span class="label">Total Queries</span>
                        <span class="value">${metrics.knowledgeQueries.total}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Avg Confidence</span>
                        <span class="value">${(metrics.knowledgeQueries.averageConfidence * 100).toFixed(1)}%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Cache Hit Rate</span>
                        <span class="value">${(metrics.knowledgeQueries.cacheHitRate * 100).toFixed(1)}%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Avg Query Time</span>
                        <span class="value">${Math.round(metrics.knowledgeQueries.averageTime)}ms</span>
                    </div>
                </div>

                <div class="card">
                    <h2>Governance</h2>
                    <div class="metric">
                        <span class="label">Checks Performed</span>
                        <span class="value">${metrics.governanceChecks.total}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Violations Found</span>
                        <span class="value">${metrics.governanceChecks.violationsFound}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Rules Evaluated</span>
                        <span class="value">${metrics.governanceChecks.rulesEvaluated}</span>
                    </div>
                    <div class="metric">
                        <span class="label">Strict Mode</span>
                        <span class="status ${config.governance.strictMode ? 'warning' : 'healthy'}">
                            ${config.governance.strictMode ? 'Enabled' : 'Disabled'}
                        </span>
                    </div>
                </div>
            </div>

            <div class="api-endpoints">
                <h3>API Endpoints</h3>
                <ul>
                    <li><a href="/api/health" target="_blank">Health Check</a> - System health status</li>
                    <li><a href="/api/metrics" target="_blank">Metrics</a> - Detailed performance metrics</li>
                    <li><a href="/api/performance" target="_blank">Performance Report</a> - Comprehensive performance analysis</li>
                    <li><a href="/api/patterns" target="_blank">Patterns</a> - Pattern analysis data</li>
                    <li><a href="/api/security" target="_blank">Security</a> - Security scan results</li>
                    <li><a href="/api/governance" target="_blank">Governance</a> - Governance compliance data</li>
                    <li><a href="/api/tools" target="_blank">Tools</a> - Tool status and performance</li>
                    <li><a href="/api/search?q=function" target="_blank">Search</a> - Code search (example: ?q=function)</li>
                </ul>
            </div>
        </div>

        <script>
            // Auto-refresh every 30 seconds
            setTimeout(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    `;
  }

  private async checkDatabaseHealth(): Promise<boolean> {
    try {
      const db = this.database.getDb();
      db.prepare('SELECT 1').get();
      return true;
    } catch {
      return false;
    }
  }

  private validateConfigUpdates(updates: any): any {
    // Basic validation and sanitization of config updates
    const allowed = ['patterns', 'security', 'governance', 'intelligence', 'server', 'tools'];
    const validated: any = {};

    for (const key of Object.keys(updates)) {
      if (allowed.includes(key)) {
        validated[key] = updates[key];
      }
    }

    return validated;
  }

  private async readRequestBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        resolve(body);
      });
      req.on('error', reject);
    });
  }

  private sendJson(res: ServerResponse, data: any): void {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(200);
    res.end(JSON.stringify(data, null, 2));
  }

  private sendError(res: ServerResponse, status: number, message: string): void {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(status);
    res.end(JSON.stringify({ error: message, status }));
  }

  private getContentType(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const types: Record<string, string> = {
      'html': 'text/html',
      'css': 'text/css',
      'js': 'application/javascript',
      'json': 'application/json',
      'png': 'image/png',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'gif': 'image/gif',
      'svg': 'image/svg+xml',
      'ico': 'image/x-icon'
    };
    return types[ext || ''] || 'text/plain';
  }

  private formatUptime(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m`;
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