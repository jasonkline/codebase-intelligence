import DatabaseManager, { Pattern, PatternInstance, StylePattern } from '../database/schema';

// Re-export Pattern for other modules
export { Pattern, PatternInstance, StylePattern };
import { ASTPattern, PatternCluster } from './PatternLearner';
import PatternMatcher, { MatchResult } from './PatternMatcher';

// Category analyzers
import AuthPatternsAnalyzer, { AuthPattern, AuthPatternMatch } from './categories/AuthPatterns';
import APIPatternsAnalyzer, { APIPattern, APIPatternMatch } from './categories/APIPatterns';
import DataAccessPatternsAnalyzer, { DataAccessPattern, DataAccessMatch } from './categories/DataAccessPatterns';
import ComponentPatternsAnalyzer, { ComponentPattern, ComponentPatternMatch } from './categories/ComponentPatterns';
import StylePatternsAnalyzer, { StylePattern as StylePatternType, StylePatternMatch } from './categories/StylePatterns';

import logger from '../utils/logger';
import { TSESTree } from '@typescript-eslint/types';

export interface PatternRegistryConfig {
  enabledCategories: string[];
  confidenceThreshold: number;
  autoApproveThreshold: number;
  maxPatternAge: number; // in days
}

export interface PatternMatch {
  pattern: Pattern;
  confidence: number;
  location: {
    file: string;
    line: number;
    column: number;
  };
  context: string;
}

export interface ParsedSymbol {
  name: string;
  kind: string;
  filePath: string;
  line: number;
  column: number;
  signature?: string;
}

export interface PatternSearchQuery {
  category?: string;
  name?: string;
  minConfidence?: number;
  isApproved?: boolean;
  tags?: string[];
  similarity?: number;
}

export interface PatternMetrics {
  totalPatterns: number;
  approvedPatterns: number;
  patternsByCategory: Record<string, number>;
  averageConfidence: number;
  recentActivity: {
    newPatterns: number;
    updatedPatterns: number;
    period: string;
  };
}

export interface PatternAnalysisResult {
  filePath: string;
  authMatches: AuthPatternMatch[];
  apiMatches: APIPatternMatch[];
  dataAccessMatches: DataAccessMatch[];
  componentMatches: ComponentPatternMatch[];
  styleMatches: StylePatternMatch[];
  overallScore: number;
  recommendations: string[];
  issues: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low';
    category: string;
    message: string;
    suggestion: string;
  }>;
}

export class PatternRegistry {
  private db: DatabaseManager;
  private matcher: PatternMatcher;
  private config: PatternRegistryConfig;
  
  // Category analyzers
  private authAnalyzer: AuthPatternsAnalyzer;
  private apiAnalyzer: APIPatternsAnalyzer;
  private dataAccessAnalyzer: DataAccessPatternsAnalyzer;
  private componentAnalyzer: ComponentPatternsAnalyzer;
  private styleAnalyzer: StylePatternsAnalyzer;

  constructor(db: DatabaseManager, config?: Partial<PatternRegistryConfig>) {
    this.db = db;
    this.matcher = new PatternMatcher();
    this.config = {
      enabledCategories: ['auth', 'api', 'data_access', 'components', 'style'],
      confidenceThreshold: 0.8,
      autoApproveThreshold: 0.95,
      maxPatternAge: 30,
      ...config
    };

    // Initialize category analyzers
    this.authAnalyzer = new AuthPatternsAnalyzer();
    this.apiAnalyzer = new APIPatternsAnalyzer();
    this.dataAccessAnalyzer = new DataAccessPatternsAnalyzer();
    this.componentAnalyzer = new ComponentPatternsAnalyzer();
    this.styleAnalyzer = new StylePatternsAnalyzer();

    logger.info('PatternRegistry initialized with categories:', this.config.enabledCategories);
  }

  async analyzeFile(
    filePath: string,
    ast: TSESTree.Program,
    sourceCode: string
  ): Promise<PatternAnalysisResult> {
    logger.info(`Analyzing patterns in file: ${filePath}`);

    const result: PatternAnalysisResult = {
      filePath,
      authMatches: [],
      apiMatches: [],
      dataAccessMatches: [],
      componentMatches: [],
      styleMatches: [],
      overallScore: 0,
      recommendations: [],
      issues: []
    };

    try {
      // Run all pattern analyses in parallel for better performance
      const analyses = await Promise.allSettled([
        this.analyzeAuthPatterns(ast, sourceCode, filePath),
        this.analyzeAPIPatterns(ast, sourceCode, filePath),
        this.analyzeDataAccessPatterns(ast, sourceCode, filePath),
        this.analyzeComponentPatterns(ast, sourceCode, filePath),
        this.analyzeStylePatterns(ast, sourceCode, filePath)
      ]);

      // Process results
      if (analyses[0].status === 'fulfilled') result.authMatches = analyses[0].value;
      if (analyses[1].status === 'fulfilled') result.apiMatches = analyses[1].value;
      if (analyses[2].status === 'fulfilled') result.dataAccessMatches = analyses[2].value;
      if (analyses[3].status === 'fulfilled') result.componentMatches = analyses[3].value;
      if (analyses[4].status === 'fulfilled') result.styleMatches = analyses[4].value;

      // Log any failed analyses
      analyses.forEach((analysis, index) => {
        if (analysis.status === 'rejected') {
          const categories = ['auth', 'api', 'data_access', 'components', 'style'];
          logger.warn(`Failed to analyze ${categories[index]} patterns:`, analysis.reason);
        }
      });

      // Calculate overall score and generate recommendations
      result.overallScore = this.calculateOverallScore(result);
      result.recommendations = this.generateRecommendations(result);
      result.issues = this.extractIssues(result);

      // Store pattern instances in database
      await this.storePatternInstances(result);

      logger.info(`Pattern analysis complete for ${filePath}. Score: ${result.overallScore}`);
      return result;

    } catch (error) {
      logger.error(`Error analyzing patterns in ${filePath}:`, error);
      throw error;
    }
  }

  private async analyzeAuthPatterns(
    ast: TSESTree.Program,
    sourceCode: string,
    filePath: string
  ): Promise<AuthPatternMatch[]> {
    if (!this.config.enabledCategories.includes('auth')) {
      return [];
    }

    const matches: AuthPatternMatch[] = [];
    
    // Analyze each top-level node
    for (const node of ast.body) {
      const nodeMatches = this.authAnalyzer.analyzeForAuthPatterns(node, sourceCode, filePath);
      matches.push(...nodeMatches);
    }

    return matches;
  }

  private async analyzeAPIPatterns(
    ast: TSESTree.Program,
    sourceCode: string,
    filePath: string
  ): Promise<APIPatternMatch[]> {
    if (!this.config.enabledCategories.includes('api')) {
      return [];
    }

    const matches: APIPatternMatch[] = [];
    
    // Analyze each top-level node
    for (const node of ast.body) {
      const nodeMatches = this.apiAnalyzer.analyzeAPIRoute(node, sourceCode, filePath);
      matches.push(...nodeMatches);
    }

    return matches;
  }

  private async analyzeDataAccessPatterns(
    ast: TSESTree.Program,
    sourceCode: string,
    filePath: string
  ): Promise<DataAccessMatch[]> {
    if (!this.config.enabledCategories.includes('data_access')) {
      return [];
    }

    const matches: DataAccessMatch[] = [];
    
    // Analyze each top-level node
    for (const node of ast.body) {
      const nodeMatches = this.dataAccessAnalyzer.analyzeDataAccess(node, sourceCode, filePath);
      matches.push(...nodeMatches);
    }

    return matches;
  }

  private async analyzeComponentPatterns(
    ast: TSESTree.Program,
    sourceCode: string,
    filePath: string
  ): Promise<ComponentPatternMatch[]> {
    if (!this.config.enabledCategories.includes('components')) {
      return [];
    }

    const matches: ComponentPatternMatch[] = [];
    
    // Analyze each top-level node
    for (const node of ast.body) {
      const nodeMatches = this.componentAnalyzer.analyzeComponent(node, sourceCode, filePath);
      matches.push(...nodeMatches);
    }

    return matches;
  }

  private async analyzeStylePatterns(
    ast: TSESTree.Program,
    sourceCode: string,
    filePath: string
  ): Promise<StylePatternMatch[]> {
    if (!this.config.enabledCategories.includes('style')) {
      return [];
    }

    const matches: StylePatternMatch[] = [];
    
    // Analyze each top-level node
    for (const node of ast.body) {
      const nodeMatches = this.styleAnalyzer.analyzeStyle(node, sourceCode, filePath);
      matches.push(...nodeMatches);
    }

    return matches;
  }

  private calculateOverallScore(result: PatternAnalysisResult): number {
    let totalScore = 0;
    let categoryCount = 0;

    // Auth patterns score
    if (result.authMatches.length > 0) {
      const authScore = result.authMatches.reduce((sum, match) => {
        return sum + match.matchResult.confidence * 100;
      }, 0) / result.authMatches.length;
      totalScore += authScore;
      categoryCount++;
    }

    // API patterns score
    if (result.apiMatches.length > 0) {
      const apiScore = result.apiMatches.reduce((sum, match) => {
        return sum + match.matchResult.confidence * 100;
      }, 0) / result.apiMatches.length;
      totalScore += apiScore;
      categoryCount++;
    }

    // Data access patterns score
    if (result.dataAccessMatches.length > 0) {
      const dataScore = result.dataAccessMatches.reduce((sum, match) => {
        return sum + match.matchResult.confidence * 100;
      }, 0) / result.dataAccessMatches.length;
      totalScore += dataScore;
      categoryCount++;
    }

    // Component patterns score
    if (result.componentMatches.length > 0) {
      const componentScore = result.componentMatches.reduce((sum, match) => {
        return sum + match.performance.score;
      }, 0) / result.componentMatches.length;
      totalScore += componentScore;
      categoryCount++;
    }

    // Style patterns score
    if (result.styleMatches.length > 0) {
      const styleScore = result.styleMatches.reduce((sum, match) => {
        return sum + match.compliance.score;
      }, 0) / result.styleMatches.length;
      totalScore += styleScore;
      categoryCount++;
    }

    return categoryCount > 0 ? Math.round(totalScore / categoryCount) : 0;
  }

  private generateRecommendations(result: PatternAnalysisResult): string[] {
    const recommendations: string[] = [];

    // Critical security issues first
    const criticalIssues = result.dataAccessMatches.filter(match => 
      match.securityRisk.level === 'critical'
    );
    if (criticalIssues.length > 0) {
      recommendations.push('🚨 CRITICAL: Fix security vulnerabilities in data access patterns');
    }

    // Auth recommendations
    const authIssues = result.authMatches.filter(match => 
      match.securityImplications.some(impl => impl.includes('CRITICAL'))
    );
    if (authIssues.length > 0) {
      recommendations.push('🔐 Add proper authentication checks to API endpoints');
    }

    // API recommendations
    const apiIssues = result.apiMatches.filter(match => 
      match.issues.some(issue => issue.severity === 'error')
    );
    if (apiIssues.length > 0) {
      recommendations.push('🔧 Improve API route implementation following best practices');
    }

    // Component recommendations
    const componentPerfIssues = result.componentMatches.filter(match => 
      match.performance.score < 70
    );
    if (componentPerfIssues.length > 0) {
      recommendations.push('⚡ Optimize React components for better performance');
    }

    // Style recommendations
    const styleIssues = result.styleMatches.filter(match => 
      match.compliance.score < 80
    );
    if (styleIssues.length > 0) {
      recommendations.push('✨ Improve code style consistency and formatting');
    }

    // Overall score recommendations
    if (result.overallScore < 60) {
      recommendations.push('📈 Overall code quality needs significant improvement');
    } else if (result.overallScore < 80) {
      recommendations.push('👍 Good code quality with some areas for improvement');
    } else {
      recommendations.push('🌟 Excellent code quality - keep up the good work!');
    }

    return recommendations;
  }

  private extractIssues(result: PatternAnalysisResult): PatternAnalysisResult['issues'] {
    const issues: PatternAnalysisResult['issues'] = [];

    // Extract auth issues
    for (const match of result.authMatches) {
      if (match.pattern.severity === 'critical') {
        issues.push({
          severity: 'critical',
          category: 'authentication',
          message: match.pattern.description,
          suggestion: match.recommendations.join('; ')
        });
      }
    }

    // Extract data access issues
    for (const match of result.dataAccessMatches) {
      const severity = match.securityRisk.level === 'critical' ? 'critical' :
                      match.securityRisk.level === 'high' ? 'high' :
                      match.securityRisk.level === 'medium' ? 'medium' : 'low';
      
      issues.push({
        severity,
        category: 'data_access',
        message: match.securityRisk.description,
        suggestion: match.recommendations.join('; ')
      });
    }

    // Extract API issues
    for (const match of result.apiMatches) {
      for (const issue of match.issues) {
        const severity = issue.severity === 'critical' ? 'critical' :
                        issue.severity === 'error' ? 'high' :
                        issue.severity === 'warning' ? 'medium' : 'low';
        
        issues.push({
          severity,
          category: 'api',
          message: issue.message,
          suggestion: issue.suggestion
        });
      }
    }

    // Extract component issues
    for (const match of result.componentMatches) {
      for (const issue of match.issues) {
        const severity = issue.severity === 'error' ? 'high' :
                        issue.severity === 'warning' ? 'medium' : 'low';
        
        issues.push({
          severity,
          category: 'components',
          message: issue.message,
          suggestion: issue.suggestion
        });
      }
    }

    // Extract style issues
    for (const match of result.styleMatches) {
      for (const violation of match.violations) {
        const severity = violation.severity === 'error' ? 'high' :
                        violation.severity === 'warning' ? 'medium' : 'low';
        
        issues.push({
          severity,
          category: 'style',
          message: violation.message,
          suggestion: violation.fix || 'Apply style guidelines'
        });
      }
    }

    // Sort by severity (critical first)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return issues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }

  private async storePatternInstances(result: PatternAnalysisResult): Promise<void> {
    try {
      // Store auth pattern instances
      for (const match of result.authMatches) {
        await this.storeAuthPatternInstance(match, result.filePath);
      }

      // Store other pattern instances...
      // (Implementation would continue for other pattern types)
      
      logger.debug(`Stored pattern instances for ${result.filePath}`);
    } catch (error) {
      logger.error(`Failed to store pattern instances for ${result.filePath}:`, error);
    }
  }

  private async storeAuthPatternInstance(match: AuthPatternMatch, filePath: string): Promise<void> {
    // Check if we have this pattern in the database
    const database = this.db.getDatabase();
    let pattern = database.prepare(`
      SELECT * FROM patterns WHERE name = ? AND category = ?
    `).get(match.pattern.name, match.pattern.category) as Pattern | undefined;

    if (!pattern) {
      // Create new pattern
      const patternId = this.db.insertPattern({
        name: match.pattern.name,
        category: match.pattern.category,
        description: match.pattern.description,
        confidence_threshold: 0.8,
        is_approved: false,
        usageCount: 1
      });
      pattern = { id: patternId, name: match.pattern.name, category: match.pattern.category, 
                 description: match.pattern.description, confidence_threshold: 0.8, is_approved: false, usageCount: 1 };
    }

    // Store pattern instance
    this.db.insertPatternInstance({
      pattern_id: pattern.id!,
      file_path: filePath,
      line_start: 1, // Would need actual line numbers from AST
      line_end: 1,
      confidence: match.matchResult.confidence,
      metadata: JSON.stringify({
        securityImplications: match.securityImplications,
        recommendations: match.recommendations
      })
    });
  }

  // Pattern management methods
  async getPattern(id: number): Promise<Pattern | null> {
    const database = this.db.getDatabase();
    const pattern = database.prepare('SELECT * FROM patterns WHERE id = ?').get(id) as Pattern | undefined;
    return pattern || null;
  }

  async searchPatterns(query: PatternSearchQuery): Promise<Pattern[]> {
    const database = this.db.getDatabase();
    let sql = 'SELECT * FROM patterns WHERE 1=1';
    const params: any[] = [];

    if (query.category) {
      sql += ' AND category = ?';
      params.push(query.category);
    }

    if (query.name) {
      sql += ' AND name LIKE ?';
      params.push(`%${query.name}%`);
    }

    if (query.minConfidence !== undefined) {
      sql += ' AND confidence_threshold >= ?';
      params.push(query.minConfidence);
    }

    if (query.isApproved !== undefined) {
      sql += ' AND is_approved = ?';
      params.push(query.isApproved ? 1 : 0);
    }

    sql += ' ORDER BY confidence_threshold DESC';

    const patterns = database.prepare(sql).all(...params) as Pattern[];
    return patterns;
  }

  async approvePattern(id: number): Promise<void> {
    const database = this.db.getDatabase();
    database.prepare('UPDATE patterns SET is_approved = 1 WHERE id = ?').run(id);
    logger.info(`Pattern ${id} approved`);
  }

  async rejectPattern(id: number): Promise<void> {
    const database = this.db.getDatabase();
    database.prepare('UPDATE patterns SET is_approved = 0 WHERE id = ?').run(id);
    logger.info(`Pattern ${id} rejected`);
  }

  async deletePattern(id: number): Promise<void> {
    const database = this.db.getDatabase();
    database.prepare('DELETE FROM pattern_instances WHERE pattern_id = ?').run(id);
    database.prepare('DELETE FROM patterns WHERE id = ?').run(id);
    logger.info(`Pattern ${id} deleted`);
  }

  async getPatternMetrics(): Promise<PatternMetrics> {
    const database = this.db.getDatabase();
    
    const totalPatterns = database.prepare('SELECT COUNT(*) as count FROM patterns').get() as { count: number };
    const approvedPatterns = database.prepare('SELECT COUNT(*) as count FROM patterns WHERE is_approved = 1').get() as { count: number };
    
    const byCategory = database.prepare(`
      SELECT category, COUNT(*) as count 
      FROM patterns 
      GROUP BY category
    `).all() as Array<{ category: string; count: number }>;

    const avgConfidence = database.prepare(`
      SELECT AVG(confidence_threshold) as avg 
      FROM patterns 
      WHERE is_approved = 1
    `).get() as { avg: number };

    const recentPatterns = database.prepare(`
      SELECT COUNT(*) as count 
      FROM patterns 
      WHERE datetime(example_line) > datetime('now', '-7 days')
    `).get() as { count: number };

    const patternsByCategory: Record<string, number> = {};
    for (const row of byCategory) {
      patternsByCategory[row.category] = row.count;
    }

    return {
      totalPatterns: totalPatterns.count,
      approvedPatterns: approvedPatterns.count,
      patternsByCategory,
      averageConfidence: avgConfidence.avg || 0,
      recentActivity: {
        newPatterns: recentPatterns.count,
        updatedPatterns: 0, // Would need to track updates
        period: 'last 7 days'
      }
    };
  }

  async generateReport(filePath?: string): Promise<string> {
    const report = ['# Pattern Analysis Report\n'];
    
    if (filePath) {
      report.push(`**File:** ${filePath}\n`);
    }

    const metrics = await this.getPatternMetrics();
    
    report.push('## Pattern Metrics');
    report.push(`- Total Patterns: ${metrics.totalPatterns}`);
    report.push(`- Approved Patterns: ${metrics.approvedPatterns}`);
    report.push(`- Average Confidence: ${Math.round(metrics.averageConfidence * 100)}%`);
    report.push('');

    report.push('## Patterns by Category');
    for (const [category, count] of Object.entries(metrics.patternsByCategory)) {
      report.push(`- ${category}: ${count} patterns`);
    }
    report.push('');

    if (filePath) {
      // Add file-specific analysis
      const database = this.db.getDatabase();
      const instances = database.prepare(`
        SELECT p.name, p.category, pi.confidence 
        FROM pattern_instances pi
        JOIN patterns p ON pi.pattern_id = p.id
        WHERE pi.file_path = ?
        ORDER BY pi.confidence DESC
      `).all(filePath) as Array<{ name: string; category: string; confidence: number }>;

      if (instances.length > 0) {
        report.push('## Pattern Instances in File');
        for (const instance of instances) {
          report.push(`- **${instance.name}** (${instance.category}): ${Math.round(instance.confidence * 100)}% confidence`);
        }
      }
    }

    return report.join('\n');
  }

  // Configuration methods
  updateConfig(newConfig: Partial<PatternRegistryConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('PatternRegistry configuration updated:', newConfig);
  }

  getConfig(): PatternRegistryConfig {
    return { ...this.config };
  }

  // Cleanup methods
  async cleanupOldPatterns(): Promise<number> {
    const database = this.db.getDatabase();
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.maxPatternAge);

    const result = database.prepare(`
      DELETE FROM patterns 
      WHERE is_approved = 0 
      AND datetime(example_line) < datetime(?)
    `).run(cutoffDate.toISOString());

    logger.info(`Cleaned up ${result.changes} old unapproved patterns`);
    return result.changes as number;
  }

  /**
   * Get patterns that match a specific file
   */
  async getPatternsByFile(filePath: string, category?: string): Promise<Pattern[]> {
    const database = this.db.getDatabase();
    let query = `
      SELECT * FROM patterns 
      WHERE json_extract(examples, '$[0].file') LIKE ?
    `;
    const params: any[] = [`%${filePath}%`];

    if (category) {
      query += ` AND category = ?`;
      params.push(category);
    }

    const patterns = database.prepare(query).all(...params) as Pattern[];
    
    logger.debug(`Found ${patterns.length} patterns for file: ${filePath}`);
    return patterns;
  }

  /**
   * Analyze patterns from parsed symbols
   */
  async analyzePatterns(symbols: ParsedSymbol[]): Promise<PatternMatch[]> {
    logger.debug(`Analyzing patterns from ${symbols.length} symbols`);
    
    const matches: PatternMatch[] = [];
    
    try {
      // Pattern matching requires AST nodes which are not available in ParsedSymbol
      // This would need to be reimplemented to work with the symbol data
      // For now, return empty matches
      logger.debug('Pattern matching temporarily disabled - requires AST node access');
      
      logger.debug(`Found ${matches.length} pattern matches`);
      return matches;
    } catch (error) {
      logger.error('Error analyzing patterns from symbols:', error);
      return [];
    }
  }

  /**
   * Learn patterns from an entire project
   */
  async learnFromProject(projectPath: string, options?: {
    categories?: string[];
    minConfidence?: number;
    maxPatterns?: number;
  }): Promise<{
    patternsLearned: number;
    categories: Record<string, number>;
    duration: number;
  }> {
    const startTime = Date.now();
    const categories = options?.categories || this.config.enabledCategories;
    const minConfidence = options?.minConfidence || this.config.confidenceThreshold;

    logger.info(`Learning patterns from project: ${projectPath}`);

    let totalPatterns = 0;
    const categoryCount: Record<string, number> = {};

    // Initialize category counts
    categories.forEach(cat => categoryCount[cat] = 0);

    // This would typically involve file scanning and analysis
    // For now, return a placeholder implementation
    const duration = Date.now() - startTime;

    logger.info(`Pattern learning completed in ${duration}ms`);
    return {
      patternsLearned: totalPatterns,
      categories: categoryCount,
      duration
    };
  }
}

export default PatternRegistry;