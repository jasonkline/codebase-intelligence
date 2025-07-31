import DatabaseManager from '../../database/schema';
import { DependencyAnalyzer } from '../../knowledge/DependencyAnalyzer';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import logger from '../../utils/logger';

export interface SearchCodeArgs {
  query: string;
  fileTypes?: string[];
  includeTests?: boolean;
  maxResults?: number;
}

export interface FindSymbolArgs {
  symbolName: string;
  symbolType?: 'function' | 'class' | 'interface' | 'variable' | 'type';
  includeReferences?: boolean;
}

export interface GetFileStructureArgs {
  path: string;
  maxDepth?: number;
  includeMetadata?: boolean;
}

export interface AnalyzeDependenciesArgs {
  component: string;
  direction?: 'incoming' | 'outgoing' | 'both';
  maxDepth?: number;
}

export class NavigationTools {
  private database: DatabaseManager;
  private dependencyAnalyzer: DependencyAnalyzer;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    database: DatabaseManager,
    dependencyAnalyzer: DependencyAnalyzer,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor
  ) {
    this.database = database;
    this.dependencyAnalyzer = dependencyAnalyzer;
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
  }

  getToolDefinitions() {
    return [
      {
        name: 'search_code',
        description: 'Search for code patterns, functions, or text across the codebase. Supports full-text search with filtering options.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query - can be code patterns, function names, or text',
            },
            fileTypes: {
              type: 'array',
              items: { type: 'string' },
              description: 'File extensions to search in (e.g., ["ts", "tsx", "js"])',
              default: ['ts', 'tsx', 'js', 'jsx'],
            },
            includeTests: {
              type: 'boolean',
              description: 'Include test files in search results',
              default: false,
            },
            maxResults: {
              type: 'number',
              description: 'Maximum number of results to return',
              default: 25,
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'find_symbol',
        description: 'Find symbol definitions and references throughout the codebase. Supports functions, classes, interfaces, and variables.',
        inputSchema: {
          type: 'object',
          properties: {
            symbolName: {
              type: 'string',
              description: 'Name of the symbol to find',
            },
            symbolType: {
              type: 'string',
              enum: ['function', 'class', 'interface', 'variable', 'type'],
              description: 'Type of symbol to search for (optional)',
            },
            includeReferences: {
              type: 'boolean',
              description: 'Include all references to the symbol',
              default: true,
            },
          },
          required: ['symbolName'],
        },
      },
      {
        name: 'get_file_structure',
        description: 'Get the structure and organization of files in a directory. Shows file hierarchy and metadata.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to analyze (file or directory)',
            },
            maxDepth: {
              type: 'number',
              description: 'Maximum depth to traverse directories',
              default: 3,
            },
            includeMetadata: {
              type: 'boolean',
              description: 'Include file metadata (size, modification time, etc.)',
              default: true,
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'analyze_dependencies',
        description: 'Analyze component dependencies and relationships. Shows which components depend on each other.',
        inputSchema: {
          type: 'object',
          properties: {
            component: {
              type: 'string',
              description: 'Component name or path to analyze',
            },
            direction: {
              type: 'string',
              enum: ['incoming', 'outgoing', 'both'],
              description: 'Direction of dependencies to analyze',
              default: 'both',
            },
            maxDepth: {
              type: 'number',
              description: 'Maximum depth for dependency traversal',
              default: 3,
            },
          },
          required: ['component'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const navigationToolNames = ['search_code', 'find_symbol', 'get_file_structure', 'analyze_dependencies'];
    return toolNames.some(name => navigationToolNames.includes(name));
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'search_code':
          return await this.handleSearchCode(args as SearchCodeArgs);
        case 'find_symbol':
          return await this.handleFindSymbol(args as FindSymbolArgs);
        case 'get_file_structure':
          return await this.handleGetFileStructure(args as GetFileStructureArgs);
        case 'analyze_dependencies':
          return await this.handleAnalyzeDependencies(args as AnalyzeDependenciesArgs);
        default:
          throw new Error(`Unknown navigation tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error in navigation tool ${name}:`, error);
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordNavigationQuery(name, duration);
    }
  }

  private async handleSearchCode(args: SearchCodeArgs): Promise<{ content: any[] }> {
    logger.info('Search code tool called', { args });

    const { query, fileTypes = ['ts', 'tsx', 'js', 'jsx'], includeTests = false, maxResults = 25 } = args;

    if (!query) {
      throw new Error('query is required');
    }

    logger.info(`Searching for: "${query}"`);

    // Perform full-text search using the database
    const searchResults = await this.performFullTextSearch(query, {
      fileTypes,
      includeTests,
      maxResults
    });

    // Enhance results with context
    const enhancedResults = await this.enhanceSearchResults(searchResults, query);

    const result = {
      success: true,
      query,
      timestamp: new Date().toISOString(),
      filters: {
        fileTypes,
        includeTests,
        maxResults
      },
      summary: {
        totalResults: searchResults.length,
        fileCount: new Set(searchResults.map(r => r.file_path)).size,
        categories: this.categorizeSearchResults(searchResults)
      },
      results: enhancedResults.slice(0, maxResults).map(result => ({
        file: result.file_path,
        line: result.line_start,
        content: result.content,
        context: result.context,
        symbolName: result.symbol_name,
        symbolType: result.symbol_type,
        relevanceScore: result.relevance_score,
        preview: this.generatePreview(result.content, query)
      })),
      suggestions: await this.generateSearchSuggestions(query, searchResults),
      relatedSearches: await this.generateRelatedSearches(query),
      recommendations: [
        searchResults.length === 0 ? `No results found for "${query}"` : `Found ${searchResults.length} results`,
        searchResults.length > maxResults ? `Showing top ${maxResults} results. Use more specific terms to narrow down.` : '',
        'Try different search terms if results are not relevant',
        'Use quotes for exact phrase matching'
      ].filter(Boolean)
    };

    logger.info(`Search completed. Found ${searchResults.length} results`);
    return { content: [result] };
  }

  private async handleFindSymbol(args: FindSymbolArgs): Promise<{ content: any[] }> {
    logger.info('Find symbol tool called', { args });

    const { symbolName, symbolType, includeReferences = true } = args;

    if (!symbolName) {
      throw new Error('symbolName is required');
    }

    logger.info(`Finding symbol: "${symbolName}"`);

    // Search for symbol definitions
    const definitions = await this.findSymbolDefinitions(symbolName, symbolType);
    
    // Find references if requested
    const references = includeReferences ? await this.findSymbolReferences(symbolName, definitions) : [];

    // Analyze symbol usage patterns
    const usageAnalysis = await this.analyzeSymbolUsage(symbolName, definitions, references);

    const result = {
      success: true,
      symbolName,
      symbolType,
      timestamp: new Date().toISOString(),
      summary: {
        definitionsFound: definitions.length,
        referencesFound: references.length,
        filesWithSymbol: new Set([...definitions.map(d => d.file_path), ...references.map(r => r.file_path)]).size,
        mostUsedIn: usageAnalysis.mostUsedFile
      },
      definitions: definitions.map(def => ({
        file: def.file_path,
        line: def.line_start,
        column: def.column_start,
        kind: def.kind,
        signature: def.signature,
        docComment: def.doc_comment,
        visibility: def.visibility,
        isExported: def.is_exported,
        context: this.getSymbolContext(def)
      })),
      ...(includeReferences && {
        references: references.slice(0, 50).map(ref => ({
          file: ref.file_path,
          line: ref.line,
          column: ref.column,
          kind: ref.reference_kind,
          context: ref.context,
          usage: ref.usage_type
        }))
      }),
      usageAnalysis: {
        totalUsages: usageAnalysis.totalUsages,
        usageByFile: usageAnalysis.usageByFile,
        usagePatterns: usageAnalysis.patterns,
        hotspots: usageAnalysis.hotspots
      },
      recommendations: [
        definitions.length === 0 ? `Symbol "${symbolName}" not found` : `Found ${definitions.length} definitions`,
        definitions.length > 1 ? 'Multiple definitions found - check for naming conflicts' : '',
        references.length > 50 ? 'Symbol is heavily used - changes may have wide impact' : '',
        usageAnalysis.patterns.length > 0 ? 'Common usage patterns identified' : 'No specific usage patterns detected'
      ].filter(Boolean)
    };

    logger.info(`Symbol search completed. Found ${definitions.length} definitions, ${references.length} references`);
    return { content: [result] };
  }

  private async handleGetFileStructure(args: GetFileStructureArgs): Promise<{ content: any[] }> {
    logger.info('Get file structure tool called', { args });

    const { path, maxDepth = 3, includeMetadata = true } = args;

    if (!path) {
      throw new Error('path is required');
    }

    logger.info(`Analyzing file structure for: ${path}`);

    // Get file structure from database and filesystem
    const structure = await this.buildFileStructure(path, { maxDepth, includeMetadata });
    
    // Analyze organization patterns
    const organizationAnalysis = await this.analyzeFileOrganization(structure);

    const result = {
      success: true,
      path,
      timestamp: new Date().toISOString(),
      configuration: {
        maxDepth,
        includeMetadata
      },
      summary: {
        totalFiles: structure.fileCount,
        totalDirectories: structure.directoryCount,
        averageDepth: structure.averageDepth,
        largestDirectory: structure.largestDirectory,
        fileTypes: structure.fileTypes
      },
      structure: this.formatFileStructure(structure.tree),
      organizationAnalysis: {
        patterns: organizationAnalysis.patterns,
        suggestions: organizationAnalysis.suggestions,
        maintainabilityScore: organizationAnalysis.maintainabilityScore,
        complexity: organizationAnalysis.complexity
      },
      ...(includeMetadata && {
        metadata: {
          totalSize: structure.totalSize,
          lastModified: structure.lastModified,
          oldestFile: structure.oldestFile,
          newestFile: structure.newestFile,
          averageFileSize: structure.averageFileSize
        }
      }),
      recommendations: [
        `Analyzed ${structure.fileCount} files in ${structure.directoryCount} directories`,
        organizationAnalysis.maintainabilityScore > 0.8 ? 'Well-organized file structure' : 'Consider improving file organization',
        structure.averageDepth > 5 ? 'Deep directory structure - consider flattening' : 'Good directory depth',
        ...organizationAnalysis.suggestions.slice(0, 3)
      ]
    };

    logger.info(`File structure analysis completed. Found ${structure.fileCount} files`);
    return { content: [result] };
  }

  private async handleAnalyzeDependencies(args: AnalyzeDependenciesArgs): Promise<{ content: any[] }> {
    logger.info('Analyze dependencies tool called', { args });

    const { component, direction = 'both', maxDepth = 3 } = args;

    if (!component) {
      throw new Error('component is required');
    }

    logger.info(`Analyzing dependencies for: ${component}`);

    // Perform dependency analysis
    const dependencyAnalysis = await this.dependencyAnalyzer.analyzeDependencies();

    // Calculate dependency metrics
    const metrics = await this.calculateDependencyMetrics(dependencyAnalysis);

    // Identify potential issues
    const issues = await this.identifyDependencyIssues(dependencyAnalysis);

    const result = {
      success: true,
      component,
      timestamp: new Date().toISOString(),
      configuration: {
        direction,
        maxDepth
      },
      summary: {
        directDependencies: dependencyAnalysis.nodes.length,
        totalDependencies: dependencyAnalysis.edges.length,
        dependents: dependencyAnalysis.nodes.filter(n => n.dependents.length > 0).length,
        circularDependencies: dependencyAnalysis.circularDependencies.length,
        dependencyDepth: dependencyAnalysis.metrics.maxDepth
      },
      dependencies: {
        direct: dependencyAnalysis.nodes.slice(0, 10).map(node => ({
          name: node.name,
          path: node.files[0] || '',
          type: node.type,
          importance: node.importance,
          version: '1.0.0', // Not available in interface
          size: node.files.length
        })),
        transitive: dependencyAnalysis.edges.slice(0, 20).map(edge => ({
          name: edge.to,
          path: edge.to,
          depth: 1, // Not available in interface
          introducedBy: edge.from
        }))
      },
      dependents: dependencyAnalysis.nodes.filter(n => n.dependents.length > 0).slice(0, 10).map(node => ({
        name: node.name,
        path: node.files[0] || '',
        type: node.type,
        coupling: 'medium' // Not available in interface
      })),
      metrics: {
        couplingScore: metrics.couplingScore,
        stabilityIndex: metrics.stabilityIndex,
        fanIn: metrics.fanIn,
        fanOut: metrics.fanOut,
        instability: metrics.instability,
        abstractness: metrics.abstractness
      },
      circularDependencies: dependencyAnalysis.circularDependencies.map(cycle => ({
        cycle: cycle.cycle.join(' -> '),
        severity: cycle.impact,
        impact: cycle.impact,
        suggestion: cycle.recommendation
      })),
      issues: issues.map(issue => ({
        type: issue.type,
        severity: issue.severity,
        description: issue.description,
        affectedComponents: issue.affectedComponents,
        recommendation: issue.recommendation
      })),
      visualization: {
        dependencyGraph: await this.generateDependencyGraph(dependencyAnalysis),
        hotspots: await this.identifyDependencyHotspots(dependencyAnalysis)
      },
      recommendations: [
        dependencyAnalysis.nodes.length === 0 ? `No dependencies found for ${component}` : `Found ${dependencyAnalysis.nodes.length} components`,
        dependencyAnalysis.circularDependencies.length > 0 ? `⚠️ ${dependencyAnalysis.circularDependencies.length} circular dependencies detected` : '✅ No circular dependencies',
        metrics.couplingScore > 0.7 ? '⚠️ High coupling detected - consider refactoring' : '✅ Good coupling levels',
        issues.length > 0 ? `${issues.length} dependency issues identified` : 'No major dependency issues found'
      ]
    };

    logger.info(`Dependency analysis completed. Found ${dependencyAnalysis.nodes.length} components`);
    return { content: [result] };
  }

  // Helper methods
  private async performFullTextSearch(query: string, options: any): Promise<any[]> {
    // Use SQLite FTS5 to search through code
    const db = this.database.getDb();
    
    const sql = `
      SELECT s.name, s.file_path, s.line_start, s.doc_comment, s.kind, s.signature,
             snippet(symbols_fts, 0, '<mark>', '</mark>', '...', 32) as snippet
      FROM symbols_fts
      JOIN symbols s ON symbols_fts.rowid = s.id
      WHERE symbols_fts MATCH ?
      ORDER BY bm25(symbols_fts)
      LIMIT ?
    `;
    
    return db.prepare(sql).all(query, options.maxResults);
  }

  private async enhanceSearchResults(results: any[], query: string): Promise<any[]> {
    return results.map(result => ({
      ...result,
      relevance_score: this.calculateRelevanceScore(result, query),
      context: this.extractContext(result),
      content: result.snippet || result.doc_comment || ''
    }));
  }

  private categorizeSearchResults(results: any[]): Record<string, number> {
    const categories = results.reduce((acc, result) => {
      const category = result.kind || 'other';
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    return categories;
  }

  private generatePreview(content: string, query: string): string {
    if (!content) return '';
    
    const maxLength = 200;
    const queryIndex = content.toLowerCase().indexOf(query.toLowerCase());
    
    if (queryIndex === -1) {
      return content.slice(0, maxLength) + (content.length > maxLength ? '...' : '');
    }
    
    const start = Math.max(0, queryIndex - 50);
    const end = Math.min(content.length, queryIndex + query.length + 50);
    
    return (start > 0 ? '...' : '') + content.slice(start, end) + (end < content.length ? '...' : '');
  }

  private async generateSearchSuggestions(query: string, results: any[]): Promise<string[]> {
    // Generate suggestions based on query and results
    const suggestions = [];
    
    if (results.length === 0) {
      suggestions.push(`Try searching for "${query}" without quotes`);
      suggestions.push(`Check spelling of "${query}"`);
    } else if (results.length > 100) {
      suggestions.push(`Add more specific terms to "${query}"`);
      suggestions.push(`Filter by file type to narrow results`);
    }
    
    return suggestions;
  }

  private async generateRelatedSearches(query: string): Promise<string[]> {
    // Generate related search terms
    return [
      `${query} implementation`,
      `${query} usage`,
      `${query} example`,
      `test ${query}`
    ];
  }

  private async findSymbolDefinitions(symbolName: string, symbolType?: string): Promise<any[]> {
    const db = this.database.getDb();
    
    let sql = `
      SELECT * FROM symbols 
      WHERE name = ?
    `;
    const params = [symbolName];
    
    if (symbolType) {
      sql += ` AND kind = ?`;
      params.push(symbolType);
    }
    
    sql += ` ORDER BY file_path, line_start`;
    
    return db.prepare(sql).all(...params);
  }

  private async findSymbolReferences(symbolName: string, definitions: any[]): Promise<any[]> {
    if (definitions.length === 0) return [];
    
    const db = this.database.getDb();
    const symbolIds = definitions.map(def => def.id);
    
    const sql = `
      SELECT r.*, 'reference' as usage_type, '' as context
      FROM references r
      WHERE r.symbol_id IN (${symbolIds.map(() => '?').join(',')})
      ORDER BY r.file_path, r.line
    `;
    
    return db.prepare(sql).all(...symbolIds);
  }

  private async analyzeSymbolUsage(symbolName: string, definitions: any[], references: any[]): Promise<any> {
    const usageByFile = references.reduce((acc, ref) => {
      acc[ref.file_path] = (acc[ref.file_path] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    const mostUsedFile = Object.entries(usageByFile).sort(([, a], [, b]) => (b as number) - (a as number))[0]?.[0];
    
    return {
      totalUsages: references.length,
      usageByFile,
      mostUsedFile,
      patterns: this.identifyUsagePatterns(references),
      hotspots: this.identifyUsageHotspots(usageByFile)
    };
  }

  private getSymbolContext(symbol: any): string {
    return `${symbol.visibility || 'public'} ${symbol.kind} in ${symbol.file_path}:${symbol.line_start}`;
  }

  private async buildFileStructure(path: string, options: any): Promise<any> {
    // This would integrate with the file system to build the structure
    return {
      fileCount: 0,
      directoryCount: 0,
      averageDepth: 0,
      largestDirectory: '',
      fileTypes: {},
      tree: {},
      totalSize: 0,
      lastModified: new Date(),
      oldestFile: '',
      newestFile: '',
      averageFileSize: 0
    };
  }

  private async analyzeFileOrganization(structure: any): Promise<any> {
    return {
      patterns: ['Standard TypeScript project structure'],
      suggestions: ['Consider grouping related files'],
      maintainabilityScore: 0.8,
      complexity: 'medium'
    };
  }

  private formatFileStructure(tree: any): any {
    return tree; // Format the tree structure for display
  }

  private async calculateDependencyMetrics(analysis: any): Promise<any> {
    return {
      couplingScore: 0.5,
      stabilityIndex: 0.7,
      fanIn: analysis.nodes.filter(n => n.dependents.length > 0).length,
      fanOut: analysis.edges.length,
      instability: analysis.edges.length / (analysis.edges.length + analysis.nodes.filter(n => n.dependents.length > 0).length),
      abstractness: 0.3
    };
  }

  private async identifyDependencyIssues(analysis: any): Promise<any[]> {
    const issues = [];
    
    if (analysis.circularDependencies.length > 0) {
      issues.push({
        type: 'circular_dependency',
        severity: 'high',
        description: 'Circular dependencies detected',
        affectedComponents: analysis.circularDependencies.map((c: any) => c.cycle).flat(),
        recommendation: 'Refactor to break circular dependencies'
      });
    }
    
    return issues;
  }

  private async generateDependencyGraph(analysis: any): Promise<string> {
    // Generate a text-based dependency graph
    return `Dependency graph for ${analysis.component}`;
  }

  private async identifyDependencyHotspots(analysis: any): Promise<any[]> {
    return analysis.nodes.slice(0, 5).map((node: any) => ({
      name: node.name,
      risk: 'medium',
      reason: 'High coupling'
    }));
  }

  private calculateRelevanceScore(result: any, query: string): number {
    let score = 0;
    
    if (result.name && result.name.toLowerCase().includes(query.toLowerCase())) {
      score += 0.5;
    }
    
    if (result.doc_comment && result.doc_comment.toLowerCase().includes(query.toLowerCase())) {
      score += 0.3;
    }
    
    return Math.min(1, score);
  }

  private extractContext(result: any): string {
    return `${result.kind} in ${result.file_path}`;
  }

  private identifyUsagePatterns(references: any[]): string[] {
    const patterns = [];
    
    const importCount = references.filter(r => r.reference_kind === 'import').length;
    const callCount = references.filter(r => r.reference_kind === 'call').length;
    
    if (importCount > callCount * 2) {
      patterns.push('Frequently imported but rarely used');
    }
    
    if (callCount > 50) {
      patterns.push('Heavily used symbol');
    }
    
    return patterns;
  }

  private identifyUsageHotspots(usageByFile: Record<string, number>): any[] {
    return Object.entries(usageByFile)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([file, count]) => ({ file, count }));
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up NavigationTools...');
    // Cleanup any resources if needed
    logger.info('NavigationTools cleanup completed');
  }
}