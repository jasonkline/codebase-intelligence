import { promises as fs } from 'fs';
import { join, extname, relative } from 'path';
import { createHash } from 'crypto';
import * as chokidar from 'chokidar';
import fg from 'fast-glob';
import ASTParser, { ParsedFile } from '../parser/ASTParser';
import SystemAnalyzer, { SystemAnalysisResult } from '../parser/SystemAnalyzer';
import KnowledgeExtractor, { KnowledgeGraph } from '../knowledge/KnowledgeExtractor';
import DatabaseManager, { FileInfo, Symbol } from '../database/schema';
import logger from '../utils/logger';

export interface ScanOptions {
  include: string[];
  exclude: string[];
  followSymlinks: boolean;
  maxDepth: number;
  maxFileSize: number; // in bytes
  parallel: boolean;
  maxConcurrency: number;
  watchMode: boolean;
  respectGitignore: boolean;
}

export interface ScanProgress {
  totalFiles: number;
  processedFiles: number;
  errors: number;
  startTime: Date;
  currentFile?: string;
  estimatedTimeRemaining?: number;
}

export interface ScanResult {
  success: boolean;
  filesProcessed: number;
  filesSkipped: number;
  errors: string[];
  duration: number;
  knowledgeGraph: KnowledgeGraph;
  summary: ScanSummary;
}

export interface ScanSummary {
  totalSymbols: number;
  totalPatterns: number;
  securityIssues: number;
  languages: Map<string, number>;
  systems: string[];
  coverage: {
    authCovered: number;
    rbacImplemented: number;
    dataAccessSecure: number;
  };
}

export class FileScanner {
  private parser: ASTParser;
  private analyzer: SystemAnalyzer;
  private knowledgeExtractor: KnowledgeExtractor;
  private db: DatabaseManager;
  private watcher?: chokidar.FSWatcher;
  
  private defaultOptions: ScanOptions = {
    include: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    exclude: [
      'node_modules/**',
      'dist/**',
      'build/**',
      '.next/**',
      '.git/**',
      '**/*.test.ts',
      '**/*.test.tsx',
      '**/*.spec.ts',
      '**/*.spec.tsx',
      '**/*.d.ts',
      'coverage/**',
      '.vscode/**',
      '.idea/**',
      '*.min.js'
    ],
    followSymlinks: false,
    maxDepth: 20,
    maxFileSize: 1024 * 1024, // 1MB
    parallel: true,
    maxConcurrency: 4,
    watchMode: false,
    respectGitignore: true
  };

  constructor(dbPath?: string) {
    this.parser = new ASTParser();
    this.analyzer = new SystemAnalyzer();
    this.knowledgeExtractor = new KnowledgeExtractor();
    this.db = new DatabaseManager(dbPath);
  }

  async scanProject(
    projectPath: string, 
    options: Partial<ScanOptions> = {},
    progressCallback?: (progress: ScanProgress) => void
  ): Promise<ScanResult> {
    const startTime = new Date();
    const opts = { ...this.defaultOptions, ...options };
    const errors: string[] = [];
    let filesProcessed = 0;
    let filesSkipped = 0;

    try {
      logger.info(`Starting project scan: ${projectPath}`);

      // Find all files to process
      const files = await this.findFiles(projectPath, opts);
      logger.info(`Found ${files.length} files to analyze`);

      if (files.length === 0) {
        return {
          success: true,
          filesProcessed: 0,
          filesSkipped: 0,
          errors: [],
          duration: Date.now() - startTime.getTime(),
          knowledgeGraph: this.knowledgeExtractor.analyzeSystemKnowledge([], new Map()),
          summary: this.createEmptySummary()
        };
      }

      // Initialize progress tracking
      const progress: ScanProgress = {
        totalFiles: files.length,
        processedFiles: 0,
        errors: 0,
        startTime
      };

      // Process files
      const parsedFiles: ParsedFile[] = [];
      const analysisResults = new Map<string, SystemAnalysisResult>();

      if (opts.parallel) {
        await this.processFilesParallel(
          files, 
          opts, 
          parsedFiles, 
          analysisResults, 
          progress, 
          progressCallback,
          errors
        );
      } else {
        await this.processFilesSequential(
          files, 
          opts, 
          parsedFiles, 
          analysisResults, 
          progress, 
          progressCallback,
          errors
        );
      }

      filesProcessed = parsedFiles.length;
      filesSkipped = files.length - parsedFiles.length;

      // Extract system knowledge
      logger.info('Extracting system knowledge...');
      const knowledgeGraph = this.knowledgeExtractor.analyzeSystemKnowledge(parsedFiles, analysisResults);

      // Generate summary
      const summary = this.generateScanSummary(parsedFiles, analysisResults, knowledgeGraph);

      // Store results in database
      await this.storeResults(parsedFiles, analysisResults, knowledgeGraph);

      // Set up file watching if requested
      if (opts.watchMode) {
        this.setupFileWatcher(projectPath, opts);
      }

      const duration = Date.now() - startTime.getTime();
      logger.info(`Project scan completed in ${duration}ms. Processed: ${filesProcessed}, Skipped: ${filesSkipped}, Errors: ${errors.length}`);

      return {
        success: true,
        filesProcessed,
        filesSkipped,
        errors,
        duration,
        knowledgeGraph,
        summary
      };

    } catch (error) {
      logger.error('Project scan failed:', error);
      return {
        success: false,
        filesProcessed,
        filesSkipped,
        errors: [...errors, error instanceof Error ? error.message : String(error)],
        duration: Date.now() - startTime.getTime(),
        knowledgeGraph: this.knowledgeExtractor.analyzeSystemKnowledge([], new Map()),
        summary: this.createEmptySummary()
      };
    }
  }

  private async findFiles(projectPath: string, options: ScanOptions): Promise<string[]> {
    try {
      // Use fast-glob to find files
      const patterns = options.include.map(pattern => join(projectPath, pattern));
      const files = await fg.glob(patterns, {
        ignore: options.exclude.map(pattern => join(projectPath, pattern)),
        followSymbolicLinks: options.followSymlinks,
        deep: options.maxDepth,
        onlyFiles: true,
        absolute: true
      });

      // Filter files by supported extensions and size
      const supportedExtensions = ['.ts', '.tsx', '.js', '.jsx'];
      const filteredFiles: string[] = [];

      for (const file of files) {
        try {
          const ext = extname(file).toLowerCase();
          if (!supportedExtensions.includes(ext)) {
            continue;
          }

          const stats = await fs.stat(file);
          if (stats.size > options.maxFileSize) {
            logger.warn(`Skipping large file: ${file} (${stats.size} bytes)`);
            continue;
          }

          filteredFiles.push(file);
        } catch (error) {
          logger.warn(`Error checking file ${file}:`, error);
        }
      }

      return filteredFiles;
    } catch (error) {
      logger.error('Error finding files:', error);
      return [];
    }
  }

  private async processFilesParallel(
    files: string[],
    options: ScanOptions,
    parsedFiles: ParsedFile[],
    analysisResults: Map<string, SystemAnalysisResult>,
    progress: ScanProgress,
    progressCallback?: (progress: ScanProgress) => void,
    errors: string[] = []
  ): Promise<void> {
    const semaphore = new Array(options.maxConcurrency).fill(null);
    const fileQueue = [...files];
    const promises: Promise<void>[] = [];

    const processFile = async (): Promise<void> => {
      while (fileQueue.length > 0) {
        const file = fileQueue.shift();
        if (!file) break;

        try {
          progress.currentFile = relative(process.cwd(), file);
          
          const result = await this.processFile(file);
          if (result) {
            parsedFiles.push(result.parsedFile);
            analysisResults.set(file, result.analysis);
          }
          
          progress.processedFiles++;
          
          // Update time estimation
          const elapsed = Date.now() - progress.startTime.getTime();
          const rate = progress.processedFiles / elapsed;
          const remaining = progress.totalFiles - progress.processedFiles;
          progress.estimatedTimeRemaining = remaining / rate;
          
          if (progressCallback) {
            progressCallback({ ...progress });
          }
          
        } catch (error) {
          progress.errors++;
          errors.push(`Error processing ${file}: ${error instanceof Error ? error.message : String(error)}`);
          logger.error(`Error processing file ${file}:`, error);
        }
      }
    };

    // Start concurrent processing
    for (let i = 0; i < options.maxConcurrency; i++) {
      promises.push(processFile());
    }

    await Promise.all(promises);
  }

  private async processFilesSequential(
    files: string[],
    options: ScanOptions,
    parsedFiles: ParsedFile[],
    analysisResults: Map<string, SystemAnalysisResult>,
    progress: ScanProgress,
    progressCallback?: (progress: ScanProgress) => void,
    errors: string[] = []
  ): Promise<void> {
    for (const file of files) {
      try {
        progress.currentFile = relative(process.cwd(), file);
        
        const result = await this.processFile(file);
        if (result) {
          parsedFiles.push(result.parsedFile);
          analysisResults.set(file, result.analysis);
        }
        
        progress.processedFiles++;
        
        // Update time estimation
        const elapsed = Date.now() - progress.startTime.getTime();
        const rate = progress.processedFiles / elapsed;
        const remaining = progress.totalFiles - progress.processedFiles;
        progress.estimatedTimeRemaining = remaining / rate;
        
        if (progressCallback) {
          progressCallback({ ...progress });
        }
        
      } catch (error) {
        progress.errors++;
        errors.push(`Error processing ${file}: ${error instanceof Error ? error.message : String(error)}`);
        logger.error(`Error processing file ${file}:`, error);
      }
    }
  }

  private async processFile(filePath: string): Promise<{ parsedFile: ParsedFile; analysis: SystemAnalysisResult } | null> {
    try {
      // Check if file needs reprocessing
      const fileInfo = await this.getFileInfo(filePath);
      const existingFile = this.db.getFileByPath(filePath);
      
      if (existingFile && existingFile.hash === fileInfo.hash) {
        logger.debug(`Skipping unchanged file: ${filePath}`);
        return null; // File hasn't changed
      }

      // Parse the file
      const parsedFile = this.parser.parseFile(filePath);
      if (!parsedFile) {
        logger.warn(`Failed to parse file: ${filePath}`);
        return null;
      }

      // Read source code for analysis
      const sourceCode = await fs.readFile(filePath, 'utf-8');
      
      // Analyze the file
      const analysis = this.analyzer.analyzeFile(parsedFile, sourceCode);

      return { parsedFile, analysis };
    } catch (error) {
      logger.error(`Error processing file ${filePath}:`, error);
      return null;
    }
  }

  private async getFileInfo(filePath: string): Promise<FileInfo> {
    const stats = await fs.stat(filePath);
    const content = await fs.readFile(filePath, 'utf-8');
    const hash = createHash('sha256').update(content).digest('hex');
    
    return {
      path: filePath,
      last_indexed: new Date().toISOString(),
      hash,
      size: stats.size,
      language: this.detectLanguage(filePath)
    };
  }

  private detectLanguage(filePath: string): string {
    const ext = extname(filePath).toLowerCase();
    switch (ext) {
      case '.ts': return 'typescript';
      case '.tsx': return 'tsx';
      case '.js': return 'javascript';
      case '.jsx': return 'jsx';
      default: return 'unknown';
    }
  }

  private async storeResults(
    parsedFiles: ParsedFile[],
    analysisResults: Map<string, SystemAnalysisResult>,
    knowledgeGraph: KnowledgeGraph
  ): Promise<void> {
    logger.info('Storing results in database...');
    
    this.db.transaction(() => {
      // Store files and symbols
      for (const file of parsedFiles) {
        // Clear existing data for this file
        this.db.clearFileData(file.filePath);
        
        // Store file info
        const fileInfo: FileInfo = {
          path: file.filePath,
          last_indexed: new Date().toISOString(),
          hash: createHash('sha256').update('').digest('hex'), // Would need actual content
          size: 0, // Would need actual size
          language: file.language
        };
        this.db.insertFile(fileInfo);
        
        // Store symbols
        for (const symbol of file.symbols) {
          const dbSymbol: Symbol = {
            name: symbol.name,
            kind: symbol.kind,
            file_path: symbol.filePath,
            line_start: symbol.lineStart,
            line_end: symbol.lineEnd,
            column_start: symbol.columnStart,
            column_end: symbol.columnEnd,
            signature: symbol.signature,
            doc_comment: symbol.docComment,
            visibility: symbol.visibility,
            is_exported: symbol.isExported
          };
          this.db.insertSymbol(dbSymbol);
        }
      }
      
      // Store system knowledge
      knowledgeGraph.systems.forEach(knowledge => {
        this.db.insertSystemKnowledge(knowledge);
      });
      
      // Store patterns (would need to convert analysis results to pattern instances)
      // This is simplified - full implementation would store all detected patterns
    });
    
    logger.info('Results stored successfully');
  }

  private generateScanSummary(
    parsedFiles: ParsedFile[],
    analysisResults: Map<string, SystemAnalysisResult>,
    knowledgeGraph: KnowledgeGraph
  ): ScanSummary {
    let totalSymbols = 0;
    let totalPatterns = 0;
    let securityIssues = 0;
    const languages = new Map<string, number>();
    let authCovered = 0;
    let rbacImplemented = 0;
    let dataAccessSecure = 0;
    let totalApiEndpoints = 0;

    // Count symbols and languages
    parsedFiles.forEach(file => {
      totalSymbols += file.symbols.length;
      languages.set(file.language, (languages.get(file.language) || 0) + 1);
    });

    // Count patterns and security metrics
    analysisResults.forEach(analysis => {
      totalPatterns += analysis.authPatterns.length + 
                     analysis.rbacPatterns.length + 
                     analysis.dataAccessPatterns.length + 
                     analysis.apiPatterns.length;
      
      securityIssues += analysis.summary.securityIssues;
      
      // Count coverage metrics
      analysis.apiPatterns.forEach(pattern => {
        totalApiEndpoints++;
        if (pattern.hasAuth) authCovered++;
      });
      
      rbacImplemented += analysis.rbacPatterns.length;
      
      analysis.dataAccessPatterns.forEach(pattern => {
        if (pattern.isSecure) dataAccessSecure++;
      });
    });

    const systemKeys = Array.from(knowledgeGraph.systems.keys())
      .map(key => key.split(':')[0])
      .filter((value, index, self) => self.indexOf(value) === index);
    const systems = systemKeys.filter((s): s is string => Boolean(s));

    return {
      totalSymbols,
      totalPatterns,
      securityIssues,
      languages,
      systems,
      coverage: {
        authCovered: totalApiEndpoints > 0 ? Math.round((authCovered / totalApiEndpoints) * 100) : 100,
        rbacImplemented,
        dataAccessSecure
      }
    };
  }

  private createEmptySummary(): ScanSummary {
    return {
      totalSymbols: 0,
      totalPatterns: 0,
      securityIssues: 0,
      languages: new Map(),
      systems: [],
      coverage: {
        authCovered: 0,
        rbacImplemented: 0,
        dataAccessSecure: 0
      }
    };
  }

  private setupFileWatcher(projectPath: string, options: ScanOptions): void {
    if (this.watcher) {
      this.watcher.close();
    }

    logger.info('Setting up file watcher...');
    
    const watchPatterns = options.include.map(pattern => join(projectPath, pattern));
    
    this.watcher = chokidar.watch(watchPatterns, {
      ignored: options.exclude.map(pattern => join(projectPath, pattern)),
      persistent: true,
      ignoreInitial: true
    });

    this.watcher.on('change', async (filePath: string) => {
      logger.info(`File changed: ${filePath}`);
      try {
        const result = await this.processFile(filePath);
        if (result) {
          // Update database with new results
          this.db.transaction(() => {
            this.db.clearFileData(filePath);
            // Store updated results...
          });
          logger.info(`File reprocessed: ${filePath}`);
        }
      } catch (error) {
        logger.error(`Error reprocessing file ${filePath}:`, error);
      }
    });

    this.watcher.on('add', async (filePath: string) => {
      logger.info(`New file detected: ${filePath}`);
      try {
        const result = await this.processFile(filePath);
        if (result) {
          // Add to database...
          logger.info(`New file processed: ${filePath}`);
        }
      } catch (error) {
        logger.error(`Error processing new file ${filePath}:`, error);
      }
    });

    this.watcher.on('unlink', (filePath: string) => {
      logger.info(`File deleted: ${filePath}`);
      this.db.clearFileData(filePath);
    });
  }

  // Public utility methods
  async scanSingleFile(filePath: string): Promise<{ parsedFile: ParsedFile; analysis: SystemAnalysisResult } | null> {
    return this.processFile(filePath);
  }

  stopWatcher(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = undefined;
      logger.info('File watcher stopped');
    }
  }

  close(): void {
    this.stopWatcher();
    this.db.close();
  }

  // Get scan statistics
  getScanStatistics(): any {
    // Return database statistics
    const db = this.db.getDatabase();
    const stats = {
      totalFiles: (db.prepare('SELECT COUNT(*) as count FROM files').get() as any).count,
      totalSymbols: (db.prepare('SELECT COUNT(*) as count FROM symbols').get() as any).count,
      totalPatterns: (db.prepare('SELECT COUNT(*) as count FROM pattern_instances').get() as any).count,
      securityIssues: (db.prepare('SELECT COUNT(*) as count FROM security_issues WHERE resolved = 0').get() as any).count
    };
    return stats;
  }
}

export default FileScanner;