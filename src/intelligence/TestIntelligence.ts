import { ParsedSymbol } from '../parser/ASTParser';
import { logger } from '../utils/logger';
import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';

export interface TestCoverageReport {
  filePath: string;
  overallCoverage: number;
  lineCoverage: number;
  branchCoverage: number;
  functionCoverage: number;
  uncoveredLines: number[];
  uncoveredFunctions: string[];
  uncoveredBranches: CoverageGap[];
  lastUpdated: number;
}

export interface CoverageGap {
  type: 'line' | 'branch' | 'function' | 'statement';
  location: {
    lineStart: number;
    lineEnd: number;
    function?: string;
    class?: string;
  };
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  complexity: number;
  riskScore: number;
}

export interface TestSuggestion {
  id: string;
  type: 'unit' | 'integration' | 'edge_case' | 'error_handling' | 'performance' | 'security';
  priority: 'low' | 'medium' | 'high' | 'critical';
  filePath: string;
  targetFunction?: string;
  targetClass?: string;
  description: string;
  reasoning: string[];
  testTemplate: string;
  testFramework: 'jest' | 'vitest' | 'mocha' | 'cypress' | 'playwright';
  estimatedEffort: number; // minutes
  riskMitigation: string[];
  prerequisites: string[];
  relatedCoverage?: CoverageGap;
}

export interface EdgeCase {
  id: string;
  filePath: string;
  function: string;
  scenario: string;
  inputValues: any[];
  expectedBehavior: string;
  currentlyCovered: boolean;
  riskLevel: 'low' | 'medium' | 'high';
  detectionMethod: 'static_analysis' | 'pattern_matching' | 'heuristic';
}

export interface TestQualityMetrics {
  filePath: string;
  testFilePath?: string;
  testCount: number;
  assertionCount: number;
  mockUsage: number;
  testComplexity: number;
  testMaintainability: number;
  duplicatedTestCode: number;
  testSmells: TestSmell[];
  coverageGaps: CoverageGap[];
  missingEdgeCases: EdgeCase[];
}

export interface TestSmell {
  type: 'duplicate_code' | 'long_test' | 'assertion_roulette' | 'eager_test' | 
        'mystery_guest' | 'resource_optimism' | 'test_code_duplication' |
        'indirect_testing' | 'for_testers_only' | 'sensitive_equality';
  location: {
    lineStart: number;
    lineEnd: number;
    testName?: string;
  };
  description: string;
  impact: string;
  suggestion: string;
}

export interface TestGenerationRequest {
  filePath: string;
  functionName?: string;
  className?: string;
  testType: TestSuggestion['type'];
  framework: TestSuggestion['testFramework'];
  includeEdgeCases: boolean;
  includeMocking: boolean;
  targetCoverage?: number;
}

export interface GeneratedTest {
  testCode: string;
  description: string;
  framework: string;
  dependencies: string[];
  setup: string[];
  teardown: string[];
  coverage: {
    lines: number[];
    branches: string[];
    functions: string[];
  };
}

export class TestIntelligence {
  private db: Database.Database;
  private coverageData: Map<string, TestCoverageReport> = new Map();
  private testSuggestions: Map<string, TestSuggestion[]> = new Map();

  constructor(private databasePath: string) {
    this.db = new Database(databasePath);
    this.initializeDatabase();
    this.loadExistingData();
  }

  private initializeDatabase(): void {
    // Test coverage table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS test_coverage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        overall_coverage REAL NOT NULL,
        line_coverage REAL NOT NULL,
        branch_coverage REAL NOT NULL,
        function_coverage REAL NOT NULL,
        uncovered_lines TEXT, -- JSON array
        uncovered_functions TEXT, -- JSON array
        uncovered_branches TEXT, -- JSON array
        last_updated INTEGER NOT NULL
      )
    `);

    // Coverage gaps table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS coverage_gaps (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        gap_type TEXT NOT NULL,
        line_start INTEGER NOT NULL,
        line_end INTEGER NOT NULL,
        function_name TEXT,
        class_name TEXT,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        complexity INTEGER NOT NULL,
        risk_score REAL NOT NULL,
        detected_at INTEGER NOT NULL
      )
    `);

    // Test suggestions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS test_suggestions (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        priority TEXT NOT NULL,
        file_path TEXT NOT NULL,
        target_function TEXT,
        target_class TEXT,
        description TEXT NOT NULL,
        reasoning TEXT, -- JSON array
        test_template TEXT NOT NULL,
        test_framework TEXT NOT NULL,
        estimated_effort INTEGER NOT NULL,
        risk_mitigation TEXT, -- JSON array
        prerequisites TEXT, -- JSON array
        created_at INTEGER NOT NULL,
        implemented BOOLEAN DEFAULT FALSE
      )
    `);

    // Edge cases table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS edge_cases (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        function_name TEXT NOT NULL,
        scenario TEXT NOT NULL,
        input_values TEXT, -- JSON array
        expected_behavior TEXT NOT NULL,
        currently_covered BOOLEAN DEFAULT FALSE,
        risk_level TEXT NOT NULL,
        detection_method TEXT NOT NULL,
        detected_at INTEGER NOT NULL
      )
    `);

    // Test quality metrics table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS test_quality_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        test_file_path TEXT,
        test_count INTEGER NOT NULL,
        assertion_count INTEGER NOT NULL,
        mock_usage INTEGER NOT NULL,
        test_complexity REAL NOT NULL,
        test_maintainability REAL NOT NULL,
        duplicated_test_code INTEGER NOT NULL,
        test_smells TEXT, -- JSON array
        measured_at INTEGER NOT NULL
      )
    `);

    // Indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_coverage_file 
      ON test_coverage(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_gaps_file_severity 
      ON coverage_gaps(file_path, severity);
      
      CREATE INDEX IF NOT EXISTS idx_suggestions_priority 
      ON test_suggestions(priority, file_path);
      
      CREATE INDEX IF NOT EXISTS idx_edge_cases_file 
      ON edge_cases(file_path, currently_covered);
      
      CREATE INDEX IF NOT EXISTS idx_test_metrics_file 
      ON test_quality_metrics(file_path);
    `);
  }

  private loadExistingData(): void {
    // Load coverage data
    const coverageStmt = this.db.prepare('SELECT * FROM test_coverage ORDER BY last_updated DESC');
    const coverageRows = coverageStmt.all() as any[];
    
    for (const row of coverageRows) {
      this.coverageData.set(row.file_path, {
        filePath: row.file_path,
        overallCoverage: row.overall_coverage,
        lineCoverage: row.line_coverage,
        branchCoverage: row.branch_coverage,
        functionCoverage: row.function_coverage,
        uncoveredLines: JSON.parse(row.uncovered_lines || '[]'),
        uncoveredFunctions: JSON.parse(row.uncovered_functions || '[]'),
        uncoveredBranches: JSON.parse(row.uncovered_branches || '[]'),
        lastUpdated: row.last_updated
      });
    }

    // Load test suggestions
    const suggestionsStmt = this.db.prepare('SELECT * FROM test_suggestions WHERE implemented = FALSE');
    const suggestionRows = suggestionsStmt.all() as any[];
    
    for (const row of suggestionRows) {
      const filePath = row.file_path;
      if (!this.testSuggestions.has(filePath)) {
        this.testSuggestions.set(filePath, []);
      }
      
      this.testSuggestions.get(filePath)!.push({
        id: row.id,
        type: row.type,
        priority: row.priority,
        filePath: row.file_path,
        targetFunction: row.target_function,
        targetClass: row.target_class,
        description: row.description,
        reasoning: JSON.parse(row.reasoning || '[]'),
        testTemplate: row.test_template,
        testFramework: row.test_framework,
        estimatedEffort: row.estimated_effort,
        riskMitigation: JSON.parse(row.risk_mitigation || '[]'),
        prerequisites: JSON.parse(row.prerequisites || '[]')
      });
    }

    logger.info(`Loaded ${coverageRows.length} coverage reports, ${suggestionRows.length} test suggestions`);
  }

  async analyzeCoverage(filePath: string, symbols: ParsedSymbol[]): Promise<TestCoverageReport> {
    try {
      // Try to find existing coverage data from common coverage tools
      const coverageData = await this.loadCoverageData(filePath);
      
      if (coverageData) {
        // Use existing coverage data
        await this.storeCoverageReport(coverageData);
        this.coverageData.set(filePath, coverageData);
        return coverageData;
      }

      // Generate synthetic coverage analysis based on test files
      const testFiles = await this.findTestFiles(filePath);
      const syntheticCoverage = await this.generateSyntheticCoverage(filePath, symbols, testFiles);
      
      await this.storeCoverageReport(syntheticCoverage);
      this.coverageData.set(filePath, syntheticCoverage);
      
      return syntheticCoverage;
    } catch (error) {
      logger.error(`Error analyzing coverage for ${filePath}:`, error);
      return this.getDefaultCoverageReport(filePath);
    }
  }

  async identifyCoverageGaps(
    filePath: string, 
    symbols: ParsedSymbol[], 
    coverage: TestCoverageReport
  ): Promise<CoverageGap[]> {
    const gaps: CoverageGap[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Identify uncovered functions
      const functions = symbols.filter(s => s.kind === 'function');
      for (const func of functions) {
        if (coverage.uncoveredFunctions.includes(func.name)) {
          const complexity = this.calculateFunctionComplexity(func, lines);
          const riskScore = this.calculateRiskScore(func, complexity);
          
          gaps.push({
            type: 'function',
            location: {
              lineStart: func.lineStart,
              lineEnd: func.lineEnd,
              function: func.name
            },
            description: `Function ${func.name} is not covered by tests`,
            severity: this.getSeverityFromRisk(riskScore),
            complexity,
            riskScore
          });
        }
      }

      // Identify uncovered lines with high complexity
      for (const lineNum of coverage.uncoveredLines) {
        if (lineNum > 0 && lineNum <= lines.length) {
          const line = lines[lineNum - 1];
          const complexity = this.analyzeLineComplexity(line);
          
          if (complexity > 2) { // Only report complex uncovered lines
            gaps.push({
              type: 'line',
              location: {
                lineStart: lineNum,
                lineEnd: lineNum
              },
              description: `Complex line ${lineNum} is not covered`,
              severity: complexity > 4 ? 'high' : 'medium',
              complexity,
              riskScore: complexity * 2
            });
          }
        }
      }

      // Identify uncovered branches
      for (const branch of coverage.uncoveredBranches) {
        gaps.push(branch);
      }

      // Store gaps
      await this.storeCoverageGaps(gaps);

      return gaps.sort((a, b) => b.riskScore - a.riskScore);
    } catch (error) {
      logger.error(`Error identifying coverage gaps for ${filePath}:`, error);
      return [];
    }
  }

  async generateTestSuggestions(
    filePath: string, 
    symbols: ParsedSymbol[], 
    gaps: CoverageGap[]
  ): Promise<TestSuggestion[]> {
    const suggestions: TestSuggestion[] = [];

    try {
      // Determine test framework
      const framework = await this.detectTestFramework(filePath);

      // Generate suggestions for coverage gaps
      for (const gap of gaps) {
        if (gap.severity === 'high' || gap.severity === 'critical') {
          const suggestion = await this.createCoverageSuggestion(gap, framework);
          if (suggestion) {
            suggestions.push(suggestion);
          }
        }
      }

      // Generate suggestions for missing edge cases
      const edgeCases = await this.identifyMissingEdgeCases(filePath, symbols);
      for (const edgeCase of edgeCases) {
        if (!edgeCase.currentlyCovered) {
          const suggestion = await this.createEdgeCaseSuggestion(edgeCase, framework);
          if (suggestion) {
            suggestions.push(suggestion);
          }
        }
      }

      // Generate suggestions for error handling
      const errorHandlingSuggestions = await this.generateErrorHandlingSuggestions(filePath, symbols, framework);
      suggestions.push(...errorHandlingSuggestions);

      // Generate suggestions for security testing
      const securitySuggestions = await this.generateSecurityTestSuggestions(filePath, symbols, framework);
      suggestions.push(...securitySuggestions);

      // Store suggestions
      await this.storeTestSuggestions(suggestions);
      this.testSuggestions.set(filePath, suggestions);

      return suggestions.sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority));
    } catch (error) {
      logger.error(`Error generating test suggestions for ${filePath}:`, error);
      return [];
    }
  }

  async identifyMissingEdgeCases(filePath: string, symbols: ParsedSymbol[]): Promise<EdgeCase[]> {
    const edgeCases: EdgeCase[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const functions = symbols.filter(s => s.kind === 'function');

      for (const func of functions) {
        const funcContent = this.extractFunctionContent(content, func);
        const cases = this.analyzeForEdgeCases(func, funcContent);
        edgeCases.push(...cases);
      }

      // Store edge cases
      await this.storeEdgeCases(edgeCases);

      return edgeCases;
    } catch (error) {
      logger.error(`Error identifying edge cases for ${filePath}:`, error);
      return [];
    }
  }

  async generateTest(request: TestGenerationRequest): Promise<GeneratedTest> {
    try {
      const content = fs.readFileSync(request.filePath, 'utf-8');
      const symbols = []; // Would need to parse the file
      
      // Generate test based on request type
      switch (request.testType) {
        case 'unit':
          return await this.generateUnitTest(request, content, symbols);
        case 'integration':
          return await this.generateIntegrationTest(request, content, symbols);
        case 'edge_case':
          return await this.generateEdgeCaseTest(request, content, symbols);
        case 'error_handling':
          return await this.generateErrorHandlingTest(request, content, symbols);
        case 'security':
          return await this.generateSecurityTest(request, content, symbols);
        case 'performance':
          return await this.generatePerformanceTest(request, content, symbols);
        default:
          throw new Error(`Unsupported test type: ${request.testType}`);
      }
    } catch (error) {
      logger.error('Error generating test:', error);
      throw error;
    }
  }

  async analyzeTestQuality(testFilePath: string, sourceFilePath: string): Promise<TestQualityMetrics> {
    try {
      const testContent = fs.readFileSync(testFilePath, 'utf-8');
      const testLines = testContent.split('\n');

      // Count tests and assertions
      const testCount = this.countTests(testContent);
      const assertionCount = this.countAssertions(testContent);
      const mockUsage = this.countMockUsage(testContent);

      // Calculate complexity
      const testComplexity = this.calculateTestComplexity(testContent);
      const testMaintainability = this.calculateTestMaintainability(testLines);
      const duplicatedTestCode = this.findDuplicatedTestCode(testLines);

      // Identify test smells
      const testSmells = this.identifyTestSmells(testLines);

      const metrics: TestQualityMetrics = {
        filePath: sourceFilePath,
        testFilePath,
        testCount,
        assertionCount,
        mockUsage,
        testComplexity,
        testMaintainability,
        duplicatedTestCode,
        testSmells,
        coverageGaps: [], // Would be filled from coverage analysis
        missingEdgeCases: [] // Would be filled from edge case analysis
      };

      await this.storeTestQualityMetrics(metrics);
      return metrics;
    } catch (error) {
      logger.error(`Error analyzing test quality for ${testFilePath}:`, error);
      throw error;
    }
  }

  // Private helper methods

  private async loadCoverageData(filePath: string): Promise<TestCoverageReport | null> {
    // Try to load from common coverage files (coverage/lcov.info, coverage.json, etc.)
    const possiblePaths = [
      'coverage/lcov.info',
      'coverage/coverage-final.json',
      'coverage.json',
      '.nyc_output/coverage.json'
    ];

    for (const coveragePath of possiblePaths) {
      try {
        if (fs.existsSync(coveragePath)) {
          return await this.parseCoverageFile(coveragePath, filePath);
        }
      } catch (error) {
        logger.debug(`Failed to parse coverage file ${coveragePath}:`, error);
      }
    }

    return null;
  }

  private async parseCoverageFile(coveragePath: string, filePath: string): Promise<TestCoverageReport | null> {
    try {
      const ext = path.extname(coveragePath);
      
      if (ext === '.json') {
        const data = JSON.parse(fs.readFileSync(coveragePath, 'utf-8'));
        return this.extractCoverageFromJson(data, filePath);
      } else if (coveragePath.includes('lcov')) {
        const data = fs.readFileSync(coveragePath, 'utf-8');
        return this.extractCoverageFromLcov(data, filePath);
      }
    } catch (error) {
      logger.debug(`Error parsing coverage file ${coveragePath}:`, error);
    }

    return null;
  }

  private extractCoverageFromJson(data: any, filePath: string): TestCoverageReport | null {
    // Parse Istanbul/NYC coverage format
    const fileData = data[filePath];
    if (!fileData) return null;

    const { s: statements, b: branches, f: functions } = fileData;
    
    const totalStatements = Object.keys(statements).length;
    const coveredStatements = Object.values(statements).filter((count: any) => count > 0).length;
    
    const totalBranches = Object.keys(branches).length;
    const coveredBranches = Object.values(branches).filter((branch: any) => 
      Array.isArray(branch) ? branch.some(count => count > 0) : branch > 0
    ).length;
    
    const totalFunctions = Object.keys(functions).length;
    const coveredFunctions = Object.values(functions).filter((count: any) => count > 0).length;

    return {
      filePath,
      overallCoverage: (coveredStatements + coveredBranches + coveredFunctions) / 
                      (totalStatements + totalBranches + totalFunctions) * 100,
      lineCoverage: totalStatements > 0 ? (coveredStatements / totalStatements) * 100 : 100,
      branchCoverage: totalBranches > 0 ? (coveredBranches / totalBranches) * 100 : 100,
      functionCoverage: totalFunctions > 0 ? (coveredFunctions / totalFunctions) * 100 : 100,
      uncoveredLines: Object.entries(statements)
        .filter(([, count]) => (count as number) === 0)
        .map(([line]) => parseInt(line)),
      uncoveredFunctions: [], // Would need more parsing
      uncoveredBranches: [], // Would need more parsing
      lastUpdated: Date.now()
    };
  }

  private extractCoverageFromLcov(data: string, filePath: string): TestCoverageReport | null {
    // Parse LCOV format - simplified implementation
    const lines = data.split('\n');
    let currentFile = '';
    let inTargetFile = false;
    
    let linesCovered = 0;
    let linesTotal = 0;
    let branchesCovered = 0;
    let branchesTotal = 0;
    let functionsCovered = 0;
    let functionsTotal = 0;

    for (const line of lines) {
      if (line.startsWith('SF:')) {
        currentFile = line.substring(3);
        inTargetFile = currentFile.includes(filePath);
      } else if (inTargetFile) {
        if (line.startsWith('LH:')) linesCovered = parseInt(line.substring(3));
        else if (line.startsWith('LF:')) linesTotal = parseInt(line.substring(3));
        else if (line.startsWith('BRH:')) branchesCovered = parseInt(line.substring(4));
        else if (line.startsWith('BRF:')) branchesTotal = parseInt(line.substring(4));
        else if (line.startsWith('FNH:')) functionsCovered = parseInt(line.substring(4));
        else if (line.startsWith('FNF:')) functionsTotal = parseInt(line.substring(4));
      }
    }

    if (!inTargetFile) return null;

    return {
      filePath,
      overallCoverage: ((linesCovered + branchesCovered + functionsCovered) / 
                       (linesTotal + branchesTotal + functionsTotal)) * 100,
      lineCoverage: linesTotal > 0 ? (linesCovered / linesTotal) * 100 : 100,
      branchCoverage: branchesTotal > 0 ? (branchesCovered / branchesTotal) * 100 : 100,
      functionCoverage: functionsTotal > 0 ? (functionsCovered / functionsTotal) * 100 : 100,
      uncoveredLines: [], // Would need more detailed parsing
      uncoveredFunctions: [],
      uncoveredBranches: [],
      lastUpdated: Date.now()
    };
  }

  private async findTestFiles(filePath: string): Promise<string[]> {
    const testFiles: string[] = [];
    const baseName = path.basename(filePath, path.extname(filePath));
    const dir = path.dirname(filePath);
    
    // Common test file patterns
    const patterns = [
      `${baseName}.test.ts`,
      `${baseName}.test.js`,
      `${baseName}.spec.ts`,
      `${baseName}.spec.js`,
      `__tests__/${baseName}.test.ts`,
      `__tests__/${baseName}.test.js`,
      `tests/${baseName}.test.ts`,
      `tests/${baseName}.test.js`
    ];

    for (const pattern of patterns) {
      const testPath = path.join(dir, pattern);
      if (fs.existsSync(testPath)) {
        testFiles.push(testPath);
      }
    }

    return testFiles;
  }

  private async generateSyntheticCoverage(
    filePath: string, 
    symbols: ParsedSymbol[], 
    testFiles: string[]
  ): Promise<TestCoverageReport> {
    // Generate synthetic coverage based on test files and heuristics
    const functions = symbols.filter(s => s.kind === 'function');
    const hasTests = testFiles.length > 0;
    
    let estimatedCoverage = 0;
    if (hasTests) {
      // Analyze test files to estimate coverage
      for (const testFile of testFiles) {
        const testContent = fs.readFileSync(testFile, 'utf-8');
        const testCount = this.countTests(testContent);
        estimatedCoverage += Math.min(testCount * 10, 80); // Cap at 80% per test file
      }
    }

    estimatedCoverage = Math.min(estimatedCoverage, hasTests ? 85 : 20);

    const uncoveredFunctions = functions
      .filter(() => Math.random() > estimatedCoverage / 100)
      .map(f => f.name);

    return {
      filePath,
      overallCoverage: estimatedCoverage,
      lineCoverage: estimatedCoverage + Math.random() * 10 - 5,
      branchCoverage: estimatedCoverage - Math.random() * 15,
      functionCoverage: estimatedCoverage + Math.random() * 5,
      uncoveredLines: [], // Would need more sophisticated analysis
      uncoveredFunctions,
      uncoveredBranches: [],
      lastUpdated: Date.now()
    };
  }

  private getDefaultCoverageReport(filePath: string): TestCoverageReport {
    return {
      filePath,
      overallCoverage: 0,
      lineCoverage: 0,
      branchCoverage: 0,
      functionCoverage: 0,
      uncoveredLines: [],
      uncoveredFunctions: [],
      uncoveredBranches: [],
      lastUpdated: Date.now()
    };
  }

  private calculateFunctionComplexity(func: ParsedSymbol, lines: string[]): number {
    // Simple cyclomatic complexity calculation
    const funcLines = lines.slice(func.lineStart - 1, func.lineEnd);
    const content = funcLines.join(' ');
    
    let complexity = 1;
    const decisions = (content.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
    complexity += decisions;
    
    return complexity;
  }

  private calculateRiskScore(func: ParsedSymbol, complexity: number): number {
    let risk = complexity * 2;
    
    // Increase risk for public functions
    if (func.visibility === 'public' || func.isExported) {
      risk *= 1.5;
    }
    
    // Increase risk for larger functions
    const lineCount = func.lineEnd - func.lineStart + 1;
    if (lineCount > 50) {
      risk += lineCount / 10;
    }
    
    return Math.min(risk, 100);
  }

  private getSeverityFromRisk(riskScore: number): CoverageGap['severity'] {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 30) return 'medium';
    return 'low';
  }

  private analyzeLineComplexity(line: string): number {
    let complexity = 0;
    
    // Count decision points
    complexity += (line.match(/if|else|while|for|\?|&&|\|\|/g) || []).length;
    
    // Count function calls
    complexity += (line.match(/\w+\(/g) || []).length * 0.5;
    
    // Count operators
    complexity += (line.match(/[+\-*/%<>=!&|]/g) || []).length * 0.1;
    
    return Math.ceil(complexity);
  }

  private async detectTestFramework(filePath: string): Promise<TestSuggestion['testFramework']> {
    // Check package.json for test framework dependencies
    const packageJsonPath = this.findPackageJson(filePath);
    if (packageJsonPath) {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };
      
      if (deps.vitest) return 'vitest';
      if (deps.jest) return 'jest';
      if (deps.mocha) return 'mocha';
      if (deps.cypress) return 'cypress';
      if (deps.playwright) return 'playwright';
    }
    
    return 'jest'; // Default
  }

  private findPackageJson(filePath: string): string | null {
    let dir = path.dirname(filePath);
    
    while (dir !== '/') {
      const packagePath = path.join(dir, 'package.json');
      if (fs.existsSync(packagePath)) {
        return packagePath;
      }
      dir = path.dirname(dir);
    }
    
    return null;
  }

  private async createCoverageSuggestion(gap: CoverageGap, framework: string): Promise<TestSuggestion | null> {
    const template = this.generateTestTemplate(gap, framework);
    if (!template) return null;

    return {
      id: `coverage-${gap.type}-${gap.location.lineStart}-${Date.now()}`,
      type: 'unit',
      priority: gap.severity === 'critical' ? 'critical' : 
               gap.severity === 'high' ? 'high' : 'medium',
      filePath: '', // Would be set by caller
      targetFunction: gap.location.function,
      targetClass: gap.location.class,
      description: `Add test to cover ${gap.description}`,
      reasoning: [
        `Coverage gap: ${gap.description}`,
        `Risk score: ${gap.riskScore}`,
        `Complexity: ${gap.complexity}`
      ],
      testTemplate: template,
      testFramework: framework as TestSuggestion['testFramework'],
      estimatedEffort: gap.complexity * 5 + 10,
      riskMitigation: [
        'Reduces risk of undetected bugs',
        'Improves code reliability',
        'Enables safe refactoring'
      ],
      prerequisites: [],
      relatedCoverage: gap
    };
  }

  private async createEdgeCaseSuggestion(edgeCase: EdgeCase, framework: string): Promise<TestSuggestion | null> {
    const template = this.generateEdgeCaseTestTemplate(edgeCase, framework);
    
    return {
      id: `edge-case-${edgeCase.id}`,
      type: 'edge_case',
      priority: edgeCase.riskLevel === 'high' ? 'high' : 'medium',
      filePath: edgeCase.filePath,
      targetFunction: edgeCase.function,
      description: `Test edge case: ${edgeCase.scenario}`,
      reasoning: [
        `Edge case scenario: ${edgeCase.scenario}`,
        `Expected behavior: ${edgeCase.expectedBehavior}`,
        `Risk level: ${edgeCase.riskLevel}`
      ],
      testTemplate: template,
      testFramework: framework as TestSuggestion['testFramework'],
      estimatedEffort: 15,
      riskMitigation: [
        'Handles edge cases gracefully',
        'Prevents unexpected behavior',
        'Improves robustness'
      ],
      prerequisites: []
    };
  }

  private async generateErrorHandlingSuggestions(
    filePath: string, 
    symbols: ParsedSymbol[], 
    framework: string
  ): Promise<TestSuggestion[]> {
    const suggestions: TestSuggestion[] = [];
    
    // Look for functions that might throw errors
    const functions = symbols.filter(s => s.kind === 'function');
    
    for (const func of functions) {
      // Heuristic: functions with 'throw', 'error', 'fail' in signature
      if (func.signature && /throw|error|fail/i.test(func.signature)) {
        suggestions.push({
          id: `error-handling-${func.name}-${Date.now()}`,
          type: 'error_handling',
          priority: 'medium',
          filePath,
          targetFunction: func.name,
          description: `Test error handling in ${func.name}`,
          reasoning: [
            'Function may throw errors',
            'Error handling should be tested',
            'Ensures graceful error handling'
          ],
          testTemplate: this.generateErrorHandlingTestTemplate(func, framework),
          testFramework: framework as TestSuggestion['testFramework'],
          estimatedEffort: 20,
          riskMitigation: [
            'Verifies error handling',
            'Prevents unhandled exceptions',
            'Improves user experience'
          ],
          prerequisites: []
        });
      }
    }
    
    return suggestions;
  }

  private async generateSecurityTestSuggestions(
    filePath: string, 
    symbols: ParsedSymbol[], 
    framework: string
  ): Promise<TestSuggestion[]> {
    const suggestions: TestSuggestion[] = [];
    
    // Look for security-sensitive functions
    const securityKeywords = ['auth', 'login', 'password', 'token', 'validate', 'sanitize'];
    const functions = symbols.filter(s => 
      s.kind === 'function' && 
      securityKeywords.some(keyword => s.name.toLowerCase().includes(keyword))
    );
    
    for (const func of functions) {
      suggestions.push({
        id: `security-${func.name}-${Date.now()}`,
        type: 'security',
        priority: 'high',
        filePath,
        targetFunction: func.name,
        description: `Security test for ${func.name}`,
        reasoning: [
          'Function handles security-sensitive operations',
          'Security testing is critical',
          'Prevents security vulnerabilities'
        ],
        testTemplate: this.generateSecurityTestTemplate(func, framework),
        testFramework: framework as TestSuggestion['testFramework'],
        estimatedEffort: 30,
        riskMitigation: [
          'Prevents security vulnerabilities',
          'Validates security controls',
          'Ensures proper authentication/authorization'
        ],
        prerequisites: ['Security test utilities']
      });
    }
    
    return suggestions;
  }

  private analyzeForEdgeCases(func: ParsedSymbol, content: string): EdgeCase[] {
    const edgeCases: EdgeCase[] = [];
    
    // Simple heuristics for edge case detection
    const scenarios = [
      {
        condition: /array|list/i.test(content),
        scenario: 'Empty array/list',
        inputs: [[]],
        expected: 'Should handle empty array gracefully'
      },
      {
        condition: /string/i.test(content),
        scenario: 'Empty string',
        inputs: [''],
        expected: 'Should handle empty string'
      },
      {
        condition: /number|int/i.test(content),
        scenario: 'Zero value',
        inputs: [0],
        expected: 'Should handle zero value'
      },
      {
        condition: /null|undefined/i.test(content),
        scenario: 'Null/undefined input',
        inputs: [null, undefined],
        expected: 'Should handle null/undefined inputs'
      }
    ];
    
    for (const scenario of scenarios) {
      if (scenario.condition) {
        edgeCases.push({
          id: `edge-${func.name}-${scenario.scenario.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`,
          filePath: func.filePath,
          function: func.name,
          scenario: scenario.scenario,
          inputValues: scenario.inputs,
          expectedBehavior: scenario.expected,
          currentlyCovered: false, // Would need more analysis to determine
          riskLevel: 'medium',
          detectionMethod: 'heuristic'
        });
      }
    }
    
    return edgeCases;
  }

  private extractFunctionContent(content: string, func: ParsedSymbol): string {
    const lines = content.split('\n');
    return lines.slice(func.lineStart - 1, func.lineEnd).join('\n');
  }

  private generateTestTemplate(gap: CoverageGap, framework: string): string {
    switch (framework) {
      case 'jest':
        return this.generateJestTemplate(gap);
      case 'vitest':
        return this.generateVitestTemplate(gap);
      default:
        return this.generateJestTemplate(gap);
    }
  }

  private generateJestTemplate(gap: CoverageGap): string {
    const functionName = gap.location.function || 'targetFunction';
    
    return `describe('${functionName}', () => {
  test('should handle ${gap.description}', () => {
    // Arrange
    const input = /* test input */;
    const expected = /* expected output */;
    
    // Act
    const result = ${functionName}(input);
    
    // Assert
    expect(result).toBe(expected);
  });
});`;
  }

  private generateVitestTemplate(gap: CoverageGap): string {
    const functionName = gap.location.function || 'targetFunction';
    
    return `import { describe, test, expect } from 'vitest';

describe('${functionName}', () => {
  test('should handle ${gap.description}', () => {
    // Arrange
    const input = /* test input */;
    const expected = /* expected output */;
    
    // Act
    const result = ${functionName}(input);
    
    // Assert
    expect(result).toBe(expected);
  });
});`;
  }

  private generateEdgeCaseTestTemplate(edgeCase: EdgeCase, framework: string): string {
    return `test('${edgeCase.scenario}', () => {
  // Test ${edgeCase.scenario}
  const inputs = ${JSON.stringify(edgeCase.inputValues)};
  
  for (const input of inputs) {
    const result = ${edgeCase.function}(input);
    // ${edgeCase.expectedBehavior}
    expect(result).toBeDefined();
  }
});`;
  }

  private generateErrorHandlingTestTemplate(func: ParsedSymbol, framework: string): string {
    return `test('${func.name} error handling', () => {
  // Test error conditions
  expect(() => {
    ${func.name}(/* invalid input */);
  }).toThrow();
  
  // Test error messages
  try {
    ${func.name}(/* invalid input */);
  } catch (error) {
    expect(error.message).toContain('expected error message');
  }
});`;
  }

  private generateSecurityTestTemplate(func: ParsedSymbol, framework: string): string {
    return `test('${func.name} security', () => {
  // Test injection attacks
  const maliciousInput = '<script>alert("xss")</script>';
  const result = ${func.name}(maliciousInput);
  expect(result).not.toContain('<script>');
  
  // Test authorization
  expect(() => {
    ${func.name}(/* unauthorized input */);
  }).toThrow('Unauthorized');
});`;
  }

  private getPriorityWeight(priority: TestSuggestion['priority']): number {
    const weights = { critical: 4, high: 3, medium: 2, low: 1 };
    return weights[priority];
  }

  private countTests(content: string): number {
    return (content.match(/test\(|it\(|describe\(/g) || []).length;
  }

  private countAssertions(content: string): number {
    return (content.match(/expect\(|assert\(/g) || []).length;
  }

  private countMockUsage(content: string): number {
    return (content.match(/mock|spy|stub/gi) || []).length;
  }

  private calculateTestComplexity(content: string): number {
    let complexity = 1;
    const decisions = (content.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
    complexity += decisions;
    return complexity;
  }

  private calculateTestMaintainability(lines: string[]): number {
    // Simple maintainability heuristic
    const avgLineLength = lines.reduce((sum, line) => sum + line.length, 0) / lines.length;
    const duplicateRatio = this.findDuplicatedTestCode(lines) / lines.length;
    
    return Math.max(0, 100 - avgLineLength - duplicateRatio * 50);
  }

  private findDuplicatedTestCode(lines: string[]): number {
    const lineMap = new Map<string, number>();
    let duplicates = 0;
    
    for (const line of lines) {
      const normalized = line.trim();
      if (normalized.length > 10) {
        const count = lineMap.get(normalized) || 0;
        lineMap.set(normalized, count + 1);
        if (count === 1) duplicates++;
      }
    }
    
    return duplicates;
  }

  private identifyTestSmells(lines: string[]): TestSmell[] {
    const smells: TestSmell[] = [];
    
    // Long test smell
    let currentTest = { start: -1, end: -1, name: '' };
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes('test(') || line.includes('it(')) {
        if (currentTest.start !== -1 && i - currentTest.start > 50) {
          smells.push({
            type: 'long_test',
            location: {
              lineStart: currentTest.start + 1,
              lineEnd: i,
              testName: currentTest.name
            },
            description: `Test is ${i - currentTest.start} lines long`,
            impact: 'Reduces readability and maintainability',
            suggestion: 'Break down into smaller, focused tests'
          });
        }
        
        currentTest = { start: i, end: -1, name: line.trim() };
      }
    }
    
    // Assertion roulette - tests with many assertions
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes('test(') || line.includes('it(')) {
        let assertionCount = 0;
        let j = i + 1;
        
        while (j < lines.length && !lines[j].includes('test(') && !lines[j].includes('it(')) {
          if (lines[j].includes('expect(')) assertionCount++;
          j++;
        }
        
        if (assertionCount > 5) {
          smells.push({
            type: 'assertion_roulette',
            location: {
              lineStart: i + 1,
              lineEnd: j,
              testName: line.trim()
            },
            description: `Test has ${assertionCount} assertions`,
            impact: 'Makes test failures hard to diagnose',
            suggestion: 'Use one assertion per test or group related assertions'
          });
        }
      }
    }
    
    return smells;
  }

  // Database storage methods

  private async storeCoverageReport(report: TestCoverageReport): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO test_coverage (
        file_path, overall_coverage, line_coverage, branch_coverage,
        function_coverage, uncovered_lines, uncovered_functions,
        uncovered_branches, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      report.filePath,
      report.overallCoverage,
      report.lineCoverage,
      report.branchCoverage,
      report.functionCoverage,
      JSON.stringify(report.uncoveredLines),
      JSON.stringify(report.uncoveredFunctions),
      JSON.stringify(report.uncoveredBranches),
      report.lastUpdated
    );
  }

  private async storeCoverageGaps(gaps: CoverageGap[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO coverage_gaps (
        id, file_path, gap_type, line_start, line_end, function_name,
        class_name, description, severity, complexity, risk_score, detected_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const gap of gaps) {
      const id = `${gap.type}-${gap.location.lineStart}-${Date.now()}`;
      stmt.run(
        id,
        '', // Would be set by caller
        gap.type,
        gap.location.lineStart,
        gap.location.lineEnd,
        gap.location.function,
        gap.location.class,
        gap.description,
        gap.severity,
        gap.complexity,
        gap.riskScore,
        Date.now()
      );
    }
  }

  private async storeTestSuggestions(suggestions: TestSuggestion[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO test_suggestions (
        id, type, priority, file_path, target_function, target_class,
        description, reasoning, test_template, test_framework,
        estimated_effort, risk_mitigation, prerequisites, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const suggestion of suggestions) {
      stmt.run(
        suggestion.id,
        suggestion.type,
        suggestion.priority,
        suggestion.filePath,
        suggestion.targetFunction,
        suggestion.targetClass,
        suggestion.description,
        JSON.stringify(suggestion.reasoning),
        suggestion.testTemplate,
        suggestion.testFramework,
        suggestion.estimatedEffort,
        JSON.stringify(suggestion.riskMitigation),
        JSON.stringify(suggestion.prerequisites),
        Date.now()
      );
    }
  }

  private async storeEdgeCases(edgeCases: EdgeCase[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO edge_cases (
        id, file_path, function_name, scenario, input_values,
        expected_behavior, currently_covered, risk_level,
        detection_method, detected_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const edgeCase of edgeCases) {
      stmt.run(
        edgeCase.id,
        edgeCase.filePath,
        edgeCase.function,
        edgeCase.scenario,
        JSON.stringify(edgeCase.inputValues),
        edgeCase.expectedBehavior,
        edgeCase.currentlyCovered,
        edgeCase.riskLevel,
        edgeCase.detectionMethod,
        Date.now()
      );
    }
  }

  private async storeTestQualityMetrics(metrics: TestQualityMetrics): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO test_quality_metrics (
        file_path, test_file_path, test_count, assertion_count,
        mock_usage, test_complexity, test_maintainability,
        duplicated_test_code, test_smells, measured_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      metrics.filePath,
      metrics.testFilePath,
      metrics.testCount,
      metrics.assertionCount,
      metrics.mockUsage,
      metrics.testComplexity,
      metrics.testMaintainability,
      metrics.duplicatedTestCode,
      JSON.stringify(metrics.testSmells),
      Date.now()
    );
  }

  // Test generation methods (simplified implementations)

  private async generateUnitTest(request: TestGenerationRequest, content: string, symbols: ParsedSymbol[]): Promise<GeneratedTest> {
    const template = `import { describe, test, expect } from '${request.framework}';
import { ${request.functionName} } from '${request.filePath}';

describe('${request.functionName}', () => {
  test('should work correctly', () => {
    // Arrange
    const input = /* test input */;
    const expected = /* expected output */;
    
    // Act
    const result = ${request.functionName}(input);
    
    // Assert
    expect(result).toBe(expected);
  });
});`;

    return {
      testCode: template,
      description: `Unit test for ${request.functionName}`,
      framework: request.framework,
      dependencies: [request.framework],
      setup: [],
      teardown: [],
      coverage: {
        lines: [],
        branches: [],
        functions: [request.functionName || '']
      }
    };
  }

  private async generateIntegrationTest(request: TestGenerationRequest, content: string, symbols: ParsedSymbol[]): Promise<GeneratedTest> {
    // Simplified integration test generation
    return this.generateUnitTest(request, content, symbols);
  }

  private async generateEdgeCaseTest(request: TestGenerationRequest, content: string, symbols: ParsedSymbol[]): Promise<GeneratedTest> {
    // Simplified edge case test generation
    return this.generateUnitTest(request, content, symbols);
  }

  private async generateErrorHandlingTest(request: TestGenerationRequest, content: string, symbols: ParsedSymbol[]): Promise<GeneratedTest> {
    // Simplified error handling test generation
    return this.generateUnitTest(request, content, symbols);
  }

  private async generateSecurityTest(request: TestGenerationRequest, content: string, symbols: ParsedSymbol[]): Promise<GeneratedTest> {
    // Simplified security test generation
    return this.generateUnitTest(request, content, symbols);
  }

  private async generatePerformanceTest(request: TestGenerationRequest, content: string, symbols: ParsedSymbol[]): Promise<GeneratedTest> {
    // Simplified performance test generation
    return this.generateUnitTest(request, content, symbols);
  }
}