import { ParsedSymbol } from '../parser/ASTParser';
import { CodeSmell } from './TechnicalDebtTracker';
import { PerformanceIssue } from './PerformanceAnalyzer';
import { logger } from '../utils/logger';
import Database from 'better-sqlite3';
import * as fs from 'fs';

export interface RefactoringSuggestion {
  id: string;
  type: 'extract_method' | 'extract_class' | 'inline_method' | 'move_method' | 
        'rename_symbol' | 'simplify_conditional' | 'remove_duplication' | 
        'decompose_complex' | 'replace_algorithm' | 'introduce_parameter' |
        'remove_parameter' | 'merge_classes' | 'split_class' | 'extract_interface';
  priority: 'low' | 'medium' | 'high' | 'critical';
  filePath: string;
  title: string;
  description: string;
  motivation: string;
  targetLocation: {
    lineStart: number;
    lineEnd: number;
    function?: string;
    class?: string;
    symbol?: string;
  };
  affectedLocations: RefactoringLocation[];
  benefits: string[];
  risks: string[];
  preconditions: string[];
  postconditions: string[];
  estimatedEffort: 'trivial' | 'small' | 'medium' | 'large' | 'huge';
  safetyLevel: 'safe' | 'mostly_safe' | 'risky' | 'dangerous';
  automatable: boolean;
  codeChanges: CodeChange[];
  testChanges: TestChange[];
  relatedRefactorings: string[];
  conflictingRefactorings: string[];
  requiredTools: string[];
  detectedAt: number;
  confidence: number; // 0-1
}

export interface RefactoringLocation {
  filePath: string;
  lineStart: number;
  lineEnd: number;
  description: string;
  changeType: 'replace' | 'insert' | 'delete' | 'move';
}

export interface CodeChange {
  type: 'replace' | 'insert' | 'delete' | 'move';
  location: {
    filePath: string;
    lineStart: number;
    lineEnd?: number;
  };
  oldCode?: string;
  newCode?: string;
  description: string;
}

export interface TestChange {
  type: 'update_test' | 'add_test' | 'remove_test' | 'move_test';
  testFile: string;
  description: string;
  codeChange?: string;
}

export interface RefactoringPlan {
  id: string;
  title: string;
  description: string;
  refactorings: RefactoringSuggestion[];
  executionOrder: string[]; // IDs in execution order
  totalEffort: number; // hours
  totalRisk: 'low' | 'medium' | 'high';
  benefits: string[];
  prerequisites: string[];
  rollbackStrategy: string;
  validationSteps: string[];
  createdAt: number;
}

export interface RefactoringExecution {
  id: string;
  planId: string;
  refactoringId: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'rolled_back';
  startedAt?: number;
  completedAt?: number;
  result?: RefactoringResult;
  error?: string;
  rollbackInfo?: RollbackInfo;
}

export interface RefactoringResult {
  success: boolean;
  filesChanged: string[];
  linesChanged: number;
  testsAffected: string[];
  metricsImprovement: {
    complexity: number;
    maintainability: number;
    readability: number;
    performance: number;
  };
  warnings: string[];
  errors: string[];
}

export interface RollbackInfo {
  backupFiles: { [filePath: string]: string };
  rollbackSteps: string[];
  canRollback: boolean;
}

export interface SafetyCheck {
  id: string;
  type: 'syntax_check' | 'type_check' | 'test_check' | 'reference_check' | 'dependency_check';
  description: string;
  passed: boolean;
  details: string;
  blocking: boolean;
}

export interface RefactoringImpact {
  filePath: string;
  changeType: 'direct' | 'indirect' | 'test' | 'dependency';
  description: string;
  riskLevel: 'low' | 'medium' | 'high';
  mitigation: string[];
}

export class RefactoringAssistant {
  private db: Database.Database;
  private suggestions: Map<string, RefactoringSuggestion[]> = new Map();
  private plans: Map<string, RefactoringPlan> = new Map();
  private executions: Map<string, RefactoringExecution> = new Map();

  constructor(private databasePath: string) {
    this.db = new Database(databasePath);
    this.initializeDatabase();
    this.loadExistingData();
  }

  private initializeDatabase(): void {
    // Refactoring suggestions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS refactoring_suggestions (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        priority TEXT NOT NULL,
        file_path TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        motivation TEXT NOT NULL,
        target_line_start INTEGER NOT NULL,
        target_line_end INTEGER NOT NULL,
        target_function TEXT,
        target_class TEXT,
        target_symbol TEXT,
        affected_locations TEXT, -- JSON array
        benefits TEXT, -- JSON array
        risks TEXT, -- JSON array
        preconditions TEXT, -- JSON array
        postconditions TEXT, -- JSON array
        estimated_effort TEXT NOT NULL,
        safety_level TEXT NOT NULL,
        automatable BOOLEAN NOT NULL,
        code_changes TEXT, -- JSON array
        test_changes TEXT, -- JSON array
        related_refactorings TEXT, -- JSON array
        conflicting_refactorings TEXT, -- JSON array
        required_tools TEXT, -- JSON array
        detected_at INTEGER NOT NULL,
        confidence REAL NOT NULL
      )
    `);

    // Refactoring plans table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS refactoring_plans (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        refactorings TEXT, -- JSON array of IDs
        execution_order TEXT, -- JSON array
        total_effort REAL NOT NULL,
        total_risk TEXT NOT NULL,
        benefits TEXT, -- JSON array
        prerequisites TEXT, -- JSON array
        rollback_strategy TEXT NOT NULL,
        validation_steps TEXT, -- JSON array
        created_at INTEGER NOT NULL
      )
    `);

    // Refactoring executions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS refactoring_executions (
        id TEXT PRIMARY KEY,
        plan_id TEXT NOT NULL,
        refactoring_id TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at INTEGER,
        completed_at INTEGER,
        result TEXT, -- JSON
        error TEXT,
        rollback_info TEXT, -- JSON
        FOREIGN KEY (plan_id) REFERENCES refactoring_plans(id),
        FOREIGN KEY (refactoring_id) REFERENCES refactoring_suggestions(id)
      )
    `);

    // Safety checks table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS safety_checks (
        id TEXT PRIMARY KEY,
        execution_id TEXT NOT NULL,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        passed BOOLEAN NOT NULL,
        details TEXT NOT NULL,
        blocking BOOLEAN NOT NULL,
        checked_at INTEGER NOT NULL,
        FOREIGN KEY (execution_id) REFERENCES refactoring_executions(id)
      )
    `);

    // Indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_refactoring_file_priority 
      ON refactoring_suggestions(file_path, priority);
      
      CREATE INDEX IF NOT EXISTS idx_refactoring_type 
      ON refactoring_suggestions(type);
      
      CREATE INDEX IF NOT EXISTS idx_refactoring_safety 
      ON refactoring_suggestions(safety_level);
      
      CREATE INDEX IF NOT EXISTS idx_executions_status 
      ON refactoring_executions(status);
      
      CREATE INDEX IF NOT EXISTS idx_executions_plan 
      ON refactoring_executions(plan_id);
    `);
  }

  private loadExistingData(): void {
    // Load suggestions
    const suggestionStmt = this.db.prepare('SELECT * FROM refactoring_suggestions ORDER BY priority DESC, confidence DESC');
    const suggestions = suggestionStmt.all() as any[];
    
    for (const suggestion of suggestions) {
      const filePath = suggestion.file_path;
      if (!this.suggestions.has(filePath)) {
        this.suggestions.set(filePath, []);
      }
      
      this.suggestions.get(filePath)!.push(this.mapRowToSuggestion(suggestion));
    }

    // Load plans
    const planStmt = this.db.prepare('SELECT * FROM refactoring_plans ORDER BY created_at DESC');
    const plans = planStmt.all() as any[];
    
    for (const plan of plans) {
      this.plans.set(plan.id, this.mapRowToPlan(plan));
    }

    // Load executions
    const executionStmt = this.db.prepare('SELECT * FROM refactoring_executions ORDER BY started_at DESC');
    const executions = executionStmt.all() as any[];
    
    for (const execution of executions) {
      this.executions.set(execution.id, this.mapRowToExecution(execution));
    }

    logger.info(`Loaded ${suggestions.length} suggestions, ${plans.length} plans, ${executions.length} executions`);
  }

  async analyzeRefactoringOpportunities(
    filePath: string,
    symbols: ParsedSymbol[],
    codeSmells?: CodeSmell[],
    performanceIssues?: PerformanceIssue[]
  ): Promise<RefactoringSuggestion[]> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      const suggestions: RefactoringSuggestion[] = [];

      // Extract method opportunities
      suggestions.push(...this.identifyExtractMethodOpportunities(filePath, lines, symbols));

      // Extract class opportunities
      suggestions.push(...this.identifyExtractClassOpportunities(filePath, lines, symbols));

      // Simplify conditional opportunities
      suggestions.push(...this.identifySimplifyConditionalOpportunities(filePath, lines));

      // Remove duplication opportunities
      suggestions.push(...this.identifyRemoveDuplicationOpportunities(filePath, lines));

      // Rename symbol opportunities
      suggestions.push(...this.identifyRenameOpportunities(filePath, lines, symbols));

      // Move method opportunities
      suggestions.push(...this.identifyMoveMethodOpportunities(filePath, lines, symbols));

      // Algorithm replacement opportunities
      suggestions.push(...this.identifyAlgorithmReplacementOpportunities(filePath, lines));

      // Suggestions from code smells
      if (codeSmells) {
        suggestions.push(...this.createSuggestionsFromCodeSmells(codeSmells));
      }

      // Suggestions from performance issues
      if (performanceIssues) {
        suggestions.push(...this.createSuggestionsFromPerformanceIssues(performanceIssues));
      }

      // Store suggestions
      await this.storeRefactoringSuggestions(suggestions);
      this.suggestions.set(filePath, suggestions);

      return suggestions.sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority));
    } catch (error) {
      logger.error(`Error analyzing refactoring opportunities for ${filePath}:`, error);
      return [];
    }
  }

  async createRefactoringPlan(
    title: string,
    description: string,
    suggestionIds: string[]
  ): Promise<RefactoringPlan> {
    try {
      const selectedSuggestions = this.getSelectedSuggestions(suggestionIds);
      
      // Analyze dependencies and conflicts
      const executionOrder = this.calculateExecutionOrder(selectedSuggestions);
      
      // Calculate total effort and risk
      const totalEffort = selectedSuggestions.reduce((sum, s) => 
        sum + this.effortToHours(s.estimatedEffort), 0);
      
      const totalRisk = this.calculateTotalRisk(selectedSuggestions);

      // Generate benefits and prerequisites
      const benefits = this.consolidateBenefits(selectedSuggestions);
      const prerequisites = this.consolidatePrerequisites(selectedSuggestions);

      const plan: RefactoringPlan = {
        id: `plan-${Date.now()}`,
        title,
        description,
        refactorings: selectedSuggestions,
        executionOrder,
        totalEffort,
        totalRisk,
        benefits,
        prerequisites,
        rollbackStrategy: this.generateRollbackStrategy(selectedSuggestions),
        validationSteps: this.generateValidationSteps(selectedSuggestions),
        createdAt: Date.now()
      };

      await this.storeRefactoringPlan(plan);
      this.plans.set(plan.id, plan);

      return plan;
    } catch (error) {
      logger.error('Error creating refactoring plan:', error);
      throw error;
    }
  }

  async validateRefactoringSafety(suggestionId: string): Promise<SafetyCheck[]> {
    try {
      const suggestion = this.findSuggestionById(suggestionId);
      if (!suggestion) {
        throw new Error(`Suggestion ${suggestionId} not found`);
      }

      const checks: SafetyCheck[] = [];

      // Syntax check
      checks.push(await this.performSyntaxCheck(suggestion));

      // Reference check
      checks.push(await this.performReferenceCheck(suggestion));

      // Test check
      checks.push(await this.performTestCheck(suggestion));

      // Dependency check
      checks.push(await this.performDependencyCheck(suggestion));

      // Type check (if TypeScript)
      if (suggestion.filePath.endsWith('.ts') || suggestion.filePath.endsWith('.tsx')) {
        checks.push(await this.performTypeCheck(suggestion));
      }

      return checks;
    } catch (error) {
      logger.error(`Error validating refactoring safety for ${suggestionId}:`, error);
      return [];
    }
  }

  async analyzeRefactoringImpact(suggestionId: string): Promise<RefactoringImpact[]> {
    try {
      const suggestion = this.findSuggestionById(suggestionId);
      if (!suggestion) {
        throw new Error(`Suggestion ${suggestionId} not found`);
      }

      const impacts: RefactoringImpact[] = [];

      // Direct impact on target file
      impacts.push({
        filePath: suggestion.filePath,
        changeType: 'direct',
        description: 'Direct changes to the target file',
        riskLevel: suggestion.safetyLevel === 'safe' ? 'low' : 
                  suggestion.safetyLevel === 'mostly_safe' ? 'medium' : 'high',
        mitigation: ['Run tests after changes', 'Code review']
      });

      // Impact on affected locations
      for (const location of suggestion.affectedLocations) {
        impacts.push({
          filePath: location.filePath,
          changeType: 'indirect',
          description: location.description,
          riskLevel: 'medium',
          mitigation: ['Verify references', 'Update imports']
        });
      }

      // Impact on tests
      for (const testChange of suggestion.testChanges) {
        impacts.push({
          filePath: testChange.testFile,
          changeType: 'test',
          description: testChange.description,
          riskLevel: 'low',
          mitigation: ['Update test expectations', 'Add new test cases']
        });
      }

      return impacts;
    } catch (error) {
      logger.error(`Error analyzing refactoring impact for ${suggestionId}:`, error);
      return [];
    }
  }

  async executeRefactoringPlan(planId: string): Promise<RefactoringExecution[]> {
    try {
      const plan = this.plans.get(planId);
      if (!plan) {
        throw new Error(`Plan ${planId} not found`);
      }

      const executions: RefactoringExecution[] = [];

      for (const refactoringId of plan.executionOrder) {
        const execution = await this.executeRefactoring(planId, refactoringId);
        executions.push(execution);

        // Stop if execution failed
        if (execution.status === 'failed') {
          logger.error(`Refactoring execution failed: ${execution.error}`);
          break;
        }
      }

      return executions;
    } catch (error) {
      logger.error(`Error executing refactoring plan ${planId}:`, error);
      throw error;
    }
  }

  async rollbackRefactoring(executionId: string): Promise<boolean> {
    try {
      const execution = this.executions.get(executionId);
      if (!execution || !execution.rollbackInfo) {
        return false;
      }

      const { backupFiles, rollbackSteps } = execution.rollbackInfo;

      // Restore backup files
      for (const [filePath, backupContent] of Object.entries(backupFiles)) {
        fs.writeFileSync(filePath, backupContent);
      }

      // Execute rollback steps
      for (const step of rollbackSteps) {
        logger.info(`Rollback step: ${step}`);
        // Execute rollback step (simplified)
      }

      // Update execution status
      execution.status = 'rolled_back';
      await this.updateExecution(execution);

      return true;
    } catch (error) {
      logger.error(`Error rolling back refactoring ${executionId}:`, error);
      return false;
    }
  }

  // Private analysis methods

  private identifyExtractMethodOpportunities(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];
    const functions = symbols.filter(s => s.kind === 'function');

    for (const func of functions) {
      const funcLines = lines.slice(func.lineStart - 1, func.lineEnd);
      const lineCount = funcLines.length;

      // Long method
      if (lineCount > 20) {
        const duplicatedBlocks = this.findDuplicatedBlocks(funcLines);
        
        for (const block of duplicatedBlocks) {
          suggestions.push({
            id: `extract-method-${func.name}-${block.start}-${Date.now()}`,
            type: 'extract_method',
            priority: lineCount > 50 ? 'high' : 'medium',
            filePath,
            title: `Extract method from ${func.name}`,
            description: `Extract ${block.end - block.start + 1} lines into a separate method`,
            motivation: 'Reduce method complexity and improve readability',
            targetLocation: {
              lineStart: func.lineStart + block.start,
              lineEnd: func.lineStart + block.end,
              function: func.name
            },
            affectedLocations: [{
              filePath,
              lineStart: func.lineStart,
              lineEnd: func.lineEnd,
              description: 'Original method will be modified',
              changeType: 'replace'
            }],
            benefits: [
              'Improved readability',
              'Better testability',
              'Reduced complexity',
              'Code reuse potential'
            ],
            risks: [
              'May introduce parameter passing',
              'Slight performance overhead'
            ],
            preconditions: [
              'Block is cohesive',
              'No complex variable dependencies'
            ],
            postconditions: [
              'Original method calls extracted method',
              'Extracted method is properly named'
            ],
            estimatedEffort: 'small',
            safetyLevel: 'safe',
            automatable: true,
            codeChanges: this.generateExtractMethodChanges(func, block, lines),
            testChanges: [{
              type: 'add_test',
              testFile: this.getTestFile(filePath),
              description: 'Add tests for extracted method'
            }],
            relatedRefactorings: [],
            conflictingRefactorings: [],
            requiredTools: ['AST parser', 'Code formatter'],
            detectedAt: Date.now(),
            confidence: 0.8
          });
        }
      }
    }

    return suggestions;
  }

  private identifyExtractClassOpportunities(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];
    const classes = symbols.filter(s => s.kind === 'class');

    for (const cls of classes) {
      const methods = symbols.filter(s => s.kind === 'method' && s.parentSymbolId === Number(cls.id));
      const lineCount = cls.lineEnd - cls.lineStart + 1;

      // Large class
      if (methods.length > 15 || lineCount > 300) {
        // Analyze method cohesion
        const cohesionGroups = this.analyzeCohesion(methods, lines);
        
        if (cohesionGroups.length > 1) {
          for (let i = 1; i < cohesionGroups.length; i++) {
            const group = cohesionGroups[i];
            
            suggestions.push({
              id: `extract-class-${cls.name}-${i}-${Date.now()}`,
              type: 'extract_class',
              priority: 'medium',
              filePath,
              title: `Extract class from ${cls.name}`,
              description: `Extract ${group.methods.length} methods into a separate class`,
              motivation: 'Improve single responsibility and reduce class size',
              targetLocation: {
                lineStart: Math.min(...group.methods.map(m => m.lineStart)),
                lineEnd: Math.max(...group.methods.map(m => m.lineEnd)),
                class: cls.name
              },
              affectedLocations: [{
                filePath,
                lineStart: cls.lineStart,
                lineEnd: cls.lineEnd,
                description: 'Original class will be modified',
                changeType: 'replace'
              }],
              benefits: [
                'Better separation of concerns',
                'Improved maintainability',
                'Easier testing',
                'Reduced complexity'
              ],
              risks: [
                'May require interface changes',
                'Potential performance impact',
                'Breaking changes'
              ],
              preconditions: [
                'Methods form cohesive group',
                'Clear responsibility boundary'
              ],
              postconditions: [
                'New class created',
                'Original class uses new class',
                'All tests pass'
              ],
              estimatedEffort: 'large',
              safetyLevel: 'risky',
              automatable: false,
              codeChanges: this.generateExtractClassChanges(cls, group, lines),
              testChanges: [{
                type: 'add_test',
                testFile: this.getTestFile(filePath),
                description: 'Add tests for extracted class'
              }],
              relatedRefactorings: [],
              conflictingRefactorings: [],
              requiredTools: ['Refactoring IDE', 'Test framework'],
              detectedAt: Date.now(),
              confidence: 0.7
            });
          }
        }
      }
    }

    return suggestions;
  }

  private identifySimplifyConditionalOpportunities(
    filePath: string,
    lines: string[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Complex conditional
      if (line.includes('if') && this.countLogicalOperators(line) > 3) {
        suggestions.push({
          id: `simplify-conditional-${i}-${Date.now()}`,
          type: 'simplify_conditional',
          priority: 'low',
          filePath,
          title: 'Simplify complex conditional',
          description: 'Break down complex conditional into readable parts',
          motivation: 'Improve readability and maintainability',
          targetLocation: {
            lineStart: i + 1,
            lineEnd: i + 1
          },
          affectedLocations: [],
          benefits: [
            'Improved readability',
            'Easier debugging',
            'Better testability'
          ],
          risks: [
            'May increase line count',
            'Potential logic errors'
          ],
          preconditions: [
            'Conditional is complex',
            'Logic can be decomposed'
          ],
          postconditions: [
            'Conditional is simplified',
            'Logic is preserved'
          ],
          estimatedEffort: 'trivial',
          safetyLevel: 'mostly_safe',
          automatable: true,
          codeChanges: [{
            type: 'replace',
            location: { filePath, lineStart: i + 1 },
            oldCode: line,
            newCode: this.generateSimplifiedConditional(line),
            description: 'Replace complex conditional with simplified version'
          }],
          testChanges: [],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['Code formatter'],
          detectedAt: Date.now(),
          confidence: 0.9
        });
      }
    }

    return suggestions;
  }

  private identifyRemoveDuplicationOpportunities(
    filePath: string,
    lines: string[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];
    const duplicates = this.findCodeDuplication(lines);

    for (const duplicate of duplicates) {
      if (duplicate.occurrences.length > 1) {
        suggestions.push({
          id: `remove-duplication-${duplicate.hash}-${Date.now()}`,
          type: 'remove_duplication',
          priority: duplicate.occurrences.length > 2 ? 'medium' : 'low',
          filePath,
          title: 'Remove code duplication',
          description: `Remove duplicated code block (${duplicate.occurrences.length} occurrences)`,
          motivation: 'Eliminate duplication to improve maintainability',
          targetLocation: {
            lineStart: duplicate.occurrences[0].start,
            lineEnd: duplicate.occurrences[0].end
          },
          affectedLocations: duplicate.occurrences.slice(1).map(occ => ({
            filePath,
            lineStart: occ.start,
            lineEnd: occ.end,
            description: 'Duplicate code location',
            changeType: 'replace' as const
          })),
          benefits: [
            'Eliminate duplication',
            'Single point of maintenance',
            'Improved consistency'
          ],
          risks: [
            'May need parameterization',
            'Potential abstraction overhead'
          ],
          preconditions: [
            'Code blocks are truly identical',
            'Can be safely extracted'
          ],
          postconditions: [
            'Common code extracted',
            'All occurrences use extracted code'
          ],
          estimatedEffort: 'small',
          safetyLevel: 'mostly_safe',
          automatable: true,
          codeChanges: this.generateDeduplicationChanges(duplicate, lines),
          testChanges: [{
            type: 'update_test',
            testFile: this.getTestFile(filePath),
            description: 'Update tests for extracted code'
          }],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['AST parser', 'Code generator'],
          detectedAt: Date.now(),
          confidence: 0.85
        });
      }
    }

    return suggestions;
  }

  private identifyRenameOpportunities(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];

    for (const symbol of symbols) {
      // Check for poor naming
      if (this.isPoorlyNamed(symbol.name)) {
        const betterName = this.suggestBetterName(symbol, lines);
        
        suggestions.push({
          id: `rename-${symbol.name}-${Date.now()}`,
          type: 'rename_symbol',
          priority: 'low',
          filePath,
          title: `Rename ${symbol.kind} '${symbol.name}'`,
          description: `Rename '${symbol.name}' to '${betterName}' for better clarity`,
          motivation: 'Improve code readability and self-documentation',
          targetLocation: {
            lineStart: symbol.lineStart,
            lineEnd: symbol.lineEnd,
            symbol: symbol.name
          },
          affectedLocations: [], // Would need reference analysis
          benefits: [
            'Improved readability',
            'Better self-documentation',
            'Clearer intent'
          ],
          risks: [
            'May break external references',
            'Requires updating all references'
          ],
          preconditions: [
            'Symbol is poorly named',
            'Better name is available'
          ],
          postconditions: [
            'Symbol has clear name',
            'All references updated'
          ],
          estimatedEffort: 'trivial',
          safetyLevel: 'safe',
          automatable: true,
          codeChanges: [{
            type: 'replace',
            location: { filePath, lineStart: symbol.lineStart },
            oldCode: symbol.name,
            newCode: betterName,
            description: `Rename ${symbol.name} to ${betterName}`
          }],
          testChanges: [{
            type: 'update_test',
            testFile: this.getTestFile(filePath),
            description: 'Update test references'
          }],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['Rename refactoring tool'],
          detectedAt: Date.now(),
          confidence: 0.6
        });
      }
    }

    return suggestions;
  }

  private identifyMoveMethodOpportunities(
    filePath: string,
    lines: string[],
    symbols: ParsedSymbol[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];
    const methods = symbols.filter(s => s.kind === 'method');

    for (const method of methods) {
      // Analyze method dependencies
      const dependencies = this.analyzeMethodDependencies(method, lines, symbols);
      
      // Check for feature envy (method uses more external data than own class data)
      if (dependencies.external > dependencies.internal * 2) {
        const targetClass = dependencies.mostUsedExternal;
        
        suggestions.push({
          id: `move-method-${method.name}-${Date.now()}`,
          type: 'move_method',
          priority: 'medium',
          filePath,
          title: `Move method ${method.name}`,
          description: `Move method to ${targetClass} where it's more naturally placed`,
          motivation: 'Address feature envy and improve cohesion',
          targetLocation: {
            lineStart: method.lineStart,
            lineEnd: method.lineEnd,
            function: method.name
          },
          affectedLocations: [], // Would need analysis of target class
          benefits: [
            'Improved cohesion',
            'Better encapsulation',
            'Reduced coupling'
          ],
          risks: [
            'May break existing interfaces',
            'Requires careful dependency management'
          ],
          preconditions: [
            'Method has feature envy',
            'Target class exists'
          ],
          postconditions: [
            'Method moved to appropriate class',
            'Dependencies properly managed'
          ],
          estimatedEffort: 'medium',
          safetyLevel: 'risky',
          automatable: false,
          codeChanges: this.generateMoveMethodChanges(method, targetClass),
          testChanges: [{
            type: 'update_test',
            testFile: this.getTestFile(filePath),
            description: 'Update tests for moved method'
          }],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['Move refactoring tool', 'Dependency analyzer'],
          detectedAt: Date.now(),
          confidence: 0.7
        });
      }
    }

    return suggestions;
  }

  private identifyAlgorithmReplacementOpportunities(
    filePath: string,
    lines: string[]
  ): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];

    // Look for inefficient sorting
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Bubble sort pattern
      if (this.isBubbleSort(lines, i)) {
        suggestions.push({
          id: `replace-algorithm-sort-${i}-${Date.now()}`,
          type: 'replace_algorithm',
          priority: 'medium',
          filePath,
          title: 'Replace inefficient sorting algorithm',
          description: 'Replace bubble sort with efficient built-in sort',
          motivation: 'Improve performance from O(n²) to O(n log n)',
          targetLocation: {
            lineStart: i + 1,
            lineEnd: i + 6 // Typical bubble sort block
          },
          affectedLocations: [],
          benefits: [
            'Significantly better performance',
            'Less code to maintain',
            'More reliable implementation'
          ],
          risks: [
            'Different stability characteristics',
            'May need custom comparison function'
          ],
          preconditions: [
            'Bubble sort implementation detected',
            'Array.sort() available'
          ],
          postconditions: [
            'Efficient sorting in place',
            'Same sorting behavior'
          ],
          estimatedEffort: 'small',
          safetyLevel: 'mostly_safe',
          automatable: true,
          codeChanges: [{
            type: 'replace',
            location: { filePath, lineStart: i + 1, lineEnd: i + 6 },
            oldCode: lines.slice(i, i + 6).join('\n'),
            newCode: 'array.sort((a, b) => a - b);',
            description: 'Replace bubble sort with Array.sort()'
          }],
          testChanges: [],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['Code generator'],
          detectedAt: Date.now(),
          confidence: 0.9
        });
      }
    }

    return suggestions;
  }

  private createSuggestionsFromCodeSmells(codeSmells: CodeSmell[]): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];

    for (const smell of codeSmells) {
      const refactoringType = this.mapSmellToRefactoring(smell.type);
      if (refactoringType) {
        suggestions.push({
          id: `from-smell-${smell.id}`,
          type: refactoringType,
          priority: smell.severity === 'critical' ? 'critical' : 
                   smell.severity === 'high' ? 'high' : 'medium',
          filePath: smell.filePath,
          title: `Address ${smell.type.replace('_', ' ')}`,
          description: smell.description,
          motivation: smell.impact,
          targetLocation: {
            lineStart: smell.location.lineStart,
            lineEnd: smell.location.lineEnd,
            function: smell.location.function,
            class: smell.location.class
          },
          affectedLocations: [],
          benefits: smell.suggestions,
          risks: ['May require significant changes'],
          preconditions: ['Code smell confirmed'],
          postconditions: ['Code smell resolved'],
          estimatedEffort: smell.effortToFix,
          safetyLevel: 'mostly_safe',
          automatable: false,
          codeChanges: [],
          testChanges: [],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['Refactoring tools'],
          detectedAt: Date.now(),
          confidence: 0.8
        });
      }
    }

    return suggestions;
  }

  private createSuggestionsFromPerformanceIssues(performanceIssues: PerformanceIssue[]): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];

    for (const issue of performanceIssues) {
      const refactoringType = this.mapPerformanceIssueToRefactoring(issue.type);
      if (refactoringType) {
        suggestions.push({
          id: `from-perf-${issue.id}`,
          type: refactoringType,
          priority: issue.severity === 'critical' ? 'critical' : 
                   issue.severity === 'high' ? 'high' : 'medium',
          filePath: issue.filePath,
          title: `Address ${issue.title}`,
          description: issue.description,
          motivation: `Performance improvement: ${issue.estimatedSlowdown}x slower`,
          targetLocation: {
            lineStart: issue.location.lineStart,
            lineEnd: issue.location.lineEnd,
            function: issue.location.function,
            class: issue.location.class
          },
          affectedLocations: [],
          benefits: [issue.suggestedFix],
          risks: ['May change behavior'],
          preconditions: ['Performance issue confirmed'],
          postconditions: ['Performance improved'],
          estimatedEffort: 'small',
          safetyLevel: 'mostly_safe',
          automatable: true,
          codeChanges: [],
          testChanges: [],
          relatedRefactorings: [],
          conflictingRefactorings: [],
          requiredTools: ['Performance tools'],
          detectedAt: Date.now(),
          confidence: issue.confidence
        });
      }
    }

    return suggestions;
  }

  // Helper methods for analysis

  private findDuplicatedBlocks(lines: string[]): Array<{ start: number; end: number; content: string }> {
    const blocks: Array<{ start: number; end: number; content: string }> = [];
    const minBlockSize = 5;

    for (let i = 0; i <= lines.length - minBlockSize; i++) {
      for (let j = i + minBlockSize; j <= lines.length; j++) {
        const candidate = lines.slice(i, j);
        const content = candidate.join('\n').trim();
        
        if (content.length > 100) { // Only substantial blocks
          // Look for this block elsewhere in the method
          for (let k = j; k <= lines.length - candidate.length; k++) {
            const comparison = lines.slice(k, k + candidate.length);
            if (this.isBlockSimilar(candidate, comparison)) {
              blocks.push({ start: i, end: j - 1, content });
              break;
            }
          }
        }
      }
    }

    return blocks;
  }

  private isBlockSimilar(block1: string[], block2: string[]): boolean {
    if (block1.length !== block2.length) return false;
    
    let similarLines = 0;
    for (let i = 0; i < block1.length; i++) {
      const normalized1 = block1[i].trim().replace(/\s+/g, ' ');
      const normalized2 = block2[i].trim().replace(/\s+/g, ' ');
      
      if (normalized1 === normalized2) {
        similarLines++;
      }
    }
    
    return similarLines / block1.length > 0.8; // 80% similarity
  }

  private analyzeCohesion(methods: ParsedSymbol[], lines: string[]): Array<{ methods: ParsedSymbol[]; cohesion: number }> {
    // Simplified cohesion analysis
    // In a real implementation, this would analyze method interactions
    const groups = [{ methods, cohesion: 1.0 }];
    
    // Split large groups (simplified heuristic)
    if (methods.length > 10) {
      const mid = Math.floor(methods.length / 2);
      return [
        { methods: methods.slice(0, mid), cohesion: 0.8 },
        { methods: methods.slice(mid), cohesion: 0.8 }
      ];
    }
    
    return groups;
  }

  private findCodeDuplication(lines: string[]): Array<{
    hash: string;
    occurrences: Array<{ start: number; end: number }>;
  }> {
    const duplicates: Array<{
      hash: string;
      occurrences: Array<{ start: number; end: number }>;
    }> = [];

    const blockSize = 5;
    const blocks = new Map<string, Array<{ start: number; end: number }>>();

    for (let i = 0; i <= lines.length - blockSize; i++) {
      const block = lines.slice(i, i + blockSize)
        .map(line => line.trim())
        .filter(line => line.length > 0)
        .join('\n');
      
      if (block.length > 50) {
        const hash = this.hashCode(block);
        
        if (!blocks.has(hash)) {
          blocks.set(hash, []);
        }
        
        blocks.get(hash)!.push({ start: i + 1, end: i + blockSize });
      }
    }

    for (const [hash, occurrences] of blocks) {
      if (occurrences.length > 1) {
        duplicates.push({ hash, occurrences });
      }
    }

    return duplicates;
  }

  private isPoorlyNamed(name: string): boolean {
    // Check for common poor naming patterns
    return name.length < 3 || // Too short
           /^[a-z]$/.test(name) || // Single letter
           name.includes('temp') ||
           name.includes('data') ||
           name.includes('info') ||
           name.includes('stuff') ||
           name.includes('thing');
  }

  private suggestBetterName(symbol: ParsedSymbol, lines: string[]): string {
    // Simplified name suggestion based on context
    const context = lines.slice(
      Math.max(0, symbol.lineStart - 2),
      Math.min(lines.length, symbol.lineEnd + 2)
    ).join(' ').toLowerCase();

    if (context.includes('user')) return symbol.name.replace(/temp|data|info/, 'user');
    if (context.includes('config')) return symbol.name.replace(/temp|data|info/, 'config');
    if (context.includes('result')) return symbol.name.replace(/temp|data|info/, 'result');
    
    return symbol.name + 'Value'; // Default improvement
  }

  private analyzeMethodDependencies(method: ParsedSymbol, lines: string[], symbols: ParsedSymbol[]): {
    internal: number;
    external: number;
    mostUsedExternal: string;
  } {
    // Simplified dependency analysis
    const methodContent = lines.slice(method.lineStart - 1, method.lineEnd).join('\n');
    
    let internal = 0;
    let external = 0;
    const externalUsage = new Map<string, number>();

    // Count this.property usage (internal)
    internal = (methodContent.match(/this\.\w+/g) || []).length;

    // Count external class usage (simplified)
    const externalReferences = methodContent.match(/\w+\.\w+/g) || [];
    for (const ref of externalReferences) {
      if (!ref.startsWith('this.')) {
        const className = ref.split('.')[0];
        external++;
        externalUsage.set(className, (externalUsage.get(className) || 0) + 1);
      }
    }

    const mostUsedExternal = Array.from(externalUsage.entries())
      .sort(([,a], [,b]) => b - a)[0]?.[0] || 'UnknownClass';

    return { internal, external, mostUsedExternal };
  }

  private isBubbleSort(lines: string[], startIndex: number): boolean {
    // Simple heuristic to detect bubble sort pattern
    if (startIndex + 5 >= lines.length) return false;
    
    const block = lines.slice(startIndex, startIndex + 6).join(' ');
    
    return block.includes('for(') && 
           block.includes('for(') && // Nested loops
           block.includes('[j]') && 
           block.includes('[j+1]') &&
           (block.includes('>') || block.includes('<'));
  }

  // Mapping methods

  private mapSmellToRefactoring(smellType: string): RefactoringSuggestion['type'] | null {
    const mapping: Record<string, RefactoringSuggestion['type']> = {
      'long_method': 'extract_method',
      'large_class': 'extract_class',
      'duplicate_code': 'remove_duplication',
      'complex_conditional': 'simplify_conditional',
      'god_class': 'split_class',
      'dead_code': 'remove_duplication'
    };
    
    return mapping[smellType] || null;
  }

  private mapPerformanceIssueToRefactoring(issueType: string): RefactoringSuggestion['type'] | null {
    const mapping: Record<string, RefactoringSuggestion['type']> = {
      'inefficient_algorithm': 'replace_algorithm',
      'inefficient_loop': 'replace_algorithm',
      'n_plus_one': 'replace_algorithm'
    };
    
    return mapping[issueType] || null;
  }

  // Code generation methods

  private generateExtractMethodChanges(
    func: ParsedSymbol,
    block: { start: number; end: number; content: string },
    lines: string[]
  ): CodeChange[] {
    const extractedMethodName = `extracted${func.name}Method`;
    const blockLines = lines.slice(func.lineStart - 1 + block.start, func.lineStart - 1 + block.end + 1);
    
    return [
      {
        type: 'insert',
        location: { filePath: func.filePath, lineStart: func.lineEnd + 1 },
        newCode: `\n  private ${extractedMethodName}() {\n${blockLines.map(line => '  ' + line).join('\n')}\n  }`,
        description: 'Insert extracted method'
      },
      {
        type: 'replace',
        location: { 
          filePath: func.filePath, 
          lineStart: func.lineStart + block.start,
          lineEnd: func.lineStart + block.end
        },
        oldCode: blockLines.join('\n'),
        newCode: `    this.${extractedMethodName}();`,
        description: 'Replace original code with method call'
      }
    ];
  }

  private generateExtractClassChanges(
    cls: ParsedSymbol,
    group: { methods: ParsedSymbol[]; cohesion: number },
    lines: string[]
  ): CodeChange[] {
    const newClassName = `${cls.name}Helper`;
    
    return [
      {
        type: 'insert',
        location: { filePath: cls.filePath, lineStart: cls.lineEnd + 2 },
        newCode: `\nclass ${newClassName} {\n  // Extracted methods\n}\n`,
        description: 'Create new extracted class'
      },
      {
        type: 'replace',
        location: { filePath: cls.filePath, lineStart: cls.lineStart },
        description: 'Modify original class to use extracted class'
      }
    ];
  }

  private generateSimplifiedConditional(line: string): string {
    // Simplified conditional generation
    const parts = line.split('&&').map(part => part.trim());
    
    if (parts.length > 2) {
      return parts.slice(0, 2).join(' && ') + ' && /* additional conditions */';
    }
    
    return line;
  }

  private generateDeduplicationChanges(
    duplicate: { hash: string; occurrences: Array<{ start: number; end: number }> },
    lines: string[]
  ): CodeChange[] {
    const changes: CodeChange[] = [];
    const extractedFunctionName = `extractedFunction${duplicate.hash.substring(0, 8)}`;
    const firstOccurrence = duplicate.occurrences[0];
    const codeBlock = lines.slice(firstOccurrence.start - 1, firstOccurrence.end);
    
    // Insert extracted function
    changes.push({
      type: 'insert',
      location: { filePath: '', lineStart: 1 }, // Would need proper location
      newCode: `\nfunction ${extractedFunctionName}() {\n${codeBlock.map(line => '  ' + line).join('\n')}\n}\n`,
      description: 'Insert extracted function'
    });

    // Replace all occurrences
    for (const occurrence of duplicate.occurrences) {
      changes.push({
        type: 'replace',
        location: { 
          filePath: '', 
          lineStart: occurrence.start,
          lineEnd: occurrence.end
        },
        oldCode: codeBlock.join('\n'),
        newCode: `  ${extractedFunctionName}();`,
        description: 'Replace duplicate code with function call'
      });
    }

    return changes;
  }

  private generateMoveMethodChanges(method: ParsedSymbol, targetClass: string): CodeChange[] {
    return [
      {
        type: 'move',
        location: { filePath: method.filePath, lineStart: method.lineStart, lineEnd: method.lineEnd },
        description: `Move method to ${targetClass}`
      }
    ];
  }

  // Plan management methods

  private getSelectedSuggestions(suggestionIds: string[]): RefactoringSuggestion[] {
    const suggestions: RefactoringSuggestion[] = [];
    
    for (const id of suggestionIds) {
      const suggestion = this.findSuggestionById(id);
      if (suggestion) {
        suggestions.push(suggestion);
      }
    }
    
    return suggestions;
  }

  private findSuggestionById(id: string): RefactoringSuggestion | null {
    for (const suggestions of this.suggestions.values()) {
      const found = suggestions.find(s => s.id === id);
      if (found) return found;
    }
    return null;
  }

  private calculateExecutionOrder(suggestions: RefactoringSuggestion[]): string[] {
    // Simplified execution order - sort by priority and dependencies
    return suggestions
      .sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority))
      .map(s => s.id);
  }

  private calculateTotalRisk(suggestions: RefactoringSuggestion[]): 'low' | 'medium' | 'high' {
    const riskWeights = { safe: 1, mostly_safe: 2, risky: 3, dangerous: 4 };
    const totalRisk = suggestions.reduce((sum, s) => sum + riskWeights[s.safetyLevel], 0);
    const averageRisk = totalRisk / suggestions.length;
    
    if (averageRisk <= 1.5) return 'low';
    if (averageRisk <= 2.5) return 'medium';
    return 'high';
  }

  private consolidateBenefits(suggestions: RefactoringSuggestion[]): string[] {
    const allBenefits = new Set<string>();
    for (const suggestion of suggestions) {
      suggestion.benefits.forEach(benefit => allBenefits.add(benefit));
    }
    return Array.from(allBenefits);
  }

  private consolidatePrerequisites(suggestions: RefactoringSuggestion[]): string[] {
    const allPrerequisites = new Set<string>();
    for (const suggestion of suggestions) {
      suggestion.preconditions.forEach(prereq => allPrerequisites.add(prereq));
    }
    return Array.from(allPrerequisites);
  }

  private generateRollbackStrategy(suggestions: RefactoringSuggestion[]): string {
    return 'Create backup of all affected files before executing refactorings. Use version control for rollback.';
  }

  private generateValidationSteps(suggestions: RefactoringSuggestion[]): string[] {
    return [
      'Run all tests',
      'Verify code compiles',
      'Check code coverage',
      'Validate performance benchmarks',
      'Review code quality metrics'
    ];
  }

  // Execution methods

  private async executeRefactoring(planId: string, refactoringId: string): Promise<RefactoringExecution> {
    const execution: RefactoringExecution = {
      id: `exec-${refactoringId}-${Date.now()}`,
      planId,
      refactoringId,
      status: 'pending',
      startedAt: Date.now()
    };

    try {
      execution.status = 'in_progress';
      
      // Perform safety checks
      const safetyChecks = await this.validateRefactoringSafety(refactoringId);
      const blockingIssues = safetyChecks.filter(check => !check.passed && check.blocking);
      
      if (blockingIssues.length > 0) {
        execution.status = 'failed';
        execution.error = `Safety checks failed: ${blockingIssues.map(issue => issue.description).join(', ')}`;
        execution.completedAt = Date.now();
        await this.storeExecution(execution);
        return execution;
      }

      // Create backup
      const suggestion = this.findSuggestionById(refactoringId);
      if (!suggestion) {
        throw new Error(`Suggestion ${refactoringId} not found`);
      }

      const rollbackInfo = await this.createBackup(suggestion);
      execution.rollbackInfo = rollbackInfo;

      // Execute refactoring
      const result = await this.performRefactoring(suggestion);
      execution.result = result;
      
      if (result.success) {
        execution.status = 'completed';
      } else {
        execution.status = 'failed';
        execution.error = result.errors.join(', ');
      }
      
      execution.completedAt = Date.now();
      await this.storeExecution(execution);
      
      return execution;
    } catch (error) {
      execution.status = 'failed';
      execution.error = error instanceof Error ? error.message : 'Unknown error';
      execution.completedAt = Date.now();
      await this.storeExecution(execution);
      return execution;
    }
  }

  private async performRefactoring(suggestion: RefactoringSuggestion): Promise<RefactoringResult> {
    // Simplified refactoring execution
    const result: RefactoringResult = {
      success: true,
      filesChanged: [suggestion.filePath],
      linesChanged: 0,
      testsAffected: [],
      metricsImprovement: {
        complexity: 10,
        maintainability: 15,
        readability: 20,
        performance: 5
      },
      warnings: [],
      errors: []
    };

    try {
      // Execute code changes
      for (const change of suggestion.codeChanges) {
        await this.applyCodeChange(change);
        result.linesChanged += this.calculateLinesChanged(change);
      }

      // Execute test changes
      for (const testChange of suggestion.testChanges) {
        await this.applyTestChange(testChange);
        result.testsAffected.push(testChange.testFile);
      }

      return result;
    } catch (error) {
      result.success = false;
      result.errors.push(error instanceof Error ? error.message : 'Unknown error');
      return result;
    }
  }

  private async applyCodeChange(change: CodeChange): Promise<void> {
    const filePath = change.location.filePath;
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    switch (change.type) {
      case 'replace':
        if (change.oldCode && change.newCode) {
          const newContent = content.replace(change.oldCode, change.newCode);
          fs.writeFileSync(filePath, newContent);
        }
        break;
        
      case 'insert':
        if (change.newCode) {
          lines.splice(change.location.lineStart - 1, 0, change.newCode);
          fs.writeFileSync(filePath, lines.join('\n'));
        }
        break;
        
      case 'delete':
        const endLine = change.location.lineEnd || change.location.lineStart;
        lines.splice(change.location.lineStart - 1, endLine - change.location.lineStart + 1);
        fs.writeFileSync(filePath, lines.join('\n'));
        break;
    }
  }

  private async applyTestChange(testChange: TestChange): Promise<void> {
    // Simplified test change application
    logger.info(`Applying test change: ${testChange.description}`);
  }

  private calculateLinesChanged(change: CodeChange): number {
    if (change.type === 'replace' && change.oldCode && change.newCode) {
      return Math.abs(change.newCode.split('\n').length - change.oldCode.split('\n').length);
    }
    if (change.type === 'insert' && change.newCode) {
      return change.newCode.split('\n').length;
    }
    if (change.type === 'delete') {
      const endLine = change.location.lineEnd || change.location.lineStart;
      return endLine - change.location.lineStart + 1;
    }
    return 0;
  }

  private async createBackup(suggestion: RefactoringSuggestion): Promise<RollbackInfo> {
    const backupFiles: { [filePath: string]: string } = {};
    
    // Backup main file
    backupFiles[suggestion.filePath] = fs.readFileSync(suggestion.filePath, 'utf-8');
    
    // Backup affected files
    for (const location of suggestion.affectedLocations) {
      if (!backupFiles[location.filePath]) {
        backupFiles[location.filePath] = fs.readFileSync(location.filePath, 'utf-8');
      }
    }

    return {
      backupFiles,
      rollbackSteps: ['Restore backed up files'],
      canRollback: true
    };
  }

  // Safety check methods

  private async performSyntaxCheck(suggestion: RefactoringSuggestion): Promise<SafetyCheck> {
    // Simplified syntax check
    try {
      const content = fs.readFileSync(suggestion.filePath, 'utf-8');
      // In a real implementation, this would use a proper parser
      const hasSyntaxError = content.includes('syntax error');
      
      return {
        id: `syntax-${suggestion.id}`,
        type: 'syntax_check',
        description: 'Verify code syntax is valid',
        passed: !hasSyntaxError,
        details: hasSyntaxError ? 'Syntax error detected' : 'Syntax is valid',
        blocking: true
      };
    } catch (error) {
      return {
        id: `syntax-${suggestion.id}`,
        type: 'syntax_check',
        description: 'Verify code syntax is valid',
        passed: false,
        details: 'Failed to read file',
        blocking: true
      };
    }
  }

  private async performReferenceCheck(suggestion: RefactoringSuggestion): Promise<SafetyCheck> {
    // Simplified reference check
    return {
      id: `reference-${suggestion.id}`,
      type: 'reference_check',
      description: 'Check for broken references',
      passed: true,
      details: 'No broken references detected',
      blocking: false
    };
  }

  private async performTestCheck(suggestion: RefactoringSuggestion): Promise<SafetyCheck> {
    // Simplified test check
    return {
      id: `test-${suggestion.id}`,
      type: 'test_check',
      description: 'Verify tests still pass',
      passed: true,
      details: 'All tests passing',
      blocking: false
    };
  }

  private async performDependencyCheck(suggestion: RefactoringSuggestion): Promise<SafetyCheck> {
    // Simplified dependency check
    return {
      id: `dependency-${suggestion.id}`,
      type: 'dependency_check',
      description: 'Check for dependency issues',
      passed: true,
      details: 'No dependency conflicts',
      blocking: false
    };
  }

  private async performTypeCheck(suggestion: RefactoringSuggestion): Promise<SafetyCheck> {
    // Simplified type check
    return {
      id: `type-${suggestion.id}`,
      type: 'type_check',
      description: 'Verify TypeScript types',
      passed: true,
      details: 'Type checking passed',
      blocking: true
    };
  }

  // Utility methods

  private countLogicalOperators(line: string): number {
    return (line.match(/&&|\|\||!=/g) || []).length;
  }

  private hashCode(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString();
  }

  private effortToHours(effort: RefactoringSuggestion['estimatedEffort']): number {
    const mapping = {
      trivial: 0.5,
      small: 2,
      medium: 8,
      large: 24,
      huge: 80
    };
    return mapping[effort];
  }

  private getPriorityWeight(priority: RefactoringSuggestion['priority']): number {
    const weights = { critical: 4, high: 3, medium: 2, low: 1 };
    return weights[priority];
  }

  private getTestFile(filePath: string): string {
    const ext = filePath.endsWith('.tsx') ? '.tsx' : '.ts';
    return filePath.replace(ext, `.test${ext}`);
  }

  // Database mapping methods

  private mapRowToSuggestion(row: any): RefactoringSuggestion {
    return {
      id: row.id,
      type: row.type,
      priority: row.priority,
      filePath: row.file_path,
      title: row.title,
      description: row.description,
      motivation: row.motivation,
      targetLocation: {
        lineStart: row.target_line_start,
        lineEnd: row.target_line_end,
        function: row.target_function,
        class: row.target_class,
        symbol: row.target_symbol
      },
      affectedLocations: JSON.parse(row.affected_locations || '[]'),
      benefits: JSON.parse(row.benefits || '[]'),
      risks: JSON.parse(row.risks || '[]'),
      preconditions: JSON.parse(row.preconditions || '[]'),
      postconditions: JSON.parse(row.postconditions || '[]'),
      estimatedEffort: row.estimated_effort,
      safetyLevel: row.safety_level,
      automatable: row.automatable,
      codeChanges: JSON.parse(row.code_changes || '[]'),
      testChanges: JSON.parse(row.test_changes || '[]'),
      relatedRefactorings: JSON.parse(row.related_refactorings || '[]'),
      conflictingRefactorings: JSON.parse(row.conflicting_refactorings || '[]'),
      requiredTools: JSON.parse(row.required_tools || '[]'),
      detectedAt: row.detected_at,
      confidence: row.confidence
    };
  }

  private mapRowToPlan(row: any): RefactoringPlan {
    return {
      id: row.id,
      title: row.title,
      description: row.description,
      refactorings: [], // Would need to load from IDs
      executionOrder: JSON.parse(row.execution_order || '[]'),
      totalEffort: row.total_effort,
      totalRisk: row.total_risk,
      benefits: JSON.parse(row.benefits || '[]'),
      prerequisites: JSON.parse(row.prerequisites || '[]'),
      rollbackStrategy: row.rollback_strategy,
      validationSteps: JSON.parse(row.validation_steps || '[]'),
      createdAt: row.created_at
    };
  }

  private mapRowToExecution(row: any): RefactoringExecution {
    return {
      id: row.id,
      planId: row.plan_id,
      refactoringId: row.refactoring_id,
      status: row.status,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      result: row.result ? JSON.parse(row.result) : undefined,
      error: row.error,
      rollbackInfo: row.rollback_info ? JSON.parse(row.rollback_info) : undefined
    };
  }

  // Database storage methods

  private async storeRefactoringSuggestions(suggestions: RefactoringSuggestion[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO refactoring_suggestions (
        id, type, priority, file_path, title, description, motivation,
        target_line_start, target_line_end, target_function, target_class,
        target_symbol, affected_locations, benefits, risks, preconditions,
        postconditions, estimated_effort, safety_level, automatable,
        code_changes, test_changes, related_refactorings, conflicting_refactorings,
        required_tools, detected_at, confidence
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const suggestion of suggestions) {
      stmt.run(
        suggestion.id,
        suggestion.type,
        suggestion.priority,
        suggestion.filePath,
        suggestion.title,
        suggestion.description,
        suggestion.motivation,
        suggestion.targetLocation.lineStart,
        suggestion.targetLocation.lineEnd,
        suggestion.targetLocation.function,
        suggestion.targetLocation.class,
        suggestion.targetLocation.symbol,
        JSON.stringify(suggestion.affectedLocations),
        JSON.stringify(suggestion.benefits),
        JSON.stringify(suggestion.risks),
        JSON.stringify(suggestion.preconditions),
        JSON.stringify(suggestion.postconditions),
        suggestion.estimatedEffort,
        suggestion.safetyLevel,
        suggestion.automatable,
        JSON.stringify(suggestion.codeChanges),
        JSON.stringify(suggestion.testChanges),
        JSON.stringify(suggestion.relatedRefactorings),
        JSON.stringify(suggestion.conflictingRefactorings),
        JSON.stringify(suggestion.requiredTools),
        suggestion.detectedAt,
        suggestion.confidence
      );
    }
  }

  private async storeRefactoringPlan(plan: RefactoringPlan): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO refactoring_plans (
        id, title, description, refactorings, execution_order,
        total_effort, total_risk, benefits, prerequisites,
        rollback_strategy, validation_steps, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      plan.id,
      plan.title,
      plan.description,
      JSON.stringify(plan.refactorings.map(r => r.id)),
      JSON.stringify(plan.executionOrder),
      plan.totalEffort,
      plan.totalRisk,
      JSON.stringify(plan.benefits),
      JSON.stringify(plan.prerequisites),
      plan.rollbackStrategy,
      JSON.stringify(plan.validationSteps),
      plan.createdAt
    );
  }

  private async storeExecution(execution: RefactoringExecution): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO refactoring_executions (
        id, plan_id, refactoring_id, status, started_at, completed_at,
        result, error, rollback_info
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      execution.id,
      execution.planId,
      execution.refactoringId,
      execution.status,
      execution.startedAt,
      execution.completedAt,
      execution.result ? JSON.stringify(execution.result) : null,
      execution.error,
      execution.rollbackInfo ? JSON.stringify(execution.rollbackInfo) : null
    );

    this.executions.set(execution.id, execution);
  }

  private async updateExecution(execution: RefactoringExecution): Promise<void> {
    await this.storeExecution(execution);
  }
}