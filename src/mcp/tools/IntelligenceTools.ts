import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ChangePredictor } from '../../intelligence/ChangePredictor.js';
import { TechnicalDebtTracker } from '../../intelligence/TechnicalDebtTracker.js';
import { TestIntelligence } from '../../intelligence/TestIntelligence.js';
import { PerformanceAnalyzer } from '../../intelligence/PerformanceAnalyzer.js';
import { RefactoringAssistant } from '../../intelligence/RefactoringAssistant.js';
import { ASTParser } from '../../parser/ASTParser.js';
import { PatternRegistry } from '../../patterns/PatternRegistry.js';
import { logger } from '../../utils/logger.js';

export class IntelligenceTools {
  private changePredictor: ChangePredictor;
  private debtTracker: TechnicalDebtTracker;
  private testIntelligence: TestIntelligence;
  private performanceAnalyzer: PerformanceAnalyzer;
  private refactoringAssistant: RefactoringAssistant;
  private astParser: ASTParser;

  constructor(
    databasePath: string,
    patternRegistry: PatternRegistry
  ) {
    this.changePredictor = new ChangePredictor(databasePath, patternRegistry);
    this.debtTracker = new TechnicalDebtTracker(databasePath);
    this.testIntelligence = new TestIntelligence(databasePath);
    this.performanceAnalyzer = new PerformanceAnalyzer(databasePath);
    this.refactoringAssistant = new RefactoringAssistant(databasePath);
    this.astParser = new ASTParser();
  }

  getTools(): Tool[] {
    return [
      // Change Prediction Tools
      {
        name: 'predict_changes',
        description: 'Predict likely changes based on code patterns and history',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            timeframe: {
              type: 'string',
              enum: ['immediate', 'short', 'medium', 'long'],
              description: 'Prediction timeframe'
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'identify_refactoring_opportunities',
        description: 'Identify opportunities for refactoring in code',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            priority: {
              type: 'string',
              enum: ['low', 'medium', 'high', 'critical'],
              description: 'Minimum priority level to return'
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'record_code_change',
        description: 'Record a code change for learning and prediction',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the changed file'
            },
            changeType: {
              type: 'string',
              enum: ['create', 'modify', 'delete', 'rename'],
              description: 'Type of change'
            },
            description: {
              type: 'string',
              description: 'Description of the change'
            },
            linesAdded: {
              type: 'number',
              description: 'Number of lines added'
            },
            linesRemoved: {
              type: 'number',
              description: 'Number of lines removed'
            },
            author: {
              type: 'string',
              description: 'Author of the change'
            },
            commit: {
              type: 'string',
              description: 'Commit hash'
            }
          },
          required: ['filePath', 'changeType', 'description']
        }
      },

      // Technical Debt Tools
      {
        name: 'analyze_debt',
        description: 'Analyze technical debt in a file or codebase',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            includeMetrics: {
              type: 'boolean',
              description: 'Include complexity metrics in the analysis',
              default: true
            },
            includeSmells: {
              type: 'boolean',
              description: 'Include code smells in the analysis',
              default: true
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'generate_debt_report',
        description: 'Generate a comprehensive technical debt report',
        inputSchema: {
          type: 'object',
          properties: {
            scope: {
              type: 'string',
              enum: ['file', 'directory', 'project'],
              description: 'Scope of the debt report'
            },
            path: {
              type: 'string',
              description: 'Path to analyze (file, directory, or project root)'
            },
            includeRecommendations: {
              type: 'boolean',
              description: 'Include recommendations for addressing debt',
              default: true
            }
          },
          required: ['scope', 'path']
        }
      },
      {
        name: 'resolve_debt_item',
        description: 'Mark a technical debt item as resolved',
        inputSchema: {
          type: 'object',
          properties: {
            debtItemId: {
              type: 'string',
              description: 'ID of the debt item to resolve'
            },
            resolution: {
              type: 'string',
              description: 'Description of how the debt was resolved'
            }
          },
          required: ['debtItemId', 'resolution']
        }
      },

      // Test Intelligence Tools
      {
        name: 'analyze_test_coverage',
        description: 'Analyze test coverage for a file',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the source file to analyze'
            },
            testFilePath: {
              type: 'string',
              description: 'Path to the corresponding test file (optional)'
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'suggest_tests',
        description: 'Generate test suggestions for a file',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to generate tests for'
            },
            testType: {
              type: 'string',
              enum: ['unit', 'integration', 'edge_case', 'error_handling', 'performance', 'security'],
              description: 'Type of tests to suggest'
            },
            maxSuggestions: {
              type: 'number',
              description: 'Maximum number of suggestions to return',
              default: 10
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'generate_test',
        description: 'Generate test code for a specific function or class',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the source file'
            },
            functionName: {
              type: 'string',
              description: 'Name of the function to test'
            },
            className: {
              type: 'string',
              description: 'Name of the class to test'
            },
            testType: {
              type: 'string',
              enum: ['unit', 'integration', 'edge_case', 'error_handling', 'performance', 'security'],
              description: 'Type of test to generate'
            },
            framework: {
              type: 'string',
              enum: ['jest', 'vitest', 'mocha', 'cypress', 'playwright'],
              description: 'Test framework to use'
            },
            includeEdgeCases: {
              type: 'boolean',
              description: 'Include edge cases in the generated test',
              default: true
            },
            includeMocking: {
              type: 'boolean',
              description: 'Include mocking in the generated test',
              default: false
            }
          },
          required: ['filePath', 'testType', 'framework']
        }
      },
      {
        name: 'identify_missing_edge_cases',
        description: 'Identify missing edge cases for a function',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the source file'
            },
            functionName: {
              type: 'string',
              description: 'Name of the function to analyze'
            }
          },
          required: ['filePath']
        }
      },

      // Performance Analysis Tools
      {
        name: 'analyze_performance',
        description: 'Analyze performance issues and optimization opportunities',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            includeOptimizations: {
              type: 'boolean',
              description: 'Include optimization suggestions',
              default: true
            },
            includeCaching: {
              type: 'boolean',
              description: 'Include caching opportunities',
              default: true
            },
            includeAsync: {
              type: 'boolean',
              description: 'Include async opportunities',
              default: true
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'analyze_memory',
        description: 'Analyze memory usage and potential leaks',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'analyze_bundle',
        description: 'Analyze bundle size and optimization opportunities',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the bundle file or entry point'
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'optimize_performance',
        description: 'Get specific performance optimization recommendations',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to optimize'
            },
            category: {
              type: 'string',
              enum: ['algorithm', 'caching', 'async', 'memory', 'database', 'ui', 'bundle'],
              description: 'Category of optimization'
            },
            priority: {
              type: 'string',
              enum: ['low', 'medium', 'high', 'critical'],
              description: 'Minimum priority level'
            }
          },
          required: ['filePath']
        }
      },

      // Refactoring Tools
      {
        name: 'suggest_refactoring',
        description: 'Get refactoring suggestions for code improvement',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to refactor'
            },
            refactoringType: {
              type: 'string',
              enum: [
                'extract_method', 'extract_class', 'inline_method', 'move_method',
                'rename_symbol', 'simplify_conditional', 'remove_duplication',
                'decompose_complex', 'replace_algorithm'
              ],
              description: 'Specific type of refactoring to suggest'
            },
            priority: {
              type: 'string',
              enum: ['low', 'medium', 'high', 'critical'],
              description: 'Minimum priority level'
            },
            safetyLevel: {
              type: 'string',
              enum: ['safe', 'mostly_safe', 'risky', 'dangerous'],
              description: 'Maximum acceptable safety level'
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'create_refactoring_plan',
        description: 'Create a comprehensive refactoring plan',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Title for the refactoring plan'
            },
            description: {
              type: 'string',
              description: 'Description of the refactoring goals'
            },
            suggestionIds: {
              type: 'array',
              items: { type: 'string' },
              description: 'IDs of refactoring suggestions to include'
            }
          },
          required: ['title', 'description', 'suggestionIds']
        }
      },
      {
        name: 'validate_refactoring_safety',
        description: 'Validate the safety of a refactoring before execution',
        inputSchema: {
          type: 'object',
          properties: {
            suggestionId: {
              type: 'string',
              description: 'ID of the refactoring suggestion to validate'
            }
          },
          required: ['suggestionId']
        }
      },
      {
        name: 'analyze_refactoring_impact',
        description: 'Analyze the impact of a proposed refactoring',
        inputSchema: {
          type: 'object',
          properties: {
            suggestionId: {
              type: 'string',
              description: 'ID of the refactoring suggestion to analyze'
            }
          },
          required: ['suggestionId']
        }
      },
      {
        name: 'execute_refactoring_plan',
        description: 'Execute a refactoring plan',
        inputSchema: {
          type: 'object',
          properties: {
            planId: {
              type: 'string',
              description: 'ID of the refactoring plan to execute'
            },
            dryRun: {
              type: 'boolean',
              description: 'Perform a dry run without making changes',
              default: false
            }
          },
          required: ['planId']
        }
      },

      // Combined Intelligence Tools
      {
        name: 'comprehensive_analysis',
        description: 'Perform comprehensive code intelligence analysis',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            includeDebt: {
              type: 'boolean',
              description: 'Include technical debt analysis',
              default: true
            },
            includePerformance: {
              type: 'boolean',
              description: 'Include performance analysis',
              default: true
            },
            includeTests: {
              type: 'boolean',
              description: 'Include test analysis',
              default: true
            },
            includeRefactoring: {
              type: 'boolean',
              description: 'Include refactoring suggestions',
              default: true
            },
            includePredictions: {
              type: 'boolean',
              description: 'Include change predictions',
              default: true
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'predict_bugs',
        description: 'Predict potential bug locations based on patterns and complexity',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            confidence: {
              type: 'number',
              minimum: 0,
              maximum: 1,
              description: 'Minimum confidence threshold (0-1)',
              default: 0.7
            }
          },
          required: ['filePath']
        }
      },
      {
        name: 'get_quality_metrics',
        description: 'Get comprehensive quality metrics for code',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file to analyze'
            },
            includeHistory: {
              type: 'boolean',
              description: 'Include historical quality trends',
              default: false
            }
          },
          required: ['filePath']
        }
      }
    ];
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    try {
      logger.info(`Handling intelligence tool call: ${name}`);

      switch (name) {
        case 'predict_changes':
          return await this.handlePredictChanges(args);
        case 'identify_refactoring_opportunities':
          return await this.handleIdentifyRefactoringOpportunities(args);
        case 'record_code_change':
          return await this.handleRecordCodeChange(args);

        case 'analyze_debt':
          return await this.handleAnalyzeDebt(args);
        case 'generate_debt_report':
          return await this.handleGenerateDebtReport(args);
        case 'resolve_debt_item':
          return await this.handleResolveDebtItem(args);

        case 'analyze_test_coverage':
          return await this.handleAnalyzeTestCoverage(args);
        case 'suggest_tests':
          return await this.handleSuggestTests(args);
        case 'generate_test':
          return await this.handleGenerateTest(args);
        case 'identify_missing_edge_cases':
          return await this.handleIdentifyMissingEdgeCases(args);

        case 'analyze_performance':
          return await this.handleAnalyzePerformance(args);
        case 'analyze_memory':
          return await this.handleAnalyzeMemory(args);
        case 'analyze_bundle':
          return await this.handleAnalyzeBundle(args);
        case 'optimize_performance':
          return await this.handleOptimizePerformance(args);

        case 'suggest_refactoring':
          return await this.handleSuggestRefactoring(args);
        case 'create_refactoring_plan':
          return await this.handleCreateRefactoringPlan(args);
        case 'validate_refactoring_safety':
          return await this.handleValidateRefactoringSafety(args);
        case 'analyze_refactoring_impact':
          return await this.handleAnalyzeRefactoringImpact(args);
        case 'execute_refactoring_plan':
          return await this.handleExecuteRefactoringPlan(args);

        case 'comprehensive_analysis':
          return await this.handleComprehensiveAnalysis(args);
        case 'predict_bugs':
          return await this.handlePredictBugs(args);
        case 'get_quality_metrics':
          return await this.handleGetQualityMetrics(args);

        default:
          throw new Error(`Unknown intelligence tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error handling intelligence tool ${name}:`, error);
      throw error;
    }
  }

  // Change Prediction Handlers
  private async handlePredictChanges(args: any) {
    const { filePath, timeframe = 'short' } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const predictions = await this.changePredictor.predictChanges(filePath, parsedFile.symbols);
    
    return {
      filePath,
      timeframe,
      predictions: predictions.filter(p => !timeframe || p.timeframe === timeframe),
      summary: {
        totalPredictions: predictions.length,
        highProbability: predictions.filter(p => p.probability > 0.7).length,
        criticalPriority: predictions.filter(p => p.priority === 'critical').length
      }
    };
  }

  private async handleIdentifyRefactoringOpportunities(args: any) {
    const { filePath, priority = 'low' } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const opportunities = await this.changePredictor.identifyRefactoringOpportunities(filePath, parsedFile.symbols);
    
    const priorityWeights = { low: 1, medium: 2, high: 3, critical: 4 };
    const minWeight = priorityWeights[priority as keyof typeof priorityWeights];
    
    return {
      filePath,
      opportunities: opportunities.filter(o => {
        const priorityKey = String(o.priority) as keyof typeof priorityWeights;
        return priorityWeights[priorityKey] >= minWeight;
      }),
      summary: {
        totalOpportunities: opportunities.length,
        byPriority: {
          critical: opportunities.filter(o => String(o.priority) === 'critical').length,
          high: opportunities.filter(o => String(o.priority) === 'high').length,
          medium: opportunities.filter(o => String(o.priority) === 'medium').length,
          low: opportunities.filter(o => String(o.priority) === 'low').length
        }
      }
    };
  }

  private async handleRecordCodeChange(args: any) {
    const { filePath, changeType, description, linesAdded = 0, linesRemoved = 0, author, commit } = args;
    
    const changeId = await this.changePredictor.recordChange({
      filePath,
      timestamp: Date.now(),
      changeType,
      linesAdded,
      linesRemoved,
      changeDescription: description,
      affectedSymbols: [], // Would need symbol analysis
      patterns: [], // Would need pattern analysis
      author,
      commit
    });

    return {
      success: true,
      changeId,
      message: 'Code change recorded successfully'
    };
  }

  // Technical Debt Handlers
  private async handleAnalyzeDebt(args: any) {
    const { filePath, includeMetrics = true, includeSmells = true } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const analysis = await this.debtTracker.analyzeFile(filePath, parsedFile.symbols);
    
    const result: any = {
      filePath,
      summary: {
        totalSmells: analysis.smells.length,
        totalDebtItems: analysis.debtItems.length,
        overallScore: this.calculateOverallScore(analysis)
      }
    };

    if (includeSmells) {
      result.codeSmells = analysis.smells;
    }

    if (includeMetrics) {
      result.metrics = analysis.metrics;
    }

    result.debtItems = analysis.debtItems;

    return result;
  }

  private async handleGenerateDebtReport(args: any) {
    const { scope, path, includeRecommendations = true } = args;
    const report = await this.debtTracker.generateDebtReport();
    
    return {
      scope,
      path,
      report,
      generatedAt: new Date().toISOString()
    };
  }

  private async handleResolveDebtItem(args: any) {
    const { debtItemId, resolution } = args;
    await this.debtTracker.resolveDebtItem(debtItemId, resolution);
    
    return {
      success: true,
      debtItemId,
      resolution,
      resolvedAt: new Date().toISOString()
    };
  }

  // Test Intelligence Handlers
  private async handleAnalyzeTestCoverage(args: any) {
    const { filePath, testFilePath } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const coverage = await this.testIntelligence.analyzeCoverage(filePath, parsedFile.symbols);
    const gaps = await this.testIntelligence.identifyCoverageGaps(filePath, parsedFile.symbols, coverage);
    
    return {
      filePath,
      testFilePath,
      coverage,
      gaps,
      summary: {
        overallCoverage: coverage.overallCoverage,
        criticalGaps: gaps.filter(g => g.severity === 'critical').length,
        recommendations: this.generateCoverageRecommendations(coverage, gaps)
      }
    };
  }

  private async handleSuggestTests(args: any) {
    const { filePath, testType, maxSuggestions = 10 } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const coverage = await this.testIntelligence.analyzeCoverage(filePath, parsedFile.symbols);
    const gaps = await this.testIntelligence.identifyCoverageGaps(filePath, parsedFile.symbols, coverage);
    const suggestions = await this.testIntelligence.generateTestSuggestions(filePath, parsedFile.symbols, gaps);
    
    let filteredSuggestions = suggestions;
    if (testType) {
      filteredSuggestions = suggestions.filter(s => s.type === testType);
    }
    
    return {
      filePath,
      testType,
      suggestions: filteredSuggestions.slice(0, maxSuggestions),
      summary: {
        totalSuggestions: suggestions.length,
        byType: this.groupSuggestionsByType(suggestions),
        byPriority: this.groupSuggestionsByPriority(suggestions)
      }
    };
  }

  private async handleGenerateTest(args: any) {
    const { filePath, functionName, className, testType, framework, includeEdgeCases = true, includeMocking = false } = args;
    
    const request = {
      filePath,
      functionName,
      className,
      testType,
      framework,
      includeEdgeCases,
      includeMocking
    };
    
    const generatedTest = await this.testIntelligence.generateTest(request);
    
    return {
      filePath,
      functionName,
      className,
      testType,
      framework,
      generatedTest
    };
  }

  private async handleIdentifyMissingEdgeCases(args: any) {
    const { filePath, functionName } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const edgeCases = await this.testIntelligence.identifyMissingEdgeCases(filePath, parsedFile.symbols);
    
    let filteredEdgeCases = edgeCases;
    if (functionName) {
      filteredEdgeCases = edgeCases.filter(e => e.function === functionName);
    }
    
    return {
      filePath,
      functionName,
      edgeCases: filteredEdgeCases,
      summary: {
        totalEdgeCases: filteredEdgeCases.length,
        uncoveredCount: filteredEdgeCases.filter(e => !e.currentlyCovered).length,
        byRisk: {
          high: filteredEdgeCases.filter(e => e.riskLevel === 'high').length,
          medium: filteredEdgeCases.filter(e => e.riskLevel === 'medium').length,
          low: filteredEdgeCases.filter(e => e.riskLevel === 'low').length
        }
      }
    };
  }

  // Performance Analysis Handlers
  private async handleAnalyzePerformance(args: any) {
    const { filePath, includeOptimizations = true, includeCaching = true, includeAsync = true } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const analysis = await this.performanceAnalyzer.analyzePerformance(filePath, parsedFile.symbols);
    
    const result: any = {
      filePath,
      issues: analysis.issues,
      summary: {
        totalIssues: analysis.issues.length,
        criticalIssues: analysis.issues.filter(i => i.severity === 'critical').length,
        averageSlowdown: this.calculateAverageSlowdown(analysis.issues)
      }
    };

    if (includeOptimizations) {
      result.optimizations = analysis.suggestions;
    }

    if (includeCaching) {
      result.cachingOpportunities = analysis.cachingOpportunities;
    }

    if (includeAsync) {
      result.asyncOpportunities = analysis.asyncOpportunities;
    }

    return result;
  }

  private async handleAnalyzeMemory(args: any) {
    const { filePath } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const analysis = await this.performanceAnalyzer.analyzeMemory(filePath, parsedFile.symbols);
    
    return {
      filePath,
      memoryAnalysis: analysis,
      summary: {
        potentialLeaksCount: analysis.potentialLeaks.length,
        heavyObjectsCount: analysis.heavyObjects.length,
        totalEstimatedSaving: analysis.totalEstimatedSaving,
        recommendations: this.generateMemoryRecommendations(analysis)
      }
    };
  }

  private async handleAnalyzeBundle(args: any) {
    const { filePath } = args;
    const analysis = await this.performanceAnalyzer.analyzeBundle(filePath);
    
    return {
      filePath,
      bundleAnalysis: analysis,
      summary: {
        bundleSize: analysis.bundleSize,
        unusedCodeSize: analysis.unusedCode.reduce((sum, code) => sum + code.size, 0),
        potentialSavings: this.calculateBundleSavings(analysis),
        recommendations: this.generateBundleRecommendations(analysis)
      }
    };
  }

  private async handleOptimizePerformance(args: any) {
    const { filePath, category, priority = 'low' } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const analysis = await this.performanceAnalyzer.analyzePerformance(filePath, parsedFile.symbols);
    
    let optimizations = analysis.suggestions;
    
    if (category) {
      optimizations = optimizations.filter(o => o.category === category);
    }
    
    const priorityWeights = { low: 1, medium: 2, high: 3, critical: 4 };
    const minWeight = priorityWeights[priority as keyof typeof priorityWeights];
    optimizations = optimizations.filter(o => priorityWeights[o.priority] >= minWeight);
    
    return {
      filePath,
      category,
      priority,
      optimizations,
      summary: {
        totalOptimizations: optimizations.length,
        expectedImprovement: this.calculateExpectedImprovement(optimizations)
      }
    };
  }

  // Refactoring Handlers
  private async handleSuggestRefactoring(args: any) {
    const { filePath, refactoringType, priority = 'low', safetyLevel = 'dangerous' } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const suggestions = await this.refactoringAssistant.analyzeRefactoringOpportunities(filePath, parsedFile.symbols);
    
    let filteredSuggestions = suggestions;
    
    if (refactoringType) {
      filteredSuggestions = filteredSuggestions.filter(s => s.type === refactoringType);
    }
    
    const priorityWeights = { low: 1, medium: 2, high: 3, critical: 4 };
    const minWeight = priorityWeights[priority as keyof typeof priorityWeights];
    filteredSuggestions = filteredSuggestions.filter(s => priorityWeights[s.priority] >= minWeight);
    
    const safetyWeights = { safe: 1, mostly_safe: 2, risky: 3, dangerous: 4 };
    const maxSafetyWeight = safetyWeights[safetyLevel as keyof typeof safetyWeights];
    filteredSuggestions = filteredSuggestions.filter(s => safetyWeights[s.safetyLevel] <= maxSafetyWeight);
    
    return {
      filePath,
      refactoringType,
      priority,
      safetyLevel,
      suggestions: filteredSuggestions,
      summary: {
        totalSuggestions: filteredSuggestions.length,
        automatable: filteredSuggestions.filter(s => s.automatable).length,
        averageEffort: this.calculateAverageEffort(filteredSuggestions)
      }
    };
  }

  private async handleCreateRefactoringPlan(args: any) {
    const { title, description, suggestionIds } = args;
    const plan = await this.refactoringAssistant.createRefactoringPlan(title, description, suggestionIds);
    
    return {
      plan,
      summary: {
        refactoringCount: plan.refactorings.length,
        totalEffort: plan.totalEffort,
        totalRisk: plan.totalRisk,
        estimatedDuration: `${Math.ceil(plan.totalEffort / 8)} days`
      }
    };
  }

  private async handleValidateRefactoringSafety(args: any) {
    const { suggestionId } = args;
    const safetyChecks = await this.refactoringAssistant.validateRefactoringSafety(suggestionId);
    
    return {
      suggestionId,
      safetyChecks,
      summary: {
        totalChecks: safetyChecks.length,
        passed: safetyChecks.filter(c => c.passed).length,
        failed: safetyChecks.filter(c => !c.passed).length,
        blockingIssues: safetyChecks.filter(c => !c.passed && c.blocking).length,
        overallSafety: safetyChecks.every(c => c.passed || !c.blocking) ? 'safe' : 'unsafe'
      }
    };
  }

  private async handleAnalyzeRefactoringImpact(args: any) {
    const { suggestionId } = args;
    const impacts = await this.refactoringAssistant.analyzeRefactoringImpact(suggestionId);
    
    return {
      suggestionId,
      impacts,
      summary: {
        totalImpacts: impacts.length,
        highRiskImpacts: impacts.filter(i => i.riskLevel === 'high').length,
        filesAffected: new Set(impacts.map(i => i.filePath)).size,
        changeTypes: [...new Set(impacts.map(i => i.changeType))]
      }
    };
  }

  private async handleExecuteRefactoringPlan(args: any) {
    const { planId, dryRun = false } = args;
    
    if (dryRun) {
      return {
        planId,
        dryRun: true,
        message: 'Dry run completed - no changes made',
        wouldExecute: 'Plan validation and safety checks would be performed'
      };
    }
    
    const executions = await this.refactoringAssistant.executeRefactoringPlan(planId);
    
    return {
      planId,
      executions,
      summary: {
        totalExecutions: executions.length,
        successful: executions.filter(e => e.status === 'completed').length,
        failed: executions.filter(e => e.status === 'failed').length,
        overallStatus: executions.every(e => e.status === 'completed') ? 'success' : 'partial_failure'
      }
    };
  }

  // Combined Intelligence Handlers
  private async handleComprehensiveAnalysis(args: any) {
    const {
      filePath,
      includeDebt = true,
      includePerformance = true,
      includeTests = true,
      includeRefactoring = true,
      includePredictions = true
    } = args;

    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const result: any = {
      filePath,
      analyzedAt: new Date().toISOString(),
      summary: {}
    };

    if (includeDebt) {
      const debtAnalysis = await this.debtTracker.analyzeFile(filePath, parsedFile.symbols);
      result.technicalDebt = {
        smells: debtAnalysis.smells,
        metrics: debtAnalysis.metrics,
        debtItems: debtAnalysis.debtItems
      };
      result.summary.debt = {
        totalSmells: debtAnalysis.smells.length,
        totalDebtHours: debtAnalysis.debtItems.reduce((sum, item) => sum + item.estimatedEffort, 0)
      };
    }

    if (includePerformance) {
      const perfAnalysis = await this.performanceAnalyzer.analyzePerformance(filePath, parsedFile.symbols);
      result.performance = {
        issues: perfAnalysis.issues,
        suggestions: perfAnalysis.suggestions
      };
      result.summary.performance = {
        totalIssues: perfAnalysis.issues.length,
        criticalIssues: perfAnalysis.issues.filter(i => i.severity === 'critical').length
      };
    }

    if (includeTests) {
      const coverage = await this.testIntelligence.analyzeCoverage(filePath, parsedFile.symbols);
      const gaps = await this.testIntelligence.identifyCoverageGaps(filePath, parsedFile.symbols, coverage);
      result.testing = { coverage, gaps };
      result.summary.testing = {
        overallCoverage: coverage.overallCoverage,
        criticalGaps: gaps.filter(g => g.severity === 'critical').length
      };
    }

    if (includeRefactoring) {
      const refactoringSuggestions = await this.refactoringAssistant.analyzeRefactoringOpportunities(filePath, parsedFile.symbols);
      result.refactoring = { suggestions: refactoringSuggestions };
      result.summary.refactoring = {
        totalSuggestions: refactoringSuggestions.length,
        highPriority: refactoringSuggestions.filter(s => s.priority === 'high' || s.priority === 'critical').length
      };
    }

    if (includePredictions) {
      const predictions = await this.changePredictor.predictChanges(filePath, parsedFile.symbols);
      result.predictions = { changes: predictions };
      result.summary.predictions = {
        totalPredictions: predictions.length,
        highProbability: predictions.filter(p => p.probability > 0.7).length
      };
    }

    // Overall quality score
    result.summary.overallQualityScore = this.calculateOverallQualityScore(result);

    return result;
  }

  private async handlePredictBugs(args: any) {
    const { filePath, confidence = 0.7 } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    
    // Combine multiple analysis types to predict bugs
    const debtAnalysis = await this.debtTracker.analyzeFile(filePath, parsedFile.symbols);
    const perfAnalysis = await this.performanceAnalyzer.analyzePerformance(filePath, parsedFile.symbols);
    const predictions = await this.changePredictor.predictChanges(filePath, parsedFile.symbols);
    
    const bugPredictions = this.combineBugPredictions(debtAnalysis, perfAnalysis, predictions, confidence);
    
    return {
      filePath,
      confidence,
      bugPredictions,
      summary: {
        totalPredictions: bugPredictions.length,
        highRisk: bugPredictions.filter(p => p.riskLevel === 'high').length,
        mediumRisk: bugPredictions.filter(p => p.riskLevel === 'medium').length,
        lowRisk: bugPredictions.filter(p => p.riskLevel === 'low').length
      }
    };
  }

  private async handleGetQualityMetrics(args: any) {
    const { filePath, includeHistory = false } = args;
    const parsedFile = await this.astParser.parseFile(filePath);
    if (!parsedFile) {
      throw new Error(`Failed to parse file: ${filePath}`);
    }
    const debtAnalysis = await this.debtTracker.analyzeFile(filePath, parsedFile.symbols);
    
    const metrics = {
      filePath,
      complexity: debtAnalysis.metrics,
      codeSmells: debtAnalysis.smells.length,
      debtHours: debtAnalysis.debtItems.reduce((sum, item) => sum + item.estimatedEffort, 0),
      qualityScore: this.calculateOverallScore(debtAnalysis),
      measuredAt: new Date().toISOString()
    };

    const result: any = { metrics };

    if (includeHistory) {
      result.trends = await this.debtTracker.getQualityTrends(30); // Last 30 days
    }

    return result;
  }

  // Helper methods
  private calculateOverallScore(analysis: any): number {
    // Simplified quality score calculation
    let score = 100;
    
    // Deduct for code smells
    score -= analysis.smells.length * 2;
    
    // Deduct for low maintainability
    if (analysis.metrics.maintainabilityIndex < 50) {
      score -= (50 - analysis.metrics.maintainabilityIndex);
    }
    
    // Deduct for high complexity
    if (analysis.metrics.cyclomaticComplexity > 10) {
      score -= (analysis.metrics.cyclomaticComplexity - 10) * 2;
    }
    
    return Math.max(0, Math.min(100, score));
  }

  private generateCoverageRecommendations(coverage: any, gaps: any[]): string[] {
    const recommendations = [];
    
    if (coverage.overallCoverage < 80) {
      recommendations.push('Increase overall test coverage to at least 80%');
    }
    
    if (gaps.filter(g => g.severity === 'critical').length > 0) {
      recommendations.push('Address critical coverage gaps immediately');
    }
    
    if (coverage.branchCoverage < coverage.lineCoverage - 10) {
      recommendations.push('Focus on improving branch coverage');
    }
    
    return recommendations;
  }

  private groupSuggestionsByType(suggestions: any[]): Record<string, number> {
    return suggestions.reduce((acc, s) => {
      acc[s.type] = (acc[s.type] || 0) + 1;
      return acc;
    }, {});
  }

  private groupSuggestionsByPriority(suggestions: any[]): Record<string, number> {
    return suggestions.reduce((acc, s) => {
      acc[s.priority] = (acc[s.priority] || 0) + 1;
      return acc;
    }, {});
  }

  private calculateAverageSlowdown(issues: any[]): number {
    if (issues.length === 0) return 1;
    return issues.reduce((sum, issue) => sum + issue.estimatedSlowdown, 0) / issues.length;
  }

  private generateMemoryRecommendations(analysis: any): string[] {
    const recommendations = [];
    
    if (analysis.potentialLeaks.length > 0) {
      recommendations.push('Address potential memory leaks');
    }
    
    if (analysis.heavyObjects.length > 0) {
      recommendations.push('Optimize heavy object usage');
    }
    
    if (analysis.totalEstimatedSaving > 10) {
      recommendations.push(`Potential memory savings: ${analysis.totalEstimatedSaving.toFixed(1)}MB`);
    }
    
    return recommendations;
  }

  private calculateBundleSavings(analysis: any): number {
    let savings = 0;
    savings += analysis.unusedCode.reduce((sum: number, code: any) => sum + code.size, 0);
    savings += analysis.compressionOpportunities.reduce((sum: number, comp: any) => sum + (analysis.bundleSize * comp.estimatedSaving / 100), 0);
    return savings;
  }

  private generateBundleRecommendations(analysis: any): string[] {
    const recommendations = [];
    
    if (analysis.unusedCode.length > 0) {
      recommendations.push('Remove unused code');
    }
    
    if (analysis.heavyDependencies.length > 0) {
      recommendations.push('Replace heavy dependencies with lighter alternatives');
    }
    
    if (analysis.splitOpportunities.length > 0) {
      recommendations.push('Implement code splitting');
    }
    
    return recommendations;
  }

  private calculateExpectedImprovement(optimizations: any[]): any {
    return {
      performance: optimizations.reduce((sum, o) => sum + o.expectedImprovement.performance, 0) / optimizations.length,
      memory: optimizations.reduce((sum, o) => sum + o.expectedImprovement.memory, 0) / optimizations.length,
      userExperience: optimizations.reduce((sum, o) => sum + o.expectedImprovement.userExperience, 0) / optimizations.length
    };
  }

  private calculateAverageEffort(suggestions: any[]): string {
    const efforts = { trivial: 1, small: 2, medium: 3, large: 4, huge: 5 };
    const avgEffort = suggestions.reduce((sum, s) => sum + efforts[s.estimatedEffort as keyof typeof efforts], 0) / suggestions.length;
    
    if (avgEffort <= 1.5) return 'trivial';
    if (avgEffort <= 2.5) return 'small';
    if (avgEffort <= 3.5) return 'medium';
    if (avgEffort <= 4.5) return 'large';
    return 'huge';
  }

  private calculateOverallQualityScore(result: any): number {
    let score = 100;
    let factors = 0;

    if (result.technicalDebt) {
      score -= result.technicalDebt.smells.length * 2;
      factors++;
    }

    if (result.performance) {
      score -= result.performance.issues.filter((i: any) => i.severity === 'critical').length * 10;
      score -= result.performance.issues.filter((i: any) => i.severity === 'high').length * 5;
      factors++;
    }

    if (result.testing) {
      score = score * (result.testing.coverage.overallCoverage / 100);
      factors++;
    }

    return Math.max(0, Math.min(100, score));
  }

  private combineBugPredictions(debtAnalysis: any, perfAnalysis: any, predictions: any, confidence: number): any[] {
    const bugPredictions = [];

    // High complexity areas are bug-prone
    if (debtAnalysis.metrics.cyclomaticComplexity > 15) {
      bugPredictions.push({
        id: `bug-complexity-${Date.now()}`,
        type: 'complexity',
        location: { lineStart: 1, lineEnd: debtAnalysis.metrics.linesOfCode },
        description: 'High complexity increases bug probability',
        riskLevel: 'high',
        confidence: 0.8,
        reasoning: [`Cyclomatic complexity: ${debtAnalysis.metrics.cyclomaticComplexity}`]
      });
    }

    // Critical code smells indicate bug-prone areas
    const criticalSmells = debtAnalysis.smells.filter((s: any) => s.severity === 'critical');
    for (const smell of criticalSmells) {
      bugPredictions.push({
        id: `bug-smell-${smell.id}`,
        type: 'code_smell',
        location: smell.location,
        description: `Code smell may lead to bugs: ${smell.type}`,
        riskLevel: 'medium',
        confidence: 0.7,
        reasoning: [smell.description]
      });
    }

    // Performance issues can cause functional problems
    const criticalPerfIssues = perfAnalysis.issues.filter((i: any) => i.severity === 'critical');
    for (const issue of criticalPerfIssues) {
      bugPredictions.push({
        id: `bug-perf-${issue.id}`,
        type: 'performance',
        location: issue.location,
        description: `Performance issue may cause functional problems: ${issue.title}`,
        riskLevel: 'high',
        confidence: 0.9,
        reasoning: [issue.description]
      });
    }

    return bugPredictions.filter(p => p.confidence >= confidence);
  }
}