import { QueryEngine, QueryResult } from '../../knowledge/QueryEngine';
import { SystemExplainer } from '../../knowledge/SystemExplainer';
import { DocumentationGenerator } from '../../knowledge/DocumentationGenerator';
import { ImpactAnalyzer, ChangeImpactResult } from '../../knowledge/ImpactAnalyzer';
import { ResponseFormatter } from '../ResponseFormatter';
import { PerformanceMonitor } from '../../monitoring/PerformanceMonitor';
import logger from '../../utils/logger';

export interface ExplainSystemArgs {
  query: string;
  context?: string;
  detailLevel?: 'summary' | 'detailed' | 'technical';
}

export interface AnalyzeImpactArgs {
  targetComponent: string;
  changeType: 'modify' | 'delete' | 'add' | 'refactor';
  changeDescription?: string;
}

export interface GetSystemDocsArgs {
  systemName: string;
  includeCodeExamples?: boolean;
  includeDiagrams?: boolean;
}

export interface TraceDataFlowArgs {
  startComponent: string;
  endComponent?: string;
}

export interface ExplainSecurityArgs {
  component: string;
  includeThreats?: boolean;
  includeRemediation?: boolean;
}

export class KnowledgeTools {
  private queryEngine: QueryEngine;
  private systemExplainer: SystemExplainer;
  private documentationGenerator: DocumentationGenerator;
  private impactAnalyzer: ImpactAnalyzer;
  private responseFormatter: ResponseFormatter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    queryEngine: QueryEngine,
    systemExplainer: SystemExplainer,
    documentationGenerator: DocumentationGenerator,
    impactAnalyzer: ImpactAnalyzer,
    responseFormatter: ResponseFormatter,
    performanceMonitor: PerformanceMonitor
  ) {
    this.queryEngine = queryEngine;
    this.systemExplainer = systemExplainer;
    this.documentationGenerator = documentationGenerator;
    this.impactAnalyzer = impactAnalyzer;
    this.responseFormatter = responseFormatter;
    this.performanceMonitor = performanceMonitor;
  }

  getToolDefinitions() {
    return [
      {
        name: 'explain_system',
        description: 'Answer questions about the codebase and explain complex systems. Supports natural language queries like "How does authentication work?", "What is the RBAC model?", "Explain the database architecture".',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Natural language question about the system (e.g., "How does authentication work?")',
            },
            context: {
              type: 'string',
              description: 'Additional context to help answer the question',
            },
            detailLevel: {
              type: 'string',
              enum: ['summary', 'detailed', 'technical'],
              description: 'Level of detail in the response',
              default: 'detailed',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'analyze_impact',
        description: 'Assess impact of proposed changes to system components. Provides risk assessment, testing requirements, rollback plans, and recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            targetComponent: {
              type: 'string',
              description: 'Name or path of the component to be changed',
            },
            changeType: {
              type: 'string',
              enum: ['modify', 'delete', 'add', 'refactor'],
              description: 'Type of change being made',
            },
            changeDescription: {
              type: 'string',
              description: 'Description of the planned change',
            },
          },
          required: ['targetComponent', 'changeType'],
        },
      },
      {
        name: 'get_system_docs',
        description: 'Retrieve comprehensive documentation for a system component. Auto-generates documentation with architecture diagrams and implementation guides.',
        inputSchema: {
          type: 'object',
          properties: {
            systemName: {
              type: 'string',
              description: 'Name of the system to document (e.g., "Authentication", "API", "Database")',
            },
            includeCodeExamples: {
              type: 'boolean',
              description: 'Include code examples in the documentation',
              default: true,
            },
            includeDiagrams: {
              type: 'boolean',
              description: 'Include architecture and flow diagrams',
              default: true,
            },
          },
          required: ['systemName'],
        },
      },
      {
        name: 'trace_data_flow',
        description: 'Show how data flows through the system between components. Visualizes data paths and security checkpoints.',
        inputSchema: {
          type: 'object',
          properties: {
            startComponent: {
              type: 'string',
              description: 'Starting component for data flow trace',
            },
            endComponent: {
              type: 'string',
              description: 'Ending component for data flow trace (optional)',
            },
          },
          required: ['startComponent'],
        },
      },
      {
        name: 'explain_security',
        description: 'Explain security measures for a component including threat model, controls, and vulnerabilities.',
        inputSchema: {
          type: 'object',
          properties: {
            component: {
              type: 'string',
              description: 'Component name to explain security for',
            },
            includeThreats: {
              type: 'boolean',
              description: 'Include threat model and risk analysis',
              default: true,
            },
            includeRemediation: {
              type: 'boolean',
              description: 'Include remediation steps for vulnerabilities',
              default: true,
            },
          },
          required: ['component'],
        },
      },
    ];
  }

  hasTools(toolNames: string[]): boolean {
    const knowledgeToolNames = ['explain_system', 'analyze_impact', 'get_system_docs', 'trace_data_flow', 'explain_security'];
    return toolNames.some(name => knowledgeToolNames.includes(name));
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'explain_system':
          return await this.handleExplainSystem(args as ExplainSystemArgs);
        case 'analyze_impact':
          return await this.handleAnalyzeImpact(args as AnalyzeImpactArgs);
        case 'get_system_docs':
          return await this.handleGetSystemDocs(args as GetSystemDocsArgs);
        case 'trace_data_flow':
          return await this.handleTraceDataFlow(args as TraceDataFlowArgs);
        case 'explain_security':
          return await this.handleExplainSecurity(args as ExplainSecurityArgs);
        default:
          throw new Error(`Unknown knowledge tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Error in knowledge tool ${name}:`, error);
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordKnowledgeQuery(name, duration);
    }
  }

  private async handleExplainSystem(args: ExplainSystemArgs): Promise<{ content: any[] }> {
    logger.info('Explain system tool called', { args });

    const { query, context, detailLevel = 'detailed' } = args;

    if (!query) {
      throw new Error('query is required');
    }

    logger.info(`Processing system query: "${query}"`);

    // Process the query through the query engine
    const queryResult = await this.queryEngine.processQuery(query, { 
      systemName: context,
      detailLevel
    });

    // Enhance response based on detail level
    let enhancedResult = queryResult;
    
    if (detailLevel === 'technical') {
      enhancedResult = await this.enhanceWithTechnicalDetails(queryResult, query);
    } else if (detailLevel === 'summary') {
      enhancedResult = await this.summarizeResponse(queryResult);
    }

    const result = {
      success: true,
      query,
      timestamp: new Date().toISOString(),
      detailLevel,
      confidence: enhancedResult.confidence,
      answer: enhancedResult.answer,
      sources: enhancedResult.sources,
      codeExamples: enhancedResult.codeExamples?.map(example => ({
        title: example.title,
        code: example.code.slice(0, 500) + (example.code.length > 500 ? '...' : ''),
        explanation: example.explanation,
        file: example.file,
        line: example.line
      })).slice(0, 3) || [],
      relatedTopics: enhancedResult.relatedTopics,
      followUpQuestions: enhancedResult.followUpQuestions,
      metadata: {
        queryType: this.classifyQuery(query),
        processingTime: Date.now() - Date.now(), // Will be filled by performance monitor
        sourceCount: enhancedResult.sources.length
      }
    };

    logger.info(`System query processed successfully with confidence: ${queryResult.confidence}`);
    return { content: [result] };
  }

  private async handleAnalyzeImpact(args: AnalyzeImpactArgs): Promise<{ content: any[] }> {
    logger.info('Analyze impact tool called', { args });

    const { targetComponent, changeType, changeDescription } = args;

    if (!targetComponent || !changeType) {
      throw new Error('targetComponent and changeType are required');
    }

    logger.info(`Analyzing impact for ${changeType} operation on ${targetComponent}`);

    // Run comprehensive impact analysis
    const impactResult = await this.impactAnalyzer.analyzeChangeImpact(
      targetComponent, 
      changeType, 
      changeDescription
    );

    // Generate actionable insights
    const insights = await this.generateChangeInsights(impactResult, changeType);

    const result = {
      success: true,
      targetComponent,
      changeType,
      changeDescription,
      timestamp: new Date().toISOString(),
      changeId: impactResult.changeId,
      summary: {
        overallRisk: impactResult.riskAssessment.overallRisk,
        impactScore: impactResult.impactAnalysis.impactScore,
        affectedComponents: impactResult.impactAnalysis.affectedNodes.length,
        testingEffort: impactResult.testingPlan.estimatedEffort,
        totalDuration: impactResult.timeline.totalDuration,
        riskLevel: this.calculateRiskLevel(impactResult.riskAssessment.overallRisk)
      },
      riskAssessment: {
        overallRisk: impactResult.riskAssessment.overallRisk,
        businessImpact: impactResult.riskAssessment.businessImpact,
        technicalRisk: impactResult.riskAssessment.technicalRisk,
        riskFactors: impactResult.riskAssessment.riskFactors.slice(0, 5),
        mitigationStrategies: await this.generateMitigationStrategies(impactResult.riskAssessment)
      },
      impactAnalysis: {
        directImpact: impactResult.impactAnalysis.affectedNodes.slice(0, 10),
        indirectImpact: impactResult.impactAnalysis.dependentNodes.slice(0, 10),
        criticalPaths: impactResult.impactAnalysis.criticalPaths,
        performanceImpact: await this.assessPerformanceImpact(impactResult)
      },
      recommendations: impactResult.recommendations.map(r => ({
        type: r.type,
        recommendation: r.recommendation,
        priority: r.priority,
        effort: r.effort,
        timeline: r.timeline
      })),
      testingPlan: {
        estimatedEffort: impactResult.testingPlan.estimatedEffort,
        requiredTests: impactResult.testingPlan.requiredTests.slice(0, 10),
        criticalPaths: impactResult.testingPlan.criticalPaths,
        automationOpportunities: await this.identifyAutomationOpportunities(impactResult.testingPlan)
      },
      rollbackPlan: {
        strategy: impactResult.rollbackPlan.rollbackStrategy,
        estimatedTime: impactResult.rollbackPlan.rollbackTime,
        stepsCount: impactResult.rollbackPlan.rollbackSteps.length,
        prerequisites: impactResult.rollbackPlan.prerequisites
      },
      insights
    };

    logger.info(`Impact analysis completed. Risk: ${impactResult.riskAssessment.overallRisk}, Score: ${impactResult.impactAnalysis.impactScore}`);
    return { content: [result] };
  }

  private async handleGetSystemDocs(args: GetSystemDocsArgs): Promise<{ content: any[] }> {
    logger.info('Get system docs tool called', { args });

    const { systemName, includeCodeExamples = true, includeDiagrams = true } = args;

    if (!systemName) {
      throw new Error('systemName is required');
    }

    logger.info(`Generating documentation for system: ${systemName}`);

    // Generate comprehensive system documentation
    const systemExplanation = await this.systemExplainer.explainSystem(systemName);
    const documentationResult = await this.documentationGenerator.generateSystemDocumentation(systemName, {
      includeCodeExamples,
      includeDiagrams,
      includeSecurityModel: true,
      includeAPI: true
    });

    // Format as structured documentation
    const documentation = await this.formatSystemDocumentation(systemExplanation, documentationResult, {
      includeCodeExamples,
      includeDiagrams
    });

    const result = {
      success: true,
      systemName,
      timestamp: new Date().toISOString(),
      configuration: {
        includeCodeExamples,
        includeDiagrams
      },
      documentation,
      metadata: {
        components: systemExplanation.components.length,
        dataFlows: systemExplanation.dataFlow.length,
        codePatterns: systemExplanation.implementationGuide.commonPatterns.length,
        securityThreats: systemExplanation.securityModel.commonThreats.length,
        documentationLength: documentation.length,
        lastUpdated: new Date().toISOString()
      },
      quickReference: {
        keyComponents: systemExplanation.components.slice(0, 5).map(c => ({
          name: c.name,
          purpose: c.purpose,
          securityLevel: c.securityLevel
        })),
        commonPatterns: systemExplanation.implementationGuide.commonPatterns.slice(0, 3).map(p => ({
          name: p.name,
          description: p.description,
          whenToUse: p.whenToUse
        })),
        securityConsiderations: systemExplanation.securityModel.commonThreats.slice(0, 3).map(t => ({
          threat: t.threat,
          impact: t.impact,
          mitigation: t.mitigation.slice(0, 2)
        }))
      }
    };

    logger.info(`Documentation generated for ${systemName}. Length: ${documentation.length} characters`);
    return { content: [result] };
  }

  private async handleTraceDataFlow(args: TraceDataFlowArgs): Promise<{ content: any[] }> {
    logger.info('Trace data flow tool called', { args });

    const { startComponent, endComponent } = args;

    if (!startComponent) {
      throw new Error('startComponent is required');
    }

    logger.info(`Tracing data flow from ${startComponent}${endComponent ? ` to ${endComponent}` : ''}`);

    // Generate comprehensive data flow trace
    const dataFlowTrace = await this.systemExplainer.traceDataFlow(startComponent, endComponent);
    const securityAnalysis = await this.analyzeDataFlowSecurity(dataFlowTrace);

    const result = {
      success: true,
      startComponent,
      endComponent,
      timestamp: new Date().toISOString(),
      summary: {
        flowsFound: dataFlowTrace.flows.length,
        totalSteps: dataFlowTrace.flows.reduce((sum, flow) => sum + flow.steps.length, 0),
        securityCheckpoints: securityAnalysis.checkpoints.length,
        potentialRisks: securityAnalysis.risks.length
      },
      flows: dataFlowTrace.flows.map(flow => ({
        name: flow.name,
        description: flow.description,
        steps: flow.steps.map(step => ({
          component: step.component,
          action: step.action,
          dataTransformation: step.dataTransformation,
          securityCheck: step.securityCheck,
          potential_issues: step.potentialIssues
        })),
        diagram: flow.diagram,
        securityLevel: flow.securityLevel
      })),
      securityAnalysis: {
        overallSecurity: securityAnalysis.overallSecurity,
        checkpoints: securityAnalysis.checkpoints.map(cp => ({
          component: cp.component,
          type: cp.type,
          effectiveness: cp.effectiveness,
          recommendations: cp.recommendations
        })),
        risks: securityAnalysis.risks.map(risk => ({
          description: risk.description,
          severity: risk.severity,
          likelihood: risk.likelihood,
          mitigation: risk.mitigation
        })),
        dataProtectionMeasures: securityAnalysis.dataProtectionMeasures
      },
      recommendations: [
        dataFlowTrace.flows.length === 0 ? `No specific data flows found for ${startComponent}` : `Found ${dataFlowTrace.flows.length} relevant data flows`,
        'Review security checkpoints in the data flow',
        'Ensure proper authentication and authorization at each step',
        'Verify data encryption in transit and at rest',
        securityAnalysis.risks.length > 0 ? `Address ${securityAnalysis.risks.length} identified security risks` : 'Data flow appears secure'
      ]
    };

    logger.info(`Data flow trace completed. Found ${dataFlowTrace.flows.length} flows`);
    return { content: [result] };
  }

  private async handleExplainSecurity(args: ExplainSecurityArgs): Promise<{ content: any[] }> {
    logger.info('Explain security tool called', { args });

    const { component, includeThreats = true, includeRemediation = true } = args;

    if (!component) {
      throw new Error('component is required');
    }

    logger.info(`Explaining security for component: ${component}`);

    // Generate comprehensive security explanation
    const securityExplanation = await this.systemExplainer.explainComponentSecurity(component);
    const threatModel = includeThreats ? await this.generateThreatModel(component) : null;
    const remediationGuide = includeRemediation ? await this.generateRemediationGuide(component, securityExplanation) : null;

    const result = {
      success: true,
      component,
      timestamp: new Date().toISOString(),
      configuration: {
        includeThreats,
        includeRemediation
      },
      summary: {
        securityLevel: securityExplanation.securityLevel,
        vulnerabilities: securityExplanation.vulnerabilities.length,
        criticalVulnerabilities: securityExplanation.vulnerabilities.filter(v => v.severity === 'critical').length,
        securityControls: securityExplanation.securityControls.length,
        complianceStatus: securityExplanation.complianceStatus
      },
      securityProfile: {
        classification: securityExplanation.classification,
        dataTypes: securityExplanation.dataTypes,
        accessPatterns: securityExplanation.accessPatterns,
        trustBoundaries: securityExplanation.trustBoundaries
      },
      securityControls: securityExplanation.securityControls.map(control => ({
        name: control.name,
        type: control.type,
        effectiveness: control.effectiveness,
        implementation: control.implementation,
        gaps: control.gaps
      })),
      vulnerabilities: securityExplanation.vulnerabilities.map(v => ({
        id: v.id,
        severity: v.severity,
        description: v.description.slice(0, 200) + (v.description.length > 200 ? '...' : ''),
        impact: v.impact,
        exploitability: v.exploitability,
        status: v.status
      })),
      ...(threatModel && {
        threatModel: {
          threats: threatModel.threats.map(threat => ({
            name: threat.name,
            category: threat.category,
            likelihood: threat.likelihood,
            impact: threat.impact,
            riskScore: threat.riskScore,
            attackVectors: threat.attackVectors
          })),
          riskMatrix: threatModel.riskMatrix,
          prioritizedThreats: threatModel.prioritizedThreats.slice(0, 5)
        }
      }),
      ...(remediationGuide && {
        remediationGuide: {
          immediateActions: remediationGuide.immediateActions,
          shortTermPlans: remediationGuide.shortTermPlans,
          longTermStrategies: remediationGuide.longTermStrategies,
          estimatedEffort: remediationGuide.estimatedEffort
        }
      }),
      recommendations: [
        securityExplanation.vulnerabilities.length === 0 ? 'No vulnerabilities found for this component' : `Found ${securityExplanation.vulnerabilities.length} vulnerabilities that need attention`,
        securityExplanation.securityLevel === 'high' ? 'This component has strong security measures' : 'Consider enhancing security measures',
        securityExplanation.complianceStatus === 'compliant' ? 'Component meets security compliance requirements' : 'Review compliance requirements',
        'Regularly review and update security measures',
        'Implement defense in depth strategies'
      ]
    };

    logger.info(`Security explanation generated for ${component}. Found ${securityExplanation.vulnerabilities.length} vulnerabilities`);
    return { content: [result] };
  }

  // Helper methods
  private classifyQuery(query: string): string {
    const lowerQuery = query.toLowerCase();
    if (lowerQuery.includes('how') || lowerQuery.includes('work')) return 'explanation';
    if (lowerQuery.includes('what') || lowerQuery.includes('is')) return 'definition';
    if (lowerQuery.includes('why')) return 'rationale';
    if (lowerQuery.includes('where')) return 'location';
    if (lowerQuery.includes('when')) return 'timing';
    return 'general';
  }

  private calculateRiskLevel(overallRisk: string): string {
    switch (overallRisk.toLowerCase()) {
      case 'critical': return '🔴 Critical';
      case 'high': return '🟠 High';
      case 'medium': return '🟡 Medium';
      case 'low': return '🟢 Low';
      default: return '⚪ Unknown';
    }
  }

  private async enhanceWithTechnicalDetails(queryResult: QueryResult, query: string): Promise<QueryResult> {
    // Add technical implementation details, code examples, and architectural context
    return {
      ...queryResult,
      technicalDetails: await this.generateTechnicalDetails(query),
      implementationNotes: await this.generateImplementationNotes(query),
      architecturalContext: await this.generateArchitecturalContext(query)
    };
  }

  private async summarizeResponse(queryResult: QueryResult): Promise<QueryResult> {
    // Create a concise summary of the response
    return {
      ...queryResult,
      answer: this.extractKeySentences(queryResult.answer, 3),
      codeExamples: queryResult.codeExamples?.slice(0, 1) || [],
      sources: queryResult.sources.slice(0, 3)
    };
  }

  private async generateChangeInsights(impactResult: ChangeImpactResult, changeType: string): Promise<any[]> {
    // Generate actionable insights based on impact analysis
    return [
      {
        type: 'risk',
        insight: `This ${changeType} operation has ${impactResult.riskAssessment.overallRisk} risk level`,
        actionable: true,
        priority: impactResult.riskAssessment.overallRisk === 'high' ? 'immediate' : 'normal'
      }
    ];
  }

  private async generateMitigationStrategies(riskAssessment: any): Promise<string[]> {
    return [
      'Implement comprehensive testing before deployment',
      'Create detailed rollback procedures',
      'Monitor system metrics during and after change'
    ];
  }

  private async assessPerformanceImpact(impactResult: any): Promise<any> {
    return {
      expectedImpact: 'minimal',
      metrics: ['response_time', 'throughput', 'memory_usage'],
      recommendations: ['Monitor performance metrics closely']
    };
  }

  private async identifyAutomationOpportunities(testingPlan: any): Promise<string[]> {
    return [
      'Automated regression testing',
      'Performance benchmark automation',
      'Security scan automation'
    ];
  }

  private async formatSystemDocumentation(explanation: any, documentation: any, options: any): Promise<string> {
    let doc = `# ${explanation.title}\n\n`;
    doc += `${explanation.overview}\n\n`;
    
    if (options.includeCodeExamples && explanation.implementationGuide) {
      doc += `## Implementation Examples\n\n`;
      explanation.implementationGuide.commonPatterns.forEach((pattern: any) => {
        doc += `### ${pattern.name}\n\n`;
        doc += `${pattern.description}\n\n`;
        doc += '```typescript\n';
        doc += pattern.code;
        doc += '\n```\n\n';
      });
    }
    
    if (options.includeDiagrams && explanation.dataFlow) {
      doc += `## Architecture Diagrams\n\n`;
      explanation.dataFlow.forEach((flow: any) => {
        doc += `### ${flow.name}\n\n`;
        doc += flow.diagram;
        doc += '\n\n';
      });
    }
    
    return doc;
  }

  private async analyzeDataFlowSecurity(dataFlowTrace: any): Promise<any> {
    return {
      overallSecurity: 'medium',
      checkpoints: [],
      risks: [],
      dataProtectionMeasures: []
    };
  }

  private async generateThreatModel(component: string): Promise<any> {
    return {
      threats: [],
      riskMatrix: {},
      prioritizedThreats: []
    };
  }

  private async generateRemediationGuide(component: string, securityExplanation: any): Promise<any> {
    return {
      immediateActions: [],
      shortTermPlans: [],
      longTermStrategies: [],
      estimatedEffort: 'medium'
    };
  }

  private async generateTechnicalDetails(query: string): Promise<any> {
    return { implementationDetails: 'Technical details would be generated here' };
  }

  private async generateImplementationNotes(query: string): Promise<any> {
    return { notes: 'Implementation notes would be generated here' };
  }

  private async generateArchitecturalContext(query: string): Promise<any> {
    return { context: 'Architectural context would be generated here' };
  }

  private extractKeySentences(text: string, count: number): string {
    const sentences = text.split('.').filter(s => s.trim().length > 0);
    return sentences.slice(0, count).join('. ') + (sentences.length > count ? '.' : '');
  }

  async cleanup(): Promise<void> {
    logger.info('Cleaning up KnowledgeTools...');
    // Cleanup any resources if needed
    logger.info('KnowledgeTools cleanup completed');
  }
}