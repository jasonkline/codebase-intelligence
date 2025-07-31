import { DatabaseManager } from '../database/schema';
import { DependencyAnalyzer, ImpactAnalysis, DependencyGraph } from './DependencyAnalyzer';
import { KnowledgeExtractor } from './KnowledgeExtractor';
import logger from '../utils/logger';

export interface ChangeImpactResult {
  changeId: string;
  targetComponent: string;
  changeType: 'modify' | 'delete' | 'add';
  impactAnalysis: ImpactAnalysis;
  riskAssessment: RiskAssessment;
  testingPlan: TestingPlan;
  rollbackPlan: RollbackPlan;
  recommendations: ChangeRecommendation[];
  timeline: ChangeTimeline;
}

export interface RiskAssessment {
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  riskFactors: RiskFactor[];
  mitigationStrategies: MitigationStrategy[];
  businessImpact: BusinessImpact;
  technicalRisk: TechnicalRisk;
}

export interface RiskFactor {
  factor: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  likelihood: number; // 0-1
  impact: number; // 0-1
  mitigation?: string;
}

export interface MitigationStrategy {
  strategy: string;
  description: string;
  effort: 'low' | 'medium' | 'high';
  effectiveness: number; // 0-1
  prerequisites: string[];
}

export interface BusinessImpact {
  userFacing: boolean;
  serviceAvailability: 'no-impact' | 'degraded' | 'outage';
  dataIntegrity: 'no-risk' | 'low-risk' | 'high-risk';
  securityImplications: string[];
  performanceImpact: 'none' | 'minor' | 'significant';
}

export interface TechnicalRisk {
  breakingChanges: boolean;
  apiCompatibility: 'maintained' | 'deprecated' | 'breaking';
  databaseMigration: boolean;
  configurationChanges: string[];
  deploymentComplexity: 'simple' | 'complex' | 'critical';
}

export interface TestingPlan {
  testingPhases: TestingPhase[];
  requiredTests: TestRequirement[];
  testEnvironments: string[];
  estimatedEffort: string;
  criticalPaths: string[];
}

export interface TestingPhase {
  phase: string;
  description: string;
  duration: string;
  prerequisites: string[];
  deliverables: string[];
}

export interface TestRequirement {
  type: 'unit' | 'integration' | 'system' | 'security' | 'performance';
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  components: string[];
  automatable: boolean;
}

export interface RollbackPlan {
  rollbackStrategy: 'database' | 'deployment' | 'configuration' | 'feature-flag';
  rollbackSteps: RollbackStep[];
  rollbackTime: string;
  dataConsiderations: string[];
  validationSteps: string[];
}

export interface RollbackStep {
  step: number;
  action: string;
  description: string;
  validation: string;
  rollbackTime: string;
}

export interface ChangeRecommendation {
  type: 'process' | 'technical' | 'timing' | 'alternative';
  recommendation: string;
  rationale: string;
  effort: 'low' | 'medium' | 'high';
  priority: 'critical' | 'high' | 'medium' | 'low';
}

export interface ChangeTimeline {
  phases: TimelinePhase[];
  totalDuration: string;
  criticalPath: string[];
  milestones: Milestone[];
}

export interface TimelinePhase {
  phase: string;
  description: string;
  duration: string;
  dependencies: string[];
  resources: string[];
}

export interface Milestone {
  name: string;
  description: string;
  criteria: string[];
  targetDate: string;
}

export interface SystemHealthMetrics {
  stability: number; // 0-1
  performance: number; // 0-1
  security: number; // 0-1
  maintainability: number; // 0-1
  testCoverage: number; // 0-1
  documentation: number; // 0-1
}

export interface ChangePredictor {
  predictedChanges: PredictedChange[];
  confidenceScore: number; // 0-1
  recommendations: string[];
  riskAreas: string[];
}

export interface PredictedChange {
  component: string;
  changeType: 'modification' | 'extension' | 'replacement';
  probability: number; // 0-1
  timeframe: 'immediate' | 'short-term' | 'medium-term' | 'long-term';
  reasoning: string;
}

export class ImpactAnalyzer {
  private db: DatabaseManager;
  private dependencyAnalyzer: DependencyAnalyzer;
  private knowledgeExtractor: KnowledgeExtractor;
  private dependencyGraph: DependencyGraph | null = null;

  constructor(
    db: DatabaseManager, 
    dependencyAnalyzer: DependencyAnalyzer,
    knowledgeExtractor: KnowledgeExtractor
  ) {
    this.db = db;
    this.dependencyAnalyzer = dependencyAnalyzer;
    this.knowledgeExtractor = knowledgeExtractor;
  }

  async analyzeChangeImpact(
    targetComponent: string, 
    changeType: 'modify' | 'delete' | 'add',
    changeDescription?: string
  ): Promise<ChangeImpactResult> {
    try {
      logger.info(`Analyzing impact for ${changeType} operation on ${targetComponent}`);

      // Ensure we have dependency graph
      if (!this.dependencyGraph) {
        this.dependencyGraph = await this.dependencyAnalyzer.analyzeDependencies();
      }

      // Get basic impact analysis
      const impactAnalysis = await this.dependencyAnalyzer.calculateChangeImpact(targetComponent, changeType);

      // Generate comprehensive risk assessment
      const riskAssessment = await this.generateRiskAssessment(targetComponent, changeType, impactAnalysis);

      // Create testing plan
      const testingPlan = this.generateTestingPlan(targetComponent, impactAnalysis, riskAssessment);

      // Create rollback plan
      const rollbackPlan = this.generateRollbackPlan(changeType, riskAssessment);

      // Generate recommendations
      const recommendations = this.generateRecommendations(targetComponent, changeType, riskAssessment, impactAnalysis);

      // Create timeline
      const timeline = this.generateTimeline(changeType, riskAssessment, testingPlan);

      const changeId = `CHANGE-${Date.now()}`;

      const result: ChangeImpactResult = {
        changeId,
        targetComponent,
        changeType,
        impactAnalysis,
        riskAssessment,
        testingPlan,
        rollbackPlan,
        recommendations,
        timeline
      };

      logger.info(`Change impact analysis completed for ${targetComponent}. Risk level: ${riskAssessment.overallRisk}`);
      return result;

    } catch (error) {
      logger.error(`Failed to analyze change impact for ${targetComponent}:`, error);
      throw error;
    }
  }

  async predictFutureChanges(component: string): Promise<ChangePredictor> {
    logger.info(`Predicting future changes for component: ${component}`);

    const dependencyGraph = this.dependencyGraph || await this.dependencyAnalyzer.analyzeDependencies();
    const targetNode = dependencyGraph.nodes.find(n => n.name === component || n.id === component);
    
    if (!targetNode) {
      throw new Error(`Component not found: ${component}`);
    }

    const predictedChanges: PredictedChange[] = [];
    let confidenceScore = 0.7; // Base confidence

    // Analyze dependency patterns to predict changes
    const dependents = dependencyGraph.nodes.filter(n => 
      n.dependencies.includes(targetNode.id)
    );

    // High coupling suggests likely changes
    if (dependents.length > 5) {
      predictedChanges.push({
        component: targetNode.name,
        changeType: 'modification',
        probability: 0.8,
        timeframe: 'short-term',
        reasoning: 'High coupling with many dependents suggests frequent modification needs'
      });
    }

    // Security components are frequently updated
    if (targetNode.securityLevel === 'public' || targetNode.name.toLowerCase().includes('auth')) {
      predictedChanges.push({
        component: targetNode.name,
        changeType: 'modification',
        probability: 0.7,
        timeframe: 'medium-term',
        reasoning: 'Security-related components require regular updates'
      });
    }

    // Analyze historical patterns (would be enhanced with actual history)
    const recentSecurityIssues = await this.getRecentSecurityIssues(targetNode.files);
    if (recentSecurityIssues.length > 0) {
      predictedChanges.push({
        component: targetNode.name,
        changeType: 'modification',
        probability: 0.9,
        timeframe: 'immediate',
        reasoning: 'Recent security issues indicate immediate changes needed'
      });
      confidenceScore = 0.9;
    }

    // API components may need versioning
    if (targetNode.name.toLowerCase().includes('api') || targetNode.type === 'component') {
      predictedChanges.push({
        component: targetNode.name,
        changeType: 'extension',
        probability: 0.6,
        timeframe: 'medium-term',
        reasoning: 'API components commonly need feature extensions'
      });
    }

    const recommendations = this.generateChangeRecommendations(predictedChanges);
    const riskAreas = this.identifyRiskAreas(targetNode, dependencyGraph);

    return {
      predictedChanges,
      confidenceScore,
      recommendations,
      riskAreas
    };
  }

  async assessSystemHealth(): Promise<SystemHealthMetrics> {
    logger.info('Assessing overall system health...');

    const dependencyGraph = this.dependencyGraph || await this.dependencyAnalyzer.analyzeDependencies();
    const securityIssues = await this.getSecurityIssues();
    const patterns = await this.getCodePatterns();

    // Calculate stability based on circular dependencies and coupling
    const stability = this.calculateStability(dependencyGraph);

    // Calculate performance based on dependency depth and complexity
    const performance = this.calculatePerformanceScore(dependencyGraph);

    // Calculate security based on security issues and coverage
    const security = this.calculateSecurityScore(securityIssues, dependencyGraph.nodes.length);

    // Calculate maintainability based on modularity and coupling
    const maintainability = dependencyGraph.metrics.modularityScore;

    // Estimate test coverage based on patterns and security checks
    const testCoverage = this.estimateTestCoverage(patterns, dependencyGraph.nodes.length);

    // Estimate documentation coverage based on knowledge base
    const documentation = await this.estimateDocumentationCoverage();

    return {
      stability: Math.round(stability * 100) / 100,
      performance: Math.round(performance * 100) / 100,
      security: Math.round(security * 100) / 100,
      maintainability: Math.round(maintainability * 100) / 100,
      testCoverage: Math.round(testCoverage * 100) / 100,
      documentation: Math.round(documentation * 100) / 100
    };
  }

  generateChangeReport(changeResult: ChangeImpactResult): string {
    let report = `# Change Impact Analysis Report\n\n`;
    report += `**Change ID**: ${changeResult.changeId}\n`;
    report += `**Target Component**: ${changeResult.targetComponent}\n`;
    report += `**Change Type**: ${changeResult.changeType}\n`;
    report += `**Overall Risk**: ${changeResult.riskAssessment.overallRisk.toUpperCase()}\n\n`;

    // Impact Summary
    report += `## Impact Summary\n\n`;
    report += `- **Affected Components**: ${changeResult.impactAnalysis.affectedNodes.length}\n`;
    report += `- **Impact Score**: ${changeResult.impactAnalysis.impactScore}/100\n`;
    report += `- **Risk Level**: ${changeResult.impactAnalysis.riskLevel}\n\n`;

    // Affected Categories
    if (changeResult.impactAnalysis.categories.length > 0) {
      report += `## Impact Categories\n\n`;
      changeResult.impactAnalysis.categories.forEach(category => {
        report += `### ${category.category.toUpperCase()} (${category.impact} impact)\n`;
        report += `${category.description}\n\n`;
        report += `**Affected Components**: ${category.affectedComponents.join(', ')}\n\n`;
      });
    }

    // Risk Assessment
    report += `## Risk Assessment\n\n`;
    report += `### Business Impact\n`;
    report += `- **User Facing**: ${changeResult.riskAssessment.businessImpact.userFacing ? 'Yes' : 'No'}\n`;
    report += `- **Service Availability**: ${changeResult.riskAssessment.businessImpact.serviceAvailability}\n`;
    report += `- **Data Integrity**: ${changeResult.riskAssessment.businessImpact.dataIntegrity}\n`;
    report += `- **Performance Impact**: ${changeResult.riskAssessment.businessImpact.performanceImpact}\n\n`;

    report += `### Technical Risk\n`;
    report += `- **Breaking Changes**: ${changeResult.riskAssessment.technicalRisk.breakingChanges ? 'Yes' : 'No'}\n`;
    report += `- **API Compatibility**: ${changeResult.riskAssessment.technicalRisk.apiCompatibility}\n`;
    report += `- **Database Migration**: ${changeResult.riskAssessment.technicalRisk.databaseMigration ? 'Required' : 'Not Required'}\n`;
    report += `- **Deployment Complexity**: ${changeResult.riskAssessment.technicalRisk.deploymentComplexity}\n\n`;

    // Risk Factors
    if (changeResult.riskAssessment.riskFactors.length > 0) {
      report += `### Risk Factors\n\n`;
      changeResult.riskAssessment.riskFactors.forEach(factor => {
        report += `**${factor.factor}** (${factor.severity})\n`;
        report += `${factor.description}\n`;
        if (factor.mitigation) {
          report += `*Mitigation*: ${factor.mitigation}\n`;
        }
        report += '\n';
      });
    }

    // Testing Plan
    report += `## Testing Plan\n\n`;
    report += `**Estimated Effort**: ${changeResult.testingPlan.estimatedEffort}\n\n`;
    report += `**Required Tests**:\n`;
    changeResult.testingPlan.requiredTests.forEach(test => {
      report += `- **${test.type.toUpperCase()}** (${test.priority}): ${test.description}\n`;
    });
    report += '\n';

    // Recommendations
    if (changeResult.recommendations.length > 0) {
      report += `## Recommendations\n\n`;
      changeResult.recommendations.forEach(rec => {
        report += `### ${rec.type.toUpperCase()} (${rec.priority})\n`;
        report += `${rec.recommendation}\n\n`;
        report += `*Rationale*: ${rec.rationale}\n`;
        report += `*Effort*: ${rec.effort}\n\n`;
      });
    }

    // Timeline
    report += `## Timeline\n\n`;
    report += `**Total Duration**: ${changeResult.timeline.totalDuration}\n\n`;
    changeResult.timeline.phases.forEach(phase => {
      report += `### ${phase.phase}\n`;
      report += `- **Duration**: ${phase.duration}\n`;
      report += `- **Description**: ${phase.description}\n`;
      if (phase.dependencies.length > 0) {
        report += `- **Dependencies**: ${phase.dependencies.join(', ')}\n`;
      }
      report += '\n';
    });

    // Rollback Plan
    report += `## Rollback Plan\n\n`;
    report += `**Strategy**: ${changeResult.rollbackPlan.rollbackStrategy}\n`;
    report += `**Estimated Rollback Time**: ${changeResult.rollbackPlan.rollbackTime}\n\n`;
    report += `**Steps**:\n`;
    changeResult.rollbackPlan.rollbackSteps.forEach(step => {
      report += `${step.step}. ${step.action}\n`;
      report += `   ${step.description}\n`;
      report += `   *Validation*: ${step.validation}\n\n`;
    });

    return report;
  }

  // Private helper methods
  private async generateRiskAssessment(
    targetComponent: string, 
    changeType: 'modify' | 'delete' | 'add',
    impactAnalysis: ImpactAnalysis
  ): Promise<RiskAssessment> {
    const riskFactors: RiskFactor[] = [];

    // Analyze component importance
    const dependencyGraph = this.dependencyGraph!;
    const targetNode = dependencyGraph.nodes.find(n => n.name === targetComponent || n.id === targetComponent);
    
    if (targetNode && targetNode.importance > 7) {
      riskFactors.push({
        factor: 'High Component Importance',
        severity: 'high',
        description: `Component has importance score of ${targetNode.importance}/10`,
        likelihood: 0.8,
        impact: 0.9,
        mitigation: 'Implement comprehensive testing and gradual rollout'
      });
    }

    // Check for security implications
    if (targetNode && targetNode.securityLevel === 'public') {
      riskFactors.push({
        factor: 'Security-Critical Component',
        severity: 'critical',
        description: 'Component is part of the public security boundary',
        likelihood: 0.7,
        impact: 1.0,
        mitigation: 'Conduct thorough security review and penetration testing'
      });
    }

    // Check deletion risks
    if (changeType === 'delete' && impactAnalysis.affectedNodes.length > 5) {
      riskFactors.push({
        factor: 'High Dependency Count',
        severity: 'critical',
        description: `${impactAnalysis.affectedNodes.length} components depend on this component`,
        likelihood: 1.0,
        impact: 0.9,
        mitigation: 'Refactor dependents before deletion or provide alternative implementation'
      });
    }

    // Determine overall risk
    const maxSeverity = riskFactors.reduce((max, factor) => {
      const severityMap = { low: 1, medium: 2, high: 3, critical: 4 };
      const currentSeverity = severityMap[factor.severity];
      const maxSeverityValue = severityMap[max];
      return currentSeverity > maxSeverityValue ? factor.severity : max;
    }, 'low' as RiskFactor['severity']);

    // Generate mitigation strategies
    const mitigationStrategies = this.generateMitigationStrategies(riskFactors, changeType);

    // Assess business impact
    const businessImpact: BusinessImpact = {
      userFacing: targetNode?.securityLevel === 'public' || false,
      serviceAvailability: changeType === 'delete' ? 'outage' : 'no-impact',
      dataIntegrity: targetNode?.name.toLowerCase().includes('database') ? 'high-risk' : 'no-risk',
      securityImplications: riskFactors.filter(f => f.severity === 'critical').map(f => f.description),
      performanceImpact: impactAnalysis.affectedNodes.length > 10 ? 'significant' : 'none'
    };

    // Assess technical risk
    const technicalRisk: TechnicalRisk = {
      breakingChanges: changeType === 'delete' || changeType === 'modify',
      apiCompatibility: changeType === 'delete' ? 'breaking' : 'maintained',
      databaseMigration: targetNode?.name.toLowerCase().includes('database') || false,
      configurationChanges: changeType !== 'add' ? ['Update deployment configuration'] : [],
      deploymentComplexity: maxSeverity === 'critical' ? 'critical' : 'simple'
    };

    return {
      overallRisk: maxSeverity,
      riskFactors,
      mitigationStrategies,
      businessImpact,
      technicalRisk
    };
  }

  private generateMitigationStrategies(riskFactors: RiskFactor[], changeType: string): MitigationStrategy[] {
    const strategies: MitigationStrategy[] = [];

    const criticalFactors = riskFactors.filter(f => f.severity === 'critical');
    if (criticalFactors.length > 0) {
      strategies.push({
        strategy: 'Phased Rollout',
        description: 'Deploy changes incrementally to minimize blast radius',
        effort: 'medium',
        effectiveness: 0.8,
        prerequisites: ['Feature flags', 'Monitoring setup', 'Rollback procedures']
      });
    }

    const securityFactors = riskFactors.filter(f => f.description.toLowerCase().includes('security'));
    if (securityFactors.length > 0) {
      strategies.push({
        strategy: 'Security Review',
        description: 'Conduct comprehensive security assessment before deployment',
        effort: 'high',
        effectiveness: 0.9,
        prerequisites: ['Security team availability', 'Penetration testing tools', 'Code review']
      });
    }

    if (changeType === 'delete') {
      strategies.push({
        strategy: 'Deprecation Period',
        description: 'Implement deprecation warnings before removal',
        effort: 'low',
        effectiveness: 0.7,
        prerequisites: ['Communication plan', 'Migration documentation']
      });
    }

    return strategies;
  }

  private generateTestingPlan(
    targetComponent: string, 
    impactAnalysis: ImpactAnalysis, 
    riskAssessment: RiskAssessment
  ): TestingPlan {
    const requiredTests: TestRequirement[] = [];

    // Always require unit tests
    requiredTests.push({
      type: 'unit',
      description: `Unit tests for ${targetComponent}`,
      priority: 'critical',
      components: [targetComponent],
      automatable: true
    });

    // Integration tests for affected components
    if (impactAnalysis.affectedNodes.length > 0) {
      requiredTests.push({
        type: 'integration',
        description: `Integration tests for affected components`,
        priority: 'high',
        components: impactAnalysis.affectedNodes,
        automatable: true
      });
    }

    // Security tests for security-critical components
    if (riskAssessment.riskFactors.some(f => f.factor.includes('Security'))) {
      requiredTests.push({
        type: 'security',
        description: 'Security vulnerability and penetration testing',
        priority: 'critical',
        components: [targetComponent],
        automatable: false
      });
    }

    // Performance tests for high-impact changes
    if (impactAnalysis.impactScore > 70) {
      requiredTests.push({
        type: 'performance',
        description: 'Performance regression testing',
        priority: 'high',
        components: impactAnalysis.affectedNodes,
        automatable: true
      });
    }

    const testingPhases: TestingPhase[] = [
      {
        phase: 'Unit Testing',
        description: 'Test individual component functionality',
        duration: '1-2 days',
        prerequisites: ['Code completion'],
        deliverables: ['Test results', 'Coverage report']
      },
      {
        phase: 'Integration Testing',
        description: 'Test component interactions',
        duration: '2-3 days',
        prerequisites: ['Unit tests passed'],
        deliverables: ['Integration test results', 'API compatibility confirmation']
      },
      {
        phase: 'System Testing',
        description: 'End-to-end system validation',
        duration: '3-5 days',
        prerequisites: ['Integration tests passed'],
        deliverables: ['System test results', 'User acceptance criteria validation']
      }
    ];

    return {
      testingPhases,
      requiredTests,
      testEnvironments: ['development', 'staging', 'production-like'],
      estimatedEffort: this.calculateTestingEffort(requiredTests),
      criticalPaths: impactAnalysis.affectedNodes.slice(0, 3)
    };
  }

  private generateRollbackPlan(changeType: string, riskAssessment: RiskAssessment): RollbackPlan {
    const rollbackSteps: RollbackStep[] = [];

    if (riskAssessment.technicalRisk.databaseMigration) {
      rollbackSteps.push({
        step: 1,
        action: 'Database Rollback',
        description: 'Revert database schema changes',
        validation: 'Verify data integrity and accessibility',
        rollbackTime: '15-30 minutes'
      });
    }

    rollbackSteps.push({
      step: rollbackSteps.length + 1,
      action: 'Code Deployment Rollback',
      description: 'Deploy previous version of the application',
      validation: 'Verify application functionality',
      rollbackTime: '5-10 minutes'
    });

    if (riskAssessment.technicalRisk.configurationChanges.length > 0) {
      rollbackSteps.push({
        step: rollbackSteps.length + 1,
        action: 'Configuration Rollback',
        description: 'Revert configuration changes',
        validation: 'Test configuration-dependent features',
        rollbackTime: '5-15 minutes'
      });
    }

    const totalTime = rollbackSteps.reduce((total, step) => {
      const time = parseInt(step.rollbackTime.split('-')[1]);
      return total + time;
    }, 0);

    return {
      rollbackStrategy: riskAssessment.technicalRisk.databaseMigration ? 'database' : 'deployment',
      rollbackSteps,
      rollbackTime: `${Math.round(totalTime * 0.7)}-${totalTime} minutes`,
      dataConsiderations: riskAssessment.technicalRisk.databaseMigration ? 
        ['Backup data before changes', 'Verify data migration rollback procedures'] : [],
      validationSteps: [
        'Verify system functionality',
        'Check critical business processes',
        'Validate user authentication',
        'Test API endpoints'
      ]
    };
  }

  private generateRecommendations(
    targetComponent: string, 
    changeType: string, 
    riskAssessment: RiskAssessment,
    impactAnalysis: ImpactAnalysis
  ): ChangeRecommendation[] {
    const recommendations: ChangeRecommendation[] = [];

    if (riskAssessment.overallRisk === 'critical') {
      recommendations.push({
        type: 'process',
        recommendation: 'Implement phased rollout with feature flags',
        rationale: 'Critical risk level requires careful deployment strategy',
        effort: 'medium',
        priority: 'critical'
      });
    }

    if (impactAnalysis.affectedNodes.length > 10) {
      recommendations.push({
        type: 'technical',
        recommendation: 'Break change into smaller incremental updates',
        rationale: 'Large number of affected components increases deployment risk',
        effort: 'high',
        priority: 'high'
      });
    }

    if (changeType === 'delete') {
      recommendations.push({
        type: 'process',
        recommendation: 'Implement deprecation period before deletion',
        rationale: 'Allows dependent systems time to adapt',
        effort: 'low',
        priority: 'high'
      });
    }

    if (riskAssessment.businessImpact.userFacing) {
      recommendations.push({
        type: 'timing',
        recommendation: 'Schedule during low-traffic maintenance window',
        rationale: 'Minimize user impact during deployment',
        effort: 'low',
        priority: 'medium'
      });
    }

    return recommendations;
  }

  private generateTimeline(changeType: string, riskAssessment: RiskAssessment, testingPlan: TestingPlan): ChangeTimeline {
    const phases: TimelinePhase[] = [];

    // Planning phase
    phases.push({
      phase: 'Planning & Design',
      description: 'Finalize implementation approach and design',
      duration: '2-3 days',
      dependencies: [],
      resources: ['Developer', 'Architect']
    });

    // Implementation phase
    const implementationDuration = riskAssessment.overallRisk === 'critical' ? '5-7 days' : '3-5 days';
    phases.push({
      phase: 'Implementation',
      description: 'Implement the planned changes',
      duration: implementationDuration,
      dependencies: ['Planning & Design'],
      resources: ['Developer', 'Code Reviewer']
    });

    // Testing phases
    testingPlan.testingPhases.forEach(testPhase => {
      phases.push({
        phase: testPhase.phase,
        description: testPhase.description,
        duration: testPhase.duration,
        dependencies: testPhase.prerequisites,
        resources: ['QA Engineer', 'Developer']
      });
    });

    // Deployment phase
    phases.push({
      phase: 'Deployment',
      description: 'Deploy changes to production',
      duration: riskAssessment.technicalRisk.deploymentComplexity === 'critical' ? '4-6 hours' : '1-2 hours',
      dependencies: ['System Testing'],
      resources: ['DevOps Engineer', 'Developer']
    });

    const totalDays = phases.reduce((total, phase) => {
      const days = parseInt(phase.duration.split('-')[1].split(' ')[0]);
      return total + (isNaN(days) ? 0.5 : days); // Treat hours as 0.5 days
    }, 0);

    const milestones: Milestone[] = [
      {
        name: 'Implementation Complete',
        description: 'All code changes implemented and reviewed',
        criteria: ['Code review passed', 'Unit tests passing'],
        targetDate: 'Day 5'
      },
      {
        name: 'Testing Complete',
        description: 'All testing phases completed successfully',
        criteria: ['All tests passing', 'Performance validated', 'Security cleared'],
        targetDate: `Day ${Math.round(totalDays * 0.8)}`
      },
      {
        name: 'Production Deployment',
        description: 'Changes successfully deployed to production',
        criteria: ['Deployment successful', 'System health validated', 'Rollback plan ready'],
        targetDate: `Day ${Math.round(totalDays)}`
      }
    ];

    return {
      phases,
      totalDuration: `${Math.round(totalDays)} days`,
      criticalPath: phases.map(p => p.phase),
      milestones
    };
  }

  private calculateStability(dependencyGraph: DependencyGraph): number {
    let stability = 1.0;
    
    // Reduce stability for circular dependencies
    stability -= (dependencyGraph.circularDependencies.length * 0.1);
    
    // Reduce stability for high coupling
    if (dependencyGraph.metrics.avgCouplingStrength > 7) {
      stability -= 0.2;
    }
    
    return Math.max(0, stability);
  }

  private calculatePerformanceScore(dependencyGraph: DependencyGraph): number {
    let performance = 1.0;
    
    // Reduce performance for deep dependency chains
    if (dependencyGraph.metrics.maxDepth > 8) {
      performance -= 0.2;
    }
    
    // Reduce performance for high node count relative to edges (sparse graph)
    const density = dependencyGraph.metrics.totalEdges / 
                   (dependencyGraph.metrics.totalNodes * (dependencyGraph.metrics.totalNodes - 1));
    if (density < 0.1) {
      performance -= 0.1;
    }
    
    return Math.max(0, performance);
  }

  private calculateSecurityScore(securityIssues: any[], totalNodes: number): number {
    if (totalNodes === 0) return 1.0;
    
    const criticalIssues = securityIssues.filter(i => i.severity === 'critical').length;
    const highIssues = securityIssues.filter(i => i.severity === 'high').length;
    
    let score = 1.0;
    score -= (criticalIssues * 0.2);
    score -= (highIssues * 0.1);
    
    return Math.max(0, score);
  }

  private estimateTestCoverage(patterns: any[], totalNodes: number): number {
    if (totalNodes === 0) return 0;
    
    const testPatterns = patterns.filter(p => 
      p.name?.includes('test') || p.category === 'testing'
    ).length;
    
    return Math.min(1.0, testPatterns / (totalNodes * 0.3)); // Assume 30% test coverage target
  }

  private async estimateDocumentationCoverage(): Promise<number> {
    const knowledgeCount = await this.getKnowledgeCount();
    const totalSystems = 10; // Estimated number of systems
    
    return Math.min(1.0, knowledgeCount / totalSystems);
  }

  private calculateTestingEffort(tests: TestRequirement[]): string {
    const effortMap = { critical: 3, high: 2, medium: 1, low: 0.5 };
    const totalEffort = tests.reduce((total, test) => total + effortMap[test.priority], 0);
    
    if (totalEffort > 8) return '2-3 weeks';
    if (totalEffort > 5) return '1-2 weeks';
    if (totalEffort > 2) return '3-5 days';
    return '1-2 days';
  }

  private generateChangeRecommendations(predictedChanges: PredictedChange[]): string[] {
    const recommendations: string[] = [];
    
    const immediateChanges = predictedChanges.filter(c => c.timeframe === 'immediate');
    if (immediateChanges.length > 0) {
      recommendations.push('Address immediate security and stability concerns first');
    }
    
    const highProbabilityChanges = predictedChanges.filter(c => c.probability > 0.8);
    if (highProbabilityChanges.length > 0) {
      recommendations.push('Plan for highly probable changes to reduce future technical debt');
    }
    
    recommendations.push('Monitor system metrics to validate predictions');
    
    return recommendations;
  }

  private identifyRiskAreas(targetNode: any, dependencyGraph: DependencyGraph): string[] {
    const riskAreas: string[] = [];
    
    if (targetNode.dependents.length > 5) {
      riskAreas.push('High fan-out - many components depend on this');
    }
    
    if (targetNode.securityLevel === 'public') {
      riskAreas.push('Security-critical component - requires careful change management');
    }
    
    const isInCriticalPath = dependencyGraph.criticalPaths.some(path => 
      path.path.includes(targetNode.id)
    );
    if (isInCriticalPath) {
      riskAreas.push('Part of critical system path - changes may have cascading effects');
    }
    
    return riskAreas;
  }

  // Database query methods
  private async getRecentSecurityIssues(files: string[]): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT * FROM security_issues 
      WHERE file_path IN (${files.map(() => '?').join(',')}) 
      AND resolved = FALSE
      AND detected_at > date('now', '-30 days')
    `);
    return stmt.all(...files);
  }

  private async getSecurityIssues(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare('SELECT * FROM security_issues WHERE resolved = FALSE');
    return stmt.all();
  }

  private async getCodePatterns(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare('SELECT * FROM patterns');
    return stmt.all();
  }

  private async getKnowledgeCount(): Promise<number> {
    const stmt = this.db.getDatabase().prepare('SELECT COUNT(*) as count FROM system_knowledge');
    const result = stmt.get() as { count: number };
    return result.count;
  }
}

export default ImpactAnalyzer;