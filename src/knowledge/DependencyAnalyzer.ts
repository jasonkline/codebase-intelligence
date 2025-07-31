import { DatabaseManager, SystemDependency } from '../database/schema';
import { 
  KnowledgeExtractor, 
  SystemArchitecture, 
  SystemComponent,
  SystemConnection 
} from './KnowledgeExtractor';
import logger from '../utils/logger';

export interface DependencyGraph {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  metrics: DependencyMetrics;
  circularDependencies: CircularDependency[];
  criticalPaths: CriticalPath[];
}

export interface DependencyNode {
  id: string;
  name: string;
  type: 'system' | 'component' | 'function' | 'class' | 'module';
  level: number; // Depth in dependency tree
  importance: number; // 1-10 based on incoming dependencies
  securityLevel: string;
  files: string[];
  dependencies: string[]; // IDs of nodes this depends on
  dependents: string[]; // IDs of nodes that depend on this
}

export interface DependencyEdge {
  from: string;
  to: string;
  type: 'import' | 'call' | 'inherit' | 'compose' | 'data_flow';
  strength: number; // 1-10 coupling strength
  security: 'secure' | 'insecure' | 'unknown';
  frequency: number; // How often this dependency is used
  isCircular: boolean;
  isCritical: boolean;
}

export interface DependencyMetrics {
  totalNodes: number;
  totalEdges: number;
  avgCouplingStrength: number;
  maxDepth: number;
  circularDependencyCount: number;
  criticalPathCount: number;
  modularityScore: number; // 0-1, higher is better
  instabilityIndex: number; // 0-1, 0 is stable
}

export interface CircularDependency {
  cycle: string[];
  strength: number;
  impact: 'high' | 'medium' | 'low';
  recommendation: string;
}

export interface CriticalPath {
  path: string[];
  description: string;
  riskLevel: 'high' | 'medium' | 'low';
  impact: string;
}

export interface ImpactAnalysis {
  affectedNodes: string[];
  riskLevel: 'high' | 'medium' | 'low';
  impactScore: number; // 1-100
  categories: ImpactCategory[];
  recommendations: string[];
  testingRequirements: string[];
}

export interface ImpactCategory {
  category: 'security' | 'functionality' | 'performance' | 'maintainability';
  impact: 'high' | 'medium' | 'low';
  description: string;
  affectedComponents: string[];
}

export interface ModuleCoupling {
  module1: string;
  module2: string;
  couplingType: 'tight' | 'loose' | 'decoupled';
  strength: number;
  interactions: string[];
  recommendations: string[];
}

export class DependencyAnalyzer {
  private db: DatabaseManager;
  private knowledgeExtractor: KnowledgeExtractor;
  private dependencyGraph: DependencyGraph | null = null;

  constructor(db: DatabaseManager, knowledgeExtractor: KnowledgeExtractor) {
    this.db = db;
    this.knowledgeExtractor = knowledgeExtractor;
  }

  async analyzeDependencies(): Promise<DependencyGraph> {
    try {
      logger.info('Starting dependency analysis...');

      const architecture = this.knowledgeExtractor.getArchitecture();
      const systemDependencies = await this.getSystemDependencies();
      const symbolDependencies = await this.getSymbolDependencies();

      // Build dependency graph
      const nodes = await this.buildDependencyNodes(architecture, systemDependencies);
      const edges = await this.buildDependencyEdges(architecture, systemDependencies, symbolDependencies);

      // Analyze graph properties
      const circularDependencies = this.findCircularDependencies(nodes, edges);
      const criticalPaths = this.findCriticalPaths(nodes, edges);
      const metrics = this.calculateMetrics(nodes, edges, circularDependencies, criticalPaths);

      this.dependencyGraph = {
        nodes,
        edges,
        metrics,
        circularDependencies,
        criticalPaths
      };

      logger.info(`Dependency analysis completed. Found ${nodes.length} nodes and ${edges.length} edges`);
      return this.dependencyGraph;

    } catch (error) {
      logger.error('Failed to analyze dependencies:', error);
      throw error;
    }
  }

  async calculateChangeImpact(targetNode: string, changeType: 'modify' | 'delete' | 'add'): Promise<ImpactAnalysis> {
    if (!this.dependencyGraph) {
      await this.analyzeDependencies();
    }

    const graph = this.dependencyGraph!;
    const target = graph.nodes.find(n => n.id === targetNode || n.name === targetNode);
    
    if (!target) {
      throw new Error(`Target node not found: ${targetNode}`);
    }

    logger.info(`Calculating impact for ${changeType} operation on ${target.name}`);

    // Find all nodes affected by this change
    const affectedNodes = this.findAffectedNodes(target, graph, changeType);
    
    // Calculate impact score
    const impactScore = this.calculateImpactScore(target, affectedNodes, graph);
    
    // Determine risk level
    const riskLevel = this.determineRiskLevel(impactScore, target, changeType);
    
    // Categorize impacts
    const categories = this.categorizeImpacts(target, affectedNodes, graph);
    
    // Generate recommendations
    const recommendations = this.generateChangeRecommendations(target, affectedNodes, changeType);
    
    // Determine testing requirements
    const testingRequirements = this.generateTestingRequirements(target, affectedNodes, categories);

    return {
      affectedNodes: affectedNodes.map(n => n.name),
      riskLevel,
      impactScore,
      categories,
      recommendations,
      testingRequirements
    };
  }

  findCircularDependencies(nodes?: DependencyNode[], edges?: DependencyEdge[]): CircularDependency[] {
    if (!this.dependencyGraph && !nodes && !edges) {
      throw new Error('No dependency graph available');
    }

    const graph = this.dependencyGraph || { nodes: nodes!, edges: edges! };
    const cycles: CircularDependency[] = [];
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    const dfs = (nodeId: string, path: string[]): void => {
      if (recursionStack.has(nodeId)) {
        // Found a cycle
        const cycleStart = path.indexOf(nodeId);
        const cycle = path.slice(cycleStart);
        cycle.push(nodeId); // Complete the cycle

        const strength = this.calculateCycleStrength(cycle, graph.edges);
        const impact = this.determineCycleImpact(cycle, graph.nodes);
        
        cycles.push({
          cycle,
          strength,
          impact,
          recommendation: this.generateCycleRecommendation(cycle, impact)
        });
        return;
      }

      if (visited.has(nodeId)) return;

      visited.add(nodeId);
      recursionStack.add(nodeId);
      
      // Find outgoing edges
      const outgoingEdges = graph.edges.filter(e => e.from === nodeId);
      
      for (const edge of outgoingEdges) {
        dfs(edge.to, [...path, nodeId]);
      }

      recursionStack.delete(nodeId);
    };

    // Check each node for cycles
    for (const node of graph.nodes) {
      if (!visited.has(node.id)) {
        dfs(node.id, []);
      }
    }

    return cycles;
  }

  identifyModuleCoupling(): ModuleCoupling[] {
    if (!this.dependencyGraph) {
      throw new Error('No dependency graph available');
    }

    const moduleGroups = this.groupNodesByModule(this.dependencyGraph.nodes);
    const couplings: ModuleCoupling[] = [];

    const modules = Array.from(moduleGroups.keys());
    
    for (let i = 0; i < modules.length; i++) {
      for (let j = i + 1; j < modules.length; j++) {
        const module1 = modules[i];
        const module2 = modules[j];
        
        const coupling = this.analyzeCouplingBetweenModules(
          module1, 
          module2, 
          moduleGroups.get(module1)!, 
          moduleGroups.get(module2)!
        );
        
        if (coupling.strength > 0) {
          couplings.push(coupling);
        }
      }
    }

    return couplings.sort((a, b) => b.strength - a.strength);
  }

  generateDependencyReport(): string {
    if (!this.dependencyGraph) {
      throw new Error('No dependency graph available');
    }

    const graph = this.dependencyGraph;
    let report = "# Dependency Analysis Report\n\n";

    // Overview
    report += "## Overview\n\n";
    report += `- **Total Components**: ${graph.metrics.totalNodes}\n`;
    report += `- **Total Dependencies**: ${graph.metrics.totalEdges}\n`;
    report += `- **Average Coupling Strength**: ${graph.metrics.avgCouplingStrength.toFixed(2)}\n`;
    report += `- **Maximum Depth**: ${graph.metrics.maxDepth}\n`;
    report += `- **Modularity Score**: ${graph.metrics.modularityScore.toFixed(2)}\n`;
    report += `- **Instability Index**: ${graph.metrics.instabilityIndex.toFixed(2)}\n\n`;

    // Circular Dependencies
    if (graph.circularDependencies.length > 0) {
      report += "## ⚠️ Circular Dependencies\n\n";
      graph.circularDependencies.forEach((cycle, index) => {
        report += `### Cycle ${index + 1} (${cycle.impact} impact)\n`;
        report += `**Path**: ${cycle.cycle.join(' → ')}\n`;
        report += `**Strength**: ${cycle.strength}/10\n`;
        report += `**Recommendation**: ${cycle.recommendation}\n\n`;
      });
    }

    // Critical Paths
    if (graph.criticalPaths.length > 0) {
      report += "## 🔥 Critical Paths\n\n";
      graph.criticalPaths.forEach((path, index) => {
        report += `### Critical Path ${index + 1} (${path.riskLevel} risk)\n`;
        report += `**Path**: ${path.path.join(' → ')}\n`;
        report += `**Impact**: ${path.impact}\n`;
        report += `**Description**: ${path.description}\n\n`;
      });
    }

    // Most Important Components
    const topComponents = graph.nodes
      .sort((a, b) => b.importance - a.importance)
      .slice(0, 10);

    report += "## 🏆 Most Important Components\n\n";
    topComponents.forEach((node, index) => {
      report += `${index + 1}. **${node.name}** (Importance: ${node.importance}/10)\n`;
      report += `   - Type: ${node.type}\n`;
      report += `   - Dependencies: ${node.dependencies.length}\n`;
      report += `   - Dependents: ${node.dependents.length}\n`;
      report += `   - Level: ${node.level}\n\n`;
    });

    // Module Coupling Analysis
    const couplings = this.identifyModuleCoupling();
    if (couplings.length > 0) {
      report += "## 🔗 Module Coupling Analysis\n\n";
      couplings.slice(0, 5).forEach((coupling, index) => {
        report += `### ${index + 1}. ${coupling.module1} ↔ ${coupling.module2}\n`;
        report += `**Coupling Type**: ${coupling.couplingType}\n`;
        report += `**Strength**: ${coupling.strength}/10\n`;
        report += `**Interactions**: ${coupling.interactions.length}\n`;
        if (coupling.recommendations.length > 0) {
          report += `**Recommendations**:\n`;
          coupling.recommendations.forEach(rec => {
            report += `- ${rec}\n`;
          });
        }
        report += '\n';
      });
    }

    return report;
  }

  // Private helper methods
  private async buildDependencyNodes(
    architecture: SystemArchitecture, 
    systemDeps: SystemDependency[]
  ): Promise<DependencyNode[]> {
    const nodes: DependencyNode[] = [];

    // Add system-level nodes
    architecture.systems.forEach(system => {
      nodes.push({
        id: `system:${system.name}`,
        name: system.name,
        type: 'system',
        level: 0, // Will be calculated later
        importance: 0, // Will be calculated later
        securityLevel: system.securityLevel,
        files: system.files,
        dependencies: [],
        dependents: []
      });
    });

    // Add symbol-level nodes from database
    const symbols = await this.getSymbols();
    symbols.forEach(symbol => {
      nodes.push({
        id: `symbol:${symbol.id}`,
        name: symbol.name,
        type: symbol.kind as DependencyNode['type'],
        level: 0,
        importance: 0,
        securityLevel: 'internal',
        files: [symbol.file_path],
        dependencies: [],
        dependents: []
      });
    });

    // Calculate levels and importance
    this.calculateNodeLevels(nodes);
    this.calculateNodeImportance(nodes);

    return nodes;
  }

  private async buildDependencyEdges(
    architecture: SystemArchitecture,
    systemDeps: SystemDependency[],
    symbolDeps: any[]
  ): Promise<DependencyEdge[]> {
    const edges: DependencyEdge[] = [];

    // Add system-level edges
    architecture.connections.forEach(conn => {
      edges.push({
        from: `system:${conn.from}`,
        to: `system:${conn.to}`,
        type: conn.type as DependencyEdge['type'],
        strength: 5, // Default strength
        security: conn.security as DependencyEdge['security'],
        frequency: 1,
        isCircular: false,
        isCritical: false
      });
    });

    // Add symbol-level edges
    symbolDeps.forEach(dep => {
      edges.push({
        from: `symbol:${dep.symbol_id}`,
        to: `symbol:${dep.target_id}`,
        type: dep.reference_kind as DependencyEdge['type'],
        strength: this.calculateDependencyStrength(dep),
        security: 'unknown',
        frequency: dep.frequency || 1,
        isCircular: false,
        isCritical: false
      });
    });

    // Mark circular and critical edges
    this.markSpecialEdges(edges);

    return edges;
  }

  private findAffectedNodes(
    target: DependencyNode, 
    graph: DependencyGraph, 
    changeType: 'modify' | 'delete' | 'add'
  ): DependencyNode[] {
    const affected = new Set<string>();
    const queue = [target.id];

    // For delete operations, include all dependents
    // For modify operations, include immediate dependents and critical paths
    // For add operations, minimal impact
    
    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (affected.has(currentId)) continue;
      
      affected.add(currentId);
      
      const currentNode = graph.nodes.find(n => n.id === currentId);
      if (!currentNode) continue;

      if (changeType === 'delete') {
        // All dependents are affected
        currentNode.dependents.forEach(depId => {
          if (!affected.has(depId)) {
            queue.push(depId);
          }
        });
      } else if (changeType === 'modify') {
        // Only immediate dependents for modifications
        currentNode.dependents.forEach(depId => {
          affected.add(depId);
        });
      }
    }

    return Array.from(affected)
      .map(id => graph.nodes.find(n => n.id === id))
      .filter(Boolean) as DependencyNode[];
  }

  private calculateImpactScore(
    target: DependencyNode, 
    affectedNodes: DependencyNode[], 
    graph: DependencyGraph
  ): number {
    let score = 0;

    // Base score from target importance
    score += target.importance * 10;

    // Add score for each affected node
    affectedNodes.forEach(node => {
      score += node.importance;
    });

    // Increase score for security-critical components
    if (target.securityLevel === 'public' || target.securityLevel === 'authenticated') {
      score += 20;
    }

    // Increase score if in critical path
    const isInCriticalPath = graph.criticalPaths.some(path => 
      path.path.includes(target.id)
    );
    if (isInCriticalPath) {
      score += 15;
    }

    return Math.min(100, score);
  }

  private determineRiskLevel(
    impactScore: number, 
    target: DependencyNode, 
    changeType: 'modify' | 'delete' | 'add'
  ): 'high' | 'medium' | 'low' {
    if (changeType === 'delete' && target.dependents.length > 5) return 'high';
    if (impactScore > 70) return 'high';
    if (impactScore > 40) return 'medium';
    return 'low';
  }

  private categorizeImpacts(
    target: DependencyNode, 
    affectedNodes: DependencyNode[], 
    graph: DependencyGraph
  ): ImpactCategory[] {
    const categories: ImpactCategory[] = [];

    // Security impact
    const securityAffected = affectedNodes.filter(n => 
      n.securityLevel === 'public' || n.securityLevel === 'authenticated'
    );
    if (securityAffected.length > 0) {
      categories.push({
        category: 'security',
        impact: securityAffected.length > 3 ? 'high' : 'medium',
        description: 'Changes may affect security-critical components',
        affectedComponents: securityAffected.map(n => n.name)
      });
    }

    // Functionality impact
    const functionalAffected = affectedNodes.filter(n => 
      n.type === 'function' || n.type === 'class'
    );
    if (functionalAffected.length > 0) {
      categories.push({
        category: 'functionality',
        impact: functionalAffected.length > 5 ? 'high' : 'medium',
        description: 'Changes may affect core functionality',
        affectedComponents: functionalAffected.map(n => n.name)
      });
    }

    return categories;
  }

  private generateChangeRecommendations(
    target: DependencyNode, 
    affectedNodes: DependencyNode[], 
    changeType: 'modify' | 'delete' | 'add'
  ): string[] {
    const recommendations: string[] = [];

    if (changeType === 'delete') {
      recommendations.push('Consider refactoring dependents before deletion');
      recommendations.push('Implement deprecation warnings first');
    }

    if (affectedNodes.length > 10) {
      recommendations.push('Break change into smaller increments');
      recommendations.push('Use feature flags for gradual rollout');
    }

    if (target.securityLevel === 'public') {
      recommendations.push('Conduct security review before changes');
      recommendations.push('Update API documentation if needed');
    }

    return recommendations;
  }

  private generateTestingRequirements(
    target: DependencyNode, 
    affectedNodes: DependencyNode[], 
    categories: ImpactCategory[]
  ): string[] {
    const requirements: string[] = [];

    requirements.push(`Test ${target.name} functionality directly`);

    if (affectedNodes.length > 0) {
      requirements.push(`Test ${affectedNodes.length} dependent components`);
    }

    categories.forEach(category => {
      switch (category.category) {
        case 'security':
          requirements.push('Run security test suite');
          requirements.push('Verify authentication/authorization flows');
          break;
        case 'functionality':
          requirements.push('Run integration tests');
          requirements.push('Verify API contract compliance');
          break;
      }
    });

    return requirements;
  }

  private calculateCycleStrength(cycle: string[], edges: DependencyEdge[]): number {
    let totalStrength = 0;
    let edgeCount = 0;

    for (let i = 0; i < cycle.length - 1; i++) {
      const edge = edges.find(e => e.from === cycle[i] && e.to === cycle[i + 1]);
      if (edge) {
        totalStrength += edge.strength;
        edgeCount++;
      }
    }

    return edgeCount > 0 ? Math.round(totalStrength / edgeCount) : 0;
  }

  private determineCycleImpact(cycle: string[], nodes: DependencyNode[]): 'high' | 'medium' | 'low' {
    const cycleNodes = cycle.map(id => nodes.find(n => n.id === id)).filter(Boolean);
    const avgImportance = cycleNodes.reduce((sum, node) => sum + node!.importance, 0) / cycleNodes.length;
    
    if (avgImportance > 7) return 'high';
    if (avgImportance > 4) return 'medium';
    return 'low';
  }

  private generateCycleRecommendation(cycle: string[], impact: 'high' | 'medium' | 'low'): string {
    if (impact === 'high') {
      return 'High-impact circular dependency. Consider breaking cycle through dependency injection or interface abstraction.';
    } else if (impact === 'medium') {
      return 'Medium-impact circular dependency. Review architecture and consider refactoring.';
    } else {
      return 'Low-impact circular dependency. Monitor and consider refactoring during next major update.';
    }
  }

  private findCriticalPaths(nodes: DependencyNode[], edges: DependencyEdge[]): CriticalPath[] {
    const paths: CriticalPath[] = [];
    
    // Find paths through high-importance nodes
    const criticalNodes = nodes.filter(n => n.importance > 7);
    
    criticalNodes.forEach(startNode => {
      const path = this.findLongestPath(startNode, nodes, edges);
      if (path.length > 3) {
        paths.push({
          path: path.map(n => n.id),
          description: `Critical path through ${startNode.name}`,
          riskLevel: this.calculatePathRisk(path),
          impact: `Changes to any component in this path could affect ${path.length} components`
        });
      }
    });

    return paths;
  }

  private findLongestPath(startNode: DependencyNode, nodes: DependencyNode[], edges: DependencyEdge[]): DependencyNode[] {
    const visited = new Set<string>();
    const path: DependencyNode[] = [];

    const dfs = (node: DependencyNode): DependencyNode[] => {
      if (visited.has(node.id)) return [];
      
      visited.add(node.id);
      const currentPath = [node];
      
      const outgoingEdges = edges.filter(e => e.from === node.id);
      let longestSubPath: DependencyNode[] = [];
      
      for (const edge of outgoingEdges) {
        const targetNode = nodes.find(n => n.id === edge.to);
        if (targetNode) {
          const subPath = dfs(targetNode);
          if (subPath.length > longestSubPath.length) {
            longestSubPath = subPath;
          }
        }
      }
      
      visited.delete(node.id);
      return currentPath.concat(longestSubPath);
    };

    return dfs(startNode);
  }

  private calculatePathRisk(path: DependencyNode[]): 'high' | 'medium' | 'low' {
    const avgImportance = path.reduce((sum, node) => sum + node.importance, 0) / path.length;
    
    if (avgImportance > 7 && path.length > 5) return 'high';
    if (avgImportance > 5 || path.length > 4) return 'medium';
    return 'low';
  }

  private calculateMetrics(
    nodes: DependencyNode[], 
    edges: DependencyEdge[], 
    cycles: CircularDependency[], 
    criticalPaths: CriticalPath[]
  ): DependencyMetrics {
    const totalStrength = edges.reduce((sum, edge) => sum + edge.strength, 0);
    const avgCouplingStrength = edges.length > 0 ? totalStrength / edges.length : 0;
    
    const maxDepth = Math.max(...nodes.map(n => n.level));
    
    // Calculate modularity (simplified)
    const modularityScore = this.calculateModularity(nodes, edges);
    
    // Calculate instability (simplified)
    const instabilityIndex = this.calculateInstability(nodes, edges);

    return {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      avgCouplingStrength: Math.round(avgCouplingStrength * 100) / 100,
      maxDepth,
      circularDependencyCount: cycles.length,
      criticalPathCount: criticalPaths.length,
      modularityScore: Math.round(modularityScore * 100) / 100,
      instabilityIndex: Math.round(instabilityIndex * 100) / 100
    };
  }

  private calculateModularity(nodes: DependencyNode[], edges: DependencyEdge[]): number {
    // Simplified modularity calculation
    const modules = this.groupNodesByModule(nodes);
    let intraModuleEdges = 0;
    let totalEdges = edges.length;

    edges.forEach(edge => {
      const fromModule = this.getNodeModule(edge.from, modules);
      const toModule = this.getNodeModule(edge.to, modules);
      
      if (fromModule === toModule) {
        intraModuleEdges++;
      }
    });

    return totalEdges > 0 ? intraModuleEdges / totalEdges : 0;
  }

  private calculateInstability(nodes: DependencyNode[], edges: DependencyEdge[]): number {
    // Instability = Outgoing / (Incoming + Outgoing)
    let totalInstability = 0;

    nodes.forEach(node => {
      const incoming = edges.filter(e => e.to === node.id).length;
      const outgoing = edges.filter(e => e.from === node.id).length;
      
      if (incoming + outgoing > 0) {
        totalInstability += outgoing / (incoming + outgoing);
      }
    });

    return nodes.length > 0 ? totalInstability / nodes.length : 0;
  }

  private groupNodesByModule(nodes: DependencyNode[]): Map<string, DependencyNode[]> {
    const modules = new Map<string, DependencyNode[]>();

    nodes.forEach(node => {
      const moduleName = this.extractModuleName(node);
      if (!modules.has(moduleName)) {
        modules.set(moduleName, []);
      }
      modules.get(moduleName)!.push(node);
    });

    return modules;
  }

  private extractModuleName(node: DependencyNode): string {
    if (node.files.length > 0) {
      const filePath = node.files[0];
      const pathParts = filePath.split('/');
      if (pathParts.length > 2) {
        return pathParts[1]; // e.g., 'src/auth/...' -> 'auth'
      }
    }
    return 'unknown';
  }

  private getNodeModule(nodeId: string, modules: Map<string, DependencyNode[]>): string {
    for (const [moduleName, nodes] of modules) {
      if (nodes.some(n => n.id === nodeId)) {
        return moduleName;
      }
    }
    return 'unknown';
  }

  private analyzeCouplingBetweenModules(
    module1: string, 
    module2: string, 
    nodes1: DependencyNode[], 
    nodes2: DependencyNode[]
  ): ModuleCoupling {
    const interactions: string[] = [];
    let totalStrength = 0;
    let interactionCount = 0;

    // Find all connections between the modules
    if (!this.dependencyGraph) {
      throw new Error('No dependency graph available');
    }

    this.dependencyGraph.edges.forEach(edge => {
      const fromModule = nodes1.some(n => n.id === edge.from) ? module1 : 
                        nodes2.some(n => n.id === edge.from) ? module2 : null;
      const toModule = nodes1.some(n => n.id === edge.to) ? module1 : 
                      nodes2.some(n => n.id === edge.to) ? module2 : null;

      if ((fromModule === module1 && toModule === module2) || 
          (fromModule === module2 && toModule === module1)) {
        interactions.push(`${edge.from} → ${edge.to} (${edge.type})`);
        totalStrength += edge.strength;
        interactionCount++;
      }
    });

    const avgStrength = interactionCount > 0 ? totalStrength / interactionCount : 0;
    const couplingType = this.determineCouplingType(avgStrength, interactionCount);
    const recommendations = this.generateCouplingRecommendations(couplingType, avgStrength);

    return {
      module1,
      module2,
      couplingType,
      strength: Math.round(avgStrength),
      interactions,
      recommendations
    };
  }

  private determineCouplingType(avgStrength: number, interactionCount: number): 'tight' | 'loose' | 'decoupled' {
    if (interactionCount === 0) return 'decoupled';
    if (avgStrength > 7 || interactionCount > 10) return 'tight';
    return 'loose';
  }

  private generateCouplingRecommendations(couplingType: 'tight' | 'loose' | 'decoupled', strength: number): string[] {
    const recommendations: string[] = [];

    switch (couplingType) {
      case 'tight':
        recommendations.push('Consider refactoring to reduce coupling');
        recommendations.push('Introduce interfaces or abstractions');
        recommendations.push('Use dependency injection pattern');
        break;
      case 'loose':
        recommendations.push('Good coupling level - maintain current structure');
        if (strength > 5) {
          recommendations.push('Monitor for increased coupling over time');
        }
        break;
      case 'decoupled':
        recommendations.push('Excellent decoupling - no action needed');
        break;
    }

    return recommendations;
  }

  private calculateNodeLevels(nodes: DependencyNode[]): void {
    // Implement topological sort to calculate levels
    const visited = new Set<string>();
    
    const calculateLevel = (nodeId: string): number => {
      if (visited.has(nodeId)) return 0;
      
      visited.add(nodeId);
      const node = nodes.find(n => n.id === nodeId);
      if (!node) return 0;

      let maxDependencyLevel = 0;
      node.dependencies.forEach(depId => {
        const depLevel = calculateLevel(depId);
        maxDependencyLevel = Math.max(maxDependencyLevel, depLevel);
      });

      node.level = maxDependencyLevel + 1;
      return node.level;
    };

    nodes.forEach(node => {
      if (!visited.has(node.id)) {
        calculateLevel(node.id);
      }
    });
  }

  private calculateNodeImportance(nodes: DependencyNode[]): void {
    nodes.forEach(node => {
      // Importance based on dependents count, level, and type
      let importance = node.dependents.length * 2; // More dependents = more important
      importance += (10 - node.level); // Higher level = more foundational = more important
      
      // Type-based importance
      if (node.type === 'system') importance += 3;
      if (node.securityLevel === 'public') importance += 2;
      
      node.importance = Math.min(10, Math.max(1, importance));
    });
  }

  private markSpecialEdges(edges: DependencyEdge[]): void {
    // This would be enhanced with actual analysis
    edges.forEach(edge => {
      if (edge.strength > 8) {
        edge.isCritical = true;
      }
    });
  }

  private calculateDependencyStrength(dep: any): number {
    // Calculate based on dependency type and frequency
    let strength = 3; // Base strength
    
    if (dep.reference_kind === 'call') strength += 2;
    if (dep.reference_kind === 'import') strength += 1;
    if (dep.frequency && dep.frequency > 5) strength += 2;
    
    return Math.min(10, strength);
  }

  // Database query methods
  private async getSystemDependencies(): Promise<SystemDependency[]> {
    const stmt = this.db.getDatabase().prepare('SELECT * FROM system_dependencies');
    return stmt.all() as SystemDependency[];
  }

  private async getSymbolDependencies(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare(`
      SELECT sr.*, s1.name as from_name, s2.name as to_name
      FROM symbol_references sr
      JOIN symbols s1 ON sr.symbol_id = s1.id
      JOIN symbols s2 ON sr.symbol_id = s2.id
    `);
    return stmt.all() as any[];
  }

  private async getSymbols(): Promise<any[]> {
    const stmt = this.db.getDatabase().prepare('SELECT * FROM symbols');
    return stmt.all() as any[];
  }
}

export default DependencyAnalyzer;