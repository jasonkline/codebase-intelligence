import { AST } from '@typescript-eslint/typescript-estree';
import { TSESTree } from '@typescript-eslint/types';
import { createHash } from 'crypto';
import logger from '../utils/logger';
import { Pattern, PatternInstance } from '../database/schema';
import DatabaseManager from '../database/schema';

export interface ASTPattern {
  nodeType: string;
  structure: Record<string, any>;
  hash: string;
  size: number;
  depth: number;
}

export interface PatternCluster {
  id: string;
  patterns: ASTPattern[];
  canonicalPattern: ASTPattern;
  confidence: number;
  category: string;
  examples: Array<{
    filePath: string;
    lineStart: number;
    lineEnd: number;
    code: string;
  }>;
}

export interface LearningConfig {
  minClusterSize: number;
  minConfidence: number;
  maxPatternDepth: number;
  ignoreNodes: string[];
  focusPatterns: string[];
}

export class PatternLearner {
  private db: DatabaseManager;
  private config: LearningConfig;
  private patterns: Map<string, ASTPattern[]> = new Map();
  private clusters: PatternCluster[] = [];

  constructor(db: DatabaseManager, config?: Partial<LearningConfig>) {
    this.db = db;
    this.config = {
      minClusterSize: 3,
      minConfidence: 0.8,
      maxPatternDepth: 5,
      ignoreNodes: ['Identifier', 'Literal', 'StringLiteral', 'NumericLiteral'],
      focusPatterns: ['FunctionDeclaration', 'MethodDefinition', 'CallExpression', 'IfStatement'],
      ...config
    };
  }

  async learnPatternsFromCode(filePath: string, ast: TSESTree.Program, sourceCode: string): Promise<PatternCluster[]> {
    logger.info(`Learning patterns from ${filePath}`);
    
    const extractedPatterns = this.extractPatternsFromAST(ast, filePath, sourceCode);
    const clusters = this.clusterSimilarPatterns(extractedPatterns);
    
    // Store patterns in the database
    for (const cluster of clusters) {
      await this.storePatternCluster(cluster, filePath);
    }
    
    this.clusters.push(...clusters);
    return clusters;
  }

  private extractPatternsFromAST(
    node: TSESTree.Node, 
    filePath: string, 
    sourceCode: string,
    depth = 0
  ): ASTPattern[] {
    const patterns: ASTPattern[] = [];
    
    if (depth > this.config.maxPatternDepth) {
      return patterns;
    }

    // Skip nodes we're not interested in
    if (this.config.ignoreNodes.includes(node.type)) {
      return patterns;
    }

    // Extract structural pattern
    const pattern = this.createASTPattern(node, sourceCode, depth);
    if (pattern) {
      patterns.push(pattern);
    }

    // Recursively extract from children
    for (const key in node) {
      const child = (node as any)[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) {
            patterns.push(...this.extractPatternsFromAST(item, filePath, sourceCode, depth + 1));
          }
        }
      } else if (child && typeof child === 'object' && child.type) {
        patterns.push(...this.extractPatternsFromAST(child, filePath, sourceCode, depth + 1));
      }
    }

    return patterns;
  }

  private createASTPattern(node: TSESTree.Node, sourceCode: string, depth: number): ASTPattern | null {
    try {
      // Create a structural representation of the node
      const structure = this.createStructuralRepresentation(node);
      
      // Generate a hash for similarity matching
      const hash = this.generatePatternHash(structure);
      
      // Calculate pattern metrics
      const size = this.calculateNodeSize(node);
      
      return {
        nodeType: node.type,
        structure,
        hash,
        size,
        depth
      };
    } catch (error) {
      logger.warn(`Failed to create pattern from node ${node.type}:`, error);
      return null;
    }
  }

  private createStructuralRepresentation(node: TSESTree.Node): Record<string, any> {
    const structure: Record<string, any> = {
      type: node.type
    };

    // Extract key structural elements while ignoring specific identifiers
    switch (node.type) {
      case 'FunctionDeclaration':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
        const func = node as TSESTree.FunctionDeclaration;
        structure.async = func.async;
        structure.generator = func.generator;
        structure.paramCount = func.params.length;
        structure.hasBody = !!func.body;
        structure.bodyType = func.body?.type;
        break;

      case 'CallExpression':
        const call = node as TSESTree.CallExpression;
        structure.callee = this.getCalleeStructure(call.callee);
        structure.argCount = call.arguments.length;
        break;

      case 'IfStatement':
        const ifStmt = node as TSESTree.IfStatement;
        structure.hasElse = !!ifStmt.alternate;
        structure.testType = ifStmt.test.type;
        break;

      case 'VariableDeclaration':
        const varDecl = node as TSESTree.VariableDeclaration;
        structure.kind = varDecl.kind;
        structure.declarationCount = varDecl.declarations.length;
        break;

      case 'ImportDeclaration':
        const importDecl = node as TSESTree.ImportDeclaration;
        structure.hasDefault = importDecl.specifiers.some(s => s.type === 'ImportDefaultSpecifier');
        structure.hasNamed = importDecl.specifiers.some(s => s.type === 'ImportSpecifier');
        structure.hasNamespace = importDecl.specifiers.some(s => s.type === 'ImportNamespaceSpecifier');
        break;

      default:
        // For other nodes, extract basic structural information
        for (const key in node) {
          const value = (node as any)[key];
          if (Array.isArray(value)) {
            structure[key] = {
              type: 'array',
              length: value.length,
              elementTypes: [...new Set(value.map(v => v?.type).filter(Boolean))]
            };
          } else if (value && typeof value === 'object' && value.type) {
            structure[key] = { type: value.type };
          } else if (typeof value === 'boolean' || typeof value === 'string') {
            structure[key] = value;
          }
        }
    }

    return structure;
  }

  private getCalleeStructure(callee: TSESTree.Node): Record<string, any> {
    switch (callee.type) {
      case 'Identifier':
        return { type: 'Identifier' };
      case 'MemberExpression':
        const member = callee as TSESTree.MemberExpression;
        return {
          type: 'MemberExpression',
          computed: member.computed,
          objectType: member.object.type,
          propertyType: member.property.type
        };
      default:
        return { type: callee.type };
    }
  }

  private generatePatternHash(structure: Record<string, any>): string {
    const normalizedStructure = JSON.stringify(structure, Object.keys(structure).sort());
    return createHash('md5').update(normalizedStructure).digest('hex').substring(0, 16);
  }

  private calculateNodeSize(node: TSESTree.Node): number {
    let size = 1;
    
    for (const key in node) {
      const value = (node as any)[key];
      if (Array.isArray(value)) {
        size += value.length;
      } else if (value && typeof value === 'object' && value.type) {
        size += 1;
      }
    }
    
    return size;
  }

  private clusterSimilarPatterns(patterns: ASTPattern[]): PatternCluster[] {
    const clusters: PatternCluster[] = [];
    const patternsByHash = new Map<string, ASTPattern[]>();

    // Group patterns by hash (exact structural matches)
    for (const pattern of patterns) {
      if (!patternsByHash.has(pattern.hash)) {
        patternsByHash.set(pattern.hash, []);
      }
      patternsByHash.get(pattern.hash)!.push(pattern);
    }

    // Create clusters from groups that meet minimum size requirement
    for (const [hash, groupPatterns] of patternsByHash) {
      if (groupPatterns.length >= this.config.minClusterSize) {
        const cluster = this.createPatternCluster(hash, groupPatterns);
        if (cluster.confidence >= this.config.minConfidence) {
          clusters.push(cluster);
        }
      }
    }

    // Merge similar clusters (fuzzy matching)
    return this.mergeSimilarClusters(clusters);
  }

  private createPatternCluster(id: string, patterns: ASTPattern[]): PatternCluster {
    // Find the canonical pattern (most common structure)
    const canonicalPattern = this.findCanonicalPattern(patterns);
    
    // Calculate cluster confidence
    const confidence = this.calculateClusterConfidence(patterns);
    
    // Determine category based on pattern characteristics
    const category = this.determinePatternCategory(canonicalPattern);

    return {
      id,
      patterns,
      canonicalPattern,
      confidence,
      category,
      examples: [] // Will be populated when storing
    };
  }

  private findCanonicalPattern(patterns: ASTPattern[]): ASTPattern {
    // For now, return the first pattern as canonical
    // In a more sophisticated version, we would analyze structural variations
    // and create a merged canonical pattern
    return patterns[0];
  }

  private calculateClusterConfidence(patterns: ASTPattern[]): number {
    if (patterns.length < this.config.minClusterSize) {
      return 0;
    }

    // Base confidence on cluster size and structural consistency
    const sizeBonus = Math.min(patterns.length / 10, 0.3);
    const baseConfidence = 0.7;
    
    return Math.min(baseConfidence + sizeBonus, 1.0);
  }

  private determinePatternCategory(pattern: ASTPattern): string {
    const nodeType = pattern.nodeType;
    const structure = pattern.structure;

    // Categorize based on AST node type and structure
    if (nodeType === 'CallExpression') {
      const callee = structure.callee;
      if (callee?.type === 'Identifier') {
        return 'function_call';
      } else if (callee?.type === 'MemberExpression') {
        return 'method_call';
      }
      return 'call';
    }

    if (nodeType.includes('Function')) {
      return 'function';
    }

    if (nodeType === 'IfStatement' || nodeType === 'ConditionalExpression') {
      return 'conditional';
    }

    if (nodeType === 'ImportDeclaration' || nodeType === 'ExportDeclaration') {
      return 'import_export';
    }

    if (nodeType === 'VariableDeclaration') {
      return 'variable';
    }

    return 'general';
  }

  private mergeSimilarClusters(clusters: PatternCluster[]): PatternCluster[] {
    // For now, return clusters as-is
    // In a more sophisticated version, we would implement fuzzy matching
    // to merge clusters with similar but not identical structures
    return clusters;
  }

  private async storePatternCluster(cluster: PatternCluster, filePath: string): Promise<void> {
    try {
      // Create pattern record
      const pattern: Pattern = {
        name: `${cluster.category}_${cluster.id}`,
        category: cluster.category,
        description: `Automatically learned ${cluster.category} pattern`,
        ast_signature: JSON.stringify(cluster.canonicalPattern.structure),
        example_file: filePath,
        confidence_threshold: cluster.confidence,
        is_approved: false, // Learned patterns start as unapproved
        usageCount: 1 // Initialize with 1 usage
      };

      const patternId = this.db.insertPattern(pattern);

      // Store pattern instances (for now, just record that we found it)
      const instance: PatternInstance = {
        pattern_id: patternId,
        file_path: filePath,
        line_start: 1, // We don't have line info yet
        line_end: 1,
        confidence: cluster.confidence,
        metadata: JSON.stringify({
          nodeType: cluster.canonicalPattern.nodeType,
          size: cluster.canonicalPattern.size,
          instanceCount: cluster.patterns.length
        })
      };

      this.db.insertPatternInstance(instance);
      
      logger.info(`Stored pattern cluster: ${cluster.category}_${cluster.id} with ${cluster.patterns.length} instances`);
    } catch (error) {
      logger.error(`Failed to store pattern cluster ${cluster.id}:`, error);
    }
  }

  async learnFromApprovedPatterns(): Promise<void> {
    // Load manually approved patterns from database and update learning model
    const database = this.db.getDatabase();
    const approvedPatterns = database.prepare(`
      SELECT * FROM patterns WHERE is_approved = 1
    `).all() as Pattern[];

    for (const pattern of approvedPatterns) {
      if (pattern.ast_signature) {
        try {
          const structure = JSON.parse(pattern.ast_signature);
          const astPattern: ASTPattern = {
            nodeType: structure.type || 'Unknown',
            structure,
            hash: this.generatePatternHash(structure),
            size: structure.size || 1,
            depth: structure.depth || 1
          };

          // Add to our pattern knowledge base
          const category = pattern.category;
          if (!this.patterns.has(category)) {
            this.patterns.set(category, []);
          }
          this.patterns.get(category)!.push(astPattern);

          logger.info(`Learned from approved pattern: ${pattern.name}`);
        } catch (error) {
          logger.warn(`Failed to parse approved pattern ${pattern.name}:`, error);
        }
      }
    }
  }

  getLearnedPatterns(): Map<string, ASTPattern[]> {
    return this.patterns;
  }

  getClusters(): PatternCluster[] {
    return this.clusters;
  }

  updateConfidenceThreshold(minConfidence: number): void {
    this.config.minConfidence = minConfidence;
  }

  async analyzePatternUsage(): Promise<Record<string, number>> {
    const database = this.db.getDatabase();
    const usage = database.prepare(`
      SELECT p.category, COUNT(pi.id) as usage_count
      FROM patterns p
      LEFT JOIN pattern_instances pi ON p.id = pi.pattern_id
      GROUP BY p.category
    `).all() as Array<{ category: string; usage_count: number }>;

    const usageMap: Record<string, number> = {};
    for (const row of usage) {
      usageMap[row.category] = row.usage_count;
    }

    return usageMap;
  }
}

export default PatternLearner;