import { TSESTree } from '@typescript-eslint/types';
import { ASTPattern } from './PatternLearner';
import logger from '../utils/logger';

export interface MatchResult {
  similarity: number;
  differences: PatternDifference[];
  matchedPattern: ASTPattern;
  isPartialMatch: boolean;
  confidence: number;
}

export interface PatternDifference {
  path: string;
  expected: any;
  actual: any;
  severity: 'minor' | 'major' | 'critical';
  description: string;
}

export interface MatchConfig {
  minSimilarity: number;
  ignoreVariableNames: boolean;
  ignoreLiteralValues: boolean;
  structuralWeight: number;
  semanticWeight: number;
  allowPartialMatches: boolean;
}

export class PatternMatcher {
  private config: MatchConfig;

  constructor(config?: Partial<MatchConfig>) {
    this.config = {
      minSimilarity: 0.7,
      ignoreVariableNames: true,
      ignoreLiteralValues: true,
      structuralWeight: 0.7,
      semanticWeight: 0.3,
      allowPartialMatches: true,
      ...config
    };
  }

  matchAgainstPatterns(
    node: TSESTree.Node,
    patterns: ASTPattern[],
    sourceCode?: string
  ): MatchResult[] {
    const results: MatchResult[] = [];

    for (const pattern of patterns) {
      const matchResult = this.matchSinglePattern(node, pattern, sourceCode);
      if (matchResult && matchResult.similarity >= this.config.minSimilarity) {
        results.push(matchResult);
      }
    }

    // Sort by similarity (best matches first)
    return results.sort((a, b) => b.similarity - a.similarity);
  }

  private matchSinglePattern(
    node: TSESTree.Node,
    pattern: ASTPattern,
    sourceCode?: string
  ): MatchResult | null {
    try {
      const nodeStructure = this.createStructuralRepresentation(node);
      const patternStructure = pattern.structure;

      const structuralSimilarity = this.calculateStructuralSimilarity(
        nodeStructure,
        patternStructure
      );

      const semanticSimilarity = this.calculateSemanticSimilarity(
        node,
        pattern,
        sourceCode
      );

      const overallSimilarity = 
        structuralSimilarity * this.config.structuralWeight +
        semanticSimilarity * this.config.semanticWeight;

      if (overallSimilarity < this.config.minSimilarity && !this.config.allowPartialMatches) {
        return null;
      }

      const differences = this.findDifferences(nodeStructure, patternStructure);
      const isPartialMatch = overallSimilarity < 0.9;
      const confidence = this.calculateMatchConfidence(overallSimilarity, differences);

      return {
        similarity: overallSimilarity,
        differences,
        matchedPattern: pattern,
        isPartialMatch,
        confidence
      };
    } catch (error) {
      logger.warn(`Error matching pattern: ${error}`);
      return null;
    }
  }

  private createStructuralRepresentation(node: TSESTree.Node): Record<string, any> {
    const structure: Record<string, any> = {
      type: node.type
    };

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
        
        // Extract parameter patterns without names
        structure.paramTypes = func.params.map(param => this.getParameterPattern(param));
        break;

      case 'CallExpression':
        const call = node as TSESTree.CallExpression;
        structure.callee = this.getNormalizedCalleeStructure(call.callee);
        structure.argCount = call.arguments.length;
        structure.argTypes = call.arguments.map(arg => arg.type);
        break;

      case 'IfStatement':
        const ifStmt = node as TSESTree.IfStatement;
        structure.hasElse = !!ifStmt.alternate;
        structure.testType = ifStmt.test.type;
        structure.consequentType = ifStmt.consequent.type;
        structure.alternateType = ifStmt.alternate?.type;
        break;

      case 'VariableDeclaration':
        const varDecl = node as TSESTree.VariableDeclaration;
        structure.kind = varDecl.kind;
        structure.declarationCount = varDecl.declarations.length;
        structure.hasInit = varDecl.declarations.some(d => d.init !== null);
        break;

      case 'BinaryExpression':
        const binExpr = node as TSESTree.BinaryExpression;
        structure.operator = binExpr.operator;
        structure.leftType = binExpr.left.type;
        structure.rightType = binExpr.right.type;
        break;

      case 'MemberExpression':
        const memberExpr = node as TSESTree.MemberExpression;
        structure.computed = memberExpr.computed;
        structure.objectType = memberExpr.object.type;
        structure.propertyType = memberExpr.property.type;
        break;

      case 'ImportDeclaration':
        const importDecl = node as TSESTree.ImportDeclaration;
        structure.hasDefault = importDecl.specifiers.some(s => s.type === 'ImportDefaultSpecifier');
        structure.hasNamed = importDecl.specifiers.some(s => s.type === 'ImportSpecifier');
        structure.hasNamespace = importDecl.specifiers.some(s => s.type === 'ImportNamespaceSpecifier');
        structure.specifierCount = importDecl.specifiers.length;
        break;

      default:
        // Generic structure extraction
        for (const key in node) {
          if (key === 'range' || key === 'loc' || key === 'parent') continue;
          
          const value = (node as any)[key];
          if (Array.isArray(value)) {
            structure[key] = {
              type: 'array',
              length: value.length,
              elementTypes: [...new Set(value.map(v => v?.type).filter(Boolean))]
            };
          } else if (value && typeof value === 'object' && value.type) {
            structure[key] = { type: value.type };
          } else if (typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
            // Only include non-identifying values
            if (!this.isIdentifyingValue(key, value)) {
              structure[key] = value;
            }
          }
        }
    }

    return structure;
  }

  private getParameterPattern(param: TSESTree.Parameter): Record<string, any> {
    const pattern: Record<string, any> = {
      type: param.type
    };

    switch (param.type) {
      case 'Identifier':
        // Don't include the actual name, just that it's an identifier
        break;
      case 'RestElement':
        const rest = param as TSESTree.RestElement;
        pattern.argumentType = rest.argument.type;
        break;
      case 'AssignmentPattern':
        const assign = param as TSESTree.AssignmentPattern;
        pattern.leftType = assign.left.type;
        pattern.rightType = assign.right.type;
        break;
      case 'ObjectPattern':
        const obj = param as TSESTree.ObjectPattern;
        pattern.propertyCount = obj.properties.length;
        break;
      case 'ArrayPattern':
        const arr = param as TSESTree.ArrayPattern;
        pattern.elementCount = arr.elements.length;
        break;
    }

    return pattern;
  }

  private getNormalizedCalleeStructure(callee: TSESTree.Node): Record<string, any> {
    const structure: Record<string, any> = {
      type: callee.type
    };

    switch (callee.type) {
      case 'Identifier':
        // Don't include the actual identifier name
        break;
      case 'MemberExpression':
        const member = callee as TSESTree.MemberExpression;
        structure.computed = member.computed;
        structure.objectType = member.object.type;
        structure.propertyType = member.property.type;
        
        // Include depth of member access (e.g., obj.prop vs obj.prop.method)
        structure.depth = this.calculateMemberDepth(member);
        break;
      case 'CallExpression':
        // Nested call expression
        structure.nestedCall = true;
        break;
    }

    return structure;
  }

  private calculateMemberDepth(member: TSESTree.MemberExpression): number {
    let depth = 1;
    let current = member.object;
    
    while (current.type === 'MemberExpression') {
      depth++;
      current = (current as TSESTree.MemberExpression).object;
    }
    
    return depth;
  }

  private isIdentifyingValue(key: string, value: any): boolean {
    // Values that make patterns too specific (variable names, literal values, etc.)
    const identifyingKeys = ['name', 'raw', 'value'];
    
    if (identifyingKeys.includes(key)) {
      return this.config.ignoreVariableNames || this.config.ignoreLiteralValues;
    }
    
    return false;
  }

  private calculateStructuralSimilarity(
    nodeStructure: Record<string, any>,
    patternStructure: Record<string, any>
  ): number {
    const allKeys = new Set([
      ...Object.keys(nodeStructure),
      ...Object.keys(patternStructure)
    ]);

    let matches = 0;
    let total = allKeys.size;

    for (const key of allKeys) {
      const nodeValue = nodeStructure[key];
      const patternValue = patternStructure[key];

      if (this.deepEqual(nodeValue, patternValue)) {
        matches++;
      } else if (this.isCompatible(nodeValue, patternValue)) {
        matches += 0.5; // Partial match
      }
    }

    return total > 0 ? matches / total : 0;
  }

  private calculateSemanticSimilarity(
    node: TSESTree.Node,
    pattern: ASTPattern,
    sourceCode?: string
  ): number {
    // Basic semantic similarity based on node type and common patterns
    let similarity = 0;

    // Node type match
    if (node.type === pattern.nodeType) {
      similarity += 0.5;
    }

    // Size similarity (nodes of similar complexity)
    const sizeRatio = Math.min(
      this.calculateNodeSize(node) / pattern.size,
      pattern.size / this.calculateNodeSize(node)
    );
    similarity += sizeRatio * 0.3;

    // Context similarity (if we have source code)
    if (sourceCode) {
      similarity += this.calculateContextSimilarity(node, pattern, sourceCode) * 0.2;
    }

    return Math.min(similarity, 1.0);
  }

  private calculateContextSimilarity(
    node: TSESTree.Node,
    pattern: ASTPattern,
    sourceCode: string
  ): number {
    // Analyze surrounding context (comments, nearby code patterns)
    // This is a simplified version - in practice, we'd analyze more context
    return 0.5; // Placeholder
  }

  private calculateNodeSize(node: TSESTree.Node): number {
    let size = 1;
    
    for (const key in node) {
      if (key === 'range' || key === 'loc' || key === 'parent') continue;
      
      const value = (node as any)[key];
      if (Array.isArray(value)) {
        size += value.length;
      } else if (value && typeof value === 'object' && value.type) {
        size += 1;
      }
    }
    
    return size;
  }

  private findDifferences(
    nodeStructure: Record<string, any>,
    patternStructure: Record<string, any>
  ): PatternDifference[] {
    const differences: PatternDifference[] = [];
    
    const allKeys = new Set([
      ...Object.keys(nodeStructure),
      ...Object.keys(patternStructure)
    ]);

    for (const key of allKeys) {
      const nodeValue = nodeStructure[key];
      const patternValue = patternStructure[key];

      if (!this.deepEqual(nodeValue, patternValue)) {
        const severity = this.determineDifferenceSeverity(key, nodeValue, patternValue);
        differences.push({
          path: key,
          expected: patternValue,
          actual: nodeValue,
          severity,
          description: this.generateDifferenceDescription(key, nodeValue, patternValue)
        });
      }
    }

    return differences;
  }

  private determineDifferenceSeverity(
    key: string,
    nodeValue: any,
    patternValue: any
  ): 'minor' | 'major' | 'critical' {
    // Critical differences that break the pattern
    const criticalKeys = ['type', 'operator'];
    if (criticalKeys.includes(key)) {
      return 'critical';
    }

    // Major differences that significantly change meaning
    const majorKeys = ['async', 'generator', 'kind', 'computed'];
    if (majorKeys.includes(key)) {
      return 'major';
    }

    // Minor differences (counts, optional properties)
    return 'minor';
  }

  private generateDifferenceDescription(
    key: string,
    nodeValue: any,
    patternValue: any
  ): string {
    if (patternValue === undefined) {
      return `Extra property '${key}' with value ${JSON.stringify(nodeValue)}`;
    }
    if (nodeValue === undefined) {
      return `Missing expected property '${key}' (expected: ${JSON.stringify(patternValue)})`;
    }
    return `Property '${key}' differs: expected ${JSON.stringify(patternValue)}, got ${JSON.stringify(nodeValue)}`;
  }

  private calculateMatchConfidence(
    similarity: number,
    differences: PatternDifference[]
  ): number {
    let confidence = similarity;

    // Reduce confidence based on critical differences
    const criticalDiffs = differences.filter(d => d.severity === 'critical').length;
    const majorDiffs = differences.filter(d => d.severity === 'major').length;

    confidence -= criticalDiffs * 0.3;
    confidence -= majorDiffs * 0.1;

    return Math.max(0, Math.min(1, confidence));
  }

  private deepEqual(a: any, b: any): boolean {
    if (a === b) return true;
    if (a == null || b == null) return false;
    if (typeof a !== typeof b) return false;

    if (typeof a === 'object') {
      if (Array.isArray(a) !== Array.isArray(b)) return false;
      
      if (Array.isArray(a)) {
        if (a.length !== b.length) return false;
        return a.every((item, index) => this.deepEqual(item, b[index]));
      }

      const keysA = Object.keys(a);
      const keysB = Object.keys(b);
      if (keysA.length !== keysB.length) return false;

      return keysA.every(key => this.deepEqual(a[key], b[key]));
    }

    return false;
  }

  private isCompatible(a: any, b: any): boolean {
    // Check if values are compatible (e.g., different numbers but same type)
    if (typeof a === typeof b) {
      if (typeof a === 'number') {
        // Numbers are compatible if they're in similar ranges
        return Math.abs(a - b) <= Math.max(a, b) * 0.5;
      }
      if (typeof a === 'object' && a != null && b != null) {
        // Objects are compatible if they have similar structure
        const keysA = Object.keys(a);
        const keysB = Object.keys(b);
        const commonKeys = keysA.filter(key => keysB.includes(key));
        return commonKeys.length / Math.max(keysA.length, keysB.length) > 0.5;
      }
    }
    return false;
  }

  matchPartialPattern(
    node: TSESTree.Node,
    patterns: ASTPattern[],
    allowedMismatches = 2
  ): MatchResult[] {
    const results: MatchResult[] = [];

    for (const pattern of patterns) {
      const matchResult = this.matchSinglePattern(node, pattern);
      if (matchResult) {
        const criticalDiffs = matchResult.differences.filter(d => d.severity === 'critical').length;
        if (criticalDiffs <= allowedMismatches) {
          matchResult.isPartialMatch = true;
          results.push(matchResult);
        }
      }
    }

    return results.sort((a, b) => b.confidence - a.confidence);
  }

  findBestMatch(node: TSESTree.Node, patterns: ASTPattern[]): MatchResult | null {
    const matches = this.matchAgainstPatterns(node, patterns);
    return matches.length > 0 ? matches[0] : null;
  }

  updateConfig(newConfig: Partial<MatchConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  getConfig(): MatchConfig {
    return { ...this.config };
  }
}

export default PatternMatcher;