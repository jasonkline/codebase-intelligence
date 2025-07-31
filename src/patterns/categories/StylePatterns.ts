import { TSESTree } from '@typescript-eslint/types';
import { ASTPattern } from '../PatternLearner';
import PatternMatcher, { MatchResult } from '../PatternMatcher';
import logger from '../../utils/logger';

export interface StylePattern {
  name: string;
  description: string;
  category: 'imports' | 'naming' | 'formatting' | 'organization' | 'typescript' | 'exports';
  level: 'required' | 'recommended' | 'optional';
  examples: string[];
  violations: string[];
  autoFixable: boolean;
}

export interface StylePatternMatch {
  pattern: StylePattern;
  matchResult: MatchResult;
  violations: Array<{
    line?: number;
    column?: number;
    severity: 'error' | 'warning' | 'info';
    message: string;
    fix?: string;
  }>;
  suggestions: string[];
  compliance: {
    score: number; // 0-100
    level: 'excellent' | 'good' | 'needs_improvement' | 'poor';
  };
}

export class StylePatternsAnalyzer {
  private matcher: PatternMatcher;
  private knownPatterns: Map<string, StylePattern> = new Map();

  constructor() {
    this.matcher = new PatternMatcher({
      minSimilarity: 0.7,
      ignoreVariableNames: false, // Style patterns care about naming
      ignoreLiteralValues: false,
      allowPartialMatches: true
    });

    this.initializeKnownPatterns();
  }

  private initializeKnownPatterns(): void {
    const patterns: StylePattern[] = [
      {
        name: 'importOrganization',
        description: 'Consistent import statement organization and ordering',
        category: 'imports',
        level: 'recommended',
        autoFixable: true,
        examples: [
          '// External libraries first\nimport React from "react"\nimport { useState } from "react"\n\n// Internal imports\nimport { Button } from "./components"',
          '// Group by: external, internal, relative\nimport lodash from "lodash"\nimport { api } from "@/lib/api"\nimport "./styles.css"'
        ],
        violations: [
          'import "./styles.css"\nimport React from "react" // Wrong order',
          'import{useState}from"react" // No spaces',
          'import * as React from "react"\nimport React from "react" // Mixed import styles'
        ]
      },
      {
        name: 'namingConventions',
        description: 'Consistent naming conventions across the codebase',
        category: 'naming',
        level: 'required',
        autoFixable: false,
        examples: [
          'const userName = "john" // camelCase for variables',
          'const API_ENDPOINT = "https://api.com" // SCREAMING_SNAKE_CASE for constants',
          'interface UserProfile { ... } // PascalCase for types',
          'function calculateTotalPrice() { ... } // camelCase for functions'
        ],
        violations: [
          'const user_name = "john" // snake_case instead of camelCase',
          'const apiEndpoint = "https://api.com" // should be SCREAMING_SNAKE_CASE',
          'interface userProfile { ... } // should be PascalCase',
          'function calculate_total_price() { ... } // should be camelCase'
        ]
      },
      {
        name: 'typeScriptBestPractices',
        description: 'TypeScript-specific coding standards and best practices',
        category: 'typescript',
        level: 'required',
        autoFixable: false,
        examples: [
          'interface Props { id: string; optional?: boolean }',
          'const items: Item[] = []',
          'function processData<T>(data: T): T { ... }',
          'type Status = "pending" | "completed" | "failed"'
        ],
        violations: [
          'const items: any[] = [] // Avoid any type',
          'function processData(data) { ... } // Missing type annotations',
          'interface Props { id; optional } // Missing type annotations',
          'let status = "pending" // Should use union types'
        ]
      },
      {
        name: 'exportPatterns',
        description: 'Consistent export patterns and module organization',
        category: 'exports',
        level: 'recommended',
        autoFixable: true,
        examples: [
          'export { default } from "./Component"',
          'export const API_VERSION = "v1"',
          'export type { User, UserProfile } from "./types"',
          'export * from "./utils"'
        ],
        violations: [
          'module.exports = Component // Use ES6 exports',
          'export default function() { ... } // Anonymous exports',
          'export { Component as default } // Inconsistent default exports'
        ]
      },
      {
        name: 'fileOrganization',
        description: 'Consistent file and directory organization patterns',
        category: 'organization',
        level: 'recommended',
        autoFixable: false,
        examples: [
          '// File: UserProfile.tsx\n// Order: imports, types, component, export',
          '// Directory: components/\n//   UserProfile/\n//     index.ts\n//     UserProfile.tsx\n//     UserProfile.test.tsx',
          '// Barrel exports in index.ts\nexport { UserProfile } from "./UserProfile"'
        ],
        violations: [
          '// Mixed organization\nfunction Component() {}\nimport React from "react"',
          '// No index.ts barrel exports',
          '// Inconsistent file naming: userProfile.tsx vs UserProfile.tsx'
        ]
      },
      {
        name: 'codeFormatting',
        description: 'Consistent code formatting and spacing',
        category: 'formatting',
        level: 'required',
        autoFixable: true,
        examples: [
          'const obj = { key: value, other: data }',
          'if (condition) {\n  doSomething()\n}',
          'const array = [1, 2, 3]',
          'function name(param1: string, param2: number): void { ... }'
        ],
        violations: [
          'const obj={key:value,other:data} // No spaces',
          'if(condition){doSomething()} // No spaces, no newlines',
          'const array = [ 1 , 2 , 3 ] // Extra spaces',
          'function name( param1:string,param2:number ):void{ ... } // Inconsistent spacing'
        ]
      }
    ];

    for (const pattern of patterns) {
      this.knownPatterns.set(pattern.name, pattern);
    }
  }

  analyzeStyle(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];

    // Analyze import organization
    if (node.type === 'Program') {
      const importMatches = this.analyzeImportOrganization(node, sourceCode);
      matches.push(...importMatches);
    }

    // Analyze naming conventions
    const namingMatches = this.analyzeNamingConventions(node, sourceCode);
    matches.push(...namingMatches);

    // Analyze TypeScript patterns
    const typeScriptMatches = this.analyzeTypeScriptPatterns(node, sourceCode);
    matches.push(...typeScriptMatches);

    // Analyze export patterns
    const exportMatches = this.analyzeExportPatterns(node, sourceCode);
    matches.push(...exportMatches);

    // Analyze file organization
    if (node.type === 'Program') {
      const organizationMatches = this.analyzeFileOrganization(node, sourceCode, filePath);
      matches.push(...organizationMatches);
    }

    // Analyze code formatting
    const formattingMatches = this.analyzeCodeFormatting(node, sourceCode);
    matches.push(...formattingMatches);

    return matches;
  }

  private analyzeImportOrganization(node: TSESTree.Program, sourceCode: string): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];
    const violations: StylePatternMatch['violations'] = [];

    // Extract all import statements
    const imports = node.body.filter(stmt => stmt.type === 'ImportDeclaration') as TSESTree.ImportDeclaration[];
    
    if (imports.length === 0) {
      return matches;
    }

    // Check import ordering
    const importSources = imports.map(imp => imp.source.value as string);
    const { externalImports, internalImports, relativeImports } = this.categorizeImports(importSources);

    // Check if imports are properly grouped and ordered
    if (!this.areImportsProperlyOrdered(imports)) {
      violations.push({
        severity: 'warning',
        message: 'Imports should be organized: external libraries first, then internal modules, then relative imports',
        fix: 'Reorder imports according to convention'
      });
    }

    // Check for consistent import syntax
    const mixedImportStyles = this.hasMixedImportStyles(imports);
    if (mixedImportStyles) {
      violations.push({
        severity: 'info',
        message: 'Mixed import styles detected (import vs import *)',
        fix: 'Use consistent import syntax throughout the file'
      });
    }

    // Check for proper spacing in imports
    const spacingIssues = this.hasImportSpacingIssues(sourceCode);
    if (spacingIssues.length > 0) {
      violations.push(...spacingIssues.map(issue => ({
        severity: 'info' as const,
        message: issue.message,
        fix: issue.fix,
        line: issue.line
      })));
    }

    const compliance = this.calculateComplianceScore('imports', violations);
    const pattern = this.knownPatterns.get('importOrganization')!;

    matches.push({
      pattern,
      matchResult: {
        similarity: violations.length === 0 ? 0.9 : Math.max(0.5, 0.9 - violations.length * 0.1),
        differences: [],
        matchedPattern: {} as ASTPattern,
        isPartialMatch: violations.length > 0,
        confidence: 0.8
      },
      violations,
      suggestions: this.generateImportSuggestions(violations),
      compliance
    });

    return matches;
  }

  private analyzeNamingConventions(node: TSESTree.Node, sourceCode: string): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];
    const violations: StylePatternMatch['violations'] = [];

    // Check variable naming
    if (node.type === 'VariableDeclaration') {
      const varDecl = node as TSESTree.VariableDeclaration;
      for (const declarator of varDecl.declarations) {
        if (declarator.id.type === 'Identifier') {
          const name = (declarator.id as TSESTree.Identifier).name;
          const expectedCase = this.getExpectedCase(varDecl.kind, declarator.init);
          
          if (!this.matchesNamingConvention(name, expectedCase)) {
            violations.push({
              severity: 'warning',
              message: `Variable '${name}' should use ${expectedCase}`,
              fix: `Rename to ${this.convertToCase(name, expectedCase)}`
            });
          }
        }
      }
    }

    // Check function naming
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      if (func.id) {
        const name = func.id.name;
        if (!this.isCamelCase(name)) {
          violations.push({
            severity: 'warning',
            message: `Function '${name}' should use camelCase`,
            fix: `Rename to ${this.toCamelCase(name)}`
          });
        }
      }
    }

    // Check interface/type naming
    if (node.type === 'TSInterfaceDeclaration' || node.type === 'TSTypeAliasDeclaration') {
      const typeDecl = node as TSESTree.TSInterfaceDeclaration | TSESTree.TSTypeAliasDeclaration;
      const name = typeDecl.id.name;
      if (!this.isPascalCase(name)) {
        violations.push({
          severity: 'error',
          message: `Type '${name}' should use PascalCase`,
          fix: `Rename to ${this.toPascalCase(name)}`
        });
      }
    }

    if (violations.length > 0) {
      const compliance = this.calculateComplianceScore('naming', violations);
      const pattern = this.knownPatterns.get('namingConventions')!;

      matches.push({
        pattern,
        matchResult: {
          similarity: Math.max(0.4, 0.8 - violations.length * 0.1),
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: true,
          confidence: 0.9
        },
        violations,
        suggestions: this.generateNamingSuggestions(violations),
        compliance
      });
    }

    return matches;
  }

  private analyzeTypeScriptPatterns(node: TSESTree.Node, sourceCode: string): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];
    const violations: StylePatternMatch['violations'] = [];

    // Check for any types
    if (this.hasAnyTypes(node, sourceCode)) {
      violations.push({
        severity: 'error',
        message: 'Avoid using "any" type - use specific types instead',
        fix: 'Replace any with specific type definitions'
      });
    }

    // Check for missing type annotations
    if (node.type === 'FunctionDeclaration') {
      const func = node as TSESTree.FunctionDeclaration;
      if (!func.returnType) {
        violations.push({
          severity: 'warning',
          message: 'Function should have explicit return type annotation',
          fix: 'Add return type annotation'
        });
      }

      // Check parameter types
      for (const param of func.params) {
        if (param.type === 'Identifier' && !(param as any).typeAnnotation) {
          violations.push({
            severity: 'warning',
            message: `Parameter '${(param as TSESTree.Identifier).name}' should have type annotation`,
            fix: 'Add type annotation to parameter'
          });
        }
      }
    }

    // Check for proper interface usage
    if (node.type === 'TSInterfaceDeclaration') {
      const interface_ = node as TSESTree.TSInterfaceDeclaration;
      for (const member of interface_.body.body) {
        if (member.type === 'TSPropertySignature' && !member.typeAnnotation) {
          violations.push({
            severity: 'error',
            message: 'Interface property should have type annotation',
            fix: 'Add type annotation to interface property'
          });
        }
      }
    }

    if (violations.length > 0) {
      const compliance = this.calculateComplianceScore('typescript', violations);
      const pattern = this.knownPatterns.get('typeScriptBestPractices')!;

      matches.push({
        pattern,
        matchResult: {
          similarity: Math.max(0.3, 0.7 - violations.length * 0.1),
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: true,
          confidence: 0.8
        },
        violations,
        suggestions: this.generateTypeScriptSuggestions(violations),
        compliance
      });
    }

    return matches;
  }

  private analyzeExportPatterns(node: TSESTree.Node, sourceCode: string): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];
    const violations: StylePatternMatch['violations'] = [];

    // Check export consistency
    if (node.type === 'ExportDefaultDeclaration') {
      const exportDecl = node as TSESTree.ExportDefaultDeclaration;
      if (exportDecl.declaration.type === 'FunctionDeclaration' && 
          !(exportDecl.declaration as TSESTree.FunctionDeclaration).id) {
        violations.push({
          severity: 'warning',
          message: 'Default export should not be anonymous',
          fix: 'Add name to exported function'
        });
      }
    }

    // Check for CommonJS exports (should use ES6)
    if (sourceCode.includes('module.exports') || sourceCode.includes('exports.')) {
      violations.push({
        severity: 'warning',
        message: 'Use ES6 export syntax instead of CommonJS',
        fix: 'Replace module.exports with export statements'
      });
    }

    if (violations.length > 0) {
      const compliance = this.calculateComplianceScore('exports', violations);
      const pattern = this.knownPatterns.get('exportPatterns')!;

      matches.push({
        pattern,
        matchResult: {
          similarity: Math.max(0.5, 0.8 - violations.length * 0.15),
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: true,
          confidence: 0.7
        },
        violations,
        suggestions: this.generateExportSuggestions(violations),
        compliance
      });
    }

    return matches;
  }

  private analyzeFileOrganization(node: TSESTree.Program, sourceCode: string, filePath: string): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];
    const violations: StylePatternMatch['violations'] = [];

    // Check file naming convention
    const fileName = filePath.split('/').pop() || '';
    if (!this.hasProperFileNaming(fileName)) {
      violations.push({
        severity: 'info',
        message: 'File name should follow naming conventions',
        fix: 'Use PascalCase for components, camelCase for utilities'
      });
    }

    // Check code organization order
    const organizationIssues = this.checkCodeOrganization(node.body);
    violations.push(...organizationIssues);

    if (violations.length > 0) {
      const compliance = this.calculateComplianceScore('organization', violations);
      const pattern = this.knownPatterns.get('fileOrganization')!;

      matches.push({
        pattern,
        matchResult: {
          similarity: Math.max(0.6, 0.9 - violations.length * 0.1),
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: true,
          confidence: 0.7
        },
        violations,
        suggestions: this.generateOrganizationSuggestions(violations),
        compliance
      });
    }

    return matches;
  }

  private analyzeCodeFormatting(node: TSESTree.Node, sourceCode: string): StylePatternMatch[] {
    const matches: StylePatternMatch[] = [];
    const violations: StylePatternMatch['violations'] = [];

    // Check for basic formatting issues
    const formattingIssues = this.checkBasicFormatting(sourceCode);
    violations.push(...formattingIssues);

    if (violations.length > 0) {
      const compliance = this.calculateComplianceScore('formatting', violations);
      const pattern = this.knownPatterns.get('codeFormatting')!;

      matches.push({
        pattern,
        matchResult: {
          similarity: Math.max(0.4, 0.8 - violations.length * 0.05),
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: true,
          confidence: 0.6
        },
        violations,
        suggestions: this.generateFormattingSuggestions(violations),
        compliance
      });
    }

    return matches;
  }

  // Helper methods
  private categorizeImports(sources: string[]): { externalImports: string[], internalImports: string[], relativeImports: string[] } {
    const externalImports: string[] = [];
    const internalImports: string[] = [];
    const relativeImports: string[] = [];

    for (const source of sources) {
      if (source.startsWith('.')) {
        relativeImports.push(source);
      } else if (source.startsWith('@/') || source.startsWith('~/')) {
        internalImports.push(source);
      } else {
        externalImports.push(source);
      }
    }

    return { externalImports, internalImports, relativeImports };
  }

  private areImportsProperlyOrdered(imports: TSESTree.ImportDeclaration[]): boolean {
    // Simplified check - would need more sophisticated logic
    return true; // Placeholder
  }

  private hasMixedImportStyles(imports: TSESTree.ImportDeclaration[]): boolean {
    const hasDefaultImports = imports.some(imp => 
      imp.specifiers.some(spec => spec.type === 'ImportDefaultSpecifier')
    );
    const hasNamespaceImports = imports.some(imp => 
      imp.specifiers.some(spec => spec.type === 'ImportNamespaceSpecifier')
    );
    
    return hasDefaultImports && hasNamespaceImports;
  }

  private hasImportSpacingIssues(sourceCode: string): Array<{ message: string; fix: string; line?: number }> {
    const issues: Array<{ message: string; fix: string; line?: number }> = [];
    
    // Check for spacing issues in import statements
    const importLines = sourceCode.split('\n').filter(line => line.trim().startsWith('import'));
    
    for (const line of importLines) {
      if (line.includes('{') && !line.includes('{ ')) {
        issues.push({
          message: 'Import destructuring should have space after opening brace',
          fix: 'Add space after { in import statement'
        });
      }
      
      if (line.includes('}') && !line.includes(' }')) {
        issues.push({
          message: 'Import destructuring should have space before closing brace',
          fix: 'Add space before } in import statement'
        });
      }
    }
    
    return issues;
  }

  private getExpectedCase(kind: string, init: TSESTree.Expression | null): 'camelCase' | 'SCREAMING_SNAKE_CASE' | 'PascalCase' {
    if (kind === 'const' && this.isConstantValue(init)) {
      return 'SCREAMING_SNAKE_CASE';
    }
    return 'camelCase';
  }

  private isConstantValue(init: TSESTree.Expression | null): boolean {
    if (!init) return false;
    return init.type === 'Literal' || 
           (init.type === 'UnaryExpression' && init.argument.type === 'Literal') ||
           (init.type === 'MemberExpression' && this.isConstantMemberExpression(init));
  }

  private isConstantMemberExpression(expr: TSESTree.MemberExpression): boolean {
    // Check for patterns like process.env.API_URL
    return expr.object.type === 'MemberExpression' || 
           (expr.object.type === 'Identifier' && 
            ['process', 'window', 'document'].includes((expr.object as TSESTree.Identifier).name));
  }

  private matchesNamingConvention(name: string, convention: string): boolean {
    switch (convention) {
      case 'camelCase':
        return this.isCamelCase(name);
      case 'SCREAMING_SNAKE_CASE':
        return this.isScreamingSnakeCase(name);
      case 'PascalCase':
        return this.isPascalCase(name);
      default:
        return true;
    }
  }

  private isCamelCase(name: string): boolean {
    return /^[a-z][a-zA-Z0-9]*$/.test(name);
  }

  private isPascalCase(name: string): boolean {
    return /^[A-Z][a-zA-Z0-9]*$/.test(name);
  }

  private isScreamingSnakeCase(name: string): boolean {
    return /^[A-Z][A-Z0-9_]*$/.test(name);
  }

  private convertToCase(name: string, targetCase: string): string {
    switch (targetCase) {
      case 'camelCase':
        return this.toCamelCase(name);
      case 'PascalCase':
        return this.toPascalCase(name);
      case 'SCREAMING_SNAKE_CASE':
        return this.toScreamingSnakeCase(name);
      default:
        return name;
    }
  }

  private toCamelCase(str: string): string {
    return str.replace(/[-_](.)/g, (_, c) => c.toUpperCase())
              .replace(/^[A-Z]/, c => c.toLowerCase());
  }

  private toPascalCase(str: string): string {
    return str.replace(/[-_](.)/g, (_, c) => c.toUpperCase())
              .replace(/^[a-z]/, c => c.toUpperCase());
  }

  private toScreamingSnakeCase(str: string): string {
    return str.replace(/([A-Z])/g, '_$1')
              .replace(/^_/, '')
              .toUpperCase();
  }

  private hasAnyTypes(node: TSESTree.Node, sourceCode: string): boolean {
    return sourceCode.includes(': any') || 
           sourceCode.includes('<any>') || 
           sourceCode.includes('any[]');
  }

  private hasProperFileNaming(fileName: string): boolean {
    // Component files should be PascalCase, utility files should be camelCase
    if (fileName.endsWith('.tsx') || fileName.endsWith('.jsx')) {
      return this.isPascalCase(fileName.replace(/\.(tsx|jsx)$/, ''));
    }
    if (fileName.endsWith('.ts') || fileName.endsWith('.js')) {
      const baseName = fileName.replace(/\.(ts|js)$/, '');
      return this.isCamelCase(baseName) || this.isPascalCase(baseName);
    }
    return true;
  }

  private checkCodeOrganization(body: TSESTree.Statement[]): StylePatternMatch['violations'] {
    const violations: StylePatternMatch['violations'] = [];
    
    // Check if imports come first
    let foundNonImport = false;
    for (const stmt of body) {
      if (stmt.type === 'ImportDeclaration') {
        if (foundNonImport) {
          violations.push({
            severity: 'warning',
            message: 'All imports should be at the top of the file',
            fix: 'Move imports to the top of the file'
          });
          break;
        }
      } else {
        foundNonImport = true;
      }
    }
    
    return violations;
  }

  private checkBasicFormatting(sourceCode: string): StylePatternMatch['violations'] {
    const violations: StylePatternMatch['violations'] = [];
    const lines = sourceCode.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Check for trailing whitespace
      if (line.endsWith(' ') || line.endsWith('\t')) {
        violations.push({
          line: i + 1,
          severity: 'info',
          message: 'Line has trailing whitespace',
          fix: 'Remove trailing whitespace'
        });
      }
      
      // Check for mixed tabs and spaces (simplified)
      if (line.includes('\t') && line.includes('  ')) {
        violations.push({
          line: i + 1,
          severity: 'warning',
          message: 'Mixed tabs and spaces for indentation',
          fix: 'Use consistent indentation (spaces or tabs)'
        });
      }
    }
    
    return violations;
  }

  private calculateComplianceScore(category: string, violations: StylePatternMatch['violations']): StylePatternMatch['compliance'] {
    let score = 100;
    
    for (const violation of violations) {
      switch (violation.severity) {
        case 'error':
          score -= 20;
          break;
        case 'warning':
          score -= 10;
          break;
        case 'info':
          score -= 5;
          break;
      }
    }
    
    score = Math.max(0, score);
    
    let level: StylePatternMatch['compliance']['level'];
    if (score >= 90) level = 'excellent';
    else if (score >= 75) level = 'good';
    else if (score >= 50) level = 'needs_improvement';
    else level = 'poor';
    
    return { score, level };
  }

  private generateImportSuggestions(violations: StylePatternMatch['violations']): string[] {
    const suggestions = [];
    
    if (violations.some(v => v.message.includes('order'))) {
      suggestions.push('Group imports: external libraries first, then internal modules, then relative imports');
    }
    
    if (violations.some(v => v.message.includes('spacing'))) {
      suggestions.push('Add proper spacing in import statements');
    }
    
    if (violations.some(v => v.message.includes('style'))) {
      suggestions.push('Use consistent import syntax throughout the file');
    }
    
    return suggestions.length > 0 ? suggestions : ['Import organization follows best practices'];
  }

  private generateNamingSuggestions(violations: StylePatternMatch['violations']): string[] {
    return [
      'Use camelCase for variables and functions',
      'Use PascalCase for types, interfaces, and components',
      'Use SCREAMING_SNAKE_CASE for constants',
      'Be consistent with naming conventions across the codebase'
    ];
  }

  private generateTypeScriptSuggestions(violations: StylePatternMatch['violations']): string[] {
    return [
      'Add explicit type annotations to all functions and variables',
      'Avoid using "any" type - use specific types instead',
      'Define interfaces for complex object types',
      'Use union types for restricted string values'
    ];
  }

  private generateExportSuggestions(violations: StylePatternMatch['violations']): string[] {
    return [
      'Use ES6 export syntax instead of CommonJS',
      'Avoid anonymous default exports',
      'Use named exports when exporting multiple items',
      'Consider using barrel exports (index.ts) for modules'
    ];
  }

  private generateOrganizationSuggestions(violations: StylePatternMatch['violations']): string[] {
    return [
      'Organize code in consistent order: imports, types, implementation, exports',
      'Use proper file naming conventions',
      'Group related functionality together',
      'Keep files focused on a single responsibility'
    ];
  }

  private generateFormattingSuggestions(violations: StylePatternMatch['violations']): string[] {
    return [
      'Use consistent indentation (spaces or tabs, not mixed)',
      'Remove trailing whitespace',
      'Add proper spacing around operators and braces',
      'Consider using Prettier for automatic formatting'
    ];
  }

  getKnownPatterns(): Map<string, StylePattern> {
    return this.knownPatterns;
  }

  addCustomPattern(pattern: StylePattern): void {
    this.knownPatterns.set(pattern.name, pattern);
    logger.info(`Added custom style pattern: ${pattern.name}`);
  }

  generateStyleReport(matches: StylePatternMatch[]): string {
    const report = ['# Code Style Analysis Report\n'];
    
    // Calculate overall compliance
    const overallScore = matches.reduce((sum, match) => sum + match.compliance.score, 0) / matches.length;
    report.push(`**Overall Compliance Score:** ${Math.round(overallScore)}/100\n`);
    
    const byCategory = new Map<string, StylePatternMatch[]>();
    for (const match of matches) {
      const category = match.pattern.category;
      if (!byCategory.has(category)) {
        byCategory.set(category, []);
      }
      byCategory.get(category)!.push(match);
    }

    for (const [category, categoryMatches] of byCategory) {
      report.push(`## ${category.toUpperCase()}\n`);
      
      for (const match of categoryMatches) {
        report.push(`### ${match.pattern.name} (${match.compliance.level})`);
        report.push(`**Compliance Score:** ${match.compliance.score}/100`);
        report.push(`**Level:** ${match.pattern.level}`);
        report.push(match.pattern.description);
        
        if (match.violations.length > 0) {
          report.push('\n**Violations Found:**');
          match.violations.forEach(violation => {
            const lineInfo = violation.line ? ` (Line ${violation.line})` : '';
            report.push(`- **${violation.severity.toUpperCase()}**${lineInfo}: ${violation.message}`);
            if (violation.fix) {
              report.push(`  *Fix:* ${violation.fix}`);
            }
          });
        }
        
        if (match.suggestions.length > 0) {
          report.push('\n**Suggestions:**');
          match.suggestions.forEach(suggestion => report.push(`- ${suggestion}`));
        }
        
        report.push('');
      }
    }

    return report.join('\n');
  }
}

export default StylePatternsAnalyzer;