import { parse } from '@typescript-eslint/typescript-estree';
import { TSESTree } from '@typescript-eslint/typescript-estree';
import { readFileSync } from 'fs';
import { extname } from 'path';
import logger from '../utils/logger';

export interface ParsedSymbol {
  id?: string;
  name: string;
  kind: string;
  type?: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  columnStart: number;
  columnEnd: number;
  parentSymbolId?: number;
  signature?: string;
  docComment?: string;
  visibility?: string;
  isExported: boolean;
  children?: ParsedSymbol[];
}

export interface ParsedImport {
  source: string;
  specifiers: {
    name: string;
    alias?: string;
    isDefault: boolean;
    isNamespace: boolean;
  }[];
  lineStart: number;
  lineEnd: number;
}

export interface ParsedExport {
  name?: string;
  source?: string;
  isDefault: boolean;
  lineStart: number;
  lineEnd: number;
}

export interface ParsedFile {
  filePath: string;
  symbols: ParsedSymbol[];
  imports: ParsedImport[];
  exports: ParsedExport[];
  comments: string[];
  language: string;
  ast: TSESTree.Program;
  sourceCode: string;
}

export class ASTParser {
  private sourceCode: string = '';
  private filePath: string = '';

  constructor() {}

  parseFile(filePath: string): ParsedFile | null {
    try {
      this.filePath = filePath;
      this.sourceCode = readFileSync(filePath, 'utf-8');
      
      const language = this.detectLanguage(filePath);
      
      const ast = parse(this.sourceCode, {
        loc: true,
        range: true,
        tokens: false,
        comments: true,
        jsx: language === 'tsx',
        useJSXTextNode: true,
        errorOnUnknownASTType: false,
        errorOnTypeScriptSyntacticAndSemanticIssues: false,
        allowInvalidAST: true,
      });

      const symbols = this.extractSymbols(ast);
      const imports = this.extractImports(ast);
      const exports = this.extractExports(ast);
      const comments = this.extractComments(ast);

      return {
        filePath,
        symbols,
        imports,
        exports,
        comments,
        language,
        ast,
        sourceCode: this.sourceCode
      };
    } catch (error) {
      logger.error(`Failed to parse file ${filePath}:`, error);
      return null;
    }
  }

  private detectLanguage(filePath: string): string {
    const ext = extname(filePath).toLowerCase();
    switch (ext) {
      case '.ts':
        return 'typescript';
      case '.tsx':
        return 'tsx';
      case '.js':
        return 'javascript';
      case '.jsx':
        return 'jsx';
      default:
        return 'unknown';
    }
  }

  private extractSymbols(ast: TSESTree.Program): ParsedSymbol[] {
    const symbols: ParsedSymbol[] = [];
    
    const visit = (node: TSESTree.Node, parentSymbol?: ParsedSymbol) => {
      let currentSymbol: ParsedSymbol | undefined;

      switch (node.type) {
        case 'FunctionDeclaration':
          currentSymbol = this.processFunctionDeclaration(node);
          break;
        case 'VariableDeclarator':
          if (node.id.type === 'Identifier') {
            currentSymbol = this.processVariableDeclarator(node);
          }
          break;
        case 'ClassDeclaration':
          currentSymbol = this.processClassDeclaration(node);
          break;
        case 'TSInterfaceDeclaration':
          currentSymbol = this.processInterfaceDeclaration(node as any);
          break;
        case 'TSTypeAliasDeclaration':
          currentSymbol = this.processTypeAliasDeclaration(node as any);
          break;
        case 'TSEnumDeclaration':
          currentSymbol = this.processEnumDeclaration(node as any);
          break;
        case 'MethodDefinition':
          currentSymbol = this.processMethodDefinition(node);
          break;
        case 'ArrowFunctionExpression':
        case 'FunctionExpression':
          // These are handled by their parent nodes (like VariableDeclarator)
          break;
      }

      if (currentSymbol) {
        if (parentSymbol) {
          currentSymbol.parentSymbolId = symbols.indexOf(parentSymbol);
          if (!parentSymbol.children) {
            parentSymbol.children = [];
          }
          parentSymbol.children.push(currentSymbol);
        }
        symbols.push(currentSymbol);
      }

      // Recursively visit child nodes
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(item => {
              if (item && typeof item === 'object' && item.type) {
                visit(item, currentSymbol || parentSymbol);
              }
            });
          } else if (child.type) {
            visit(child, currentSymbol || parentSymbol);
          }
        }
      }
    };

    ast.body.forEach(node => visit(node));
    return symbols;
  }

  private processFunctionDeclaration(node: TSESTree.FunctionDeclaration): ParsedSymbol | undefined {
    if (!node.id || !node.loc) return undefined;

    const signature = this.getFunctionSignature(node);
    const docComment = this.getLeadingComment(node);

    return {
      name: node.id.name,
      kind: 'function',
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      signature,
      docComment,
      isExported: this.isExported(node),
    };
  }

  private processVariableDeclarator(node: TSESTree.VariableDeclarator): ParsedSymbol | undefined {
    if (node.id.type !== 'Identifier' || !node.loc) return undefined;

    let kind = 'variable';
    let signature: string | undefined;

    // Check if it's a function
    if (node.init) {
      if (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression') {
        kind = 'function';
        signature = this.getFunctionSignature(node.init);
      }
    }

    const docComment = this.getLeadingComment(node);

    return {
      name: node.id.name,
      kind,
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      signature,
      docComment,
      isExported: this.isExported(node),
    };
  }

  private processClassDeclaration(node: TSESTree.ClassDeclaration): ParsedSymbol | undefined {
    if (!node.id || !node.loc) return undefined;

    const docComment = this.getLeadingComment(node);

    return {
      name: node.id.name,
      kind: 'class',
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      docComment,
      isExported: this.isExported(node),
    };
  }

  private processInterfaceDeclaration(node: TSESTree.TSInterfaceDeclaration): ParsedSymbol | undefined {
    if (!node.loc) return undefined;

    const docComment = this.getLeadingComment(node);

    return {
      name: node.id.name,
      kind: 'interface',
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      docComment,
      isExported: this.isExported(node),
    };
  }

  private processTypeAliasDeclaration(node: TSESTree.TSTypeAliasDeclaration): ParsedSymbol | undefined {
    if (!node.loc) return undefined;

    const docComment = this.getLeadingComment(node);

    return {
      name: node.id.name,
      kind: 'type',
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      docComment,
      isExported: this.isExported(node),
    };
  }

  private processEnumDeclaration(node: TSESTree.TSEnumDeclaration): ParsedSymbol | undefined {
    if (!node.loc) return undefined;

    const docComment = this.getLeadingComment(node);

    return {
      name: node.id.name,
      kind: 'enum',
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      docComment,
      isExported: this.isExported(node),
    };
  }

  private processMethodDefinition(node: TSESTree.MethodDefinition): ParsedSymbol | undefined {
    if (node.key.type !== 'Identifier' || !node.loc) return undefined;

    const signature = this.getFunctionSignature(node.value);
    const docComment = this.getLeadingComment(node);
    const visibility = this.getVisibility(node);

    return {
      name: node.key.name,
      kind: node.kind === 'constructor' ? 'constructor' : 'method',
      filePath: this.filePath,
      lineStart: node.loc.start.line,
      lineEnd: node.loc.end.line,
      columnStart: node.loc.start.column,
      columnEnd: node.loc.end.column,
      signature,
      docComment,
      visibility,
      isExported: false, // Methods are not directly exported
    };
  }

  private getFunctionSignature(node: any): string {
    const params = node.params.map((param: any) => {
      if (param.type === 'Identifier') {
        return param.name;
      } else if (param.type === 'RestElement' && param.argument.type === 'Identifier') {
        return `...${param.argument.name}`;
      }
      return 'param';
    }).join(', ');

    return `(${params})`;
  }

  private getLeadingComment(node: TSESTree.Node): string | undefined {
    // This is a simplified version - in a full implementation,
    // you'd need to access the comments from the parser options
    return undefined;
  }

  private getVisibility(node: TSESTree.MethodDefinition): string {
    // Check for TypeScript access modifiers
    if (node.accessibility) {
      return node.accessibility;
    }
    return 'public';
  }

  private isExported(node: TSESTree.Node): boolean {
    // Check if node is part of an export declaration
    let parent = (node as any).parent;
    while (parent) {
      if (parent.type === 'ExportNamedDeclaration' || parent.type === 'ExportDefaultDeclaration') {
        return true;
      }
      parent = parent.parent;
    }
    return false;
  }

  private extractImports(ast: TSESTree.Program): ParsedImport[] {
    const imports: ParsedImport[] = [];

    ast.body.forEach(node => {
      if (node.type === 'ImportDeclaration' && node.loc) {
        const specifiers = node.specifiers.map(spec => {
          if (spec.type === 'ImportDefaultSpecifier') {
            return {
              name: spec.local.name,
              isDefault: true,
              isNamespace: false,
            };
          } else if (spec.type === 'ImportNamespaceSpecifier') {
            return {
              name: spec.local.name,
              isDefault: false,
              isNamespace: true,
            };
          } else if (spec.type === 'ImportSpecifier') {
            return {
              name: (spec.imported as any).name,
              alias: spec.local.name !== (spec.imported as any).name ? spec.local.name : undefined,
              isDefault: false,
              isNamespace: false,
            };
          }
          return {
            name: 'unknown',
            isDefault: false,
            isNamespace: false,
          };
        });

        imports.push({
          source: node.source.value as string,
          specifiers,
          lineStart: node.loc.start.line,
          lineEnd: node.loc.end.line,
        });
      }
    });

    return imports;
  }

  private extractExports(ast: TSESTree.Program): ParsedExport[] {
    const exports: ParsedExport[] = [];

    ast.body.forEach(node => {
      if (node.loc) {
        if (node.type === 'ExportDefaultDeclaration') {
          exports.push({
            isDefault: true,
            lineStart: node.loc.start.line,
            lineEnd: node.loc.end.line,
          });
        } else if (node.type === 'ExportNamedDeclaration') {
          if (node.specifiers.length > 0) {
            node.specifiers.forEach(spec => {
              if (spec.type === 'ExportSpecifier') {
                exports.push({
                  name: (spec.exported as any).name,
                  isDefault: false,
                  lineStart: node.loc!.start.line,
                  lineEnd: node.loc!.end.line,
                });
              }
            });
          } else if (node.declaration) {
            // Export declaration (export function foo() {})
            if (node.declaration.type === 'FunctionDeclaration' && node.declaration.id) {
              exports.push({
                name: node.declaration.id.name,
                isDefault: false,
                lineStart: node.loc.start.line,
                lineEnd: node.loc.end.line,
              });
            } else if (node.declaration.type === 'ClassDeclaration' && node.declaration.id) {
              exports.push({
                name: node.declaration.id.name,
                isDefault: false,
                lineStart: node.loc.start.line,
                lineEnd: node.loc.end.line,
              });
            }
          }
        }
      }
    });

    return exports;
  }

  private extractComments(ast: TSESTree.Program): string[] {
    // Comments are typically attached to the AST during parsing
    // This is a placeholder - full implementation would extract actual comments
    return [];
  }

  // React-specific helpers
  isReactComponent(symbol: ParsedSymbol): boolean {
    if (symbol.kind === 'function' || symbol.kind === 'variable') {
      // Check if function returns JSX (simplified check)
      return symbol.name.charAt(0) === symbol.name.charAt(0).toUpperCase();
    }
    if (symbol.kind === 'class') {
      // In a full implementation, you'd check if it extends React.Component
      return true;
    }
    return false;
  }

  // Utility method to get the source code of a symbol
  getSymbolSource(symbol: ParsedSymbol): string {
    const lines = this.sourceCode.split('\n');
    return lines.slice(symbol.lineStart - 1, symbol.lineEnd).join('\n');
  }
}

export default ASTParser;