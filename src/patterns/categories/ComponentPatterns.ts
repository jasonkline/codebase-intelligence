import { TSESTree } from '@typescript-eslint/types';
import { ASTPattern } from '../PatternLearner';
import PatternMatcher, { MatchResult } from '../PatternMatcher';
import logger from '../../utils/logger';

export interface ComponentPattern {
  name: string;
  description: string;
  category: 'structure' | 'hooks' | 'props' | 'state_management' | 'lifecycle' | 'performance';
  framework: 'react' | 'nextjs' | 'generic';
  examples: string[];
  bestPractices: string[];
  antiPatterns: string[];
}

export interface ComponentPatternMatch {
  pattern: ComponentPattern;
  matchResult: MatchResult;
  componentName?: string;
  componentType: 'functional' | 'class' | 'unknown';
  issues: Array<{
    severity: 'info' | 'warning' | 'error';
    message: string;
    suggestion: string;
    line?: number;
  }>;
  recommendations: string[];
  performance: {
    score: number; // 0-100
    issues: string[];
    suggestions: string[];
  };
}

export class ComponentPatternsAnalyzer {
  private matcher: PatternMatcher;
  private knownPatterns: Map<string, ComponentPattern> = new Map();

  constructor() {
    this.matcher = new PatternMatcher({
      minSimilarity: 0.6,
      ignoreVariableNames: true,
      ignoreLiteralValues: true,
      allowPartialMatches: true
    });

    this.initializeKnownPatterns();
  }

  private initializeKnownPatterns(): void {
    const patterns: ComponentPattern[] = [
      {
        name: 'functionalComponentStructure',
        description: 'Well-structured functional React component',
        category: 'structure',
        framework: 'react',
        examples: [
          'export function ComponentName({ prop1, prop2 }: Props) { ... }',
          'const ComponentName: React.FC<Props> = ({ children }) => { ... }',
          'export default function ComponentName(props: Props) { ... }'
        ],
        bestPractices: [
          'Use TypeScript interfaces for props',
          'Export component as named export when possible',
          'Keep component pure when possible',
          'Use destructuring for props'
        ],
        antiPatterns: [
          'function Component(props) { ... } // No TypeScript types',
          'export default (props) => { ... } // Anonymous export',
          'const Component = (props) => { return <div>{props.data.user.name}</div> } // Deep prop access'
        ]
      },
      {
        name: 'hooksPattern',
        description: 'Proper React hooks usage and ordering',
        category: 'hooks',
        framework: 'react',
        examples: [
          'const [state, setState] = useState(initialValue)',
          'const data = useQuery("key", fetchFn)',
          'useEffect(() => { ... }, [dependencies])',
          'const memoizedValue = useMemo(() => computation, [deps])'
        ],
        bestPractices: [
          'Call hooks at the top level',
          'Order hooks consistently (state, effects, custom)',
          'Use proper dependency arrays',
          'Clean up effects when needed'
        ],
        antiPatterns: [
          'if (condition) { useState(value) } // Conditional hooks',
          'useEffect(() => { ... }) // Missing dependency array',
          'useEffect(() => { ... }, []) // Empty deps when it should have deps'
        ]
      },
      {
        name: 'propsValidation',
        description: 'Proper TypeScript props validation and typing',
        category: 'props',
        framework: 'react',
        examples: [
          'interface Props { id: string; optional?: boolean }',
          'type ComponentProps = { children: React.ReactNode }',
          'const Component: React.FC<Props> = ({ id, optional = false }) => { ... }'
        ],
        bestPractices: [
          'Define interfaces for all props',
          'Use optional properties appropriately',
          'Provide default values for optional props',
          'Use proper React types (ReactNode, ReactElement)'
        ],
        antiPatterns: [
          'function Component(props: any) { ... }',
          'const Component = (props) => { ... } // No types',
          'interface Props { data: object } // Vague types'
        ]
      },
      {
        name: 'stateManagement',
        description: 'Effective local state management patterns',
        category: 'state_management',
        framework: 'react',
        examples: [
          'const [items, setItems] = useState<Item[]>([])',
          'const [state, dispatch] = useReducer(reducer, initialState)',
          'const { data, loading, error } = useQuery(key, fetcher)'
        ],
        bestPractices: [
          'Use useState for simple state',
          'Use useReducer for complex state logic',
          'Keep state as local as possible',
          'Use proper state update patterns'
        ],
        antiPatterns: [
          'setItems(items.push(newItem)) // Mutating state',
          'const [data, setData] = useState({}); setData({ ...data, [key]: value }) // Object state updates',
          'useState(props.initialValue) // Using props as initial state without deps'
        ]
      },
      {
        name: 'organizationContext',
        description: 'Proper organization context usage in multi-tenant apps',
        category: 'state_management',
        framework: 'nextjs',
        examples: [
          'const { organization, user } = useOrganization()',
          'const orgData = useOrgQuery("key", fetcher)',
          'if (!organization) return <Loading />'
        ],
        bestPractices: [
          'Always check for organization context',
          'Use organization-scoped queries',
          'Handle loading and error states',
          'Protect routes with organization checks'
        ],
        antiPatterns: [
          'const data = useQuery("users", fetchUsers) // No org context',
          'if (user.orgId === "acme") { ... } // Hardcoded org check',
          'const Component = () => { const org = useOrganization().organization; ... } // No destructuring'
        ]
      },
      {
        name: 'performanceOptimization',
        description: 'Performance optimization patterns with memoization',
        category: 'performance',
        framework: 'react',
        examples: [
          'const MemoizedComponent = React.memo(Component)',
          'const expensiveValue = useMemo(() => heavyComputation(), [deps])',
          'const handleClick = useCallback(() => { ... }, [deps])',
          'const Component = React.memo(({ data }) => { ... })'
        ],
        bestPractices: [
          'Memoize expensive computations',
          'Use React.memo for pure components',
          'Use useCallback for event handlers passed to children',
          'Profile before optimizing'
        ],
        antiPatterns: [
          'const value = expensiveComputation() // Runs every render',
          'const handleClick = () => { ... } // New function every render',
          'React.memo(() => { ... }) // Unnecessary memoization'
        ]
      }
    ];

    for (const pattern of patterns) {
      this.knownPatterns.set(pattern.name, pattern);
    }
  }

  analyzeComponent(
    node: TSESTree.Node,
    sourceCode: string,
    filePath: string
  ): ComponentPatternMatch[] {
    const matches: ComponentPatternMatch[] = [];

    // Only analyze React component files
    if (!this.isReactComponentFile(filePath, sourceCode)) {
      return matches;
    }

    // Analyze component structure
    if (this.isComponentDeclaration(node)) {
      const structureMatches = this.analyzeComponentStructure(node, sourceCode);
      matches.push(...structureMatches);
    }

    // Analyze hooks usage
    const hooksMatches = this.analyzeHooksUsage(node, sourceCode);
    matches.push(...hooksMatches);

    // Analyze props patterns
    const propsMatches = this.analyzePropsPatterns(node, sourceCode);
    matches.push(...propsMatches);

    // Analyze organization context usage
    const orgMatches = this.analyzeOrganizationContext(node, sourceCode);
    matches.push(...orgMatches);

    // Analyze performance patterns
    const perfMatches = this.analyzePerformancePatterns(node, sourceCode);
    matches.push(...perfMatches);

    return matches;
  }

  private isReactComponentFile(filePath: string, sourceCode: string): boolean {
    // Check file extension
    if (!['.tsx', '.jsx'].some(ext => filePath.endsWith(ext))) {
      return false;
    }

    // Check for React imports or JSX
    return sourceCode.includes('import React') ||
           sourceCode.includes('from "react"') ||
           sourceCode.includes('JSX.Element') ||
           sourceCode.includes('<') && sourceCode.includes('/>');
  }

  private isComponentDeclaration(node: TSESTree.Node): boolean {
    // Function component
    if (node.type === 'FunctionDeclaration' || 
        (node.type === 'VariableDeclaration' && this.isComponentVariable(node))) {
      return true;
    }

    // Export declaration
    if (node.type === 'ExportNamedDeclaration' || node.type === 'ExportDefaultDeclaration') {
      const exported = (node as any).declaration;
      return exported && (
        exported.type === 'FunctionDeclaration' ||
        this.isComponentVariable(exported)
      );
    }

    return false;
  }

  private isComponentVariable(node: TSESTree.Node): boolean {
    if (node.type !== 'VariableDeclaration') return false;
    
    const varDecl = node as TSESTree.VariableDeclaration;
    return varDecl.declarations.some(decl => {
      if (decl.id.type === 'Identifier') {
        const name = (decl.id as TSESTree.Identifier).name;
        // Component names should start with capital letter
        return /^[A-Z]/.test(name);
      }
      return false;
    });
  }

  private analyzeComponentStructure(node: TSESTree.Node, sourceCode: string): ComponentPatternMatch[] {
    const matches: ComponentPatternMatch[] = [];
    const issues: ComponentPatternMatch['issues'] = [];

    let componentName = this.getComponentName(node);
    let componentType: 'functional' | 'class' | 'unknown' = 'unknown';

    // Determine component type
    if (node.type === 'FunctionDeclaration' || this.isFunctionalComponent(node)) {
      componentType = 'functional';
    } else if (this.isClassComponent(node)) {
      componentType = 'class';
    }

    // Check component naming
    if (componentName && !/^[A-Z][a-zA-Z0-9]*$/.test(componentName)) {
      issues.push({
        severity: 'warning',
        message: 'Component name should use PascalCase',
        suggestion: `Rename to ${this.toPascalCase(componentName)}`
      });
    }

    // Check for TypeScript types
    if (!this.hasProperTyping(node, sourceCode)) {
      issues.push({
        severity: 'warning',
        message: 'Component should have proper TypeScript typing',
        suggestion: 'Add interface for props and type annotations'
      });
    }

    // Check for props destructuring
    if (componentType === 'functional' && !this.hasPropsDestructuring(node)) {
      issues.push({
        severity: 'info',
        message: 'Consider destructuring props for better readability',
        suggestion: 'Use ({ prop1, prop2 }: Props) instead of (props: Props)'
      });
    }

    const pattern = this.knownPatterns.get('functionalComponentStructure')!;
    matches.push({
      pattern,
      matchResult: {
        similarity: issues.length === 0 ? 0.9 : Math.max(0.6, 0.9 - issues.length * 0.1),
        differences: [],
        matchedPattern: {} as ASTPattern,
        isPartialMatch: issues.length > 0,
        confidence: 0.8
      },
      componentName,
      componentType,
      issues,
      recommendations: this.generateStructureRecommendations(issues),
      performance: { score: 80, issues: [], suggestions: [] }
    });

    return matches;
  }

  private analyzeHooksUsage(node: TSESTree.Node, sourceCode: string): ComponentPatternMatch[] {
    const matches: ComponentPatternMatch[] = [];
    const issues: ComponentPatternMatch['issues'] = [];

    // Check for hooks calls
    const hooksCalls = this.findHooksCalls(node, sourceCode);
    
    if (hooksCalls.length === 0) {
      return matches; // No hooks to analyze
    }

    // Check hooks ordering
    if (!this.areHooksOrderedProperly(hooksCalls)) {
      issues.push({
        severity: 'warning',
        message: 'Hooks should be ordered consistently (state, effects, custom)',
        suggestion: 'Reorder hooks: useState first, then useEffect, then custom hooks'
      });
    }

    // Check for conditional hooks
    if (this.hasConditionalHooks(node, sourceCode)) {
      issues.push({
        severity: 'error',
        message: 'Hooks should not be called conditionally',
        suggestion: 'Move conditional logic inside hooks, not around them'
      });
    }

    // Check useEffect dependency arrays
    const effectIssues = this.checkEffectDependencies(hooksCalls, sourceCode);
    issues.push(...effectIssues);

    const pattern = this.knownPatterns.get('hooksPattern')!;
    matches.push({
      pattern,
      matchResult: {
        similarity: issues.length === 0 ? 0.85 : Math.max(0.5, 0.85 - issues.length * 0.15),
        differences: [],
        matchedPattern: {} as ASTPattern,
        isPartialMatch: issues.length > 0,
        confidence: 0.8
      },
      componentType: 'functional',
      issues,
      recommendations: this.generateHooksRecommendations(issues),
      performance: this.calculateHooksPerformance(hooksCalls, issues)
    });

    return matches;
  }

  private analyzePropsPatterns(node: TSESTree.Node, sourceCode: string): ComponentPatternMatch[] {
    const matches: ComponentPatternMatch[] = [];
    const issues: ComponentPatternMatch['issues'] = [];

    // Check for props interface
    if (!this.hasPropsInterface(sourceCode)) {
      issues.push({
        severity: 'warning',
        message: 'Component should define a props interface',
        suggestion: 'Create an interface Props { ... } for component props'
      });
    }

    // Check for any types
    if (this.hasAnyTypes(sourceCode)) {
      issues.push({
        severity: 'error',
        message: 'Avoid using "any" type for props',
        suggestion: 'Define specific types for all props'
      });
    }

    // Check for optional props handling
    if (!this.hasProperOptionalPropsHandling(sourceCode)) {
      issues.push({
        severity: 'info',
        message: 'Consider providing default values for optional props',
        suggestion: 'Use default parameters or default values in destructuring'
      });
    }

    if (issues.length > 0) {
      const pattern = this.knownPatterns.get('propsValidation')!;
      matches.push({
        pattern,
        matchResult: {
          similarity: Math.max(0.4, 0.8 - issues.length * 0.2),
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: true,
          confidence: 0.7
        },
        componentType: 'functional',
        issues,
        recommendations: [
          'Define clear TypeScript interfaces for props',
          'Avoid any types in favor of specific types',
          'Handle optional props with default values'
        ],
        performance: { score: 70, issues: [], suggestions: [] }
      });
    }

    return matches;
  }

  private analyzeOrganizationContext(node: TSESTree.Node, sourceCode: string): ComponentPatternMatch[] {
    const matches: ComponentPatternMatch[] = [];
    const issues: ComponentPatternMatch['issues'] = [];

    // Check if component uses organization context
    const usesOrgContext = sourceCode.includes('useOrganization');
    const hasDataFetching = sourceCode.includes('useQuery') || 
                           sourceCode.includes('useMutation') ||
                           sourceCode.includes('fetch');

    if (hasDataFetching && !usesOrgContext) {
      issues.push({
        severity: 'warning',
        message: 'Component fetches data but may not use organization context',
        suggestion: 'Use useOrganization() hook to ensure proper tenant isolation'
      });
    }

    // Check for hardcoded organization references
    if (this.hasHardcodedOrgReferences(sourceCode)) {
      issues.push({
        severity: 'error',
        message: 'Component contains hardcoded organization references',
        suggestion: 'Use organization context instead of hardcoded values'
      });
    }

    if (usesOrgContext || issues.length > 0) {
      const pattern = this.knownPatterns.get('organizationContext')!;
      matches.push({
        pattern,
        matchResult: {
          similarity: issues.length === 0 ? 0.9 : 0.5,
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: issues.length > 0,
          confidence: 0.8
        },
        componentType: 'functional',
        issues,
        recommendations: issues.length === 0 
          ? ['Continue using proper organization context']
          : ['Add organization context usage', 'Remove hardcoded organization references'],
        performance: { score: 85, issues: [], suggestions: [] }
      });
    }

    return matches;
  }

  private analyzePerformancePatterns(node: TSESTree.Node, sourceCode: string): ComponentPatternMatch[] {
    const matches: ComponentPatternMatch[] = [];
    const issues: ComponentPatternMatch['issues'] = [];
    const suggestions: string[] = [];

    // Check for memoization opportunities
    if (this.hasExpensiveComputations(sourceCode) && !this.usesMemo(sourceCode)) {
      issues.push({
        severity: 'info',
        message: 'Component has expensive computations that could be memoized',
        suggestion: 'Use useMemo() for expensive calculations'
      });
      suggestions.push('Add useMemo() for expensive computations');
    }

    // Check for callback optimization
    if (this.hasEventHandlers(sourceCode) && !this.usesCallback(sourceCode)) {
      issues.push({
        severity: 'info',
        message: 'Event handlers could be optimized with useCallback',
        suggestion: 'Use useCallback() for event handlers passed to child components'
      });
      suggestions.push('Add useCallback() for event handlers');
    }

    // Check for React.memo usage
    if (this.shouldUseMemo(sourceCode) && !this.isMemoed(sourceCode)) {
      issues.push({
        severity: 'info',
        message: 'Component could benefit from React.memo',
        suggestion: 'Wrap component with React.memo for performance'
      });
      suggestions.push('Consider using React.memo()');
    }

    const performanceScore = this.calculatePerformanceScore(sourceCode, issues);

    if (issues.length > 0 || this.hasPerformanceOptimizations(sourceCode)) {
      const pattern = this.knownPatterns.get('performanceOptimization')!;
      matches.push({
        pattern,
        matchResult: {
          similarity: performanceScore > 70 ? 0.8 : 0.5,
          differences: [],
          matchedPattern: {} as ASTPattern,
          isPartialMatch: issues.length > 0,
          confidence: 0.7
        },
        componentType: 'functional',
        issues,
        recommendations: suggestions.length > 0 ? suggestions : ['Component has good performance patterns'],
        performance: {
          score: performanceScore,
          issues: issues.map(i => i.message),
          suggestions
        }
      });
    }

    return matches;
  }

  // Helper methods
  private getComponentName(node: TSESTree.Node): string | undefined {
    if (node.type === 'FunctionDeclaration') {
      return (node as TSESTree.FunctionDeclaration).id?.name;
    }
    
    if (node.type === 'VariableDeclaration') {
      const decl = (node as TSESTree.VariableDeclaration).declarations[0];
      if (decl.id.type === 'Identifier') {
        return (decl.id as TSESTree.Identifier).name;
      }
    }

    return undefined;
  }

  private isFunctionalComponent(node: TSESTree.Node): boolean {
    // Check if it's a variable declaration with arrow function
    if (node.type === 'VariableDeclaration') {
      const decl = (node as TSESTree.VariableDeclaration).declarations[0];
      return decl.init?.type === 'ArrowFunctionExpression';
    }
    return false;
  }

  private isClassComponent(node: TSESTree.Node): boolean {
    return node.type === 'ClassDeclaration';
  }

  private hasProperTyping(node: TSESTree.Node, sourceCode: string): boolean {
    return sourceCode.includes('interface ') || 
           sourceCode.includes('type ') ||
           sourceCode.includes(': React.FC') ||
           sourceCode.includes(': Props');
  }

  private hasPropsDestructuring(node: TSESTree.Node): boolean {
    // This would require more detailed AST analysis
    // For now, we'll use a simplified check
    return true; // Placeholder
  }

  private findHooksCalls(node: TSESTree.Node, sourceCode: string): string[] {
    const hookPatterns = [
      /use[A-Z]\w+/g
    ];
    
    const hooks: string[] = [];
    for (const pattern of hookPatterns) {
      const matches = sourceCode.match(pattern);
      if (matches) {
        hooks.push(...matches);
      }
    }
    
    return [...new Set(hooks)]; // Remove duplicates
  }

  private areHooksOrderedProperly(hooks: string[]): boolean {
    // Simplified check - in practice, would need position analysis
    return true; // Placeholder
  }

  private hasConditionalHooks(node: TSESTree.Node, sourceCode: string): boolean {
    // Look for hooks inside if statements or loops
    return /if\s*\([^)]+\)\s*{[^}]*use[A-Z]/.test(sourceCode) ||
           /for\s*\([^)]+\)\s*{[^}]*use[A-Z]/.test(sourceCode);
  }

  private checkEffectDependencies(hooks: string[], sourceCode: string): ComponentPatternMatch['issues'] {
    const issues: ComponentPatternMatch['issues'] = [];
    
    // Check for useEffect without dependency array
    if (hooks.includes('useEffect') && !sourceCode.includes('], [')) {
      issues.push({
        severity: 'warning',
        message: 'useEffect should have a dependency array',
        suggestion: 'Add dependency array to useEffect'
      });
    }

    return issues;
  }

  private hasPropsInterface(sourceCode: string): boolean {
    return sourceCode.includes('interface Props') || 
           sourceCode.includes('type Props') ||
           sourceCode.includes('interface ') && sourceCode.includes('Props');
  }

  private hasAnyTypes(sourceCode: string): boolean {
    return sourceCode.includes(': any') || sourceCode.includes('<any>');
  }

  private hasProperOptionalPropsHandling(sourceCode: string): boolean {
    return sourceCode.includes('= ') || sourceCode.includes('?.');
  }

  private hasHardcodedOrgReferences(sourceCode: string): boolean {
    return /["'][\w-]+-org["']/.test(sourceCode) ||
           /["'][\w-]+-corp["']/.test(sourceCode) ||
           /orgId\s*===\s*["'][\w-]+["']/.test(sourceCode);
  }

  private hasExpensiveComputations(sourceCode: string): boolean {
    return sourceCode.includes('.filter(') ||
           sourceCode.includes('.map(') ||
           sourceCode.includes('.reduce(') ||
           sourceCode.includes('.sort(');
  }

  private usesMemo(sourceCode: string): boolean {
    return sourceCode.includes('useMemo(');
  }

  private hasEventHandlers(sourceCode: string): boolean {
    return sourceCode.includes('onClick') ||
           sourceCode.includes('onChange') ||
           sourceCode.includes('onSubmit') ||
           sourceCode.includes('const handle');
  }

  private usesCallback(sourceCode: string): boolean {
    return sourceCode.includes('useCallback(');
  }

  private shouldUseMemo(sourceCode: string): boolean {
    // Simple heuristic - components with complex props or children
    return sourceCode.includes('children') && sourceCode.length > 1000;
  }

  private isMemoed(sourceCode: string): boolean {
    return sourceCode.includes('React.memo(') || sourceCode.includes('memo(');
  }

  private hasPerformanceOptimizations(sourceCode: string): boolean {
    return this.usesMemo(sourceCode) || this.usesCallback(sourceCode) || this.isMemoed(sourceCode);
  }

  private calculatePerformanceScore(sourceCode: string, issues: ComponentPatternMatch['issues']): number {
    let score = 100;
    
    // Deduct points for performance issues
    score -= issues.length * 15;
    
    // Add points for optimizations
    if (this.usesMemo(sourceCode)) score += 10;
    if (this.usesCallback(sourceCode)) score += 10;
    if (this.isMemoed(sourceCode)) score += 10;
    
    return Math.max(0, Math.min(100, score));
  }

  private calculateHooksPerformance(hooks: string[], issues: ComponentPatternMatch['issues']): ComponentPatternMatch['performance'] {
    const score = Math.max(50, 90 - issues.length * 10);
    const performanceIssues = issues.filter(i => i.severity === 'error').map(i => i.message);
    const suggestions = issues.map(i => i.suggestion);
    
    return { score, issues: performanceIssues, suggestions };
  }

  private toPascalCase(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  private generateStructureRecommendations(issues: ComponentPatternMatch['issues']): string[] {
    const recommendations: string[] = [];
    
    if (issues.some(i => i.message.includes('PascalCase'))) {
      recommendations.push('Use PascalCase for component names');
    }
    
    if (issues.some(i => i.message.includes('TypeScript'))) {
      recommendations.push('Add proper TypeScript typing for props and state');
    }
    
    if (issues.some(i => i.message.includes('destructuring'))) {
      recommendations.push('Use props destructuring for better readability');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('Component structure follows best practices');
    }
    
    return recommendations;
  }

  private generateHooksRecommendations(issues: ComponentPatternMatch['issues']): string[] {
    const recommendations: string[] = [];
    
    if (issues.some(i => i.message.includes('order'))) {
      recommendations.push('Follow consistent hooks ordering');
    }
    
    if (issues.some(i => i.message.includes('conditional'))) {
      recommendations.push('Never call hooks conditionally');
    }
    
    if (issues.some(i => i.message.includes('dependency'))) {
      recommendations.push('Always provide correct dependency arrays for useEffect');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('Hooks usage follows React best practices');
    }
    
    return recommendations;
  }

  getKnownPatterns(): Map<string, ComponentPattern> {
    return this.knownPatterns;
  }

  addCustomPattern(pattern: ComponentPattern): void {
    this.knownPatterns.set(pattern.name, pattern);
    logger.info(`Added custom component pattern: ${pattern.name}`);
  }

  generateComponentReport(matches: ComponentPatternMatch[]): string {
    const report = ['# Component Pattern Analysis Report\n'];
    
    const byCategory = new Map<string, ComponentPatternMatch[]>();
    for (const match of matches) {
      const category = match.pattern.category;
      if (!byCategory.has(category)) {
        byCategory.set(category, []);
      }
      byCategory.get(category)!.push(match);
    }

    for (const [category, categoryMatches] of byCategory) {
      report.push(`## ${category.replace('_', ' ').toUpperCase()}\n`);
      
      for (const match of categoryMatches) {
        report.push(`### ${match.pattern.name}`);
        if (match.componentName) {
          report.push(`**Component:** ${match.componentName} (${match.componentType})`);
        }
        report.push(`**Performance Score:** ${match.performance.score}/100`);
        report.push(match.pattern.description);
        
        if (match.issues.length > 0) {
          report.push('\n**Issues Found:**');
          match.issues.forEach(issue => {
            report.push(`- **${issue.severity.toUpperCase()}:** ${issue.message}`);
            report.push(`  *Suggestion:* ${issue.suggestion}`);
          });
        }
        
        if (match.performance.suggestions.length > 0) {
          report.push('\n**Performance Suggestions:**');
          match.performance.suggestions.forEach(suggestion => report.push(`- ${suggestion}`));
        }
        
        if (match.recommendations.length > 0) {
          report.push('\n**Recommendations:**');
          match.recommendations.forEach(rec => report.push(`- ${rec}`));
        }
        
        report.push('');
      }
    }

    return report.join('\n');
  }
}

export default ComponentPatternsAnalyzer;