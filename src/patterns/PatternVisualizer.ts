import { Pattern, PatternInstance } from '../database/schema';
import { PatternAnalysisResult } from './PatternRegistry';
import logger from '../utils/logger';

export interface PatternVisualization {
  id: string;
  name: string;
  category: string;
  description: string;
  usageCount: number;
  confidence: number;
  examples: Array<{
    file: string;
    line: number;
    code: string;
  }>;
  relationships: Array<{
    relatedPattern: string;
    relationship: 'extends' | 'uses' | 'conflicts' | 'complements';
    strength: number;
  }>;
  documentation: {
    bestPractices: string[];
    antiPatterns: string[];
    whenToUse: string;
    alternatives: string[];
  };
}

export interface PatternReport {
  summary: {
    totalPatterns: number;
    categoryCounts: Record<string, number>;
    mostUsedPattern: string;
    averageConfidence: number;
    coverage: number;
  };
  patterns: PatternVisualization[];
  recommendations: string[];
  htmlReport: string;
  markdownReport: string;
}

export interface PatternDashboard {
  overview: {
    totalPatterns: number;
    totalUsages: number;
    categoriesCount: number;
    avgConfidence: number;
  };
  categoryBreakdown: Array<{
    category: string;
    count: number;
    percentage: number;
    topPatterns: string[];
  }>;
  trendData: Array<{
    date: string;
    newPatterns: number;
    totalUsages: number;
  }>;
  qualityMetrics: {
    highConfidencePatterns: number;
    approvedPatterns: number;
    needsReviewPatterns: number;
  };
}

export class PatternVisualizer {
  constructor() {
    logger.info('PatternVisualizer initialized');
  }

  async generatePatternReport(patterns: Pattern[], instances: PatternInstance[]): Promise<PatternReport> {
    logger.info(`Generating pattern report for ${patterns.length} patterns`);

    const patternVisualizations = await this.createPatternVisualizations(patterns, instances);
    
    const summary = {
      totalPatterns: patterns.length,
      categoryCounts: this.calculateCategoryCounts(patterns),
      mostUsedPattern: this.findMostUsedPattern(patterns, instances),
      averageConfidence: this.calculateAverageConfidence(patterns),
      coverage: this.calculateCoverage(patterns, instances)
    };

    const recommendations = this.generateRecommendations(summary, patternVisualizations);
    
    const htmlReport = this.generateHTMLReport(summary, patternVisualizations);
    const markdownReport = this.generateMarkdownReport(summary, patternVisualizations);

    return {
      summary,
      patterns: patternVisualizations,
      recommendations,
      htmlReport,
      markdownReport
    };
  }

  private async createPatternVisualizations(patterns: Pattern[], instances: PatternInstance[]): Promise<PatternVisualization[]> {
    const visualizations: PatternVisualization[] = [];

    for (const pattern of patterns) {
      const patternInstances = instances.filter(i => i.pattern_id === pattern.id);
      
      const visualization: PatternVisualization = {
        id: pattern.id?.toString() || 'unknown',
        name: pattern.name,
        category: pattern.category,
        description: pattern.description || 'No description available',
        usageCount: patternInstances.length,
        confidence: pattern.confidence_threshold,
        examples: await this.extractExamples(pattern, patternInstances.slice(0, 3)),
        relationships: await this.findRelatedPatterns(pattern, patterns),
        documentation: await this.generatePatternDocumentation(pattern, patternInstances)
      };

      visualizations.push(visualization);
    }

    return visualizations.sort((a, b) => b.usageCount - a.usageCount);
  }

  private async extractExamples(pattern: Pattern, instances: PatternInstance[]): Promise<PatternVisualization['examples']> {
    const examples: PatternVisualization['examples'] = [];

    for (const instance of instances) {
      try {
        // In a real implementation, we'd read the actual file content
        const codeExample = `// Example usage of ${pattern.name}
// File: ${instance.file_path}
// Lines: ${instance.line_start}-${instance.line_end}
// Confidence: ${Math.round(instance.confidence * 100)}%

// Pattern implementation would be shown here
// This is a placeholder for the actual code`;

        examples.push({
          file: instance.file_path,
          line: instance.line_start,
          code: codeExample
        });
      } catch (error) {
        logger.warn(`Failed to extract example for pattern ${pattern.name}:`, error);
      }
    }

    return examples;
  }

  private async findRelatedPatterns(pattern: Pattern, allPatterns: Pattern[]): Promise<PatternVisualization['relationships']> {
    const relationships: PatternVisualization['relationships'] = [];

    // Find patterns in the same category
    const sameCategory = allPatterns.filter(p => 
      p.category === pattern.category && p.id !== pattern.id
    );

    for (const related of sameCategory.slice(0, 3)) {
      relationships.push({
        relatedPattern: related.name,
        relationship: 'complements',
        strength: 0.7
      });
    }

    // Find patterns that might conflict (based on naming)
    if (pattern.name.includes('forbid') || pattern.name.includes('avoid')) {
      const conflicting = allPatterns.filter(p => 
        !p.name.includes('forbid') && !p.name.includes('avoid') && 
        p.category === pattern.category && p.id !== pattern.id
      );

      for (const conflict of conflicting.slice(0, 2)) {
        relationships.push({
          relatedPattern: conflict.name,
          relationship: 'conflicts',
          strength: 0.5
        });
      }
    }

    return relationships;
  }

  private async generatePatternDocumentation(pattern: Pattern, instances: PatternInstance[]): Promise<PatternVisualization['documentation']> {
    // Generate documentation based on pattern analysis
    const bestPractices: string[] = [];
    const antiPatterns: string[] = [];
    let whenToUse = '';
    const alternatives: string[] = [];

    // Generate content based on pattern category and name
    switch (pattern.category) {
      case 'auth':
        bestPractices.push(
          'Always validate authentication before accessing protected resources',
          'Use consistent authentication patterns across all API endpoints',
          'Include proper error handling for authentication failures'
        );
        antiPatterns.push(
          'Hardcoding authentication tokens',
          'Skipping authentication checks for "internal" endpoints',
          'Using weak or predictable session identifiers'
        );
        whenToUse = 'Use this pattern for all API endpoints that require user authentication';
        alternatives.push('JWT-based authentication', 'OAuth 2.0 flows', 'Session-based authentication');
        break;

      case 'api':
        bestPractices.push(
          'Include proper HTTP status codes in responses',
          'Validate all input parameters',
          'Implement comprehensive error handling'
        );
        antiPatterns.push(
          'Returning internal error details to clients',
          'Missing input validation',
          'Inconsistent response formats'
        );
        whenToUse = 'Use this pattern for all API route implementations';
        alternatives.push('GraphQL endpoints', 'tRPC procedures', 'REST alternatives');
        break;

      case 'data_access':
        bestPractices.push(
          'Use authenticated database connections with RLS',
          'Parameterize all database queries',
          'Implement proper error handling for database operations'
        );
        antiPatterns.push(
          'Direct database connections bypassing security',
          'String concatenation in SQL queries',
          'Exposing database errors to users'
        );
        whenToUse = 'Use this pattern for all database access operations';
        alternatives.push('ORM-based access', 'Query builders', 'Database abstraction layers');
        break;

      case 'components':
        bestPractices.push(
          'Use TypeScript interfaces for all props',
          'Follow consistent component structure',
          'Implement proper error boundaries'
        );
        antiPatterns.push(
          'Using any types for props',
          'Deeply nested component structures',
          'Missing key props in lists'
        );
        whenToUse = 'Use this pattern for all React component implementations';
        alternatives.push('Class components', 'Compound components', 'Render props pattern');
        break;

      case 'style':
        bestPractices.push(
          'Follow consistent naming conventions',
          'Use proper TypeScript typing',
          'Maintain consistent code formatting'
        );
        antiPatterns.push(
          'Inconsistent variable naming',
          'Missing type annotations',
          'Mixed indentation styles'
        );
        whenToUse = 'Apply this pattern to all code files for consistency';
        alternatives.push('Different naming conventions', 'Alternative formatting styles');
        break;

      default:
        bestPractices.push('Follow established coding standards');
        antiPatterns.push('Inconsistent implementation patterns');
        whenToUse = 'Use when implementing similar functionality';
    }

    return {
      bestPractices,
      antiPatterns,
      whenToUse,
      alternatives
    };
  }

  private calculateCategoryCounts(patterns: Pattern[]): Record<string, number> {
    const counts: Record<string, number> = {};
    
    for (const pattern of patterns) {
      counts[pattern.category] = (counts[pattern.category] || 0) + 1;
    }

    return counts;
  }

  private findMostUsedPattern(patterns: Pattern[], instances: PatternInstance[]): string {
    const usageCounts = new Map<number, number>();

    for (const instance of instances) {
      const currentCount = usageCounts.get(instance.pattern_id) || 0;
      usageCounts.set(instance.pattern_id, currentCount + 1);
    }

    let maxUsage = 0;
    let mostUsedPatternId = 0;

    for (const [patternId, count] of usageCounts) {
      if (count > maxUsage) {
        maxUsage = count;
        mostUsedPatternId = patternId;
      }
    }

    const mostUsedPattern = patterns.find(p => p.id === mostUsedPatternId);
    return mostUsedPattern?.name || 'No patterns found';
  }

  private calculateAverageConfidence(patterns: Pattern[]): number {
    if (patterns.length === 0) return 0;
    
    const total = patterns.reduce((sum, pattern) => sum + pattern.confidence_threshold, 0);
    return Math.round((total / patterns.length) * 100) / 100;
  }

  private calculateCoverage(patterns: Pattern[], instances: PatternInstance[]): number {
    // Calculate what percentage of the codebase follows established patterns
    // This is a simplified calculation
    const totalInstances = instances.length;
    const approvedPatterns = patterns.filter(p => p.is_approved).length;
    
    if (patterns.length === 0) return 0;
    
    return Math.round((approvedPatterns / patterns.length) * 100);
  }

  private generateRecommendations(summary: PatternReport['summary'], patterns: PatternVisualization[]): string[] {
    const recommendations: string[] = [];

    if (summary.totalPatterns === 0) {
      recommendations.push('No patterns detected - consider establishing coding standards');
      return recommendations;
    }

    if (summary.averageConfidence < 0.7) {
      recommendations.push('Pattern confidence is low - review and refine pattern definitions');
    }

    if (summary.coverage < 50) {
      recommendations.push('Pattern coverage is low - encourage adoption of established patterns');
    }

    const lowUsagePatterns = patterns.filter(p => p.usageCount < 3);
    if (lowUsagePatterns.length > patterns.length * 0.5) {
      recommendations.push('Many patterns have low usage - consider consolidating or removing unused patterns');
    }

    const categoryImbalance = Object.values(summary.categoryCounts);
    const maxCategory = Math.max(...categoryImbalance);
    const minCategory = Math.min(...categoryImbalance);
    
    if (maxCategory > minCategory * 3) {
      recommendations.push('Pattern distribution is uneven - consider developing patterns for underrepresented categories');
    }

    if (recommendations.length === 0) {
      recommendations.push('Pattern usage looks healthy - continue following established patterns');
    }

    return recommendations;
  }

  private generateHTMLReport(summary: PatternReport['summary'], patterns: PatternVisualization[]): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pattern Analysis Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; line-height: 1.6; }
    .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
    .metric { background: white; padding: 15px; border: 1px solid #e9ecef; border-radius: 6px; text-align: center; }
    .metric-value { font-size: 2em; font-weight: bold; color: #0066cc; }
    .metric-label { color: #6c757d; text-transform: uppercase; font-size: 0.8em; }
    .pattern { background: white; border: 1px solid #e9ecef; border-radius: 6px; padding: 20px; margin-bottom: 20px; }
    .pattern-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    .pattern-title { font-size: 1.2em; font-weight: bold; margin: 0; }
    .pattern-category { background: #007bff; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
    .pattern-usage { color: #28a745; font-weight: bold; }
    .code-example { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 15px; margin: 10px 0; overflow-x: auto; }
    .code-example code { font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9em; }
    .best-practices { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 10px 0; }
    .anti-patterns { background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Pattern Analysis Report</h1>
    <p>Generated on ${new Date().toLocaleDateString()}</p>
  </div>

  <div class="summary">
    <div class="metric">
      <div class="metric-value">${summary.totalPatterns}</div>
      <div class="metric-label">Total Patterns</div>
    </div>
    <div class="metric">
      <div class="metric-value">${summary.averageConfidence}</div>
      <div class="metric-label">Avg Confidence</div>
    </div>
    <div class="metric">
      <div class="metric-value">${summary.coverage}%</div>
      <div class="metric-label">Coverage</div>
    </div>
    <div class="metric">
      <div class="metric-value">${Object.keys(summary.categoryCounts).length}</div>
      <div class="metric-label">Categories</div>
    </div>
  </div>

  <h2>Patterns by Category</h2>
  ${Object.entries(summary.categoryCounts).map(([category, count]) => 
    `<p><strong>${category}:</strong> ${count} patterns</p>`
  ).join('')}

  <h2>Pattern Details</h2>
  ${patterns.map(pattern => `
    <div class="pattern">
      <div class="pattern-header">
        <h3 class="pattern-title">${pattern.name}</h3>
        <div>
          <span class="pattern-category">${pattern.category}</span>
          <span class="pattern-usage">${pattern.usageCount} uses</span>
        </div>
      </div>
      
      <p>${pattern.description}</p>
      
      <p><strong>When to use:</strong> ${pattern.documentation.whenToUse}</p>
      
      ${pattern.examples.length > 0 ? `
        <h4>Example Usage</h4>
        <div class="code-example">
          <code>${pattern.examples[0].code.replace(/\n/g, '<br>')}</code>
        </div>
      ` : ''}
      
      <div class="best-practices">
        <h4>Best Practices</h4>
        <ul>
          ${pattern.documentation.bestPractices.map(practice => `<li>${practice}</li>`).join('')}
        </ul>
      </div>
      
      <div class="anti-patterns">
        <h4>Anti-Patterns</h4>
        <ul>
          ${pattern.documentation.antiPatterns.map(antiPattern => `<li>${antiPattern}</li>`).join('')}
        </ul>
      </div>
    </div>
  `).join('')}

</body>
</html>`;
  }

  private generateMarkdownReport(summary: PatternReport['summary'], patterns: PatternVisualization[]): string {
    const report = [
      '# Pattern Analysis Report',
      '',
      `Generated on ${new Date().toLocaleDateString()}`,
      '',
      '## Summary',
      '',
      `- **Total Patterns:** ${summary.totalPatterns}`,
      `- **Average Confidence:** ${summary.averageConfidence}`,
      `- **Coverage:** ${summary.coverage}%`,
      `- **Most Used Pattern:** ${summary.mostUsedPattern}`,
      '',
      '## Patterns by Category',
      ''
    ];

    for (const [category, count] of Object.entries(summary.categoryCounts)) {
      report.push(`- **${category}:** ${count} patterns`);
    }

    report.push('', '## Pattern Details', '');

    for (const pattern of patterns) {
      report.push(
        `### ${pattern.name}`,
        '',
        `**Category:** ${pattern.category} | **Usage:** ${pattern.usageCount} times | **Confidence:** ${Math.round(pattern.confidence * 100)}%`,
        '',
        pattern.description,
        '',
        `**When to use:** ${pattern.documentation.whenToUse}`,
        ''
      );

      if (pattern.examples.length > 0) {
        report.push(
          '**Example Usage:**',
          '',
          '```typescript',
          pattern.examples[0].code,
          '```',
          ''
        );
      }

      report.push(
        '**Best Practices:**',
        ''
      );

      for (const practice of pattern.documentation.bestPractices) {
        report.push(`- ${practice}`);
      }

      report.push(
        '',
        '**Anti-Patterns:**',
        ''
      );

      for (const antiPattern of pattern.documentation.antiPatterns) {
        report.push(`- ${antiPattern}`);
      }

      if (pattern.documentation.alternatives.length > 0) {
        report.push(
          '',
          '**Alternatives:**',
          ''
        );

        for (const alternative of pattern.documentation.alternatives) {
          report.push(`- ${alternative}`);
        }
      }

      report.push('', '---', '');
    }

    return report.join('\n');
  }

  async generateDashboard(analysisResults: PatternAnalysisResult[]): Promise<PatternDashboard> {
    logger.info(`Generating pattern dashboard for ${analysisResults.length} analysis results`);

    // Aggregate data from analysis results
    const allPatterns = analysisResults.flatMap(result => [
      ...result.authMatches.map(m => ({ category: 'auth', name: m.pattern.name })),
      ...result.apiMatches.map(m => ({ category: 'api', name: m.pattern.name })),
      ...result.dataAccessMatches.map(m => ({ category: 'data_access', name: m.pattern.name })),
      ...result.componentMatches.map(m => ({ category: 'components', name: m.pattern.name })),
      ...result.styleMatches.map(m => ({ category: 'style', name: m.pattern.name }))
    ]);

    const categoryCounts = allPatterns.reduce((acc, pattern) => {
      acc[pattern.category] = (acc[pattern.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const totalPatterns = Object.values(categoryCounts).reduce((sum, count) => sum + count, 0);

    const overview = {
      totalPatterns: new Set(allPatterns.map(p => p.name)).size,
      totalUsages: allPatterns.length,
      categoriesCount: Object.keys(categoryCounts).length,
      avgConfidence: analysisResults.reduce((sum, r) => sum + r.overallScore, 0) / analysisResults.length
    };

    const categoryBreakdown = Object.entries(categoryCounts).map(([category, count]) => {
      const categoryPatterns = allPatterns.filter(p => p.category === category);
      const topPatterns = [...new Set(categoryPatterns.map(p => p.name))].slice(0, 3);
      
      return {
        category,
        count,
        percentage: Math.round((count / totalPatterns) * 100),
        topPatterns
      };
    });

    // Mock trend data (in a real implementation, this would come from historical data)
    const trendData = Array.from({ length: 7 }, (_, i) => ({
      date: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      newPatterns: Math.floor(Math.random() * 5),
      totalUsages: Math.floor(Math.random() * 20) + 10
    })).reverse();

    const qualityMetrics = {
      highConfidencePatterns: analysisResults.filter(r => r.overallScore > 80).length,
      approvedPatterns: Math.floor(overview.totalPatterns * 0.8), // Mock data
      needsReviewPatterns: Math.floor(overview.totalPatterns * 0.2) // Mock data
    };

    return {
      overview,
      categoryBreakdown,
      trendData,
      qualityMetrics
    };
  }
}

export default PatternVisualizer;