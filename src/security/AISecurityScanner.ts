import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface AISecurityVulnerability {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  file: string;
  line: number;
  code: string;
  remediation: string;
  references: string[];
  mlRisk: 'high' | 'medium' | 'low';
  impactArea: string[];
}

export interface AISystemAnalysis {
  hasMLModels: boolean;
  modelTypes: string[];
  dataProcessing: string[];
  aiLibraries: string[];
  endpoints: string[];
  vulnerabilities: AISecurityVulnerability[];
}

export interface AIScanResult {
  vulnerabilities: AISecurityVulnerability[];
  analysis: AISystemAnalysis;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    categories: Map<string, number>;
  };
  recommendations: string[];
}

export class AISecurityScanner {
  private astParser: ASTParser;
  private aiPatterns: Map<string, any> = new Map();
  private mlLibraries: Set<string> = new Set();
  private dangerousAIPatterns: Map<string, RegExp> = new Map();

  constructor() {
    this.astParser = new ASTParser();
    this.initializeAISecurityPatterns();
    this.initializeMLLibraries();
    this.initializeDangerousPatterns();
  }

  private initializeAISecurityPatterns(): void {
    // Model Security Patterns
    this.aiPatterns.set('model_security', {
      title: 'Model Security Issues',
      patterns: [
        'insecure_model_loading',
        'model_injection',
        'model_extraction',
        'adversarial_vulnerability'
      ],
      scanners: [
        this.scanModelSecurity.bind(this)
      ]
    });

    // Data Poisoning Patterns
    this.aiPatterns.set('data_poisoning', {
      title: 'Data Poisoning Vulnerabilities',
      patterns: [
        'untrusted_training_data',
        'data_validation_bypass',
        'input_sanitization_missing'
      ],
      scanners: [
        this.scanDataPoisoning.bind(this)
      ]
    });

    // Prompt Injection Patterns
    this.aiPatterns.set('prompt_injection', {
      title: 'Prompt Injection Vulnerabilities',
      patterns: [
        'unvalidated_user_prompts',
        'prompt_template_injection',
        'system_prompt_manipulation'
      ],
      scanners: [
        this.scanPromptInjection.bind(this)
      ]
    });

    // AI Model Inference Security
    this.aiPatterns.set('inference_security', {
      title: 'AI Inference Security Issues',
      patterns: [
        'model_inversion_attack',
        'membership_inference',
        'property_inference'
      ],
      scanners: [
        this.scanInferenceSecurity.bind(this)
      ]
    });

    // AI Ethics and Bias
    this.aiPatterns.set('ethics_bias', {
      title: 'AI Ethics and Bias Issues',
      patterns: [
        'biased_training_data',
        'unfair_model_outcomes',
        'discriminatory_features'
      ],
      scanners: [
        this.scanEthicsAndBias.bind(this)
      ]
    });

    // AI Supply Chain Security
    this.aiPatterns.set('supply_chain', {
      title: 'AI Supply Chain Security',
      patterns: [
        'untrusted_model_sources',
        'vulnerable_ai_dependencies',
        'model_tampering'
      ],
      scanners: [
        this.scanSupplyChainSecurity.bind(this)
      ]
    });
  }

  private initializeMLLibraries(): void {
    const libraries = [
      // Python ML/AI libraries
      'tensorflow', 'torch', 'pytorch', 'sklearn', 'scikit-learn',
      'keras', 'numpy', 'pandas', 'opencv', 'transformers',
      'huggingface', 'langchain', 'openai', 'anthropic',
      // JavaScript ML/AI libraries
      '@tensorflow/tfjs', 'ml5', 'brain.js', 'synaptic',
      'natural', 'compromise', 'node-nlp', 'wit-ai',
      // General AI service libraries
      'aws-sdk', 'google-cloud', 'azure-cognitiveservices',
      'replicate', 'cohere', 'pinecone'
    ];

    libraries.forEach(lib => this.mlLibraries.add(lib));
  }

  private initializeDangerousPatterns(): void {
    // Prompt injection patterns
    this.dangerousAIPatterns.set('prompt_injection', 
      /ignore.*previous.*instructions|forget.*instructions|system.*prompt|jailbreak|roleplay.*admin/gi
    );

    // Model extraction patterns
    this.dangerousAIPatterns.set('model_extraction',
      /model\.state_dict|model\.parameters|model\.weights|extract.*model|steal.*model/gi
    );

    // Adversarial attack patterns
    this.dangerousAIPatterns.set('adversarial_attack',
      /adversarial.*attack|fgsm|pgd.*attack|c&w.*attack|deepfool/gi
    );

    // Data poisoning patterns
    this.dangerousAIPatterns.set('data_poisoning',
      /poison.*data|backdoor.*attack|trigger.*pattern|malicious.*samples/gi
    );

    // Bias indicators
    this.dangerousAIPatterns.set('bias_indicators',
      /race|gender|age|religion|ethnicity.*feature|protected.*attribute|demographic.*data/gi
    );
  }

  public async scanFile(filePath: string): Promise<AIScanResult> {
    try {
      logger.info(`Running AI security scan on: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return this.createEmptyResult();
      }

      const result: AIScanResult = {
        vulnerabilities: [],
        analysis: {
          hasMLModels: false,
          modelTypes: [],
          dataProcessing: [],
          aiLibraries: [],
          endpoints: [],
          vulnerabilities: []
        },
        summary: {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          categories: new Map()
        },
        recommendations: []
      };

      // Analyze AI system components
      result.analysis = await this.analyzeAISystem(content, filePath);

      // Skip scanning if no AI/ML components detected
      if (!result.analysis.hasMLModels && result.analysis.aiLibraries.length === 0) {
        return result;
      }

      // Run all AI security scanners
      for (const [category, pattern] of this.aiPatterns) {
        for (const scanner of pattern.scanners) {
          const vulnerabilities = await scanner(content, filePath, category);
          result.vulnerabilities.push(...vulnerabilities);
        }
      }

      // Process results
      this.processResults(result);

      return result;
    } catch (error) {
      logger.error(`Error running AI security scan on ${filePath}:`, error);
      return this.createEmptyResult();
    }
  }

  public async scanDirectory(dirPath: string): Promise<AIScanResult> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const aggregatedResult: AIScanResult = {
      vulnerabilities: [],
      analysis: {
        hasMLModels: false,
        modelTypes: [],
        dataProcessing: [],
        aiLibraries: [],
        endpoints: [],
        vulnerabilities: []
      },
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        categories: new Map()
      },
      recommendations: []
    };
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next', '__pycache__'].includes(entry.name)) {
            continue;
          }
          const subResult = await this.scanDirectory(fullPath);
          this.mergeResults(aggregatedResult, subResult);
        } else if (entry.isFile() && this.isAIRelatedFile(entry.name)) {
          const fileResult = await this.scanFile(fullPath);
          this.mergeResults(aggregatedResult, fileResult);
        }
      }
    } catch (error) {
      logger.error(`Error scanning directory ${dirPath}:`, error);
    }
    
    // Process final results
    this.processResults(aggregatedResult);
    
    return aggregatedResult;
  }

  private async analyzeAISystem(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): Promise<AISystemAnalysis> {
    const analysis: AISystemAnalysis = {
      hasMLModels: false,
      modelTypes: [],
      dataProcessing: [],
      aiLibraries: [],
      endpoints: [],
      vulnerabilities: []
    };

    // Check for AI/ML library imports
    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.ImportDeclaration) {
        const importSource = node.source.value as string;
        if (this.mlLibraries.has(importSource) || this.isAILibrary(importSource)) {
          analysis.aiLibraries.push(importSource);
          analysis.hasMLModels = true;
        }
      }

      // Check for model loading patterns
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        if (this.isModelLoadingCall(code)) {
          analysis.hasMLModels = true;
          analysis.modelTypes.push(this.extractModelType(code));
        }

        if (this.isDataProcessingCall(code)) {
          analysis.dataProcessing.push(this.extractDataProcessingType(code));
        }
      }

      // Check for API endpoints that might be AI-related
      if (node.type === AST_NODE_TYPES.FunctionDeclaration && this.isAIEndpoint(node, filePath)) {
        const functionName = node.id?.name || 'unknown';
        analysis.endpoints.push(functionName);
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);

    return analysis;
  }

  // Model Security Scanner
  private async scanModelSecurity(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    category: string
  ): Promise<AISecurityVulnerability[]> {
    const vulnerabilities: AISecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for insecure model loading
        if (this.hasInsecureModelLoading(code)) {
          vulnerabilities.push({
            id: `ai-model-insecure-${node.loc?.start.line}`,
            category: 'Model Security',
            title: 'Insecure Model Loading',
            description: 'Model loaded from untrusted source without verification',
            severity: VulnerabilitySeverity.HIGH,
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Verify model integrity and load from trusted sources only',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'high',
            impactArea: ['model_integrity', 'supply_chain']
          });
        }

        // Check for model extraction vulnerabilities
        if (this.hasModelExtractionRisk(code)) {
          vulnerabilities.push({
            id: `ai-model-extraction-${node.loc?.start.line}`,
            category: 'Model Security',
            title: 'Model Extraction Risk',
            description: 'Model parameters or architecture may be exposed',
            severity: VulnerabilitySeverity.MEDIUM,
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Implement model protection mechanisms and access controls',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'medium',
            impactArea: ['intellectual_property', 'model_theft']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // Data Poisoning Scanner
  private async scanDataPoisoning(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    category: string
  ): Promise<AISecurityVulnerability[]> {
    const vulnerabilities: AISecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for untrusted data sources
      if (this.hasUntrustedDataSource(line)) {
        vulnerabilities.push({
          id: `ai-data-poison-${index}`,
          category: 'Data Poisoning',
          title: 'Untrusted Training Data Source',
          description: 'Training data loaded from untrusted or unvalidated source',
          severity: VulnerabilitySeverity.HIGH,
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Validate and sanitize all training data sources',
          references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
          mlRisk: 'high',
          impactArea: ['data_integrity', 'model_performance']
        });
      }

      // Check for missing data validation
      if (this.hasMissingDataValidation(line)) {
        vulnerabilities.push({
          id: `ai-data-validation-${index}`,
          category: 'Data Poisoning',
          title: 'Missing Data Validation',
          description: 'Input data processed without proper validation',
          severity: VulnerabilitySeverity.MEDIUM,
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Implement comprehensive data validation and sanitization',
          references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
          mlRisk: 'medium',
          impactArea: ['data_quality', 'model_robustness']
        });
      }
    });

    return vulnerabilities;
  }

  // Prompt Injection Scanner
  private async scanPromptInjection(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    category: string
  ): Promise<AISecurityVulnerability[]> {
    const vulnerabilities: AISecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for unvalidated user prompts
      if (this.hasUnvalidatedUserPrompt(line)) {
        vulnerabilities.push({
          id: `ai-prompt-injection-${index}`,
          category: 'Prompt Injection',
          title: 'Unvalidated User Prompt',
          description: 'User input directly used in AI prompt without validation',
          severity: VulnerabilitySeverity.HIGH,
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Validate and sanitize user inputs before using in prompts',
          references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
          mlRisk: 'high',
          impactArea: ['prompt_manipulation', 'system_compromise']
        });
      }

      // Check for dangerous prompt patterns
      for (const [patternName, pattern] of this.dangerousAIPatterns) {
        if (pattern.test(line) && patternName === 'prompt_injection') {
          vulnerabilities.push({
            id: `ai-dangerous-prompt-${index}`,
            category: 'Prompt Injection',
            title: 'Dangerous Prompt Pattern',
            description: 'Code contains patterns associated with prompt injection attacks',
            severity: VulnerabilitySeverity.MEDIUM,
            file: filePath,
            line: index + 1,
            code: line.trim(),
            remediation: 'Review and sanitize prompt templates',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'medium',
            impactArea: ['prompt_security', 'system_integrity']
          });
        }
      }
    });

    return vulnerabilities;
  }

  // AI Inference Security Scanner
  private async scanInferenceSecurity(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    category: string
  ): Promise<AISecurityVulnerability[]> {
    const vulnerabilities: AISecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for model inference without rate limiting
        if (this.isModelInferenceCall(code) && !this.hasRateLimit(code)) {
          vulnerabilities.push({
            id: `ai-inference-rate-${node.loc?.start.line}`,
            category: 'Inference Security',
            title: 'Unprotected Model Inference',
            description: 'Model inference endpoint lacks rate limiting protection',
            severity: VulnerabilitySeverity.MEDIUM,
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Implement rate limiting for model inference endpoints',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'medium',
            impactArea: ['resource_exhaustion', 'model_abuse']
          });
        }

        // Check for model inversion attack risks
        if (this.hasModelInversionRisk(code)) {
          vulnerabilities.push({
            id: `ai-model-inversion-${node.loc?.start.line}`,
            category: 'Inference Security',
            title: 'Model Inversion Attack Risk',
            description: 'Model may be vulnerable to inversion attacks',
            severity: VulnerabilitySeverity.MEDIUM,
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Implement differential privacy or output perturbation',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'medium',
            impactArea: ['privacy_leakage', 'data_reconstruction']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // AI Ethics and Bias Scanner
  private async scanEthicsAndBias(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    category: string
  ): Promise<AISecurityVulnerability[]> {
    const vulnerabilities: AISecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for potential bias indicators
      const biasPattern = this.dangerousAIPatterns.get('bias_indicators');
      if (biasPattern && biasPattern.test(line) && this.isFeatureSelection(line)) {
        vulnerabilities.push({
          id: `ai-bias-feature-${index}`,
          category: 'Ethics and Bias',
          title: 'Potential Bias in Feature Selection',
          description: 'Feature selection may introduce bias based on protected attributes',
          severity: VulnerabilitySeverity.LOW,
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Review feature selection for fairness and bias implications',
          references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
          mlRisk: 'low',
          impactArea: ['fairness', 'discrimination']
        });
      }

      // Check for missing fairness evaluation
      if (this.hasMissingFairnessEvaluation(line)) {
        vulnerabilities.push({
          id: `ai-fairness-eval-${index}`,
          category: 'Ethics and Bias',
          title: 'Missing Fairness Evaluation',
          description: 'Model evaluation lacks fairness metrics',
          severity: VulnerabilitySeverity.LOW,
          file: filePath,
          line: index + 1,
          code: line.trim(),
          remediation: 'Implement fairness metrics in model evaluation',
          references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
          mlRisk: 'low',
          impactArea: ['model_fairness', 'ethical_ai']
        });
      }
    });

    return vulnerabilities;
  }

  // AI Supply Chain Security Scanner
  private async scanSupplyChainSecurity(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    category: string
  ): Promise<AISecurityVulnerability[]> {
    const vulnerabilities: AISecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      // Check for untrusted model sources
      if (node.type === AST_NODE_TYPES.ImportDeclaration) {
        const importSource = node.source.value as string;
        if (this.isUntrustedModelSource(importSource)) {
          vulnerabilities.push({
            id: `ai-untrusted-source-${node.loc?.start.line}`,
            category: 'Supply Chain Security',
            title: 'Untrusted Model Source',
            description: `Model imported from potentially untrusted source: ${importSource}`,
            severity: VulnerabilitySeverity.MEDIUM,
            file: filePath,
            line: node.loc?.start.line || 0,
            code: this.getNodeCode(node, content.sourceCode),
            remediation: 'Verify model source integrity and use trusted repositories',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'medium',
            impactArea: ['supply_chain', 'model_integrity']
          });
        }
      }

      // Check for vulnerable AI dependencies
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        if (this.hasVulnerableAIDependency(code)) {
          vulnerabilities.push({
            id: `ai-vulnerable-dep-${node.loc?.start.line}`,
            category: 'Supply Chain Security',
            title: 'Vulnerable AI Dependency',
            description: 'Usage of AI library with known vulnerabilities',
            severity: VulnerabilitySeverity.HIGH,
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            remediation: 'Update to secure versions of AI dependencies',
            references: ['https://owasp.org/www-project-ai-security-and-privacy-guide/'],
            mlRisk: 'high',
            impactArea: ['dependency_security', 'system_compromise']
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // Helper methods
  private createEmptyResult(): AIScanResult {
    return {
      vulnerabilities: [],
      analysis: {
        hasMLModels: false,
        modelTypes: [],
        dataProcessing: [],
        aiLibraries: [],
        endpoints: [],
        vulnerabilities: []
      },
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        categories: new Map()
      },
      recommendations: []
    };
  }

  private mergeResults(target: AIScanResult, source: AIScanResult): void {
    target.vulnerabilities.push(...source.vulnerabilities);
    
    // Merge analysis
    target.analysis.hasMLModels = target.analysis.hasMLModels || source.analysis.hasMLModels;
    target.analysis.modelTypes.push(...source.analysis.modelTypes);
    target.analysis.dataProcessing.push(...source.analysis.dataProcessing);
    target.analysis.aiLibraries.push(...source.analysis.aiLibraries);
    target.analysis.endpoints.push(...source.analysis.endpoints);
  }

  private processResults(result: AIScanResult): void {
    // Calculate summary
    result.summary.total = result.vulnerabilities.length;
    result.vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case VulnerabilitySeverity.CRITICAL:
          result.summary.critical++;
          break;
        case VulnerabilitySeverity.HIGH:
          result.summary.high++;
          break;
        case VulnerabilitySeverity.MEDIUM:
          result.summary.medium++;
          break;
        case VulnerabilitySeverity.LOW:
          result.summary.low++;
          break;
      }

      // Count by category
      const count = result.summary.categories.get(vuln.category) || 0;
      result.summary.categories.set(vuln.category, count + 1);
    });

    // Generate recommendations
    result.recommendations = this.generateRecommendations(result);
  }

  private generateRecommendations(result: AIScanResult): string[] {
    const recommendations: string[] = [];

    if (result.summary.critical > 0) {
      recommendations.push(`🚨 Address ${result.summary.critical} critical AI security issues immediately`);
    }

    if (result.summary.high > 0) {
      recommendations.push(`⚠️ Fix ${result.summary.high} high-severity AI security issues`);
    }

    if (result.analysis.hasMLModels) {
      recommendations.push('📊 Implement AI model governance and monitoring');
      recommendations.push('🔒 Consider implementing model protection mechanisms');
    }

    if (result.analysis.aiLibraries.length > 0) {
      recommendations.push('📦 Regularly audit AI dependencies for vulnerabilities');
    }

    if (result.summary.categories.has('Prompt Injection')) {
      recommendations.push('💬 Implement prompt injection protection measures');
    }

    if (result.summary.categories.has('Data Poisoning')) {
      recommendations.push('🧹 Strengthen data validation and sanitization processes');
    }

    if (result.summary.total === 0 && result.analysis.hasMLModels) {
      recommendations.push('✅ AI system appears secure, maintain regular security assessments');
    } else if (result.summary.total === 0) {
      recommendations.push('ℹ️ No AI/ML components detected in this scan');
    }

    return recommendations;
  }

  private isAIRelatedFile(fileName: string): boolean {
    const extensions = ['.py', '.ts', '.tsx', '.js', '.jsx', '.ipynb'];
    const aiKeywords = ['model', 'ml', 'ai', 'neural', 'deep', 'learning', 'inference', 'predict'];
    
    return extensions.some(ext => fileName.endsWith(ext)) &&
           (aiKeywords.some(keyword => fileName.toLowerCase().includes(keyword)) ||
            extensions.some(ext => fileName.endsWith(ext)));
  }

  private getNodeCode(node: TSESTree.Node, sourceCode: string): string {
    if (!node.range) return '';
    return sourceCode.slice(node.range[0], node.range[1]);
  }

  private traverseNode(node: TSESTree.Node, callback: (node: TSESTree.Node) => void): void {
    for (const key in node) {
      const child = (node as any)[key];
      if (child && typeof child === 'object') {
        if (Array.isArray(child)) {
          child.forEach(item => {
            if (item && typeof item === 'object' && item.type) {
              callback(item);
            }
          });
        } else if (child.type) {
          callback(child);
        }
      }
    }
  }

  // Detection helper methods
  private isAILibrary(importSource: string): boolean {
    const aiPatterns = [
      /tensorflow/i, /torch/i, /pytorch/i, /sklearn/i, /keras/i,
      /openai/i, /anthropic/i, /huggingface/i, /langchain/i,
      /transformers/i, /ml5/i, /brain\.js/i, /natural/i
    ];
    
    return aiPatterns.some(pattern => pattern.test(importSource));
  }

  private isModelLoadingCall(code: string): boolean {
    const modelLoadPatterns = [
      /load_model|loadModel/i,
      /from_pretrained|fromPretrained/i,
      /torch\.load|tf\.keras\.models\.load/i,
      /joblib\.load|pickle\.load/i
    ];
    
    return modelLoadPatterns.some(pattern => pattern.test(code));
  }

  private isDataProcessingCall(code: string): boolean {
    const dataPatterns = [
      /read_csv|readCSV/i,
      /fit|transform|predict/i,
      /train_test_split|trainTestSplit/i,
      /preprocess|normalize/i
    ];
    
    return dataPatterns.some(pattern => pattern.test(code));
  }

  private isAIEndpoint(node: TSESTree.FunctionDeclaration, filePath: string): boolean {
    const functionName = node.id?.name?.toLowerCase() || '';
    const aiEndpointPatterns = ['predict', 'inference', 'classify', 'generate', 'complete', 'chat'];
    
    return aiEndpointPatterns.some(pattern => functionName.includes(pattern)) ||
           filePath.includes('/ai/') || filePath.includes('/ml/');
  }

  private extractModelType(code: string): string {
    if (/tensorflow|tf\./i.test(code)) return 'TensorFlow';
    if (/torch|pytorch/i.test(code)) return 'PyTorch';
    if (/sklearn|scikit/i.test(code)) return 'Scikit-learn';
    if (/keras/i.test(code)) return 'Keras';
    if (/transformers/i.test(code)) return 'Transformers';
    return 'Unknown';
  }

  private extractDataProcessingType(code: string): string {
    if (/pandas|pd\./i.test(code)) return 'Pandas';
    if (/numpy|np\./i.test(code)) return 'NumPy';
    if (/csv/i.test(code)) return 'CSV Processing';
    if (/json/i.test(code)) return 'JSON Processing';
    return 'Unknown';
  }

  private hasInsecureModelLoading(code: string): boolean {
    return /load.*http|load.*url|download.*model|fetch.*model/i.test(code) &&
           !/verify|hash|checksum|signature/i.test(code);
  }

  private hasModelExtractionRisk(code: string): boolean {
    return /state_dict|parameters|weights|model\.save|model\.export/i.test(code);
  }

  private hasUntrustedDataSource(line: string): boolean {
    return /read.*http|load.*url|fetch.*data|download.*dataset/i.test(line) &&
           !/trusted|verified|internal/i.test(line);
  }

  private hasMissingDataValidation(line: string): boolean {
    return /(fit|train|predict).*\(.*req\.|input.*req\./i.test(line) &&
           !/validate|sanitize|check|verify/i.test(line);
  }

  private hasUnvalidatedUserPrompt(line: string): boolean {
    return /prompt.*req\.|prompt.*input|template.*req\./i.test(line) &&
           !/validate|sanitize|escape|filter/i.test(line);
  }

  private isModelInferenceCall(code: string): boolean {
    return /predict|inference|forward|generate|complete/i.test(code);
  }

  private hasRateLimit(code: string): boolean {
    return /rateLimit|rate.*limit|throttle|limiter/i.test(code);
  }

  private hasModelInversionRisk(code: string): boolean {
    return /predict.*confidence|predict.*probability|model\.predict/i.test(code) &&
           !/differential.*privacy|noise|perturbation/i.test(code);
  }

  private isFeatureSelection(line: string): boolean {
    return /feature|column|attribute/i.test(line) && /select|choose|include/i.test(line);
  }

  private hasMissingFairnessEvaluation(line: string): boolean {
    return /evaluate|metrics|score/i.test(line) && /model/i.test(line) &&
           !/fairness|bias|equity|demographic/i.test(line);
  }

  private isUntrustedModelSource(importSource: string): boolean {
    const trustedSources = ['@tensorflow', '@huggingface', 'sklearn', 'torch'];
    const untrustedPatterns = [/github\.com\/[^/]+\/[^/]+\.git/, /http:/, /ftp:/];
    
    return !trustedSources.some(trusted => importSource.startsWith(trusted)) &&
           untrustedPatterns.some(pattern => pattern.test(importSource));
  }

  private hasVulnerableAIDependency(code: string): boolean {
    // This would typically check against a vulnerability database
    // For now, we'll check for obviously outdated versions
    const vulnerablePatterns = [
      /tensorflow.*1\./i,
      /torch.*0\./i,
      /sklearn.*0\.[0-9](?:[^0-9]|$)/i
    ];
    
    return vulnerablePatterns.some(pattern => pattern.test(code));
  }
}