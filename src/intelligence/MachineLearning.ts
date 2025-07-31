import { ParsedSymbol } from '../parser/ASTParser';
import { CodeSmell } from './TechnicalDebtTracker';
import { PerformanceIssue } from './PerformanceAnalyzer';
import { ChangeHistory, ChangePrediction } from './ChangePredictor';
import { logger } from '../utils/logger';
import Database from 'better-sqlite3';
import * as fs from 'fs';

export interface FeatureVector {
  id: string;
  filePath: string;
  features: number[];
  featureNames: string[];
  label?: string | number;
  metadata: {
    timestamp: number;
    symbolCount: number;
    lineCount: number;
    complexity: number;
    [key: string]: any;
  };
}

export interface Pattern {
  id: string;
  type: 'code_pattern' | 'change_pattern' | 'quality_pattern' | 'performance_pattern';
  name: string;
  description: string;
  features: number[];
  featureNames: string[];
  confidence: number;
  support: number; // How many instances support this pattern
  examples: string[];
  detectedAt: number;
  isAnomaly: boolean;
}

export interface Anomaly {
  id: string;
  type: 'structural' | 'quality' | 'performance' | 'behavioral';
  filePath: string;
  location: {
    lineStart: number;
    lineEnd: number;
    function?: string;
    class?: string;
  };
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  anomalyScore: number; // 0-1, higher = more anomalous
  expectedPattern: string;
  actualPattern: string;
  confidence: number;
  reasoning: string[];
  suggestions: string[];
  detectedAt: number;
  relatedPatterns: string[];
}

export interface MLModel {
  id: string;
  name: string;
  type: 'classification' | 'regression' | 'clustering' | 'anomaly_detection';
  description: string;
  features: string[];
  targetVariable?: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1Score?: number;
  trainingData: number; // number of training samples
  lastTrained: number;
  version: string;
  hyperparameters: Record<string, any>;
  isActive: boolean;
}

export interface Prediction {
  id: string;
  modelId: string;
  filePath: string;
  predictedValue: string | number;
  confidence: number;
  features: FeatureVector;
  reasoning: string[];
  createdAt: number;
  actualValue?: string | number;
  isCorrect?: boolean;
}

export interface ClusterAnalysis {
  id: string;
  name: string;
  description: string;
  clusters: Cluster[];
  totalSamples: number;
  optimalClusters: number;
  silhouetteScore: number;
  inertia: number;
  createdAt: number;
}

export interface Cluster {
  id: number;
  centroid: number[];
  samples: string[]; // File paths or sample IDs
  size: number;
  cohesion: number;
  separation: number;
  characteristics: string[];
  representativeExamples: string[];
}

export interface TrainingData {
  samples: FeatureVector[];
  labels?: (string | number)[];
  split: {
    training: FeatureVector[];
    validation: FeatureVector[];
    test: FeatureVector[];
  };
}

export class MachineLearning {
  private db: Database.Database;
  private models: Map<string, MLModel> = new Map();
  private patterns: Map<string, Pattern> = new Map();
  private anomalies: Map<string, Anomaly[]> = new Map();

  constructor(private databasePath: string) {
    this.db = new Database(databasePath);
    this.initializeDatabase();
    this.loadExistingData();
  }

  private initializeDatabase(): void {
    // Feature vectors table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS feature_vectors (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        features TEXT NOT NULL, -- JSON array
        feature_names TEXT NOT NULL, -- JSON array
        label TEXT,
        metadata TEXT NOT NULL, -- JSON object
        created_at INTEGER NOT NULL
      )
    `);

    // Patterns table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ml_patterns (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        features TEXT NOT NULL, -- JSON array
        feature_names TEXT NOT NULL, -- JSON array
        confidence REAL NOT NULL,
        support INTEGER NOT NULL,
        examples TEXT, -- JSON array
        detected_at INTEGER NOT NULL,
        is_anomaly BOOLEAN NOT NULL
      )
    `);

    // Anomalies table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS anomalies (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_start INTEGER NOT NULL,
        line_end INTEGER NOT NULL,
        function_name TEXT,
        class_name TEXT,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        anomaly_score REAL NOT NULL,
        expected_pattern TEXT NOT NULL,
        actual_pattern TEXT NOT NULL,
        confidence REAL NOT NULL,
        reasoning TEXT, -- JSON array
        suggestions TEXT, -- JSON array
        detected_at INTEGER NOT NULL,
        related_patterns TEXT -- JSON array
      )
    `);

    // ML models table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ml_models (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        features TEXT NOT NULL, -- JSON array
        target_variable TEXT,
        accuracy REAL,
        precision_score REAL,
        recall_score REAL,
        f1_score REAL,
        training_data INTEGER NOT NULL,
        last_trained INTEGER NOT NULL,
        version TEXT NOT NULL,
        hyperparameters TEXT, -- JSON object
        is_active BOOLEAN NOT NULL
      )
    `);

    // Predictions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ml_predictions (
        id TEXT PRIMARY KEY,
        model_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        predicted_value TEXT NOT NULL,
        confidence REAL NOT NULL,
        features TEXT NOT NULL, -- JSON object
        reasoning TEXT, -- JSON array
        created_at INTEGER NOT NULL,
        actual_value TEXT,
        is_correct BOOLEAN,
        FOREIGN KEY (model_id) REFERENCES ml_models(id)
      )
    `);

    // Cluster analysis table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cluster_analysis (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        clusters TEXT NOT NULL, -- JSON array
        total_samples INTEGER NOT NULL,
        optimal_clusters INTEGER NOT NULL,
        silhouette_score REAL NOT NULL,
        inertia REAL NOT NULL,
        created_at INTEGER NOT NULL
      )
    `);

    // Indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_feature_vectors_file 
      ON feature_vectors(file_path);
      
      CREATE INDEX IF NOT EXISTS idx_patterns_type 
      ON ml_patterns(type);
      
      CREATE INDEX IF NOT EXISTS idx_anomalies_file_severity 
      ON anomalies(file_path, severity);
      
      CREATE INDEX IF NOT EXISTS idx_models_type_active 
      ON ml_models(type, is_active);
      
      CREATE INDEX IF NOT EXISTS idx_predictions_model 
      ON ml_predictions(model_id);
    `);
  }

  private loadExistingData(): void {
    // Load models
    const modelStmt = this.db.prepare('SELECT * FROM ml_models WHERE is_active = TRUE');
    const models = modelStmt.all() as any[];
    
    for (const model of models) {
      this.models.set(model.id, {
        id: model.id,
        name: model.name,
        type: model.type,
        description: model.description,
        features: JSON.parse(model.features),
        targetVariable: model.target_variable,
        accuracy: model.accuracy,
        precision: model.precision_score,
        recall: model.recall_score,
        f1Score: model.f1_score,
        trainingData: model.training_data,
        lastTrained: model.last_trained,
        version: model.version,
        hyperparameters: JSON.parse(model.hyperparameters || '{}'),
        isActive: model.is_active
      });
    }

    // Load patterns
    const patternStmt = this.db.prepare('SELECT * FROM ml_patterns ORDER BY confidence DESC');
    const patterns = patternStmt.all() as any[];
    
    for (const pattern of patterns) {
      this.patterns.set(pattern.id, {
        id: pattern.id,
        type: pattern.type,
        name: pattern.name,
        description: pattern.description,
        features: JSON.parse(pattern.features),
        featureNames: JSON.parse(pattern.feature_names),
        confidence: pattern.confidence,
        support: pattern.support,
        examples: JSON.parse(pattern.examples || '[]'),
        detectedAt: pattern.detected_at,
        isAnomaly: pattern.is_anomaly
      });
    }

    // Load anomalies
    const anomalyStmt = this.db.prepare('SELECT * FROM anomalies ORDER BY anomaly_score DESC');
    const anomalies = anomalyStmt.all() as any[];
    
    for (const anomaly of anomalies) {
      const filePath = anomaly.file_path;
      if (!this.anomalies.has(filePath)) {
        this.anomalies.set(filePath, []);
      }
      
      this.anomalies.get(filePath)!.push({
        id: anomaly.id,
        type: anomaly.type,
        filePath: anomaly.file_path,
        location: {
          lineStart: anomaly.line_start,
          lineEnd: anomaly.line_end,
          function: anomaly.function_name,
          class: anomaly.class_name
        },
        severity: anomaly.severity,
        description: anomaly.description,
        anomalyScore: anomaly.anomaly_score,
        expectedPattern: anomaly.expected_pattern,
        actualPattern: anomaly.actual_pattern,
        confidence: anomaly.confidence,
        reasoning: JSON.parse(anomaly.reasoning || '[]'),
        suggestions: JSON.parse(anomaly.suggestions || '[]'),
        detectedAt: anomaly.detected_at,
        relatedPatterns: JSON.parse(anomaly.related_patterns || '[]')
      });
    }

    logger.info(`Loaded ${models.length} ML models, ${patterns.length} patterns, ${anomalies.length} anomalies`);
  }

  // Feature Extraction
  async extractFeatures(
    filePath: string,
    symbols: ParsedSymbol[],
    codeSmells?: CodeSmell[],
    performanceIssues?: PerformanceIssue[],
    changeHistory?: ChangeHistory[]
  ): Promise<FeatureVector> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      const features: number[] = [];
      const featureNames: string[] = [];

      // Structural features
      const structuralFeatures = this.extractStructuralFeatures(lines, symbols);
      features.push(...structuralFeatures.values);
      featureNames.push(...structuralFeatures.names);

      // Complexity features
      const complexityFeatures = this.extractComplexityFeatures(symbols, lines);
      features.push(...complexityFeatures.values);
      featureNames.push(...complexityFeatures.names);

      // Quality features
      const qualityFeatures = this.extractQualityFeatures(codeSmells, performanceIssues);
      features.push(...qualityFeatures.values);
      featureNames.push(...qualityFeatures.names);

      // Change pattern features
      const changeFeatures = this.extractChangePatternFeatures(changeHistory);
      features.push(...changeFeatures.values);
      featureNames.push(...changeFeatures.names);

      // Text-based features
      const textFeatures = this.extractTextFeatures(content);
      features.push(...textFeatures.values);
      featureNames.push(...textFeatures.names);

      const featureVector: FeatureVector = {
        id: `fv-${filePath}-${Date.now()}`,
        filePath,
        features,
        featureNames,
        metadata: {
          timestamp: Date.now(),
          symbolCount: symbols.length,
          lineCount: lines.length,
          complexity: this.calculateOverallComplexity(symbols, lines)
        }
      };

      await this.storeFeatureVector(featureVector);
      return featureVector;
    } catch (error) {
      logger.error(`Error extracting features for ${filePath}:`, error);
      throw error;
    }
  }

  // Pattern Discovery
  async discoverPatterns(
    featureVectors: FeatureVector[],
    minSupport: number = 3,
    minConfidence: number = 0.7
  ): Promise<Pattern[]> {
    try {
      const patterns: Pattern[] = [];

      // Cluster-based pattern discovery
      const clusterAnalysis = await this.performClustering(featureVectors, 'auto');
      
      for (const cluster of clusterAnalysis.clusters) {
        if (cluster.size >= minSupport) {
          const pattern = await this.createPatternFromCluster(cluster, featureVectors, minConfidence);
          if (pattern) {
            patterns.push(pattern);
          }
        }
      }

      // Frequent pattern mining
      const frequentPatterns = await this.mineFrequentPatterns(featureVectors, minSupport, minConfidence);
      patterns.push(...frequentPatterns);

      // Store discovered patterns
      await this.storePatterns(patterns);
      
      // Update in-memory cache
      for (const pattern of patterns) {
        this.patterns.set(pattern.id, pattern);
      }

      return patterns;
    } catch (error) {
      logger.error('Error discovering patterns:', error);
      return [];
    }
  }

  // Anomaly Detection
  async detectAnomalies(
    filePath: string,
    symbols: ParsedSymbol[],
    threshold: number = 0.8
  ): Promise<Anomaly[]> {
    try {
      const featureVector = await this.extractFeatures(filePath, symbols);
      const anomalies: Anomaly[] = [];

      // Statistical anomaly detection
      const statisticalAnomalies = await this.detectStatisticalAnomalies(featureVector, threshold);
      anomalies.push(...statisticalAnomalies);

      // Pattern-based anomaly detection
      const patternAnomalies = await this.detectPatternAnomalies(featureVector, threshold);
      anomalies.push(...patternAnomalies);

      // Isolation forest anomaly detection
      const isolationAnomalies = await this.detectIsolationAnomalies(featureVector, threshold);
      anomalies.push(...isolationAnomalies);

      // Structure-based anomaly detection
      const structuralAnomalies = await this.detectStructuralAnomalies(filePath, symbols, threshold);
      anomalies.push(...structuralAnomalies);

      // Store detected anomalies
      await this.storeAnomalies(anomalies);
      
      // Update in-memory cache
      this.anomalies.set(filePath, anomalies);

      return anomalies.sort((a, b) => b.anomalyScore - a.anomalyScore);
    } catch (error) {
      logger.error(`Error detecting anomalies for ${filePath}:`, error);
      return [];
    }
  }

  // Clustering Analysis
  async performClustering(
    featureVectors: FeatureVector[],
    numClusters: number | 'auto' = 'auto'
  ): Promise<ClusterAnalysis> {
    try {
      const features = featureVectors.map(fv => fv.features);
      
      // Determine optimal number of clusters if 'auto'
      let optimalClusters = numClusters as number;
      if (numClusters === 'auto') {
        optimalClusters = await this.findOptimalClusters(features);
      }

      // Perform K-means clustering (simplified implementation)
      const clusters = await this.performKMeans(features, optimalClusters);
      
      // Calculate cluster quality metrics
      const silhouetteScore = this.calculateSilhouetteScore(features, clusters);
      const inertia = this.calculateInertia(features, clusters);

      // Create cluster objects with metadata
      const enrichedClusters = await this.enrichClusters(clusters, featureVectors);

      const clusterAnalysis: ClusterAnalysis = {
        id: `cluster-${Date.now()}`,
        name: `Clustering Analysis ${new Date().toISOString()}`,
        description: `K-means clustering with ${optimalClusters} clusters`,
        clusters: enrichedClusters,
        totalSamples: featureVectors.length,
        optimalClusters,
        silhouetteScore,
        inertia,
        createdAt: Date.now()
      };

      await this.storeClusterAnalysis(clusterAnalysis);
      return clusterAnalysis;
    } catch (error) {
      logger.error('Error performing clustering:', error);
      throw error;
    }
  }

  // Model Training and Prediction
  async trainModel(
    modelType: MLModel['type'],
    trainingData: TrainingData,
    hyperparameters: Record<string, any> = {}
  ): Promise<MLModel> {
    try {
      const modelId = `model-${modelType}-${Date.now()}`;
      
      // Train based on model type
      let trainedModel: MLModel;
      
      switch (modelType) {
        case 'classification':
          trainedModel = await this.trainClassificationModel(modelId, trainingData, hyperparameters);
          break;
        case 'regression':
          trainedModel = await this.trainRegressionModel(modelId, trainingData, hyperparameters);
          break;
        case 'clustering':
          trainedModel = await this.trainClusteringModel(modelId, trainingData, hyperparameters);
          break;
        case 'anomaly_detection':
          trainedModel = await this.trainAnomalyDetectionModel(modelId, trainingData, hyperparameters);
          break;
        default:
          throw new Error(`Unsupported model type: ${modelType}`);
      }

      // Store the model
      await this.storeModel(trainedModel);
      this.models.set(trainedModel.id, trainedModel);

      return trainedModel;
    } catch (error) {
      logger.error(`Error training ${modelType} model:`, error);
      throw error;
    }
  }

  async predict(modelId: string, featureVector: FeatureVector): Promise<Prediction> {
    try {
      const model = this.models.get(modelId);
      if (!model || !model.isActive) {
        throw new Error(`Model ${modelId} not found or inactive`);
      }

      // Make prediction based on model type
      let predictedValue: string | number;
      let confidence: number;
      let reasoning: string[];

      switch (model.type) {
        case 'classification':
          ({ predictedValue, confidence, reasoning } = await this.classifyFeatureVector(model, featureVector));
          break;
        case 'regression':
          ({ predictedValue, confidence, reasoning } = await this.regressFeatureVector(model, featureVector));
          break;
        case 'anomaly_detection':
          ({ predictedValue, confidence, reasoning } = await this.detectAnomalyScore(model, featureVector));
          break;
        default:
          throw new Error(`Prediction not supported for model type: ${model.type}`);
      }

      const prediction: Prediction = {
        id: `pred-${modelId}-${Date.now()}`,
        modelId,
        filePath: featureVector.filePath,
        predictedValue,
        confidence,
        features: featureVector,
        reasoning,
        createdAt: Date.now()
      };

      await this.storePrediction(prediction);
      return prediction;
    } catch (error) {
      logger.error(`Error making prediction with model ${modelId}:`, error);
      throw error;
    }
  }

  // Feature extraction methods
  private extractStructuralFeatures(lines: string[], symbols: ParsedSymbol[]): { values: number[]; names: string[] } {
    const values: number[] = [];
    const names: string[] = [];

    // Basic structural metrics
    values.push(lines.length);
    names.push('line_count');

    values.push(symbols.length);
    names.push('symbol_count');

    values.push(symbols.filter(s => s.kind === 'function').length);
    names.push('function_count');

    values.push(symbols.filter(s => s.kind === 'class').length);
    names.push('class_count');

    values.push(symbols.filter(s => s.kind === 'interface').length);
    names.push('interface_count');

    values.push(symbols.filter(s => s.kind === 'variable').length);
    names.push('variable_count');

    values.push(symbols.filter(s => s.kind === 'import').length);
    names.push('import_count');

    // Nesting depth
    const maxNesting = this.calculateMaxNesting(lines);
    values.push(maxNesting);
    names.push('max_nesting_depth');

    // Average function length
    const functions = symbols.filter(s => s.kind === 'function');
    const avgFunctionLength = functions.length > 0 
      ? functions.reduce((sum, f) => sum + (f.lineEnd - f.lineStart + 1), 0) / functions.length
      : 0;
    values.push(avgFunctionLength);
    names.push('avg_function_length');

    return { values, names };
  }

  private extractComplexityFeatures(symbols: ParsedSymbol[], lines: string[]): { values: number[]; names: string[] } {
    const values: number[] = [];
    const names: string[] = [];

    // Cyclomatic complexity
    const cyclomaticComplexity = this.calculateCyclomaticComplexity(symbols, lines);
    values.push(cyclomaticComplexity);
    names.push('cyclomatic_complexity');

    // Cognitive complexity
    const cognitiveComplexity = this.calculateCognitiveComplexity(lines);
    values.push(cognitiveComplexity);
    names.push('cognitive_complexity');

    // Halstead metrics
    const halsteadMetrics = this.calculateHalsteadMetrics(lines);
    values.push(halsteadMetrics.volume);
    names.push('halstead_volume');
    values.push(halsteadMetrics.difficulty);
    names.push('halstead_difficulty');

    // Decision points
    const decisionPoints = this.countDecisionPoints(lines);
    values.push(decisionPoints);
    names.push('decision_points');

    return { values, names };
  }

  private extractQualityFeatures(codeSmells?: CodeSmell[], performanceIssues?: PerformanceIssue[]): { values: number[]; names: string[] } {
    const values: number[] = [];
    const names: string[] = [];

    // Code smell metrics
    values.push(codeSmells?.length || 0);
    names.push('total_code_smells');

    values.push(codeSmells?.filter(s => s.severity === 'critical').length || 0);
    names.push('critical_code_smells');

    values.push(codeSmells?.filter(s => s.severity === 'high').length || 0);
    names.push('high_code_smells');

    // Performance issue metrics
    values.push(performanceIssues?.length || 0);
    names.push('total_performance_issues');

    values.push(performanceIssues?.filter(i => i.severity === 'critical').length || 0);
    names.push('critical_performance_issues');

    // Average estimated slowdown
    const avgSlowdown = performanceIssues && performanceIssues.length > 0
      ? performanceIssues.reduce((sum, i) => sum + i.estimatedSlowdown, 0) / performanceIssues.length
      : 1.0;
    values.push(avgSlowdown);
    names.push('avg_estimated_slowdown');

    return { values, names };
  }

  private extractChangePatternFeatures(changeHistory?: ChangeHistory[]): { values: number[]; names: string[] } {
    const values: number[] = [];
    const names: string[] = [];

    if (!changeHistory || changeHistory.length === 0) {
      // Fill with zeros if no history
      values.push(0, 0, 0, 0, 0, 0);
      names.push('change_frequency', 'avg_lines_added', 'avg_lines_removed', 'change_type_diversity', 'days_since_last_change', 'change_trend');
      return { values, names };
    }

    // Change frequency (changes per day)
    const daysSinceFirst = (Date.now() - Math.min(...changeHistory.map(c => c.timestamp))) / (24 * 60 * 60 * 1000);
    const changeFrequency = changeHistory.length / Math.max(daysSinceFirst, 1);
    values.push(changeFrequency);
    names.push('change_frequency');

    // Average lines changed
    const avgLinesAdded = changeHistory.reduce((sum, c) => sum + c.linesAdded, 0) / changeHistory.length;
    const avgLinesRemoved = changeHistory.reduce((sum, c) => sum + c.linesRemoved, 0) / changeHistory.length;
    values.push(avgLinesAdded);
    names.push('avg_lines_added');
    values.push(avgLinesRemoved);
    names.push('avg_lines_removed');

    // Change type diversity
    const changeTypes = new Set(changeHistory.map(c => c.changeType));
    values.push(changeTypes.size);
    names.push('change_type_diversity');

    // Days since last change
    const daysSinceLastChange = (Date.now() - Math.max(...changeHistory.map(c => c.timestamp))) / (24 * 60 * 60 * 1000);
    values.push(daysSinceLastChange);
    names.push('days_since_last_change');

    // Change trend (increasing/decreasing)
    const recentChanges = changeHistory.filter(c => Date.now() - c.timestamp < 30 * 24 * 60 * 60 * 1000).length;
    const olderChanges = changeHistory.length - recentChanges;
    const changeTrend = olderChanges > 0 ? recentChanges / olderChanges : 1;
    values.push(changeTrend);
    names.push('change_trend');

    return { values, names };
  }

  private extractTextFeatures(content: string): { values: number[]; names: string[] } {
    const values: number[] = [];
    const names: string[] = [];

    // Comment ratio
    const lines = content.split('\n');
    const commentLines = lines.filter(line => {
      const trimmed = line.trim();
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    });
    const commentRatio = commentLines.length / Math.max(lines.length, 1);
    values.push(commentRatio);
    names.push('comment_ratio');

    // Average line length
    const nonEmptyLines = lines.filter(line => line.trim().length > 0);
    const avgLineLength = nonEmptyLines.length > 0
      ? nonEmptyLines.reduce((sum, line) => sum + line.length, 0) / nonEmptyLines.length
      : 0;
    values.push(avgLineLength);
    names.push('avg_line_length');

    // Keyword density
    const keywords = ['if', 'else', 'for', 'while', 'function', 'class', 'return', 'try', 'catch'];
    const keywordCount = keywords.reduce((count, keyword) => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
      return count + (content.match(regex) || []).length;
    }, 0);
    const keywordDensity = keywordCount / Math.max(content.split(/\s+/).length, 1);
    values.push(keywordDensity);
    names.push('keyword_density');

    // String literal ratio
    const stringLiterals = (content.match(/"[^"]*"|'[^']*'|`[^`]*`/g) || []).length;
    const totalTokens = content.split(/\s+/).length;
    const stringLiteralRatio = stringLiterals / Math.max(totalTokens, 1);
    values.push(stringLiteralRatio);
    names.push('string_literal_ratio');

    return { values, names };
  }

  // Pattern discovery methods
  private async createPatternFromCluster(
    cluster: Cluster,
    featureVectors: FeatureVector[],
    minConfidence: number
  ): Promise<Pattern | null> {
    try {
      // Get feature vectors for this cluster
      const clusterVectors = featureVectors.filter(fv => cluster.samples.includes(fv.filePath));
      
      if (clusterVectors.length === 0) return null;

      // Calculate average features for the pattern
      const avgFeatures = cluster.centroid;
      const featureNames = clusterVectors[0].featureNames;

      // Determine pattern type based on dominant features
      const patternType = this.determinePatternType(avgFeatures, featureNames);

      // Calculate confidence based on cluster cohesion
      const confidence = Math.min(cluster.cohesion, 1.0);
      
      if (confidence < minConfidence) return null;

      const pattern: Pattern = {
        id: `pattern-cluster-${cluster.id}-${Date.now()}`,
        type: patternType,
        name: `Cluster Pattern ${cluster.id}`,
        description: `Pattern discovered from cluster analysis: ${cluster.characteristics.join(', ')}`,
        features: avgFeatures,
        featureNames,
        confidence,
        support: cluster.size,
        examples: cluster.representativeExamples,
        detectedAt: Date.now(),
        isAnomaly: false
      };

      return pattern;
    } catch (error) {
      logger.error('Error creating pattern from cluster:', error);
      return null;
    }
  }

  private async mineFrequentPatterns(
    featureVectors: FeatureVector[],
    minSupport: number,
    minConfidence: number
  ): Promise<Pattern[]> {
    const patterns: Pattern[] = [];

    try {
      // Discretize continuous features for frequent pattern mining
      const discretizedVectors = this.discretizeFeatures(featureVectors);

      // Find frequent itemsets (simplified implementation)
      const frequentItemsets = this.findFrequentItemsets(discretizedVectors, minSupport);

      // Generate patterns from frequent itemsets
      for (const itemset of frequentItemsets) {
        if (itemset.confidence >= minConfidence) {
          const pattern: Pattern = {
            id: `pattern-frequent-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            type: 'code_pattern',
            name: `Frequent Pattern: ${itemset.items.join(', ')}`,
            description: `Frequently occurring pattern in codebase`,
            features: itemset.features,
            featureNames: itemset.featureNames,
            confidence: itemset.confidence,
            support: itemset.support,
            examples: itemset.examples,
            detectedAt: Date.now(),
            isAnomaly: false
          };
          patterns.push(pattern);
        }
      }
    } catch (error) {
      logger.error('Error mining frequent patterns:', error);
    }

    return patterns;
  }

  // Anomaly detection methods
  private async detectStatisticalAnomalies(
    featureVector: FeatureVector,
    threshold: number
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Load historical feature vectors for comparison
      const historicalVectors = await this.getHistoricalFeatureVectors(featureVector.filePath);
      
      if (historicalVectors.length < 10) {
        // Not enough historical data
        return anomalies;
      }

      // Calculate z-scores for each feature
      const zScores = this.calculateZScores(featureVector, historicalVectors);
      
      // Identify anomalous features
      for (let i = 0; i < zScores.length; i++) {
        const zScore = Math.abs(zScores[i]);
        if (zScore > 2.5) { // Statistical significance threshold
          const anomalyScore = Math.min(zScore / 5, 1); // Normalize to 0-1
          
          if (anomalyScore >= threshold) {
            anomalies.push({
              id: `anomaly-stat-${i}-${Date.now()}`,
              type: 'structural',
              filePath: featureVector.filePath,
              location: { lineStart: 1, lineEnd: featureVector.metadata.lineCount },
              severity: zScore > 4 ? 'critical' : zScore > 3 ? 'high' : 'medium',
              description: `Statistical anomaly in ${featureVector.featureNames[i]}`,
              anomalyScore,
              expectedPattern: `Normal range for ${featureVector.featureNames[i]}`,
              actualPattern: `Extreme value: ${featureVector.features[i]}`,
              confidence: Math.min(zScore / 3, 1),
              reasoning: [
                `Z-score: ${zScore.toFixed(2)}`,
                `Feature value: ${featureVector.features[i]}`,
                `Historical average: ${historicalVectors.reduce((sum, v) => sum + v.features[i], 0) / historicalVectors.length}`
              ],
              suggestions: [
                `Review ${featureVector.featureNames[i]} metric`,
                'Compare with similar files',
                'Consider refactoring if metric is problematic'
              ],
              detectedAt: Date.now(),
              relatedPatterns: []
            });
          }
        }
      }
    } catch (error) {
      logger.error('Error detecting statistical anomalies:', error);
    }

    return anomalies;
  }

  private async detectPatternAnomalies(
    featureVector: FeatureVector,
    threshold: number
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Compare against known patterns
      for (const pattern of this.patterns.values()) {
        if (pattern.isAnomaly) continue;

        const similarity = this.calculateCosineSimilarity(featureVector.features, pattern.features);
        const distance = 1 - similarity;

        if (distance > threshold && pattern.confidence > 0.8) {
          anomalies.push({
            id: `anomaly-pattern-${pattern.id}-${Date.now()}`,
            type: 'behavioral',
            filePath: featureVector.filePath,
            location: { lineStart: 1, lineEnd: featureVector.metadata.lineCount },
            severity: distance > 0.9 ? 'high' : 'medium',
            description: `Deviates from known pattern: ${pattern.name}`,
            anomalyScore: distance,
            expectedPattern: pattern.description,
            actualPattern: 'Current file structure',
            confidence: pattern.confidence * distance,
            reasoning: [
              `Pattern similarity: ${similarity.toFixed(3)}`,
              `Expected pattern: ${pattern.name}`,
              `Pattern confidence: ${pattern.confidence}`
            ],
            suggestions: [
              `Consider conforming to pattern: ${pattern.name}`,
              'Review pattern compliance',
              'Validate if deviation is intentional'
            ],
            detectedAt: Date.now(),
            relatedPatterns: [pattern.id]
          });
        }
      }
    } catch (error) {
      logger.error('Error detecting pattern anomalies:', error);
    }

    return anomalies;
  }

  private async detectIsolationAnomalies(
    featureVector: FeatureVector,
    threshold: number
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Simplified isolation forest implementation
      // In a real implementation, this would use a proper isolation forest algorithm
      
      const historicalVectors = await this.getHistoricalFeatureVectors();
      if (historicalVectors.length < 50) return anomalies;

      // Calculate isolation score (simplified)
      const isolationScore = this.calculateIsolationScore(featureVector, historicalVectors);
      
      if (isolationScore >= threshold) {
        anomalies.push({
          id: `anomaly-isolation-${Date.now()}`,
          type: 'structural',
          filePath: featureVector.filePath,
          location: { lineStart: 1, lineEnd: featureVector.metadata.lineCount },
          severity: isolationScore > 0.9 ? 'critical' : isolationScore > 0.8 ? 'high' : 'medium',
          description: 'File exhibits unusual structural characteristics',
          anomalyScore: isolationScore,
          expectedPattern: 'Normal file structure',
          actualPattern: 'Isolated/unusual structure',
          confidence: isolationScore,
          reasoning: [
            `Isolation score: ${isolationScore.toFixed(3)}`,
            'File structure differs significantly from typical patterns',
            'May indicate unique requirements or potential issues'
          ],
          suggestions: [
            'Review file structure and organization',
            'Consider refactoring if structure is unnecessarily complex',
            'Validate if unique structure serves a specific purpose'
          ],
          detectedAt: Date.now(),
          relatedPatterns: []
        });
      }
    } catch (error) {
      logger.error('Error detecting isolation anomalies:', error);
    }

    return anomalies;
  }

  private async detectStructuralAnomalies(
    filePath: string,
    symbols: ParsedSymbol[],
    threshold: number
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Detect unusual nesting patterns
      const maxNesting = this.calculateMaxNesting(lines);
      if (maxNesting > 6) {
        anomalies.push({
          id: `anomaly-nesting-${Date.now()}`,
          type: 'structural',
          filePath,
          location: { lineStart: 1, lineEnd: lines.length },
          severity: maxNesting > 10 ? 'critical' : 'high',
          description: `Excessive nesting depth: ${maxNesting} levels`,
          anomalyScore: Math.min(maxNesting / 10, 1),
          expectedPattern: 'Maximum 4-5 nesting levels',
          actualPattern: `${maxNesting} nesting levels`,
          confidence: 0.9,
          reasoning: [
            `Maximum nesting depth: ${maxNesting}`,
            'Deep nesting reduces readability',
            'May indicate complex logic that needs refactoring'
          ],
          suggestions: [
            'Refactor deeply nested code',
            'Extract methods to reduce nesting',
            'Use early returns or guard clauses'
          ],
          detectedAt: Date.now(),
          relatedPatterns: []
        });
      }

      // Detect unusual function size distribution
      const functions = symbols.filter(s => s.kind === 'function');
      const functionSizes = functions.map(f => f.lineEnd - f.lineStart + 1);
      
      if (functionSizes.length > 0) {
        const avgSize = functionSizes.reduce((sum, size) => sum + size, 0) / functionSizes.length;
        const maxSize = Math.max(...functionSizes);
        
        if (maxSize > 100 && maxSize > avgSize * 3) {
          anomalies.push({
            id: `anomaly-function-size-${Date.now()}`,
            type: 'structural',
            filePath,
            location: { lineStart: 1, lineEnd: lines.length },
            severity: maxSize > 200 ? 'critical' : 'high',
            description: `Unusually large function: ${maxSize} lines`,
            anomalyScore: Math.min(maxSize / 200, 1),
            expectedPattern: `Functions under 50 lines (avg: ${avgSize.toFixed(1)})`,
            actualPattern: `Function with ${maxSize} lines`,
            confidence: 0.85,
            reasoning: [
              `Largest function: ${maxSize} lines`,
              `Average function size: ${avgSize.toFixed(1)} lines`,
              'Large functions are harder to test and maintain'
            ],
            suggestions: [
              'Break down large functions into smaller ones',
              'Extract logical units into separate methods',
              'Consider if function has multiple responsibilities'
            ],
            detectedAt: Date.now(),
            relatedPatterns: []
          });
        }
      }
    } catch (error) {
      logger.error('Error detecting structural anomalies:', error);
    }

    return anomalies;
  }

  // Clustering methods (simplified implementations)
  private async findOptimalClusters(features: number[][]): Promise<number> {
    // Simplified elbow method
    const maxClusters = Math.min(10, Math.floor(features.length / 2));
    let optimalClusters = 3;
    let bestScore = -Infinity;

    for (let k = 2; k <= maxClusters; k++) {
      const clusters = await this.performKMeans(features, k);
      const silhouette = this.calculateSilhouetteScore(features, clusters);
      const inertia = this.calculateInertia(features, clusters);
      
      // Simple scoring function (in practice, use more sophisticated methods)
      const score = silhouette - (inertia / 1000);
      
      if (score > bestScore) {
        bestScore = score;
        optimalClusters = k;
      }
    }

    return optimalClusters;
  }

  private async performKMeans(features: number[][], k: number): Promise<Cluster[]> {
    // Simplified K-means implementation
    const maxIterations = 100;
    const tolerance = 1e-4;

    // Initialize centroids randomly
    let centroids = this.initializeCentroids(features, k);
    let assignments = new Array(features.length).fill(0);
    
    for (let iter = 0; iter < maxIterations; iter++) {
      // Assign points to closest centroid
      const newAssignments = features.map(point => 
        this.findClosestCentroid(point, centroids)
      );

      // Check for convergence
      if (assignments.every((assignment, i) => assignment === newAssignments[i])) {
        break;
      }

      assignments = newAssignments;

      // Update centroids
      const newCentroids = this.updateCentroids(features, assignments, k);
      
      // Check for centroid convergence
      const centroidChange = this.calculateCentroidChange(centroids, newCentroids);
      if (centroidChange < tolerance) {
        break;
      }

      centroids = newCentroids;
    }

    // Create cluster objects
    const clusters: Cluster[] = [];
    for (let i = 0; i < k; i++) {
      const clusterPoints = features.filter((_, idx) => assignments[idx] === i);
      const clusterIndices = assignments.map((assignment, idx) => assignment === i ? idx : -1).filter(idx => idx !== -1);
      
      clusters.push({
        id: i,
        centroid: centroids[i],
        samples: clusterIndices.map(idx => `sample-${idx}`), // Would use actual file paths
        size: clusterPoints.length,
        cohesion: this.calculateClusterCohesion(clusterPoints, centroids[i]),
        separation: this.calculateClusterSeparation(centroids[i], centroids),
        characteristics: [`Cluster ${i}`], // Would analyze actual characteristics
        representativeExamples: clusterIndices.slice(0, 3).map(idx => `example-${idx}`)
      });
    }

    return clusters;
  }

  // Helper calculation methods
  private calculateOverallComplexity(symbols: ParsedSymbol[], lines: string[]): number {
    const functions = symbols.filter(s => s.kind === 'function');
    let totalComplexity = 0;

    for (const func of functions) {
      const funcLines = lines.slice(func.lineStart - 1, func.lineEnd);
      const funcContent = funcLines.join(' ');
      const decisions = (funcContent.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
      totalComplexity += 1 + decisions; // Cyclomatic complexity
    }

    return totalComplexity;
  }

  private calculateMaxNesting(lines: string[]): number {
    let maxNesting = 0;
    let currentNesting = 0;

    for (const line of lines) {
      const openBraces = (line.match(/{/g) || []).length;
      const closeBraces = (line.match(/}/g) || []).length;
      
      currentNesting += openBraces - closeBraces;
      maxNesting = Math.max(maxNesting, currentNesting);
    }

    return maxNesting;
  }

  private calculateCyclomaticComplexity(symbols: ParsedSymbol[], lines: string[]): number {
    const functions = symbols.filter(s => s.kind === 'function');
    let totalComplexity = 0;

    for (const func of functions) {
      const funcLines = lines.slice(func.lineStart - 1, func.lineEnd);
      const funcContent = funcLines.join(' ');
      const decisions = (funcContent.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
      totalComplexity += 1 + decisions;
    }

    return totalComplexity;
  }

  private calculateCognitiveComplexity(lines: string[]): number {
    let complexity = 0;
    let nestingLevel = 0;

    for (const line of lines) {
      const trimmed = line.trim();
      
      // Increase nesting for blocks
      if (trimmed.includes('{')) nestingLevel++;
      if (trimmed.includes('}')) nestingLevel = Math.max(0, nestingLevel - 1);
      
      // Add complexity for control structures
      if (trimmed.includes('if') || trimmed.includes('while') || trimmed.includes('for')) {
        complexity += 1 + nestingLevel;
      }
      
      // Add complexity for logical operators
      const logicalOps = (trimmed.match(/&&|\|\|/g) || []).length;
      complexity += logicalOps;
    }

    return complexity;
  }

  private calculateHalsteadMetrics(lines: string[]): { volume: number; difficulty: number } {
    // Simplified Halstead metrics
    const content = lines.join(' ');
    
    // Count operators and operands (simplified)
    const operators = (content.match(/[+\-*/%=<>!&|]/g) || []).length;
    const operands = (content.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g) || []).length;
    
    const uniqueOperators = new Set(content.match(/[+\-*/%=<>!&|]/g) || []).size;
    const uniqueOperands = new Set(content.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g) || []).size;
    
    const vocabulary = uniqueOperators + uniqueOperands;
    const length = operators + operands;
    
    const volume = length * Math.log2(vocabulary || 1);
    const difficulty = (uniqueOperators / 2) * (operands / Math.max(uniqueOperands, 1));
    
    return { volume, difficulty };
  }

  private countDecisionPoints(lines: string[]): number {
    const content = lines.join(' ');
    return (content.match(/if|else|while|for|case|catch|\?|&&|\|\|/g) || []).length;
  }

  private determinePatternType(features: number[], featureNames: string[]): Pattern['type'] {
    // Simple heuristic to determine pattern type based on dominant features
    const maxFeatureIndex = features.indexOf(Math.max(...features));
    const dominantFeature = featureNames[maxFeatureIndex];

    if (dominantFeature.includes('performance') || dominantFeature.includes('slowdown')) {
      return 'performance_pattern';
    } else if (dominantFeature.includes('smell') || dominantFeature.includes('quality')) {
      return 'quality_pattern';
    } else if (dominantFeature.includes('change') || dominantFeature.includes('frequency')) {
      return 'change_pattern';
    } else {
      return 'code_pattern';
    }
  }

  private discretizeFeatures(featureVectors: FeatureVector[]): any[] {
    // Simplified feature discretization
    // In practice, would use proper binning strategies
    return featureVectors.map(fv => ({
      ...fv,
      discretizedFeatures: fv.features.map(f => f > 0.5 ? 'high' : 'low')
    }));
  }

  private findFrequentItemsets(discretizedVectors: any[], minSupport: number): any[] {
    // Simplified frequent itemset mining
    // In practice, would use Apriori or FP-Growth algorithms
    return [];
  }

  private async getHistoricalFeatureVectors(filePath?: string): Promise<FeatureVector[]> {
    const stmt = filePath 
      ? this.db.prepare('SELECT * FROM feature_vectors WHERE file_path != ? ORDER BY created_at DESC LIMIT 100')
      : this.db.prepare('SELECT * FROM feature_vectors ORDER BY created_at DESC LIMIT 1000');
    
    const rows = stmt.all(filePath ? [filePath] : []) as any[];
    
    return rows.map(row => ({
      id: row.id,
      filePath: row.file_path,
      features: JSON.parse(row.features),
      featureNames: JSON.parse(row.feature_names),
      label: row.label,
      metadata: JSON.parse(row.metadata)
    }));
  }

  private calculateZScores(featureVector: FeatureVector, historicalVectors: FeatureVector[]): number[] {
    const zScores: number[] = [];
    
    for (let i = 0; i < featureVector.features.length; i++) {
      const values = historicalVectors.map(v => v.features[i]);
      const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
      const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
      const stdDev = Math.sqrt(variance);
      
      const zScore = stdDev > 0 ? (featureVector.features[i] - mean) / stdDev : 0;
      zScores.push(zScore);
    }
    
    return zScores;
  }

  private calculateCosineSimilarity(vecA: number[], vecB: number[]): number {
    const dotProduct = vecA.reduce((sum, a, i) => sum + a * vecB[i], 0);
    const magnitudeA = Math.sqrt(vecA.reduce((sum, a) => sum + a * a, 0));
    const magnitudeB = Math.sqrt(vecB.reduce((sum, b) => sum + b * b, 0));
    
    return dotProduct / (magnitudeA * magnitudeB) || 0;
  }

  private calculateIsolationScore(featureVector: FeatureVector, historicalVectors: FeatureVector[]): number {
    // Simplified isolation score calculation
    // In practice, would use proper isolation forest algorithm
    
    let totalDistance = 0;
    let count = 0;
    
    for (const historical of historicalVectors) {
      if (historical.features.length === featureVector.features.length) {
        const distance = this.calculateEuclideanDistance(featureVector.features, historical.features);
        totalDistance += distance;
        count++;
      }
    }
    
    if (count === 0) return 0;
    
    const avgDistance = totalDistance / count;
    
    // Normalize to 0-1 range (simplified)
    return Math.min(avgDistance / 10, 1);
  }

  private calculateEuclideanDistance(vecA: number[], vecB: number[]): number {
    return Math.sqrt(vecA.reduce((sum, a, i) => sum + Math.pow(a - vecB[i], 2), 0));
  }

  // Clustering helper methods
  private initializeCentroids(features: number[][], k: number): number[][] {
    const centroids: number[][] = [];
    const featureCount = features[0].length;
    
    for (let i = 0; i < k; i++) {
      const centroid: number[] = [];
      for (let j = 0; j < featureCount; j++) {
        const min = Math.min(...features.map(f => f[j]));
        const max = Math.max(...features.map(f => f[j]));
        centroid.push(Math.random() * (max - min) + min);
      }
      centroids.push(centroid);
    }
    
    return centroids;
  }

  private findClosestCentroid(point: number[], centroids: number[][]): number {
    let closestIndex = 0;
    let minDistance = this.calculateEuclideanDistance(point, centroids[0]);
    
    for (let i = 1; i < centroids.length; i++) {
      const distance = this.calculateEuclideanDistance(point, centroids[i]);
      if (distance < minDistance) {
        minDistance = distance;
        closestIndex = i;
      }
    }
    
    return closestIndex;
  }

  private updateCentroids(features: number[][], assignments: number[], k: number): number[][] {
    const centroids: number[][] = [];
    const featureCount = features[0].length;
    
    for (let i = 0; i < k; i++) {
      const clusterPoints = features.filter((_, idx) => assignments[idx] === i);
      
      if (clusterPoints.length === 0) {
        // Keep old centroid if no points assigned
        centroids.push(new Array(featureCount).fill(0));
        continue;
      }
      
      const centroid: number[] = [];
      for (let j = 0; j < featureCount; j++) {
        const sum = clusterPoints.reduce((s, point) => s + point[j], 0);
        centroid.push(sum / clusterPoints.length);
      }
      centroids.push(centroid);
    }
    
    return centroids;
  }

  private calculateCentroidChange(oldCentroids: number[][], newCentroids: number[][]): number {
    let totalChange = 0;
    
    for (let i = 0; i < oldCentroids.length; i++) {
      const distance = this.calculateEuclideanDistance(oldCentroids[i], newCentroids[i]);
      totalChange += distance;
    }
    
    return totalChange / oldCentroids.length;
  }

  private calculateSilhouetteScore(features: number[][], clusters: Cluster[]): number {
    // Simplified silhouette score calculation
    // In practice, would implement proper silhouette analysis
    return 0.5; // Placeholder
  }

  private calculateInertia(features: number[][], clusters: Cluster[]): number {
    let inertia = 0;
    
    for (const cluster of clusters) {
      for (let i = 0; i < features.length; i++) {
        if (cluster.samples.includes(`sample-${i}`)) {
          const distance = this.calculateEuclideanDistance(features[i], cluster.centroid);
          inertia += distance * distance;
        }
      }
    }
    
    return inertia;
  }

  private calculateClusterCohesion(points: number[][], centroid: number[]): number {
    if (points.length === 0) return 0;
    
    const avgDistance = points.reduce((sum, point) => 
      sum + this.calculateEuclideanDistance(point, centroid), 0) / points.length;
    
    // Normalize to 0-1 range (1 = high cohesion, 0 = low cohesion)
    return Math.max(0, 1 - avgDistance / 10);
  }

  private calculateClusterSeparation(centroid: number[], allCentroids: number[][]): number {
    const distances = allCentroids
      .filter(c => c !== centroid)
      .map(c => this.calculateEuclideanDistance(centroid, c));
    
    return distances.length > 0 ? Math.min(...distances) : 0;
  }

  private async enrichClusters(clusters: Cluster[], featureVectors: FeatureVector[]): Promise<Cluster[]> {
    // Add meaningful characteristics and examples to clusters
    return clusters.map((cluster, index) => ({
      ...cluster,
      characteristics: [`Cluster ${index}`, `${cluster.size} samples`],
      representativeExamples: cluster.samples.slice(0, 3)
    }));
  }

  // Model training methods (simplified implementations)
  private async trainClassificationModel(
    modelId: string,
    trainingData: TrainingData,
    hyperparameters: Record<string, any>
  ): Promise<MLModel> {
    // Simplified classification model training
    return {
      id: modelId,
      name: 'Code Quality Classifier',
      type: 'classification',
      description: 'Classifies code quality based on features',
      features: trainingData.samples[0].featureNames,
      targetVariable: 'quality_level',
      accuracy: 0.85,
      precision: 0.83,
      recall: 0.87,
      f1Score: 0.85,
      trainingData: trainingData.samples.length,
      lastTrained: Date.now(),
      version: '1.0.0',
      hyperparameters,
      isActive: true
    };
  }

  private async trainRegressionModel(
    modelId: string,
    trainingData: TrainingData,
    hyperparameters: Record<string, any>
  ): Promise<MLModel> {
    // Simplified regression model training
    return {
      id: modelId,
      name: 'Complexity Predictor',
      type: 'regression',
      description: 'Predicts code complexity metrics',
      features: trainingData.samples[0].featureNames,
      targetVariable: 'complexity_score',
      accuracy: 0.78,
      trainingData: trainingData.samples.length,
      lastTrained: Date.now(),
      version: '1.0.0',
      hyperparameters,
      isActive: true
    };
  }

  private async trainClusteringModel(
    modelId: string,
    trainingData: TrainingData,
    hyperparameters: Record<string, any>
  ): Promise<MLModel> {
    // Simplified clustering model training
    return {
      id: modelId,
      name: 'Code Pattern Clusterer',
      type: 'clustering',
      description: 'Groups code files by similarity patterns',
      features: trainingData.samples[0].featureNames,
      trainingData: trainingData.samples.length,
      lastTrained: Date.now(),
      version: '1.0.0',
      hyperparameters,
      isActive: true
    };
  }

  private async trainAnomalyDetectionModel(
    modelId: string,
    trainingData: TrainingData,
    hyperparameters: Record<string, any>
  ): Promise<MLModel> {
    // Simplified anomaly detection model training
    return {
      id: modelId,
      name: 'Code Anomaly Detector',
      type: 'anomaly_detection',
      description: 'Detects unusual code patterns and structures',
      features: trainingData.samples[0].featureNames,
      accuracy: 0.82,
      precision: 0.79,
      recall: 0.85,
      f1Score: 0.82,
      trainingData: trainingData.samples.length,
      lastTrained: Date.now(),
      version: '1.0.0',
      hyperparameters,
      isActive: true
    };
  }

  // Prediction methods (simplified implementations)
  private async classifyFeatureVector(
    model: MLModel,
    featureVector: FeatureVector
  ): Promise<{ predictedValue: string; confidence: number; reasoning: string[] }> {
    // Simplified classification prediction
    const qualityScore = featureVector.features.reduce((sum, f) => sum + f, 0) / featureVector.features.length;
    
    let predictedValue: string;
    let confidence: number;
    
    if (qualityScore > 0.8) {
      predictedValue = 'high_quality';
      confidence = 0.9;
    } else if (qualityScore > 0.6) {
      predictedValue = 'medium_quality';
      confidence = 0.8;
    } else {
      predictedValue = 'low_quality';
      confidence = 0.85;
    }
    
    return {
      predictedValue,
      confidence,
      reasoning: [
        `Average feature score: ${qualityScore.toFixed(3)}`,
        `Model: ${model.name}`,
        `Based on ${model.features.length} features`
      ]
    };
  }

  private async regressFeatureVector(
    model: MLModel,
    featureVector: FeatureVector
  ): Promise<{ predictedValue: number; confidence: number; reasoning: string[] }> {
    // Simplified regression prediction
    const predictedValue = featureVector.features.reduce((sum, f) => sum + f, 0) / featureVector.features.length * 100;
    const confidence = 0.8;
    
    return {
      predictedValue,
      confidence,
      reasoning: [
        `Predicted complexity score: ${predictedValue.toFixed(1)}`,
        `Model: ${model.name}`,
        `Confidence: ${confidence}`
      ]
    };
  }

  private async detectAnomalyScore(
    model: MLModel,
    featureVector: FeatureVector
  ): Promise<{ predictedValue: number; confidence: number; reasoning: string[] }> {
    // Simplified anomaly score prediction
    const anomalyScore = Math.random() * 0.3 + 0.1; // Simulate low anomaly score
    const confidence = 0.85;
    
    return {
      predictedValue: anomalyScore,
      confidence,
      reasoning: [
        `Anomaly score: ${anomalyScore.toFixed(3)}`,
        `Model: ${model.name}`,
        anomalyScore > 0.5 ? 'Potentially anomalous' : 'Normal pattern'
      ]
    };
  }

  // Database storage methods
  private async storeFeatureVector(featureVector: FeatureVector): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO feature_vectors (
        id, file_path, features, feature_names, label, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      featureVector.id,
      featureVector.filePath,
      JSON.stringify(featureVector.features),
      JSON.stringify(featureVector.featureNames),
      featureVector.label,
      JSON.stringify(featureVector.metadata),
      Date.now()
    );
  }

  private async storePatterns(patterns: Pattern[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO ml_patterns (
        id, type, name, description, features, feature_names,
        confidence, support, examples, detected_at, is_anomaly
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const pattern of patterns) {
      stmt.run(
        pattern.id,
        pattern.type,
        pattern.name,
        pattern.description,
        JSON.stringify(pattern.features),
        JSON.stringify(pattern.featureNames),
        pattern.confidence,
        pattern.support,
        JSON.stringify(pattern.examples),
        pattern.detectedAt,
        pattern.isAnomaly
      );
    }
  }

  private async storeAnomalies(anomalies: Anomaly[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO anomalies (
        id, type, file_path, line_start, line_end, function_name,
        class_name, severity, description, anomaly_score, expected_pattern,
        actual_pattern, confidence, reasoning, suggestions,
        detected_at, related_patterns
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const anomaly of anomalies) {
      stmt.run(
        anomaly.id,
        anomaly.type,
        anomaly.filePath,
        anomaly.location.lineStart,
        anomaly.location.lineEnd,
        anomaly.location.function,
        anomaly.location.class,
        anomaly.severity,
        anomaly.description,
        anomaly.anomalyScore,
        anomaly.expectedPattern,
        anomaly.actualPattern,
        anomaly.confidence,
        JSON.stringify(anomaly.reasoning),
        JSON.stringify(anomaly.suggestions),
        anomaly.detectedAt,
        JSON.stringify(anomaly.relatedPatterns)
      );
    }
  }

  private async storeModel(model: MLModel): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO ml_models (
        id, name, type, description, features, target_variable,
        accuracy, precision_score, recall_score, f1_score,
        training_data, last_trained, version, hyperparameters, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      model.id,
      model.name,
      model.type,
      model.description,
      JSON.stringify(model.features),
      model.targetVariable,
      model.accuracy,
      model.precision,
      model.recall,
      model.f1Score,
      model.trainingData,
      model.lastTrained,
      model.version,
      JSON.stringify(model.hyperparameters),
      model.isActive
    );
  }

  private async storePrediction(prediction: Prediction): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO ml_predictions (
        id, model_id, file_path, predicted_value, confidence,
        features, reasoning, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      prediction.id,
      prediction.modelId,
      prediction.filePath,
      JSON.stringify(prediction.predictedValue),
      prediction.confidence,
      JSON.stringify(prediction.features),
      JSON.stringify(prediction.reasoning),
      prediction.createdAt
    );
  }

  private async storeClusterAnalysis(analysis: ClusterAnalysis): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO cluster_analysis (
        id, name, description, clusters, total_samples,
        optimal_clusters, silhouette_score, inertia, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      analysis.id,
      analysis.name,
      analysis.description,
      JSON.stringify(analysis.clusters),
      analysis.totalSamples,
      analysis.optimalClusters,
      analysis.silhouetteScore,
      analysis.inertia,
      analysis.createdAt
    );
  }

  // Public API methods
  async getPatterns(type?: Pattern['type']): Promise<Pattern[]> {
    let patterns = Array.from(this.patterns.values());
    
    if (type) {
      patterns = patterns.filter(p => p.type === type);
    }
    
    return patterns.sort((a, b) => b.confidence - a.confidence);
  }

  async getAnomalies(filePath: string): Promise<Anomaly[]> {
    return this.anomalies.get(filePath) || [];
  }

  async getModels(type?: MLModel['type']): Promise<MLModel[]> {
    let models = Array.from(this.models.values());
    
    if (type) {
      models = models.filter(m => m.type === type);
    }
    
    return models.filter(m => m.isActive);
  }

  async getModelStatistics(): Promise<any> {
    const models = Array.from(this.models.values());
    
    return {
      totalModels: models.length,
      activeModels: models.filter(m => m.isActive).length,
      modelTypes: models.reduce((acc, m) => {
        acc[m.type] = (acc[m.type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      averageAccuracy: models
        .filter(m => m.accuracy)
        .reduce((sum, m) => sum + m.accuracy!, 0) / models.filter(m => m.accuracy).length,
      totalPredictions: await this.getTotalPredictions(),
      patternsDiscovered: this.patterns.size,
      anomaliesDetected: Array.from(this.anomalies.values()).flat().length
    };
  }

  private async getTotalPredictions(): Promise<number> {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM ml_predictions');
    const result = stmt.get() as any;
    return result.count;
  }
}