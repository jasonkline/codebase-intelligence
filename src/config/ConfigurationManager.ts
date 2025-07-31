import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join, resolve } from 'path';
import logger from '../utils/logger';

export interface CodeIntelligenceConfig {
  version?: string;
  include: string[];
  exclude: string[];
  database: {
    path: string;
    maxSize: string;
    backupEnabled?: boolean;
    backupInterval?: string;
  };
  patterns: {
    learningMode: 'auto' | 'manual' | 'disabled';
    minConfidence: number;
    categories: string[];
    customPatterns?: string[];
  };
  security: {
    enabled: boolean;
    scanOnSave: boolean;
    blockCritical: boolean;
    warnOnHigh: boolean;
    owasp: boolean;
    customRules?: string;
    reportingLevel: 'all' | 'high' | 'critical';
  };
  knowledge: {
    autoDocument: boolean;
    updateFrequency: 'on_change' | 'hourly' | 'daily';
    includeArchitectureDocs: boolean;
    generateFlowDiagrams: boolean;
    maxDocumentationSize?: string;
  };
  governance: {
    enabled: boolean;
    strictMode: boolean;
    autoSuggest: boolean;
    enforceStyles: boolean;
    requireApprovedPatterns: string[];
    customRulesets?: string[];
  };
  intelligence: {
    explainComplexity: boolean;
    suggestRefactoring: boolean;
    trackTechnicalDebt: boolean;
    predictiveAnalysis?: boolean;
  };
  server: {
    port?: number;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
    enableUI: boolean;
    uiPort?: number;
    maxConcurrentRequests?: number;
    requestTimeout?: number;
  };
  performance: {
    enableCaching: boolean;
    cacheSize: string;
    enableProfiling: boolean;
    maxMemoryUsage: string;
  };
  tools: {
    enabled: string[];
    disabled: string[];
    rateLimit?: {
      requestsPerMinute: number;
      burstLimit: number;
    };
  };
  integrations?: {
    vscode?: {
      enabled: boolean;
      port?: number;
    };
    github?: {
      enabled: boolean;
      webhooks?: boolean;
    };
    slack?: {
      enabled: boolean;
      webhook?: string;
    };
  };
}

const DEFAULT_CONFIG: CodeIntelligenceConfig = {
  version: '1.0.0',
  include: ['src/**/*.ts', 'src/**/*.tsx', 'app/**/*.ts', 'app/**/*.tsx', 'lib/**/*.ts'],
  exclude: ['node_modules', 'dist', '*.test.ts', '.next', '**/*.d.ts'],
  database: {
    path: '.codeintel/index.db',
    maxSize: '1GB',
    backupEnabled: true,
    backupInterval: 'daily'
  },
  patterns: {
    learningMode: 'auto',
    minConfidence: 0.85,
    categories: ['auth', 'rbac', 'api', 'data_access', 'validation', 'error_handling', 'ui_components', 'styles'],
    customPatterns: []
  },
  security: {
    enabled: true,
    scanOnSave: true,
    blockCritical: true,
    warnOnHigh: true,
    owasp: true,
    reportingLevel: 'high'
  },
  knowledge: {
    autoDocument: true,
    updateFrequency: 'on_change',
    includeArchitectureDocs: true,
    generateFlowDiagrams: true,
    maxDocumentationSize: '10MB'
  },
  governance: {
    enabled: true,
    strictMode: false,
    autoSuggest: true,
    enforceStyles: true,
    requireApprovedPatterns: ['auth', 'rbac', 'data_access'],
    customRulesets: []
  },
  intelligence: {
    explainComplexity: true,
    suggestRefactoring: true,
    trackTechnicalDebt: true,
    predictiveAnalysis: false
  },
  server: {
    port: 7345,
    logLevel: 'info',
    enableUI: false,
    uiPort: 7346,
    maxConcurrentRequests: 10,
    requestTimeout: 30000
  },
  performance: {
    enableCaching: true,
    cacheSize: '256MB',
    enableProfiling: false,
    maxMemoryUsage: '1GB'
  },
  tools: {
    enabled: ['*'], // All tools enabled by default
    disabled: []
  }
};

export class ConfigurationManager {
  private config: CodeIntelligenceConfig;
  private configPath: string;
  private envOverrides: Record<string, any> = {};

  constructor(configPath?: string) {
    this.configPath = configPath || this.findConfigFile();
    this.loadEnvironmentOverrides();
    this.config = this.loadConfiguration();
    this.validateConfiguration();
  }

  getConfig(): CodeIntelligenceConfig {
    return { ...this.config };
  }

  updateConfig(updates: Partial<CodeIntelligenceConfig>): void {
    this.config = this.mergeConfig(this.config, updates);
    this.saveConfiguration();
    logger.info('Configuration updated', { updates });
  }

  isToolEnabled(toolName: string): boolean {
    const { enabled, disabled } = this.config.tools;
    
    // Check if tool is explicitly disabled
    if (disabled.includes(toolName)) {
      return false;
    }
    
    // Check if all tools are enabled
    if (enabled.includes('*')) {
      return true;
    }
    
    // Check if tool is explicitly enabled
    return enabled.includes(toolName);
  }

  getSecurityConfig() {
    return this.config.security;
  }

  getDatabaseConfig() {
    return this.config.database;
  }

  getPerformanceConfig() {
    return this.config.performance;
  }

  getServerConfig() {
    return this.config.server;
  }

  enableTool(toolName: string): void {
    if (!this.config.tools.enabled.includes(toolName) && !this.config.tools.enabled.includes('*')) {
      this.config.tools.enabled.push(toolName);
    }
    this.config.tools.disabled = this.config.tools.disabled.filter(name => name !== toolName);
    this.saveConfiguration();
  }

  disableTool(toolName: string): void {
    if (!this.config.tools.disabled.includes(toolName)) {
      this.config.tools.disabled.push(toolName);
    }
    this.config.tools.enabled = this.config.tools.enabled.filter(name => name !== toolName);
    this.saveConfiguration();
  }

  createDefaultConfig(targetPath?: string): string {
    const configPath = targetPath || join(process.cwd(), '.codeintelligence.json');
    const configWithComments = this.addConfigComments(DEFAULT_CONFIG);
    
    writeFileSync(configPath, JSON.stringify(configWithComments, null, 2));
    logger.info(`Default configuration created at: ${configPath}`);
    
    return configPath;
  }

  validateConfiguration(): void {
    const errors = this.validateConfig(this.config);
    
    if (errors.length > 0) {
      logger.warn('Configuration validation issues:', errors);
      
      // Auto-fix common issues
      this.autoFixConfiguration(errors);
    }
  }

  watchConfiguration(callback: (config: CodeIntelligenceConfig) => void): void {
    if (!existsSync(this.configPath)) {
      return;
    }

    const fs = require('fs');
    let debounceTimer: NodeJS.Timeout;

    fs.watchFile(this.configPath, () => {
      // Debounce file changes
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        try {
          const newConfig = this.loadConfiguration();
          if (JSON.stringify(newConfig) !== JSON.stringify(this.config)) {
            this.config = newConfig;
            this.validateConfiguration();
            callback(this.config);
            logger.info('Configuration reloaded from file');
          }
        } catch (error) {
          logger.error('Error reloading configuration:', error);
        }
      }, 500);
    });
  }

  private findConfigFile(): string {
    const possiblePaths = [
      join(process.cwd(), '.codeintelligence.json'),
      join(process.cwd(), '.codeintel.json'),
      join(process.cwd(), 'codeintelligence.config.json'),
      join(process.env.HOME || '~', '.codeintelligence.json')
    ];

    for (const path of possiblePaths) {
      if (existsSync(path)) {
        logger.info(`Using configuration file: ${path}`);
        return path;
      }
    }

    logger.info('No configuration file found, using defaults');
    return possiblePaths[0]; // Default location for saving
  }

  private loadEnvironmentOverrides(): void {
    // Load configuration from environment variables
    const envPrefix = 'CODEINTEL_';
    
    Object.keys(process.env).forEach(key => {
      if (key.startsWith(envPrefix)) {
        const configKey = key.substring(envPrefix.length).toLowerCase();
        const value = process.env[key];
        
        if (value) {
          this.envOverrides[configKey] = this.parseEnvValue(value);
        }
      }
    });

    if (Object.keys(this.envOverrides).length > 0) {
      logger.info('Environment overrides loaded:', Object.keys(this.envOverrides));
    }
  }

  private parseEnvValue(value: string): any {
    // Try to parse as JSON first
    try {
      return JSON.parse(value);
    } catch {
      // Parse boolean strings
      if (value.toLowerCase() === 'true') return true;
      if (value.toLowerCase() === 'false') return false;
      
      // Parse numbers
      if (/^\d+$/.test(value)) return parseInt(value, 10);
      if (/^\d+\.\d+$/.test(value)) return parseFloat(value);
      
      // Return as string
      return value;
    }
  }

  private loadConfiguration(): CodeIntelligenceConfig {
    let fileConfig = {};

    if (existsSync(this.configPath)) {
      try {
        const content = readFileSync(this.configPath, 'utf-8');
        fileConfig = JSON.parse(content);
        logger.info(`Configuration loaded from: ${this.configPath}`);
      } catch (error) {
        logger.error(`Error reading configuration file: ${this.configPath}`, error);
        logger.info('Using default configuration');
      }
    }

    // Merge default config, file config, and environment overrides
    const merged = this.mergeConfig(DEFAULT_CONFIG, fileConfig);
    return this.applyEnvironmentOverrides(merged);
  }

  private mergeConfig(base: any, override: any): any {
    const result = { ...base };

    for (const key in override) {
      if (override.hasOwnProperty(key)) {
        if (typeof override[key] === 'object' && override[key] !== null && !Array.isArray(override[key])) {
          result[key] = this.mergeConfig(result[key] || {}, override[key]);
        } else {
          result[key] = override[key];
        }
      }
    }

    return result;
  }

  private applyEnvironmentOverrides(config: CodeIntelligenceConfig): CodeIntelligenceConfig {
    const result = { ...config };

    // Apply specific environment overrides
    if (this.envOverrides.loglevel) {
      result.server.logLevel = this.envOverrides.loglevel;
    }
    
    if (this.envOverrides.port) {
      result.server.port = this.envOverrides.port;
    }
    
    if (this.envOverrides.database_path) {
      result.database.path = this.envOverrides.database_path;
    }

    return result;
  }

  private saveConfiguration(): void {
    try {
      writeFileSync(this.configPath, JSON.stringify(this.config, null, 2));
      logger.debug(`Configuration saved to: ${this.configPath}`);
    } catch (error) {
      logger.error('Error saving configuration:', error);
    }
  }

  private validateConfig(config: CodeIntelligenceConfig): string[] {
    const errors: string[] = [];

    // Validate required fields
    if (!config.include || config.include.length === 0) {
      errors.push('include patterns are required');
    }

    if (!config.database?.path) {
      errors.push('database.path is required');
    }

    // Validate numeric values
    if (config.patterns.minConfidence < 0 || config.patterns.minConfidence > 1) {
      errors.push('patterns.minConfidence must be between 0 and 1');
    }

    if (config.server.port && (config.server.port < 1024 || config.server.port > 65535)) {
      errors.push('server.port must be between 1024 and 65535');
    }

    // Validate enum values
    const validLogLevels = ['debug', 'info', 'warn', 'error'];
    if (!validLogLevels.includes(config.server.logLevel)) {
      errors.push(`server.logLevel must be one of: ${validLogLevels.join(', ')}`);
    }

    // Validate paths exist
    const dbDir = resolve(config.database.path, '..');
    try {
      require('fs').accessSync(dbDir, require('fs').constants.W_OK);
    } catch {
      errors.push(`database directory is not writable: ${dbDir}`);
    }

    return errors;
  }

  private autoFixConfiguration(errors: string[]): void {
    let fixed = false;

    errors.forEach(error => {
      if (error.includes('minConfidence must be between 0 and 1')) {
        this.config.patterns.minConfidence = Math.max(0, Math.min(1, this.config.patterns.minConfidence));
        fixed = true;
      }

      if (error.includes('server.port must be between')) {
        if (this.config.server.port) {
          this.config.server.port = Math.max(1024, Math.min(65535, this.config.server.port));
          fixed = true;
        }
      }

      if (error.includes('include patterns are required')) {
        this.config.include = DEFAULT_CONFIG.include;
        fixed = true;
      }
    });

    if (fixed) {
      this.saveConfiguration();
      logger.info('Configuration auto-fixed');
    }
  }

  private addConfigComments(config: CodeIntelligenceConfig): any {
    return {
      $schema: 'https://raw.githubusercontent.com/codebase-intelligence/schema/main/config.schema.json',
      $comment: 'Codebase Intelligence Configuration - See documentation at https://docs.codebase-intelligence.com',
      ...config,
      patterns: {
        ...config.patterns,
        $comment: 'Pattern learning and recognition settings'
      },
      security: {
        ...config.security,
        $comment: 'Security scanning and vulnerability detection settings'
      },
      governance: {
        ...config.governance,
        $comment: 'Code governance and compliance settings'
      }
    };
  }

  // Utility methods for common configuration tasks
  enableSecurityScanning(): void {
    this.updateConfig({
      security: {
        ...this.config.security,
        enabled: true,
        scanOnSave: true
      }
    });
  }

  enableStrictMode(): void {
    this.updateConfig({
      governance: {
        ...this.config.governance,
        strictMode: true,
        blockCritical: true
      },
      security: {
        ...this.config.security,
        blockCritical: true
      }
    });
  }

  enableDevelopmentMode(): void {
    this.updateConfig({
      server: {
        ...this.config.server,
        logLevel: 'debug',
        enableUI: true
      },
      performance: {
        ...this.config.performance,
        enableProfiling: true
      }
    });
  }

  enableProductionMode(): void {
    this.updateConfig({
      server: {
        ...this.config.server,
        logLevel: 'warn'
      },
      performance: {
        ...this.config.performance,
        enableProfiling: false,
        enableCaching: true
      },
      governance: {
        ...this.config.governance,
        strictMode: true
      }
    });
  }
}