import { spawn } from 'child_process';
import { join, basename, extname, relative } from 'path';
import { logger } from '../utils/logger';
import { DatabaseManager, IaCSecurityFinding } from '../database/schema';

export interface CheckovScanOptions {
  frameworks?: string[]; // 'terraform', 'cloudformation', 'kubernetes', etc.
  excludeChecks?: string[]; // Checkov check IDs to exclude
  includeChecks?: string[]; // Specific checks to include
  minSeverity?: CheckovSeverity;
  timeout?: number; // milliseconds
  skipDownload?: boolean; // Skip policy download for faster scans
  quiet?: boolean;
  compactOutput?: boolean;
}

export enum CheckovSeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH', 
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO'
}

export interface CheckovFinding {
  check_id: string;
  check_name: string;
  file_path: string;
  file_line_range: [number, number];
  resource: string;
  evaluations: null;
  check_class: string;
  fixed_definition: string | null;
  entity_tags: Record<string, any>;
  caller_file_path: string | null;
  caller_file_line_range: [number, number] | null;
  resource_address: string | null;
  severity: CheckovSeverity;
  bc_check_id: string;
  remediation: string;
  details: string[];
  short_description: string;
  description: string;
  connected_node: any;
  guideline: string;
  frameworks: string[];
  breadcrumbs: any;
}

export interface CheckovScanResult {
  results: {
    passed_checks: CheckovFinding[];
    failed_checks: CheckovFinding[];
    skipped_checks: CheckovFinding[];
    parsing_errors: string[];
  };
  summary: {
    passed: number;
    failed: number;
    skipped: number;
    parsing_errors: number;
    resource_count: number;
    checkov_version: string;
  };
  url: string;
}


export class CheckovScanner {
  private dbManager: DatabaseManager;
  private checkovPath: string;

  constructor(dbManager: DatabaseManager, checkovPath?: string) {
    this.dbManager = dbManager;
    this.checkovPath = checkovPath || this.findCheckovPath();
  }

  private findCheckovPath(): string {
    const fs = require('fs');
    
    // Try common Checkov installation paths
    const commonPaths = [
      'checkov', // System PATH
      '/usr/local/bin/checkov', // Homebrew
      '/opt/homebrew/bin/checkov', // Homebrew M1 Mac
      `${process.env.HOME}/Library/Python/3.9/bin/checkov`, // Python user install
      `${process.env.HOME}/Library/Python/3.10/bin/checkov`, // Python user install
      `${process.env.HOME}/Library/Python/3.11/bin/checkov`, // Python user install
      `${process.env.HOME}/.local/bin/checkov`, // Linux user install
    ];

    // Check each path and return the first one that exists
    for (const path of commonPaths) {
      if (path === 'checkov') {
        // For system PATH, we'll try it and let the command fail if not found
        return path;
      }
      
      try {
        if (fs.existsSync(path)) {
          logger.info(`Found Checkov at: ${path}`);
          return path;
        }
      } catch (error) {
        // Continue to next path
      }
    }

    // Default to checkov in PATH if nothing found
    return 'checkov';
  }

  public async isAvailable(): Promise<boolean> {
    try {
      const result = await this.runCheckovCommand(['--version'], { timeout: 5000 });
      return result.exitCode === 0;
    } catch (error) {
      logger.warn('Checkov not available:', error);
      return false;
    }
  }

  public static getInstallationInstructions(): string {
    return `Checkov is not installed or not accessible. Please install it using one of these methods:

1. **Using pip (recommended):**
   pip install checkov

2. **Using pip3:**
   pip3 install checkov

3. **Using homebrew (macOS):**
   brew install checkov

4. **Using docker:**
   docker pull bridgecrew/checkov

5. **If installed but not in PATH, try:**
   - Add Python user bin to PATH: export PATH="$PATH:$HOME/Library/Python/3.9/bin"
   - Or specify custom path in configuration: checkovPath

After installation, verify with: checkov --version
For more details: https://www.checkov.io/1.Welcome/Quick%20Start.html`;
  }

  public async scanFile(filePath: string, options: CheckovScanOptions = {}): Promise<IaCSecurityFinding[]> {
    if (!this.isIaCFile(filePath)) {
      logger.debug(`Skipping non-IaC file: ${filePath}`);
      return [];
    }

    try {
      logger.info(`Scanning IaC file with Checkov: ${filePath}`);
      
      const args = this.buildCheckovArgs(filePath, options);
      const result = await this.runCheckovCommand(args, { 
        timeout: options.timeout || 60000 
      });

      if (result.exitCode !== 0 && result.exitCode !== 1) {
        // Exit code 1 is expected when there are failed checks
        throw new Error(`Checkov scan failed: ${result.stderr}`);
      }

      const scanResult = this.parseCheckovOutput(result.stdout);
      const findings = this.convertToSecurityFindings(scanResult, filePath, options);
      
      // Store findings in database
      await this.storeFindings(findings);
      
      logger.info(`Found ${findings.length} IaC security issues in ${filePath}`);
      return findings;
    } catch (error) {
      logger.error(`Error scanning file ${filePath}:`, error);
      return [];
    }
  }

  public async scanDirectory(dirPath: string, options: CheckovScanOptions = {}): Promise<IaCSecurityFinding[]> {
    try {
      logger.info(`Scanning IaC directory with Checkov: ${dirPath}`);
      
      const args = this.buildCheckovArgs(dirPath, options);
      const result = await this.runCheckovCommand(args, { 
        timeout: options.timeout || 300000 // 5 minutes for directory scans
      });

      if (result.exitCode !== 0 && result.exitCode !== 1) {
        throw new Error(`Checkov directory scan failed: ${result.stderr}`);
      }

      const scanResult = this.parseCheckovOutput(result.stdout);
      const findings = this.convertToSecurityFindings(scanResult, dirPath, options);
      
      // Store findings in database
      await this.storeFindings(findings);
      
      logger.info(`Found ${findings.length} IaC security issues in ${dirPath}`);
      return findings;
    } catch (error) {
      logger.error(`Error scanning directory ${dirPath}:`, error);
      return [];
    }
  }

  public async validateCompliance(
    targetPath: string, 
    frameworks: string[] = ['cis', 'nist', 'pci'],
    options: CheckovScanOptions = {}
  ): Promise<{
    findings: IaCSecurityFinding[];
    complianceScore: number;
    frameworkScores: Record<string, number>;
  }> {
    const scanOptions = { ...options, frameworks };
    const findings = await (this.isDirectory(targetPath) 
      ? this.scanDirectory(targetPath, scanOptions)
      : this.scanFile(targetPath, scanOptions));

    // Calculate compliance scores
    const totalChecks = findings.length;
    const passedChecks = findings.filter(f => f.severity === 'info').length;
    const complianceScore = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 100;

    // Calculate framework-specific scores
    const frameworkScores: Record<string, number> = {};
    for (const framework of frameworks) {
      const frameworkFindings = findings.filter(f => 
        f.compliance_frameworks?.includes(framework) || 
        f.frameworks?.includes(framework)
      );
      const frameworkPassed = frameworkFindings.filter(f => f.severity === 'info').length;
      frameworkScores[framework] = frameworkFindings.length > 0 
        ? Math.round((frameworkPassed / frameworkFindings.length) * 100) 
        : 100;
    }

    return {
      findings,
      complianceScore,
      frameworkScores
    };
  }

  private isIaCFile(filePath: string): boolean {
    const ext = extname(filePath).toLowerCase();
    const basename_file = basename(filePath).toLowerCase();
    
    // Check common IaC file patterns
    const iacExtensions = ['.tf', '.hcl', '.yaml', '.yml', '.json'];
    const iacPatterns = [
      /terraform/i,
      /cloudformation/i,
      /kubernetes/i,
      /k8s/i,
      /helm/i,
      /docker/i,
      /serverless/i
    ];

    return iacExtensions.includes(ext) || 
           iacPatterns.some(pattern => pattern.test(basename_file));
  }

  private isDirectory(path: string): boolean {
    try {
      const fs = require('fs');
      return fs.statSync(path).isDirectory();
    } catch {
      return false;
    }
  }

  private buildCheckovArgs(targetPath: string, options: CheckovScanOptions): string[] {
    const args = [
      '--output', 'json',
      '--output-file-path', '/dev/stdout'
    ];

    // Add target path
    if (this.isDirectory(targetPath)) {
      args.push('--directory', targetPath);
    } else {
      args.push('--file', targetPath);
    }

    // Framework selection
    if (options.frameworks && options.frameworks.length > 0) {
      args.push('--framework', options.frameworks.join(','));
    }

    // Check exclusions
    if (options.excludeChecks && options.excludeChecks.length > 0) {
      args.push('--skip-check', options.excludeChecks.join(','));
    }

    // Check inclusions
    if (options.includeChecks && options.includeChecks.length > 0) {
      args.push('--check', options.includeChecks.join(','));
    }

    // Skip policy download for faster scans
    if (options.skipDownload) {
      args.push('--skip-download');
    }

    // Quiet mode
    if (options.quiet) {
      args.push('--quiet');
    }

    // Compact output
    if (options.compactOutput) {
      args.push('--compact');
    }

    return args;
  }

  private async runCheckovCommand(
    args: string[], 
    options: { timeout?: number } = {}
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.checkovPath, args, {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      const timeoutId = options.timeout 
        ? setTimeout(() => {
            child.kill('SIGTERM');
            reject(new Error(`Checkov scan timed out after ${options.timeout}ms`));
          }, options.timeout)
        : null;

      child.on('close', (code) => {
        if (timeoutId) clearTimeout(timeoutId);
        resolve({
          stdout,
          stderr,
          exitCode: code || 0
        });
      });

      child.on('error', (error) => {
        if (timeoutId) clearTimeout(timeoutId);
        reject(error);
      });
    });
  }

  private parseCheckovOutput(output: string): CheckovScanResult {
    try {
      const lines = output.split('\n').filter(line => line.trim());
      
      // Find the JSON output line (Checkov sometimes outputs extra info)
      let jsonLine = '';
      for (const line of lines) {
        try {
          JSON.parse(line);
          jsonLine = line;
          break;
        } catch {
          continue;
        }
      }

      if (!jsonLine) {
        throw new Error('No valid JSON output found from Checkov');
      }

      return JSON.parse(jsonLine) as CheckovScanResult;
    } catch (error) {
      logger.error('Failed to parse Checkov output:', error);
      logger.debug('Raw output:', output);
      throw new Error(`Failed to parse Checkov output: ${error}`);
    }
  }

  private convertToSecurityFindings(
    scanResult: CheckovScanResult, 
    targetPath: string,
    options: CheckovScanOptions
  ): IaCSecurityFinding[] {
    const findings: IaCSecurityFinding[] = [];

    // Process failed checks (these are the security issues)
    for (const check of scanResult.results.failed_checks) {
      const severity = this.mapCheckovSeverity(check.severity);
      
      // Skip findings below minimum severity
      if (options.minSeverity && this.compareSeverity(severity, options.minSeverity) < 0) {
        continue;
      }

      const finding: IaCSecurityFinding = {
        finding_id: `${check.check_id}-${check.file_path}-${check.file_line_range[0]}`,
        check_id: check.check_id,
        check_type: this.determineCheckType(check),
        resource_type: this.extractResourceType(check.resource),
        resource_name: check.resource,
        file_path: check.file_path,
        line_start: check.file_line_range[0],
        line_end: check.file_line_range[1],
        severity,
        description: check.description || check.check_name,
        remediation: check.remediation || check.guideline || 'Review and fix the security configuration',
        cwe_id: this.extractCweId(check),
        compliance_frameworks: JSON.stringify(this.extractComplianceFrameworks(check)),
        detected_at: new Date().toISOString(),
        resolved: false,
        bc_check_id: check.bc_check_id,
        guideline: check.guideline,
        frameworks: JSON.stringify(check.frameworks || []),
        risk_score: this.calculateRiskScore(check)
      };

      findings.push(finding);
    }

    return findings;
  }

  private mapCheckovSeverity(checkovSeverity: CheckovSeverity): string {
    switch (checkovSeverity) {
      case CheckovSeverity.CRITICAL:
        return 'critical';
      case CheckovSeverity.HIGH:
        return 'high';
      case CheckovSeverity.MEDIUM:
        return 'medium';
      case CheckovSeverity.LOW:
        return 'low';
      case CheckovSeverity.INFO:
        return 'info';
      default:
        return 'medium';
    }
  }

  private compareSeverity(severity1: string, severity2: CheckovSeverity): number {
    const severityOrder = {
      'critical': 0,
      'high': 1,
      'medium': 2,
      'low': 3,
      'info': 4
    };

    const order1 = severityOrder[severity1 as keyof typeof severityOrder] ?? 2;
    const order2 = severityOrder[this.mapCheckovSeverity(severity2) as keyof typeof severityOrder] ?? 2;

    return order1 - order2;
  }

  private determineCategory(check: CheckovFinding): string {
    const checkId = check.check_id.toLowerCase();
    const description = check.description?.toLowerCase() || '';
    
    if (checkId.includes('iam') || description.includes('permission') || description.includes('role')) {
      return 'auth';
    }
    if (checkId.includes('encrypt') || description.includes('encrypt') || description.includes('tls')) {
      return 'crypto';
    }
    if (checkId.includes('network') || description.includes('security group') || description.includes('firewall')) {
      return 'network';
    }
    if (checkId.includes('log') || description.includes('logging') || description.includes('audit')) {
      return 'logging';
    }
    if (checkId.includes('secret') || description.includes('password') || description.includes('key')) {
      return 'secrets';
    }
    if (checkId.includes('storage') || description.includes('bucket') || description.includes('database')) {
      return 'data';
    }
    
    return 'iac_config';
  }

  private determineCheckType(check: CheckovFinding): string {
    if (check.frameworks?.includes('terraform')) return 'terraform';
    if (check.frameworks?.includes('cloudformation')) return 'cloudformation';
    if (check.frameworks?.includes('kubernetes')) return 'kubernetes';
    if (check.frameworks?.includes('dockerfile')) return 'dockerfile';
    if (check.frameworks?.includes('helm')) return 'helm';
    
    // Fallback based on file extension
    if (check.file_path.endsWith('.tf')) return 'terraform';
    if (check.file_path.includes('cloudformation')) return 'cloudformation';
    if (check.file_path.includes('k8s') || check.file_path.includes('kubernetes')) return 'kubernetes';
    
    return 'unknown';
  }

  private extractResourceType(resource: string): string {
    // Extract resource type from Terraform resource format (e.g., "aws_s3_bucket.example")
    const parts = resource.split('.');
    return parts[0] || resource;
  }

  private extractCweId(check: CheckovFinding): string | undefined {
    // Look for CWE references in the check details or guideline
    const text = `${check.description} ${check.guideline} ${check.details?.join(' ') || ''}`;
    const cweMatch = text.match(/CWE-(\d+)/i);
    return cweMatch ? `CWE-${cweMatch[1]}` : undefined;
  }

  private extractComplianceFrameworks(check: CheckovFinding): string[] {
    const frameworks: string[] = [];
    const text = `${check.description} ${check.guideline} ${check.check_id}`.toLowerCase();
    
    if (text.includes('cis')) frameworks.push('cis');
    if (text.includes('nist')) frameworks.push('nist');
    if (text.includes('pci')) frameworks.push('pci');
    if (text.includes('hipaa')) frameworks.push('hipaa');
    if (text.includes('gdpr')) frameworks.push('gdpr');
    if (text.includes('sox')) frameworks.push('sox');
    
    return frameworks;
  }

  private async storeFindings(findings: IaCSecurityFinding[]): Promise<void> {
    try {
      this.dbManager.transaction(() => {
        for (const finding of findings) {
          this.dbManager.insertIaCSecurityFinding(finding);
        }
      });
      
      logger.debug(`Stored ${findings.length} IaC security findings in database`);
    } catch (error) {
      logger.error('Error storing IaC security findings:', error);
    }
  }

  private calculateRiskScore(check: CheckovFinding): number {
    let score = 5; // Base score
    
    // Adjust based on severity
    switch (check.severity) {
      case CheckovSeverity.CRITICAL:
        score = 10;
        break;
      case CheckovSeverity.HIGH:
        score = 8;
        break;
      case CheckovSeverity.MEDIUM:
        score = 5;
        break;
      case CheckovSeverity.LOW:
        score = 3;
        break;
      case CheckovSeverity.INFO:
        score = 1;
        break;
    }
    
    // Boost score for security-critical categories
    const description = check.description?.toLowerCase() || '';
    if (description.includes('encrypt') || description.includes('secret') || description.includes('password')) {
      score = Math.min(10, score + 2);
    }
    
    return score;
  }
}