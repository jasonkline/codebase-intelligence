import { IaCSecurityFinding } from '../database/schema';
import { logger } from '../utils/logger';

// OWASP Cloud Security Top 10 2025 (emerging standards)
export interface OwaspCloudControl {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  cloudSpecific: boolean;
  frameworks: string[]; // Which IaC frameworks this applies to
  checkPatterns: string[]; // Checkov check ID patterns that map to this control
  remediation: string;
  references: string[];
}

export interface OwaspCloudMapping {
  findingId: string;
  owaspId: string;
  confidence: number; // 0.0 to 1.0
  mappingReason: string;
  additionalContext?: string;
}

export class OwaspCloudMapper {
  private cloudControls: Map<string, OwaspCloudControl> = new Map();

  constructor() {
    this.initializeCloudControls();
  }

  private initializeCloudControls(): void {
    // CC01: Identity and Access Management (IAM) Misconfigurations
    this.cloudControls.set('CC01:2025', {
      id: 'CC01:2025',
      title: 'Identity and Access Management (IAM) Misconfigurations',
      description: 'Insecure IAM policies, roles, and permissions that can lead to privilege escalation or unauthorized access',
      category: 'access_control',
      severity: 'critical',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes', 'helm'],
      checkPatterns: [
        'CKV_AWS_.*IAM.*',
        'CKV_AWS_60', // IAM policy attached to users
        'CKV_AWS_61', // IAM policy attached to groups  
        'CKV_AWS_62', // IAM policy attached to roles
        'CKV_AWS_39', // IAM root user access key
        'CKV_AWS_40', // IAM policies attached to users
        'CKV_GCP_.*IAM.*',
        'CKV_AZURE_.*IAM.*',
        'CKV_K8S_.*RBAC.*'
      ],
      remediation: 'Follow principle of least privilege, use IAM roles instead of users, enable MFA, regularly audit permissions',
      references: [
        'https://owasp.org/www-project-cloud-security/',
        'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
      ]
    });

    // CC02: Insecure Data Storage and Encryption
    this.cloudControls.set('CC02:2025', {
      id: 'CC02:2025',
      title: 'Insecure Data Storage and Encryption',
      description: 'Unencrypted data at rest or in transit, weak encryption algorithms, or missing encryption key management',
      category: 'crypto',
      severity: 'high',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation'],
      checkPatterns: [
        'CKV_AWS_.*[Ee]ncrypt.*',
        'CKV_AWS_2', // S3 bucket public access
        'CKV_AWS_18', // S3 bucket logging
        'CKV_AWS_19', // S3 bucket encryption
        'CKV_AWS_20', // S3 bucket versioning
        'CKV_AWS_21', // S3 bucket MFA delete
        'CKV_AWS_144', // S3 bucket public read
        'CKV_AWS_145', // S3 bucket public write
        'CKV_GCP_.*[Ee]ncrypt.*',
        'CKV_AZURE_.*[Ee]ncrypt.*'
      ],
      remediation: 'Enable encryption at rest and in transit, use strong encryption algorithms, implement proper key management',
      references: [
        'https://owasp.org/www-project-cloud-security/',
        'https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryption.html'
      ]
    });

    // CC03: Insecure Network Configuration
    this.cloudControls.set('CC03:2025', {
      id: 'CC03:2025',
      title: 'Insecure Network Configuration',
      description: 'Overly permissive security groups, open ports, missing VPC security, insecure network policies',
      category: 'network',
      severity: 'high',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes'],
      checkPatterns: [
        'CKV_AWS_.*[Ss]ecurity.*[Gg]roup.*',
        'CKV_AWS_23', // Security group ingress open to 0.0.0.0/0
        'CKV_AWS_24', // Security group egress open to 0.0.0.0/0
        'CKV_AWS_25', // Security group only allows SSH from limited sources
        'CKV_K8S_.*[Nn]etwork.*',
        'CKV_K8S_19', // Network policies
        'CKV_K8S_20', // Containers should not run with allowPrivilegeEscalation
        'CKV_GCP_.*[Ff]irewall.*',
        'CKV_AZURE_.*[Nn]etwork.*'
      ],
      remediation: 'Use least privilege network access, implement network segmentation, restrict ingress/egress rules',
      references: [
        'https://owasp.org/www-project-cloud-security/',
        'https://kubernetes.io/docs/concepts/services-networking/network-policies/'
      ]
    });

    // CC04: Insecure Container and Orchestration Configuration  
    this.cloudControls.set('CC04:2025', {
      id: 'CC04:2025',
      title: 'Insecure Container and Orchestration Configuration',
      description: 'Containers running as root, privileged containers, insecure Kubernetes configurations',
      category: 'container_security',
      severity: 'high',
      cloudSpecific: true,
      frameworks: ['kubernetes', 'helm', 'dockerfile'],
      checkPatterns: [
        'CKV_K8S_.*',
        'CKV_DOCKER_.*',
        'CKV_K8S_8', // Liveness probe
        'CKV_K8S_9', // Readiness probe  
        'CKV_K8S_10', // CPU requests
        'CKV_K8S_11', // CPU limits
        'CKV_K8S_12', // Memory requests
        'CKV_K8S_13', // Memory limits
        'CKV_K8S_14', // Image tag
        'CKV_K8S_15', // Image pull policy
        'CKV_K8S_16', // Container image not latest
        'CKV_K8S_17', // Containers should not run as root
        'CKV_K8S_18', // Containers should not run with allowPrivilegeEscalation'
      ],
      remediation: 'Run containers as non-root, use security contexts, implement resource limits, scan container images',
      references: [
        'https://owasp.org/www-project-kubernetes-top-ten/',
        'https://kubernetes.io/docs/concepts/security/pod-security-standards/'
      ]
    });

    // CC05: Inadequate Logging and Monitoring
    this.cloudControls.set('CC05:2025', {
      id: 'CC05:2025',
      title: 'Inadequate Logging and Monitoring',
      description: 'Missing audit trails, insufficient monitoring, lack of security event logging',
      category: 'logging',
      severity: 'medium',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes'],
      checkPatterns: [
        'CKV_AWS_.*[Ll]og.*',
        'CKV_AWS_.*[Mm]onitor.*',
        'CKV_AWS_.*[Tt]rail.*',
        'CKV_AWS_35', // CloudTrail encryption
        'CKV_AWS_36', // CloudTrail log file validation
        'CKV_AWS_92', // ELB access logs
        'CKV_K8S_.*[Ll]og.*',
        'CKV_GCP_.*[Ll]og.*',
        'CKV_AZURE_.*[Ll]og.*'
      ],
      remediation: 'Enable comprehensive logging, implement monitoring and alerting, secure log storage',
      references: [
        'https://owasp.org/www-project-cloud-security/',
        'https://docs.aws.amazon.com/cloudtrail/latest/userguide/best-practices-security.html'
      ]
    });

    // CC06: Secrets Management Failures
    this.cloudControls.set('CC06:2025', {
      id: 'CC06:2025',
      title: 'Secrets Management Failures',
      description: 'Hardcoded secrets, insecure secret storage, poor key rotation practices',
      category: 'secrets',
      severity: 'critical',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes', 'dockerfile'],
      checkPatterns: [
        'CKV_.*[Ss]ecret.*',
        'CKV_.*[Pp]assword.*',
        'CKV_.*[Kk]ey.*',
        'CKV_K8S_.*[Ss]ecret.*',
        'CKV_DOCKER_.*[Ss]ecret.*',
        'CKV_AWS_.*[Kk]ms.*',
        'CKV_AWS_.*[Ss]ecrets.*'
      ],
      remediation: 'Use managed secret services, implement key rotation, avoid hardcoded secrets in code',
      references: [
        'https://owasp.org/www-project-cloud-security/',
        'https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html'
      ]
    });

    // CC07: Insecure API and Service Communication
    this.cloudControls.set('CC07:2025', {
      id: 'CC07:2025',
      title: 'Insecure API and Service Communication',
      description: 'Unencrypted API communication, missing authentication, insecure service mesh configuration',
      category: 'api_security',
      severity: 'high',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes'],
      checkPatterns: [
        'CKV_AWS_.*[Aa]pi.*',
        'CKV_AWS_.*[Tt]ls.*',
        'CKV_AWS_.*[Ss]sl.*',
        'CKV_K8S_.*[Tt]ls.*',
        'CKV_K8S_.*[Ii]ngress.*',
        'CKV_GCP_.*[Aa]pi.*',
        'CKV_AZURE_.*[Aa]pi.*'
      ],
      remediation: 'Use TLS for all communications, implement proper API authentication, secure service mesh',
      references: [
        'https://owasp.org/www-project-api-security/',
        'https://kubernetes.io/docs/concepts/services-networking/ingress/'
      ]
    });

    // CC08: Supply Chain and Dependency Vulnerabilities
    this.cloudControls.set('CC08:2025', {
      id: 'CC08:2025',
      title: 'Supply Chain and Dependency Vulnerabilities',
      description: 'Vulnerable base images, unverified third-party components, insecure CI/CD pipelines',
      category: 'supply_chain',
      severity: 'high',
      cloudSpecific: true,
      frameworks: ['dockerfile', 'kubernetes', 'helm'],
      checkPatterns: [
        'CKV_DOCKER_.*[Ii]mage.*',
        'CKV_K8S_.*[Ii]mage.*',
        'CKV_DOCKER_.*[Uu]ser.*',
        'CKV_DOCKER_.*[Vv]ersion.*'
      ],
      remediation: 'Scan container images, use trusted base images, implement SBOM, secure CI/CD pipelines',
      references: [
        'https://owasp.org/www-project-cloud-security/',
        'https://kubernetes.io/docs/concepts/security/supply-chain-security/'
      ]
    });

    // CC09: Insufficient Resource and Cost Management
    this.cloudControls.set('CC09:2025', {
      id: 'CC09:2025',
      title: 'Insufficient Resource and Cost Management',
      description: 'Unrestricted resource allocation, missing cost controls, resource exhaustion vulnerabilities',
      category: 'resource_management',
      severity: 'medium',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes'],
      checkPatterns: [
        'CKV_K8S_.*[Ll]imit.*',
        'CKV_K8S_.*[Rr]esource.*',
        'CKV_AWS_.*[Bb]illing.*',
        'CKV_AWS_.*[Bb]udget.*'
      ],
      remediation: 'Implement resource limits, use cost monitoring, implement resource quotas',
      references: [
        'https://kubernetes.io/docs/concepts/policy/resource-quotas/',
        'https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/budgets-managing-costs.html'
      ]
    });

    // CC10: Insecure DevOps and Infrastructure as Code Practices  
    this.cloudControls.set('CC10:2025', {
      id: 'CC10:2025',
      title: 'Insecure DevOps and Infrastructure as Code Practices',
      description: 'Insecure IaC templates, missing security scanning, insufficient access controls for infrastructure',
      category: 'devops_security',
      severity: 'medium',
      cloudSpecific: true,
      frameworks: ['terraform', 'cloudformation', 'kubernetes', 'helm'],
      checkPatterns: [
        'CKV_.*[Tt]erraform.*',
        'CKV_.*[Cc]loudformation.*',
        'CKV_.*[Vv]ersion.*',
        'CKV_.*[Ss]tate.*'
      ],
      remediation: 'Implement IaC security scanning, use version control, secure state management, implement policy as code',
      references: [
        'https://owasp.org/www-project-devsecops-guideline/',
        'https://www.terraform.io/docs/cloud/sentinel/'
      ]
    });

    logger.info(`Initialized ${this.cloudControls.size} OWASP Cloud Security controls`);
  }

  /**
   * Map an IaC security finding to OWASP Cloud Security controls
   */
  public mapFindingToOwasp(finding: IaCSecurityFinding): OwaspCloudMapping[] {
    const mappings: OwaspCloudMapping[] = [];

    for (const [owaspId, control] of this.cloudControls) {
      const mapping = this.evaluateMapping(finding, control);
      if (mapping) {
        mappings.push({
          findingId: finding.finding_id,
          owaspId,
          confidence: mapping.confidence,
          mappingReason: mapping.reason,
          additionalContext: mapping.context
        });
      }
    }

    // Sort by confidence (highest first)
    mappings.sort((a, b) => b.confidence - a.confidence);

    return mappings;
  }

  private evaluateMapping(finding: IaCSecurityFinding, control: OwaspCloudControl): {
    confidence: number;
    reason: string;
    context?: string;
  } | null {
    let confidence = 0;
    const reasons: string[] = [];
    let context = '';

    // Check if framework matches
    if (!control.frameworks.includes(finding.check_type)) {
      return null; // Framework not supported by this control
    }

    // Check pattern matching
    for (const pattern of control.checkPatterns) {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(finding.check_id)) {
        confidence += 0.8;
        reasons.push(`Check ID matches pattern: ${pattern}`);
        break;
      }
    }

    // Check category matching
    if (this.categoriesMatch(finding, control)) {
      confidence += 0.3;
      reasons.push('Category alignment');
    }

    // Check severity alignment
    if (this.severityAligns(finding.severity, control.severity)) {
      confidence += 0.2;
      reasons.push('Severity alignment');
    }

    // Check description similarity (basic keyword matching)
    const descriptionMatch = this.checkDescriptionSimilarity(finding.description, control.description);
    if (descriptionMatch > 0) {
      confidence += descriptionMatch * 0.3;
      reasons.push('Description similarity');
    }

    // Must have at least some confidence to be considered a valid mapping
    if (confidence < 0.3) {
      return null;
    }

    // Cap confidence at 1.0
    confidence = Math.min(confidence, 1.0);

    return {
      confidence,
      reason: reasons.join(', '),
      context: context || undefined
    };
  }

  private categoriesMatch(finding: IaCSecurityFinding, control: OwaspCloudControl): boolean {
    // Map IaC categories to OWASP categories
    const categoryMap: Record<string, string[]> = {
      'auth': ['access_control', 'iam'],
      'crypto': ['crypto', 'encryption'],
      'network': ['network', 'networking'],
      'logging': ['logging', 'monitoring'],
      'secrets': ['secrets', 'secret_management'],
      'iac_config': ['devops_security', 'configuration'],
      'container_security': ['container_security', 'kubernetes'],
      'api_security': ['api_security', 'service_communication'],
      'data': ['data_storage', 'encryption']
    };

    const findingCategories = this.extractCategories(finding);
    const mappedCategories = findingCategories.flatMap(cat => categoryMap[cat] || []);
    
    return mappedCategories.includes(control.category) || 
           findingCategories.some(cat => control.category.includes(cat));
  }

  private extractCategories(finding: IaCSecurityFinding): string[] {
    const categories: string[] = [];
    const text = `${finding.description} ${finding.check_id} ${finding.resource_type}`.toLowerCase();

    if (text.includes('iam') || text.includes('role') || text.includes('permission')) {
      categories.push('auth');
    }
    if (text.includes('encrypt') || text.includes('tls') || text.includes('ssl')) {
      categories.push('crypto');
    }
    if (text.includes('network') || text.includes('security group') || text.includes('firewall')) {
      categories.push('network');
    }
    if (text.includes('log') || text.includes('monitor') || text.includes('audit')) {
      categories.push('logging');
    }
    if (text.includes('secret') || text.includes('password') || text.includes('key')) {
      categories.push('secrets');
    }
    if (text.includes('container') || text.includes('docker') || text.includes('kubernetes')) {
      categories.push('container_security');
    }
    if (text.includes('api') || text.includes('endpoint') || text.includes('service')) {
      categories.push('api_security');
    }

    return categories.length > 0 ? categories : ['iac_config'];
  }

  private severityAligns(findingSeverity: string, controlSeverity: string): boolean {
    const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
    const findingIndex = severityOrder.indexOf(findingSeverity.toLowerCase());
    const controlIndex = severityOrder.indexOf(controlSeverity.toLowerCase());
    
    // Allow some flexibility in severity matching
    return Math.abs(findingIndex - controlIndex) <= 1;
  }

  private checkDescriptionSimilarity(findingDesc: string, controlDesc: string): number {
    const findingWords = findingDesc.toLowerCase().split(/\s+/);
    const controlWords = controlDesc.toLowerCase().split(/\s+/);
    
    const commonWords = findingWords.filter(word => 
      word.length > 3 && controlWords.includes(word)
    );
    
    return commonWords.length / Math.max(findingWords.length, controlWords.length);
  }

  /**
   * Get all available OWASP Cloud Security controls
   */
  public getCloudControls(): OwaspCloudControl[] {
    return Array.from(this.cloudControls.values());
  }

  /**
   * Get a specific OWASP Cloud Security control by ID
   */
  public getCloudControl(owaspId: string): OwaspCloudControl | undefined {
    return this.cloudControls.get(owaspId);
  }

  /**
   * Generate a compliance report mapping findings to OWASP controls
   */
  public generateComplianceReport(findings: IaCSecurityFinding[]): {
    totalFindings: number;
    mappedFindings: number;
    unmappedFindings: number;
    controlCoverage: Record<string, number>;
    mappings: OwaspCloudMapping[];
    recommendations: string[];
  } {
    const mappings: OwaspCloudMapping[] = [];
    const controlCoverage: Record<string, number> = {};
    
    // Initialize control coverage
    for (const control of this.cloudControls.values()) {
      controlCoverage[control.id] = 0;
    }

    // Map each finding
    for (const finding of findings) {
      const findingMappings = this.mapFindingToOwasp(finding);
      mappings.push(...findingMappings);
      
      // Count coverage (only high confidence mappings)
      for (const mapping of findingMappings) {
        if (mapping.confidence >= 0.7) {
          controlCoverage[mapping.owaspId]++;
        }
      }
    }

    const mappedFindings = new Set(mappings.map(m => m.findingId)).size;
    const recommendations = this.generateRecommendations(controlCoverage, findings.length);

    return {
      totalFindings: findings.length,
      mappedFindings,
      unmappedFindings: findings.length - mappedFindings,
      controlCoverage,
      mappings,
      recommendations
    };
  }

  private generateRecommendations(controlCoverage: Record<string, number>, totalFindings: number): string[] {
    const recommendations: string[] = [];
    
    // Find controls with most violations
    const topViolations = Object.entries(controlCoverage)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3)
      .filter(([,count]) => count > 0);

    for (const [owaspId, count] of topViolations) {
      const control = this.cloudControls.get(owaspId);
      if (control) {
        recommendations.push(
          `Priority: Address ${control.title} (${count} violations) - ${control.remediation}`
        );
      }
    }

    // General recommendations
    if (totalFindings > 0) {
      recommendations.push(
        'Implement infrastructure security scanning in your CI/CD pipeline',
        'Regularly review and update IaC security policies',
        'Consider using policy-as-code tools like OPA/Gatekeeper for Kubernetes'
      );
    }

    return recommendations;
  }
}