import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { 
  SecurityFinding, 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  vulnerabilityDatabase 
} from './VulnerabilityDatabase';
import { logger } from '../utils/logger';

export interface MobileSecurityVulnerability {
  id: string;
  mobileId: string; // M1 - M10
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  category: string;
  file: string;
  line: number;
  code: string;
  platform: 'iOS' | 'Android' | 'Cross-Platform' | 'Web';
  remediation: string;
  references: string[];
  cweId?: number;
}

export interface MobileApp {
  platform: 'iOS' | 'Android' | 'Cross-Platform' | 'Web';
  framework: string;
  permissions: string[];
  dataStorage: string[];
  networkUsage: string[];
  cryptoUsage: string[];
  authMechanisms: string[];
}

export interface MobileScanResult {
  vulnerabilities: MobileSecurityVulnerability[];
  appAnalysis: MobileApp;
  analysis: {
    hasMobileFrameworks: boolean;
    detectedPlatforms: string[];
    mobileFrameworks: string[];
  };
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    byPlatform: Map<string, number>;
    categories: Map<string, number>;
  };
  complianceMatrix: Map<string, boolean>;
  recommendations: string[];
}

export class MobileSecurityScanner {
  private astParser: ASTParser;
  private mobilePatterns: Map<string, any> = new Map();
  private mobileFrameworks: Set<string> = new Set();
  private platformPatterns: Map<string, RegExp> = new Map();

  constructor() {
    this.astParser = new ASTParser();
    this.initializeMobileSecurityPatterns();
    this.initializeMobileFrameworks();
    this.initializePlatformPatterns();
  }

  private initializeMobileSecurityPatterns(): void {
    // M1: Improper Platform Usage
    this.mobilePatterns.set('M1:2016', {
      title: 'Improper Platform Usage',
      description: 'Misuse of platform features or security controls',
      patterns: [
        'platform_api_misuse',
        'permission_abuse',
        'security_control_bypass'
      ],
      scanner: this.scanImproperPlatformUsage.bind(this)
    });

    // M2: Insecure Data Storage
    this.mobilePatterns.set('M2:2016', {
      title: 'Insecure Data Storage',
      description: 'Insecure storage of sensitive data on the device',
      patterns: [
        'unencrypted_storage',
        'external_storage_misuse',
        'keychain_misuse'
      ],
      scanner: this.scanInsecureDataStorage.bind(this)
    });

    // M3: Insecure Communication
    this.mobilePatterns.set('M3:2016', {
      title: 'Insecure Communication',
      description: 'Poor handshaking, incorrect SSL versions, weak negotiation',
      patterns: [
        'unencrypted_communication',
        'weak_ssl_tls',
        'certificate_validation_disabled'
      ],
      scanner: this.scanInsecureCommunication.bind(this)
    });

    // M4: Insecure Authentication
    this.mobilePatterns.set('M4:2016', {
      title: 'Insecure Authentication',
      description: 'Poor or missing authentication controls',
      patterns: [
        'weak_authentication',
        'missing_authentication',
        'biometric_bypass'
      ],
      scanner: this.scanInsecureAuthentication.bind(this)
    });

    // M5: Insufficient Cryptography
    this.mobilePatterns.set('M5:2016', {
      title: 'Insufficient Cryptography',
      description: 'Use of weak or inappropriate cryptographic algorithms',
      patterns: [
        'weak_encryption',
        'hardcoded_keys',
        'custom_crypto_implementation'
      ],
      scanner: this.scanInsufficientCryptography.bind(this)
    });

    // M6: Insecure Authorization
    this.mobilePatterns.set('M6:2016', {
      title: 'Insecure Authorization',
      description: 'Poor or missing authorization controls',
      patterns: [
        'missing_authorization',
        'privilege_escalation',
        'role_based_access_failure'
      ],
      scanner: this.scanInsecureAuthorization.bind(this)
    });

    // M7: Client Code Quality
    this.mobilePatterns.set('M7:2016', {
      title: 'Client Code Quality',
      description: 'Code-level implementation issues in the mobile client',
      patterns: [
        'buffer_overflow',
        'format_string_vulnerability',
        'memory_corruption'
      ],
      scanner: this.scanClientCodeQuality.bind(this)
    });

    // M8: Code Tampering
    this.mobilePatterns.set('M8:2016', {
      title: 'Code Tampering',
      description: 'Binary patching, local resource modification, method hooking',
      patterns: [
        'anti_tampering_missing',
        'debug_code_present',
        'obfuscation_missing'
      ],
      scanner: this.scanCodeTampering.bind(this)
    });

    // M9: Reverse Engineering
    this.mobilePatterns.set('M9:2016', {
      title: 'Reverse Engineering',
      description: 'Analysis of the final core binary to determine source code',
      patterns: [
        'code_obfuscation_missing',
        'debug_symbols_present',
        'string_obfuscation_missing'
      ],
      scanner: this.scanReverseEngineering.bind(this)
    });

    // M10: Extraneous Functionality
    this.mobilePatterns.set('M10:2016', {
      title: 'Extraneous Functionality',
      description: 'Hidden backdoors or internal development security controls',
      patterns: [
        'debug_endpoints',
        'test_code_in_production',
        'hidden_functionality'
      ],
      scanner: this.scanExtraneousFunctionality.bind(this)
    });
  }

  private initializeMobileFrameworks(): void {
    const frameworks = [
      // React Native
      'react-native', '@react-native', 'expo',
      // Ionic
      '@ionic', 'cordova', 'phonegap',
      // Flutter (Dart)
      'flutter', 'dart',
      // Native iOS
      'swift', 'objective-c', 'ios',
      // Native Android
      'android', 'kotlin', 'java',
      // Cross-platform
      'xamarin', 'nativescript', 'titanium'
    ];

    frameworks.forEach(framework => this.mobileFrameworks.add(framework));
  }

  private initializePlatformPatterns(): void {
    // iOS specific patterns
    this.platformPatterns.set('iOS', 
      /UIKit|Foundation|CoreData|Keychain|TouchID|FaceID|CryptoKit/i
    );

    // Android specific patterns
    this.platformPatterns.set('Android', 
      /android\.|androidx\.|SharedPreferences|SQLiteDatabase|BiometricPrompt/i
    );

    // React Native patterns
    this.platformPatterns.set('ReactNative', 
      /react-native|@react-native|AsyncStorage|SecureStore/i
    );

    // Ionic/Cordova patterns
    this.platformPatterns.set('Ionic', 
      /@ionic|cordova|phonegap|ionic-native/i
    );
  }

  public async scanFile(filePath: string): Promise<MobileScanResult> {
    try {
      logger.info(`Running mobile security scan on: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return this.createEmptyResult();
      }

      const result: MobileScanResult = {
        vulnerabilities: [],
        appAnalysis: {
          platform: 'Cross-Platform',
          framework: 'Unknown',
          permissions: [],
          dataStorage: [],
          networkUsage: [],
          cryptoUsage: [],
          authMechanisms: []
        },
        analysis: {
          hasMobileFrameworks: false,
          detectedPlatforms: [],
          mobileFrameworks: []
        },
        summary: {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          byPlatform: new Map(),
          categories: new Map()
        },
        complianceMatrix: new Map(),
        recommendations: []
      };

      // Analyze mobile app characteristics
      result.appAnalysis = await this.analyzeMobileApp(content, filePath);

      // Skip scanning if not a mobile app
      if (result.appAnalysis.framework === 'Unknown' && !this.isMobileFile(filePath)) {
        return result;
      }

      // Run all mobile security scanners
      for (const [mobileId, pattern] of this.mobilePatterns) {
        const vulnerabilities = await pattern.scanner(content, filePath, mobileId, result.appAnalysis);
        result.vulnerabilities.push(...vulnerabilities);
        
        // Update compliance matrix
        result.complianceMatrix.set(mobileId, vulnerabilities.length === 0);
      }

      // Process results
      this.processResults(result);

      return result;
    } catch (error) {
      logger.error(`Error running mobile security scan on ${filePath}:`, error);
      return this.createEmptyResult();
    }
  }

  public async scanDirectory(dirPath: string): Promise<MobileScanResult> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const aggregatedResult: MobileScanResult = {
      vulnerabilities: [],
      appAnalysis: {
        platform: 'Cross-Platform',
        framework: 'Unknown',
        permissions: [],
        dataStorage: [],
        networkUsage: [],
        cryptoUsage: [],
        authMechanisms: []
      },
      analysis: {
        hasMobileFrameworks: false,
        detectedPlatforms: [],
        mobileFrameworks: []
      },
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        byPlatform: new Map(),
        categories: new Map()
      },
      complianceMatrix: new Map(),
      recommendations: []
    };
    
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next', 'Pods'].includes(entry.name)) {
            continue;
          }
          const subResult = await this.scanDirectory(fullPath);
          this.mergeResults(aggregatedResult, subResult);
        } else if (entry.isFile() && this.isMobileFile(fullPath)) {
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

  private async analyzeMobileApp(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): Promise<MobileApp> {
    const app: MobileApp = {
      platform: 'Cross-Platform',
      framework: 'Unknown',
      permissions: [],
      dataStorage: [],
      networkUsage: [],
      cryptoUsage: [],
      authMechanisms: []
    };

    // Detect platform and framework
    for (const [platform, pattern] of this.platformPatterns) {
      if (pattern.test(content.sourceCode)) {
        app.platform = this.mapPlatform(platform);
        app.framework = platform;
        break;
      }
    }

    // Analyze imports and usage patterns
    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.ImportDeclaration) {
        const importSource = node.source.value as string;
        
        if (this.mobileFrameworks.has(importSource) || this.isMobileLibrary(importSource)) {
          if (app.framework === 'Unknown') {
            app.framework = importSource;
          }
        }

        // Check for storage-related imports
        if (this.isStorageLibrary(importSource)) {
          app.dataStorage.push(importSource);
        }

        // Check for network-related imports
        if (this.isNetworkLibrary(importSource)) {
          app.networkUsage.push(importSource);
        }

        // Check for crypto-related imports
        if (this.isCryptoLibrary(importSource)) {
          app.cryptoUsage.push(importSource);
        }

        // Check for auth-related imports
        if (this.isAuthLibrary(importSource)) {
          app.authMechanisms.push(importSource);
        }
      }

      // Check for permission usage
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        const permissions = this.extractPermissions(code);
        app.permissions.push(...permissions);
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);

    return app;
  }

  // M1: Improper Platform Usage
  private async scanImproperPlatformUsage(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for deprecated API usage
      if (this.hasDeprecatedAPIUsage(line, appAnalysis.platform)) {
        vulnerabilities.push({
          id: `m1-deprecated-api-${index}`,
          mobileId,
          title: 'Deprecated API Usage',
          description: 'Usage of deprecated platform APIs that may have security implications',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Platform Security',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Update to use current, secure platform APIs',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage'],
          cweId: 477
        });
      }

      // Check for excessive permissions
      if (this.hasExcessivePermissions(line)) {
        vulnerabilities.push({
          id: `m1-excessive-permissions-${index}`,
          mobileId,
          title: 'Excessive Permissions',
          description: 'App requests unnecessary permissions that violate principle of least privilege',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Platform Security',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Request only necessary permissions and implement runtime permission checks',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage'],
          cweId: 250
        });
      }
    });

    return vulnerabilities;
  }

  // M2: Insecure Data Storage
  private async scanInsecureDataStorage(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for unencrypted storage of sensitive data
        if (this.hasUnencryptedSensitiveStorage(code, appAnalysis.platform)) {
          vulnerabilities.push({
            id: `m2-unencrypted-storage-${node.loc?.start.line}`,
            mobileId,
            title: 'Unencrypted Sensitive Data Storage',
            description: 'Sensitive data stored without encryption',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Data Storage',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            platform: appAnalysis.platform,
            remediation: 'Encrypt sensitive data before storage using platform-specific secure storage APIs',
            references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage'],
            cweId: 312
          });
        }

        // Check for external storage misuse
        if (this.hasExternalStorageMisuse(code, appAnalysis.platform)) {
          vulnerabilities.push({
            id: `m2-external-storage-${node.loc?.start.line}`,
            mobileId,
            title: 'Insecure External Storage Usage',
            description: 'Sensitive data stored in external/shared storage',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Data Storage',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            platform: appAnalysis.platform,
            remediation: 'Use internal storage for sensitive data or implement proper encryption',
            references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage'],
            cweId: 200
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // M3: Insecure Communication
  private async scanInsecureCommunication(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for HTTP usage instead of HTTPS
      if (this.hasInsecureHTTP(line)) {
        vulnerabilities.push({
          id: `m3-insecure-http-${index}`,
          mobileId,
          title: 'Insecure HTTP Communication',
          description: 'App uses HTTP instead of HTTPS for network communication',
          severity: VulnerabilitySeverity.HIGH,
          category: 'Network Security',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use HTTPS for all network communication and implement certificate pinning',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication'],
          cweId: 319
        });
      }

      // Check for disabled certificate validation
      if (this.hasDisabledCertificateValidation(line)) {
        vulnerabilities.push({
          id: `m3-cert-validation-${index}`,
          mobileId,
          title: 'Disabled Certificate Validation',
          description: 'SSL/TLS certificate validation is disabled',
          severity: VulnerabilitySeverity.CRITICAL,
          category: 'Network Security',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Enable proper certificate validation and implement certificate pinning',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication'],
          cweId: 295
        });
      }

      // Check for weak TLS configuration
      if (this.hasWeakTLSConfiguration(line)) {
        vulnerabilities.push({
          id: `m3-weak-tls-${index}`,
          mobileId,
          title: 'Weak TLS Configuration',
          description: 'Weak TLS version or cipher suite configuration',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Network Security',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use TLS 1.2 or higher with strong cipher suites',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication'],
          cweId: 327
        });
      }
    });

    return vulnerabilities;
  }

  // M4: Insecure Authentication
  private async scanInsecureAuthentication(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for weak authentication mechanisms
        if (this.hasWeakAuthentication(code)) {
          vulnerabilities.push({
            id: `m4-weak-auth-${node.loc?.start.line}`,
            mobileId,
            title: 'Weak Authentication Mechanism',
            description: 'Authentication mechanism is insufficient or easily bypassable',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Authentication',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            platform: appAnalysis.platform,
            remediation: 'Implement strong authentication with multi-factor authentication',
            references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication'],
            cweId: 287
          });
        }

        // Check for missing biometric authentication validation
        if (this.hasMissingBiometricValidation(code, appAnalysis.platform)) {
          vulnerabilities.push({
            id: `m4-biometric-validation-${node.loc?.start.line}`,
            mobileId,
            title: 'Insufficient Biometric Validation',
            description: 'Biometric authentication lacks proper validation or fallback mechanisms',
            severity: VulnerabilitySeverity.MEDIUM,
            category: 'Authentication',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            platform: appAnalysis.platform,
            remediation: 'Implement proper biometric validation with secure fallback methods',
            references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication'],
            cweId: 287
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // M5: Insufficient Cryptography
  private async scanInsufficientCryptography(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for weak encryption algorithms
      if (this.hasWeakEncryption(line)) {
        vulnerabilities.push({
          id: `m5-weak-encryption-${index}`,
          mobileId,
          title: 'Weak Encryption Algorithm',
          description: 'Usage of weak or deprecated encryption algorithms',
          severity: VulnerabilitySeverity.HIGH,
          category: 'Cryptography',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use strong, industry-standard encryption algorithms (AES-256, etc.)',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography'],
          cweId: 327
        });
      }

      // Check for hardcoded cryptographic keys
      if (this.hasHardcodedCryptoKeys(line)) {
        vulnerabilities.push({
          id: `m5-hardcoded-keys-${index}`,
          mobileId,
          title: 'Hardcoded Cryptographic Keys',
          description: 'Cryptographic keys are hardcoded in the application',
          severity: VulnerabilitySeverity.CRITICAL,
          category: 'Cryptography',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use secure key management systems and avoid hardcoding keys',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography'],
          cweId: 798
        });
      }

      // Check for custom cryptographic implementations
      if (this.hasCustomCryptoImplementation(line)) {
        vulnerabilities.push({
          id: `m5-custom-crypto-${index}`,
          mobileId,
          title: 'Custom Cryptographic Implementation',
          description: 'Custom cryptographic implementation detected instead of proven libraries',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Cryptography',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use well-tested cryptographic libraries instead of custom implementations',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography'],
          cweId: 327
        });
      }
    });

    return vulnerabilities;
  }

  // M6: Insecure Authorization
  private async scanInsecureAuthorization(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for missing authorization checks
        if (this.hasMissingAuthorization(code)) {
          vulnerabilities.push({
            id: `m6-missing-authz-${node.loc?.start.line}`,
            mobileId,
            title: 'Missing Authorization Check',
            description: 'Sensitive operation performed without proper authorization check',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Authorization',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            platform: appAnalysis.platform,
            remediation: 'Implement proper authorization checks for all sensitive operations',
            references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m6-insecure-authorization'],
            cweId: 285
          });
        }

        // Check for client-side authorization
        if (this.hasClientSideAuthorization(code)) {
          vulnerabilities.push({
            id: `m6-client-authz-${node.loc?.start.line}`,
            mobileId,
            title: 'Client-Side Authorization',
            description: 'Authorization logic implemented on client-side only',
            severity: VulnerabilitySeverity.HIGH,
            category: 'Authorization',
            file: filePath,
            line: node.loc?.start.line || 0,
            code: code.slice(0, 200),
            platform: appAnalysis.platform,
            remediation: 'Move authorization logic to server-side and validate on backend',
            references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m6-insecure-authorization'],
            cweId: 602
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);
    return vulnerabilities;
  }

  // M7: Client Code Quality
  private async scanClientCodeQuality(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for potential buffer overflow vulnerabilities
      if (this.hasBufferOverflowRisk(line)) {
        vulnerabilities.push({
          id: `m7-buffer-overflow-${index}`,
          mobileId,
          title: 'Potential Buffer Overflow',
          description: 'Code pattern that may lead to buffer overflow vulnerability',
          severity: VulnerabilitySeverity.HIGH,
          category: 'Code Quality',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use safe string manipulation functions and validate input lengths',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality'],
          cweId: 120
        });
      }

      // Check for format string vulnerabilities
      if (this.hasFormatStringVulnerability(line)) {
        vulnerabilities.push({
          id: `m7-format-string-${index}`,
          mobileId,
          title: 'Format String Vulnerability',
          description: 'Unsafe use of format strings with user-controlled input',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Code Quality',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Use parameterized formatting and validate format strings',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality'],
          cweId: 134
        });
      }
    });

    return vulnerabilities;
  }

  // M8: Code Tampering
  private async scanCodeTampering(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for missing anti-tampering measures
      if (this.hasMissingAntiTampering(line, appAnalysis.platform)) {
        vulnerabilities.push({
          id: `m8-anti-tampering-${index}`,
          mobileId,
          title: 'Missing Anti-Tampering Protection',
          description: 'Application lacks protection against code tampering',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Code Protection',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Implement anti-tampering measures and runtime integrity checks',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering'],
          cweId: 494
        });
      }

      // Check for debug code in production
      if (this.hasDebugCodeInProduction(line)) {
        vulnerabilities.push({
          id: `m8-debug-code-${index}`,
          mobileId,
          title: 'Debug Code in Production',
          description: 'Debug code or logging statements present in production build',
          severity: VulnerabilitySeverity.LOW,
          category: 'Code Protection',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Remove debug code and logging from production builds',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering'],
          cweId: 489
        });
      }
    });

    return vulnerabilities;
  }

  // M9: Reverse Engineering
  private async scanReverseEngineering(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for missing code obfuscation
      if (this.hasMissingCodeObfuscation(line)) {
        vulnerabilities.push({
          id: `m9-missing-obfuscation-${index}`,
          mobileId,
          title: 'Missing Code Obfuscation',
          description: 'Sensitive code lacks obfuscation protection',
          severity: VulnerabilitySeverity.LOW,
          category: 'Code Protection',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Implement code obfuscation for sensitive functionality',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering'],
          cweId: 311
        });
      }

      // Check for debug symbols
      if (this.hasDebugSymbols(line)) {
        vulnerabilities.push({
          id: `m9-debug-symbols-${index}`,
          mobileId,
          title: 'Debug Symbols Present',
          description: 'Debug symbols present in production build',
          severity: VulnerabilitySeverity.LOW,
          category: 'Code Protection',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Strip debug symbols from production builds',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering'],
          cweId: 200
        });
      }
    });

    return vulnerabilities;
  }

  // M10: Extraneous Functionality
  private async scanExtraneousFunctionality(
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string,
    mobileId: string,
    appAnalysis: MobileApp
  ): Promise<MobileSecurityVulnerability[]> {
    const vulnerabilities: MobileSecurityVulnerability[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for debug endpoints
      if (this.hasDebugEndpoints(line)) {
        vulnerabilities.push({
          id: `m10-debug-endpoints-${index}`,
          mobileId,
          title: 'Debug Endpoints Present',
          description: 'Debug or test endpoints accessible in production',
          severity: VulnerabilitySeverity.MEDIUM,
          category: 'Extraneous Functionality',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Remove debug endpoints from production builds',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m10-extraneous-functionality'],
          cweId: 489
        });
      }

      // Check for test code in production
      if (this.hasTestCodeInProduction(line)) {
        vulnerabilities.push({
          id: `m10-test-code-${index}`,
          mobileId,
          title: 'Test Code in Production',
          description: 'Test or development code present in production build',
          severity: VulnerabilitySeverity.LOW,
          category: 'Extraneous Functionality',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Remove test and development code from production builds',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m10-extraneous-functionality'],
          cweId: 489
        });
      }

      // Check for backdoor functionality
      if (this.hasBackdoorFunctionality(line)) {
        vulnerabilities.push({
          id: `m10-backdoor-${index}`,
          mobileId,
          title: 'Potential Backdoor Functionality',
          description: 'Code contains patterns that may indicate backdoor functionality',
          severity: VulnerabilitySeverity.CRITICAL,
          category: 'Extraneous Functionality',
          file: filePath,
          line: index + 1,
          code: line.trim(),
          platform: appAnalysis.platform,
          remediation: 'Review and remove any backdoor or hidden functionality',
          references: ['https://owasp.org/www-project-mobile-top-10/2016-risks/m10-extraneous-functionality'],
          cweId: 506
        });
      }
    });

    return vulnerabilities;
  }

  // Helper methods
  private createEmptyResult(): MobileScanResult {
    return {
      vulnerabilities: [],
      appAnalysis: {
        platform: 'Cross-Platform',
        framework: 'Unknown',
        permissions: [],
        dataStorage: [],
        networkUsage: [],
        cryptoUsage: [],
        authMechanisms: []
      },
      analysis: {
        hasMobileFrameworks: false,
        detectedPlatforms: [],
        mobileFrameworks: []
      },
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        byPlatform: new Map(),
        categories: new Map()
      },
      complianceMatrix: new Map(),
      recommendations: []
    };
  }

  private mergeResults(target: MobileScanResult, source: MobileScanResult): void {
    target.vulnerabilities.push(...source.vulnerabilities);
    
    // Merge app analysis
    if (source.appAnalysis.framework !== 'Unknown') {
      target.appAnalysis = source.appAnalysis;
    }
    
    // Merge compliance matrix
    source.complianceMatrix.forEach((value, key) => {
      const existing = target.complianceMatrix.get(key) ?? true;
      target.complianceMatrix.set(key, existing && value);
    });
  }

  private processResults(result: MobileScanResult): void {
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

      // Count by platform
      const count = result.summary.byPlatform.get(vuln.platform) || 0;
      result.summary.byPlatform.set(vuln.platform, count + 1);

      // Count by category
      const categoryCount = result.summary.categories.get(vuln.category) || 0;
      result.summary.categories.set(vuln.category, categoryCount + 1);
    });

    // Update analysis information
    result.analysis.hasMobileFrameworks = result.appAnalysis.framework !== 'Unknown';
    result.analysis.detectedPlatforms = [result.appAnalysis.platform];
    result.analysis.mobileFrameworks = [result.appAnalysis.framework];

    // Generate recommendations
    result.recommendations = this.generateMobileRecommendations(result);
  }

  private generateMobileRecommendations(result: MobileScanResult): string[] {
    const recommendations: string[] = [];

    if (result.summary.critical > 0) {
      recommendations.push(`🚨 Fix ${result.summary.critical} critical mobile security issues immediately`);
    }

    if (result.summary.high > 0) {
      recommendations.push(`⚠️ Address ${result.summary.high} high-severity mobile security issues`);
    }

    if (result.analysis.hasMobileFrameworks) {
      recommendations.push(`📱 Mobile framework detected: ${result.appAnalysis.framework}`);
      recommendations.push('🔒 Implement mobile-specific security controls');
    }

    if (result.summary.categories.has('Data Storage')) {
      recommendations.push('💾 Review data storage security practices');
    }

    if (result.summary.categories.has('Communication')) {
      recommendations.push('📡 Ensure secure network communication');
    }

    if (result.summary.total === 0) {
      recommendations.push('✅ Mobile security appears well-implemented');
    }

    return recommendations.slice(0, 5);
  }

  private isMobileFile(filePath: string): boolean {
    const mobileIndicators = [
      '/ios/', '/android/', '/mobile/', '/app/',
      'react-native', 'ionic', 'cordova', 'phonegap',
      '.tsx', '.jsx', '.swift', '.kt', '.java'
    ];
    
    return mobileIndicators.some(indicator => filePath.toLowerCase().includes(indicator));
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

  // Platform and framework detection methods
  private mapPlatform(detectedPlatform: string): 'iOS' | 'Android' | 'Cross-Platform' | 'Web' {
    switch (detectedPlatform) {
      case 'iOS':
        return 'iOS';
      case 'Android':
        return 'Android';
      case 'ReactNative':
      case 'Ionic':
        return 'Cross-Platform';
      default:
        return 'Cross-Platform';
    }
  }

  private isMobileLibrary(importSource: string): boolean {
    return this.mobileFrameworks.has(importSource) ||
           /react-native|ionic|cordova|phonegap|xamarin/i.test(importSource);
  }

  private isStorageLibrary(importSource: string): boolean {
    const storageLibraries = [
      'async-storage', '@react-native-async-storage',
      'expo-secure-store', 'react-native-keychain',
      'sqlite', 'realm', 'mmkv'
    ];
    return storageLibraries.some(lib => importSource.includes(lib));
  }

  private isNetworkLibrary(importSource: string): boolean {
    const networkLibraries = ['axios', 'fetch', 'xhr', 'http', 'https'];
    return networkLibraries.some(lib => importSource.includes(lib));
  }

  private isCryptoLibrary(importSource: string): boolean {
    const cryptoLibraries = ['crypto', 'cryptojs', 'bcrypt', 'crypto-js'];
    return cryptoLibraries.some(lib => importSource.includes(lib));
  }

  private isAuthLibrary(importSource: string): boolean {
    const authLibraries = ['auth', 'passport', 'jwt', 'oauth', 'biometric'];
    return authLibraries.some(lib => importSource.includes(lib));
  }

  private extractPermissions(code: string): string[] {
    const permissions: string[] = [];
    const permissionPatterns = [
      /permission\s*[=:]\s*['"]([^'"]+)['"]/gi,
      /requestPermission\s*\(\s*['"]([^'"]+)['"]/gi,
      /uses-permission.*android:name=['"]([^'"]+)['"]/gi
    ];

    permissionPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        permissions.push(match[1]);
      }
    });

    return permissions;
  }

  // Detection helper methods for vulnerabilities
  private hasDeprecatedAPIUsage(line: string, platform: string): boolean {
    const deprecatedPatterns = new Map([
      ['iOS', /UIWebView|NSURLConnection|SecRandomCopyBytes/i],
      ['Android', /WebView\.loadUrl|HttpURLConnection|SSLSocketFactory/i],
      ['Cross-Platform', /deprecated|obsolete/i]
    ]);

    const pattern = deprecatedPatterns.get(platform);
    return pattern ? pattern.test(line) : false;
  }

  private hasExcessivePermissions(line: string): boolean {
    const dangerousPermissions = [
      'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
      'ACCESS_FINE_LOCATION', 'CAMERA', 'RECORD_AUDIO',
      'READ_CONTACTS', 'SEND_SMS'
    ];
    return dangerousPermissions.some(perm => line.includes(perm));
  }

  private hasUnencryptedSensitiveStorage(code: string, platform: string): boolean {
    const sensitiveDataPatterns = /password|token|key|secret|credential/i;
    const storagePatterns = new Map([
      ['iOS', /NSUserDefaults|UserDefaults/i],
      ['Android', /SharedPreferences|SQLiteDatabase/i],
      ['Cross-Platform', /AsyncStorage|localStorage|setItem/i]
    ]);

    const storagePattern = storagePatterns.get(platform) || storagePatterns.get('Cross-Platform');
    return sensitiveDataPatterns.test(code) && storagePattern!.test(code) && 
           !/encrypt|secure|keychain|keystore/i.test(code);
  }

  private hasExternalStorageMisuse(code: string, platform: string): boolean {
    const externalStoragePatterns = new Map([
      ['Android', /getExternalStorageDirectory|EXTERNAL_STORAGE/i],
      ['iOS', /NSDocumentDirectory.*NSUserDomainMask/i]
    ]);

    const pattern = externalStoragePatterns.get(platform);
    return pattern ? pattern.test(code) && /password|token|key|secret/i.test(code) : false;
  }

  private hasInsecureHTTP(line: string): boolean {
    return /http:\/\/(?!localhost|127\.0\.0\.1)/i.test(line);
  }

  private hasDisabledCertificateValidation(line: string): boolean {
    const disablePatterns = [
      /trustAllCerts|trustAll|allowAllHostnames/i,
      /setHostnameVerifier.*ALLOW_ALL/i,
      /verify.*return\s+true/i,
      /checkServerTrusted.*{}/i
    ];
    return disablePatterns.some(pattern => pattern.test(line));
  }

  private hasWeakTLSConfiguration(line: string): boolean {
    return /SSLv3|TLSv1\.0|TLSv1\.1|SSL_ALLOW_ALL/i.test(line);
  }

  private hasWeakAuthentication(code: string): boolean {
    return /password.*==|password.*equals|hardcoded.*auth/i.test(code) &&
           !/bcrypt|scrypt|argon2|pbkdf2/i.test(code);
  }

  private hasMissingBiometricValidation(code: string, platform: string): boolean {
    const biometricPatterns = new Map([
      ['iOS', /TouchID|FaceID|BiometricAuthentication/i],
      ['Android', /BiometricPrompt|FingerprintManager/i]
    ]);

    const pattern = biometricPatterns.get(platform);
    return pattern ? pattern.test(code) && !/fallback|error.*handling/i.test(code) : false;
  }

  private hasWeakEncryption(line: string): boolean {
    return /DES|3DES|RC4|MD5|SHA1(?!.*HMAC)|ECB/i.test(line);
  }

  private hasHardcodedCryptoKeys(line: string): boolean {
    return /key\s*[=:]\s*['"][A-Fa-f0-9]{16,}['"]|iv\s*[=:]\s*['"][A-Fa-f0-9]{16,}['"]/i.test(line);
  }

  private hasCustomCryptoImplementation(line: string): boolean {
    return /function.*encrypt|function.*decrypt|class.*Crypto/i.test(line) &&
           !/CryptoJS|crypto-js|native.*crypto/i.test(line);
  }

  private hasMissingAuthorization(code: string): boolean {
    const sensitiveOperations = /delete|update|admin|private|sensitive/i;
    return sensitiveOperations.test(code) && 
           !/authorize|permission|role|canAccess/i.test(code);
  }

  private hasClientSideAuthorization(code: string): boolean {
    return /if.*role.*==.*admin|if.*user.*type.*admin/i.test(code) &&
           !/server|backend|api\.verify/i.test(code);
  }

  private hasBufferOverflowRisk(line: string): boolean {
    return /strcpy|strcat|sprintf|gets(?!\w)/i.test(line);
  }

  private hasFormatStringVulnerability(line: string): boolean {
    return /printf.*%.*user|sprintf.*%.*input|NSLog.*%.*user/i.test(line);
  }

  private hasMissingAntiTampering(line: string, platform: string): boolean {
    const criticalFunctions = /auth|payment|license|verify/i;
    const antiTamperingPatterns = /integrity.*check|checksum|signature.*verify/i;
    
    return criticalFunctions.test(line) && !antiTamperingPatterns.test(line);
  }

  private hasDebugCodeInProduction(line: string): boolean {
    return /console\.log|NSLog|Log\.d|debugger|DEBUG/i.test(line) &&
           !/if.*debug|ifdef.*debug/i.test(line);
  }

  private hasMissingCodeObfuscation(line: string): boolean {
    const sensitivePatterns = /api.*key|secret|algorithm|crypto/i;
    return sensitivePatterns.test(line) && !/obfuscated|protected|encrypted/i.test(line);
  }

  private hasDebugSymbols(line: string): boolean {
    return /\.dSYM|debug.*info|symbol.*table/i.test(line);
  }

  private hasDebugEndpoints(line: string): boolean {
    return /\/debug|\/test|\/dev|\.debug|\.test/i.test(line);
  }

  private hasTestCodeInProduction(line: string): boolean {
    return /test.*function|mock.*data|fixture|stub/i.test(line) &&
           !/if.*test|ifdef.*test/i.test(line);
  }

  private hasBackdoorFunctionality(line: string): boolean {
    return /backdoor|master.*key|god.*mode|override.*auth|bypass.*security/i.test(line);
  }
}