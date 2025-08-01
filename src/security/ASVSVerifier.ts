import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/types';
import { ASTParser } from '../parser/ASTParser';
import { logger } from '../utils/logger';

export interface ASVSControl {
  id: string;
  level: 1 | 2 | 3;
  category: string;
  subcategory: string;
  requirement: string;
  description: string;
  testable: boolean;
  automated: boolean;
  cwe: number[];
}

export interface ASVSControlResult {
  control: ASVSControl;
  status: 'pass' | 'fail' | 'not_applicable' | 'manual_review';
  confidence: number;
  evidence: string[];
  violations: Array<{
    file: string;
    line: number;
    description: string;
    code: string;
  }>;
  remediation: string;
}

export interface ASVSAssessment {
  projectPath: string;
  timestamp: string;
  level: 1 | 2 | 3;
  summary: {
    totalControls: number;
    passed: number;
    failed: number;
    notApplicable: number;
    manualReview: number;
    complianceScore: number;
  };
  results: ASVSControlResult[];
  recommendations: string[];
  nextSteps: string[];
}

export class ASVSVerifier {
  private astParser: ASTParser;
  private controls: Map<string, ASVSControl> = new Map();

  constructor() {
    this.astParser = new ASTParser();
    this.initializeASVSControls();
  }

  private initializeASVSControls(): void {
    const controls: ASVSControl[] = [
      // V1: Architecture, Design and Threat Modeling
      {
        id: 'V1.1.1',
        level: 1,
        category: 'Architecture',
        subcategory: 'Secure Software Development Lifecycle',
        requirement: 'Verify the use of a secure software development lifecycle',
        description: 'Application security requirements are defined and documented',
        testable: false,
        automated: false,
        cwe: [657]
      },
      {
        id: 'V1.2.1',
        level: 1,
        category: 'Architecture',
        subcategory: 'Authentication Architecture',
        requirement: 'Verify authentication architecture',
        description: 'Authentication controls are centrally implemented',
        testable: true,
        automated: true,
        cwe: [306]
      },

      // V2: Authentication
      {
        id: 'V2.1.1',
        level: 1,
        category: 'Authentication',
        subcategory: 'Password Security',
        requirement: 'Verify password length and complexity',
        description: 'Passwords are at least 12 characters or 8 characters with complexity',
        testable: true,
        automated: true,
        cwe: [521]
      },
      {
        id: 'V2.1.2',
        level: 1,
        category: 'Authentication',
        subcategory: 'Password Security',
        requirement: 'Verify passwords over 64 characters are permitted',
        description: 'Long passwords up to 128 characters are supported',
        testable: true,
        automated: true,
        cwe: [521]
      },
      {
        id: 'V2.1.3',
        level: 1,
        category: 'Authentication',
        subcategory: 'Password Security',
        requirement: 'Verify password truncation is not performed',
        description: 'Passwords are not silently truncated',
        testable: true,
        automated: true,
        cwe: [521]
      },
      {
        id: 'V2.2.1',
        level: 2,
        category: 'Authentication',
        subcategory: 'Multi-Factor Authentication',
        requirement: 'Verify MFA is enforced for administrative interfaces',
        description: 'Multi-factor authentication protects high-value transactions',
        testable: true,
        automated: false,
        cwe: [287]
      },

      // V3: Session Management
      {
        id: 'V3.1.1',
        level: 1,
        category: 'Session Management',
        subcategory: 'Session Security',
        requirement: 'Verify session tokens use secure random generation',
        description: 'Session tokens are generated using cryptographically secure random',
        testable: true,
        automated: true,
        cwe: [330]
      },
      {
        id: 'V3.2.1',
        level: 1,
        category: 'Session Management',
        subcategory: 'Session Attributes',
        requirement: 'Verify session cookies have secure attributes',
        description: 'Cookies have secure, httpOnly, and appropriate sameSite attributes',
        testable: true,
        automated: true,
        cwe: [614]
      },
      {
        id: 'V3.2.2',
        level: 1,
        category: 'Session Management',
        subcategory: 'Session Attributes',
        requirement: 'Verify session timeout implementation',
        description: 'Sessions timeout after inactivity',
        testable: true,
        automated: true,
        cwe: [613]
      },

      // V4: Access Control
      {
        id: 'V4.1.1',
        level: 1,
        category: 'Access Control',
        subcategory: 'General Access Control',
        requirement: 'Verify application enforces access controls',
        description: 'Trusted service layer enforces access controls',
        testable: true,
        automated: true,
        cwe: [284]
      },
      {
        id: 'V4.1.2',
        level: 1,
        category: 'Access Control',
        subcategory: 'General Access Control',
        requirement: 'Verify direct object references are protected',
        description: 'Direct object references are protected by access controls',
        testable: true,
        automated: true,
        cwe: [639]
      },
      {
        id: 'V4.2.1',
        level: 1,
        category: 'Access Control',
        subcategory: 'Operation Level Access Control',
        requirement: 'Verify sensitive data and APIs are protected',
        description: 'Sensitive resources have additional authorization',
        testable: true,
        automated: true,
        cwe: [285]
      },

      // V5: Validation, Sanitization and Encoding
      {
        id: 'V5.1.1',
        level: 1,
        category: 'Validation',
        subcategory: 'Input Validation',
        requirement: 'Verify input validation is performed',
        description: 'Input validation controls are implemented',
        testable: true,
        automated: true,
        cwe: [20]
      },
      {
        id: 'V5.1.2',
        level: 1,
        category: 'Validation',
        subcategory: 'Input Validation',
        requirement: 'Verify structured data is validated',
        description: 'Structured data like JSON and XML is schema validated',
        testable: true,
        automated: true,
        cwe: [20]
      },
      {
        id: 'V5.3.1',
        level: 1,
        category: 'Validation',
        subcategory: 'Output Encoding',
        requirement: 'Verify output encoding is context-appropriate',
        description: 'Output encoding is applied based on output context',
        testable: true,
        automated: true,
        cwe: [116]
      },

      // V6: Stored Cryptography
      {
        id: 'V6.1.1',
        level: 1,
        category: 'Cryptography',
        subcategory: 'Data Classification',
        requirement: 'Verify sensitive data identification',
        description: 'Sensitive data is identified and classified',
        testable: false,
        automated: false,
        cwe: [200]
      },
      {
        id: 'V6.2.1',
        level: 1,
        category: 'Cryptography',
        subcategory: 'Algorithms',
        requirement: 'Verify approved cryptographic algorithms',
        description: 'Only approved, strong cryptographic algorithms are used',
        testable: true,
        automated: true,
        cwe: [327]
      },
      {
        id: 'V6.2.2',
        level: 2,
        category: 'Cryptography',
        subcategory: 'Algorithms',
        requirement: 'Verify random number generation',
        description: 'Cryptographically secure random number generators are used',
        testable: true,
        automated: true,
        cwe: [338]
      },

      // V7: Error Handling and Logging
      {
        id: 'V7.1.1',
        level: 1,
        category: 'Error Handling',
        subcategory: 'Log Content',
        requirement: 'Verify no sensitive information in logs',
        description: 'Logs do not contain sensitive information',
        testable: true,
        automated: true,
        cwe: [532]
      },
      {
        id: 'V7.1.2',
        level: 1,
        category: 'Error Handling',
        subcategory: 'Log Content',
        requirement: 'Verify security events are logged',
        description: 'Security events are logged with sufficient detail',
        testable: true,
        automated: false,
        cwe: [778]
      },
      {
        id: 'V7.4.1',
        level: 1,
        category: 'Error Handling',
        subcategory: 'Error Handling',
        requirement: 'Verify generic error messages',
        description: 'Error messages do not reveal sensitive information',
        testable: true,
        automated: true,
        cwe: [209]
      }
    ];

    controls.forEach(control => {
      this.controls.set(control.id, control);
    });

    logger.info(`Initialized ${controls.length} ASVS controls`);
  }

  public async assessFile(filePath: string, targetLevel: 1 | 2 | 3 = 1): Promise<ASVSControlResult[]> {
    try {
      logger.info(`Running ASVS assessment on: ${filePath}`);
      
      const content = await this.astParser.parseFile(filePath);
      if (!content) {
        logger.warn(`Could not parse file: ${filePath}`);
        return [];
      }

      const results: ASVSControlResult[] = [];
      const applicableControls = Array.from(this.controls.values())
        .filter(control => control.level <= targetLevel && control.automated);

      for (const control of applicableControls) {
        const result = await this.assessControl(control, content, filePath);
        results.push(result);
      }

      return results;
    } catch (error) {
      logger.error(`Error running ASVS assessment on ${filePath}:`, error);
      return [];
    }
  }

  public async assessProject(projectPath: string, targetLevel: 1 | 2 | 3 = 1): Promise<ASVSAssessment> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const allResults: ASVSControlResult[] = [];
    
    try {
      const entries = await fs.readdir(projectPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(projectPath, entry.name);
        
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
            continue;
          }
          const subResults = await this.assessProject(fullPath, targetLevel);
          allResults.push(...subResults.results);
        } else if (entry.isFile() && this.isAssessableFile(entry.name)) {
          const fileResults = await this.assessFile(fullPath, targetLevel);
          allResults.push(...fileResults);
        }
      }
    } catch (error) {
      logger.error(`Error assessing project ${projectPath}:`, error);
    }

    return this.generateAssessment(projectPath, targetLevel, allResults);
  }

  private async assessControl(
    control: ASVSControl,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): Promise<ASVSControlResult> {
    const result: ASVSControlResult = {
      control,
      status: 'not_applicable',
      confidence: 0,
      evidence: [],
      violations: [],
      remediation: ''
    };

    switch (control.id) {
      case 'V2.1.1':
        return this.assessPasswordComplexity(result, content, filePath);
      case 'V2.1.2':
        return this.assessPasswordLength(result, content, filePath);
      case 'V3.1.1':
        return this.assessSessionRandomness(result, content, filePath);
      case 'V3.2.1':
        return this.assessCookieAttributes(result, content, filePath);
      case 'V4.1.1':
        return this.assessAccessControls(result, content, filePath);
      case 'V4.1.2':
        return this.assessDirectObjectReferences(result, content, filePath);
      case 'V5.1.1':
        return this.assessInputValidation(result, content, filePath);
      case 'V5.3.1':
        return this.assessOutputEncoding(result, content, filePath);
      case 'V6.2.1':
        return this.assessCryptographicAlgorithms(result, content, filePath);
      case 'V6.2.2':
        return this.assessRandomGeneration(result, content, filePath);
      case 'V7.1.1':
        return this.assessLogSensitivity(result, content, filePath);
      case 'V7.4.1':
        return this.assessErrorMessages(result, content, filePath);
      default:
        result.status = 'manual_review';
        result.remediation = 'This control requires manual assessment';
        return result;
    }
  }

  private assessPasswordComplexity(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    // Look for password validation patterns
    const lines = content.sourceCode.split('\n');
    let hasPasswordValidation = false;
    let hasComplexityRules = false;

    lines.forEach((line, index) => {
      // Check for password validation
      if (/password.*valid|valid.*password|password.*check|check.*password/i.test(line)) {
        hasPasswordValidation = true;
        evidence.push(`Password validation found at line ${index + 1}`);
      }

      // Check for complexity requirements
      if (/minlength.*[8-9]|minlength.*1[0-9]|length.*>=.*[8-9]|length.*>=.*1[0-9]/i.test(line)) {
        hasComplexityRules = true;
        evidence.push(`Password length requirement found at line ${index + 1}`);
      }

      // Check for weak password patterns
      if (/password.*=.*['"][^'"]{1,7}['"]|minlength.*[1-7][^0-9]/i.test(line)) {
        violations.push({
          file: filePath,
          line: index + 1,
          description: 'Weak password requirements detected',
          code: line.trim()
        });
      }
    });

    if (hasPasswordValidation && hasComplexityRules && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.8;
      result.remediation = 'Password complexity requirements appear to be implemented';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Implement strong password requirements: minimum 8 characters with complexity or 12 characters minimum';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No password validation logic detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessSessionRandomness(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for secure random generation
        if (/crypto\.random|crypto\.webcrypto|randomUUID|randomBytes/.test(code)) {
          evidence.push(`Secure random generation found: ${code.slice(0, 50)}`);
        }
        
        // Check for weak random generation in session context
        if (/session.*Math\.random|token.*Math\.random|sessionid.*Math\.random/.test(code)) {
          violations.push({
            file: filePath,
            line: node.loc?.start.line || 0,
            description: 'Weak random number generation for session tokens',
            code: code.slice(0, 100)
          });
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.8;
      result.remediation = 'Secure random generation appears to be used';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Use cryptographically secure random number generation for session tokens';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No session token generation detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessCookieAttributes(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      if (/cookie|setCookie/i.test(line)) {
        if (/secure.*true|httponly.*true|samesite/i.test(line)) {
          evidence.push(`Secure cookie attributes found at line ${index + 1}`);
        } else if (!/secure|httponly|samesite/i.test(line)) {
          violations.push({
            file: filePath,
            line: index + 1,
            description: 'Cookie missing security attributes',
            code: line.trim()
          });
        }
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.8;
      result.remediation = 'Cookie security attributes appear to be properly configured';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Configure cookies with secure, httpOnly, and sameSite attributes';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No cookie usage detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessAccessControls(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.FunctionDeclaration || node.type === AST_NODE_TYPES.ArrowFunctionExpression) {
        if (this.isAPIEndpoint(node, filePath)) {
          const code = this.getNodeCode(node, content.sourceCode);
          
          if (/auth|permission|role|authorize/.test(code)) {
            evidence.push(`Access control found in API endpoint`);
          } else {
            violations.push({
              file: filePath,
              line: node.loc?.start.line || 0,
              description: 'API endpoint missing access control',
              code: code.slice(0, 100)
            });
          }
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.7;
      result.remediation = 'Access controls appear to be implemented';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.8;
      result.remediation = 'Implement proper access controls for all API endpoints';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No API endpoints detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessDirectObjectReferences(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const traverse = (node: TSESTree.Node) => {
      if (node.type === AST_NODE_TYPES.CallExpression) {
        const code = this.getNodeCode(node, content.sourceCode);
        
        // Check for database operations with user input
        if (this.isDatabaseOperation(code) && this.hasUserInput(node, content.sourceCode)) {
          if (/owner|user.*id|permission|authorize/.test(code)) {
            evidence.push(`Protected object access found`);
          } else {
            violations.push({
              file: filePath,
              line: node.loc?.start.line || 0,
              description: 'Potential insecure direct object reference',
              code: code.slice(0, 100)
            });
          }
        }
      }

      this.traverseNode(node, traverse);
    };

    traverse(content.ast);

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.7;
      result.remediation = 'Object access appears to be properly protected';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.8;
      result.remediation = 'Verify object ownership or permissions before allowing access';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No direct object references detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessInputValidation(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      if (/req\.body|req\.query|req\.params|params\.|body\./.test(line)) {
        if (/validate|sanitize|parse|schema|zod|joi|yup/.test(line)) {
          evidence.push(`Input validation found at line ${index + 1}`);
        } else if (!/validate|sanitize|parse/.test(line)) {
          violations.push({
            file: filePath,
            line: index + 1,
            description: 'User input processed without validation',
            code: line.trim()
          });
        }
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.7;
      result.remediation = 'Input validation appears to be implemented';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.8;
      result.remediation = 'Validate and sanitize all user inputs';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No user input processing detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessOutputEncoding(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      if (/dangerouslySetInnerHTML/.test(line)) {
        if (/DOMPurify|sanitize|escape/.test(line)) {
          evidence.push(`Output sanitization found at line ${index + 1}`);
        } else {
          violations.push({
            file: filePath,
            line: index + 1,
            description: 'Unsafe HTML rendering without sanitization',
            code: line.trim()
          });
        }
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.8;
      result.remediation = 'Output encoding appears to be properly implemented';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Sanitize HTML content before rendering';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No HTML rendering detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessCryptographicAlgorithms(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for weak algorithms
      if (/md5|sha1|des|rc4|blowfish/i.test(line) && !/comment|\/\/|\/\*/.test(line)) {
        violations.push({
          file: filePath,
          line: index + 1,
          description: 'Weak cryptographic algorithm detected',
          code: line.trim()
        });
      }
      
      // Check for strong algorithms
      if (/aes|sha256|sha512|pbkdf2|bcrypt|scrypt|argon2/i.test(line)) {
        evidence.push(`Strong cryptographic algorithm found at line ${index + 1}`);
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.8;
      result.remediation = 'Strong cryptographic algorithms appear to be used';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Replace weak cryptographic algorithms with strong alternatives';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No cryptographic operations detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessRandomGeneration(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      // Check for weak random generation
      if (/Math\.random|Date\.now.*random|new Date.*random/.test(line)) {
        violations.push({
          file: filePath,
          line: index + 1,
          description: 'Weak random number generation detected',
          code: line.trim()
        });
      }
      
      // Check for secure random generation
      if (/crypto\.getRandomValues|crypto\.randomBytes|crypto\.randomUUID|webcrypto/.test(line)) {
        evidence.push(`Secure random generation found at line ${index + 1}`);
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.8;
      result.remediation = 'Cryptographically secure random generation appears to be used';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Use cryptographically secure random number generators';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No random number generation detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessLogSensitivity(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      if (/log|console\.|logger/.test(line)) {
        // Check for sensitive data in logs
        if (/password|secret|token|key|ssn|credit.*card/i.test(line) && !/\*\*\*|redacted|masked/.test(line)) {
          violations.push({
            file: filePath,
            line: index + 1,
            description: 'Sensitive information logged without redaction',
            code: line.trim()
          });
        } else if (/\*\*\*|redacted|masked/.test(line)) {
          evidence.push(`Redacted logging found at line ${index + 1}`);
        }
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.7;
      result.remediation = 'Sensitive data appears to be properly redacted in logs';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.9;
      result.remediation = 'Remove or redact sensitive information from log messages';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No logging detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  private assessErrorMessages(
    result: ASVSControlResult,
    content: { ast: TSESTree.Program; sourceCode: string },
    filePath: string
  ): ASVSControlResult {
    const violations: Array<{ file: string; line: number; description: string; code: string }> = [];
    const evidence: string[] = [];

    const lines = content.sourceCode.split('\n');
    lines.forEach((line, index) => {
      if (/throw|error|exception/.test(line) && /message|string/.test(line)) {
        // Check for verbose error messages
        if (/\.stack|\.message|error\./i.test(line) && /res\.|response\.|send\(|json\(/i.test(line)) {
          violations.push({
            file: filePath,
            line: index + 1,
            description: 'Verbose error message may leak sensitive information',
            code: line.trim()
          });
        } else if (/generic|unauthorized|forbidden|error occurred/i.test(line)) {
          evidence.push(`Generic error message found at line ${index + 1}`);
        }
      }
    });

    if (evidence.length > 0 && violations.length === 0) {
      result.status = 'pass';
      result.confidence = 0.7;
      result.remediation = 'Generic error messages appear to be used appropriately';
    } else if (violations.length > 0) {
      result.status = 'fail';
      result.confidence = 0.8;
      result.remediation = 'Use generic error messages to avoid information disclosure';
    } else {
      result.status = 'not_applicable';
      result.confidence = 0.5;
      result.remediation = 'No error handling detected in this file';
    }

    result.evidence = evidence;
    result.violations = violations;
    return result;
  }

  // Additional assessment methods would go here for other controls...
  private assessPasswordLength(result: ASVSControlResult, content: any, filePath: string): ASVSControlResult {
    // Implement password length assessment logic
    result.status = 'manual_review';
    result.remediation = 'Manually verify password length requirements';
    return result;
  }

  private generateAssessment(projectPath: string, level: 1 | 2 | 3, results: ASVSControlResult[]): ASVSAssessment {
    const summary = {
      totalControls: results.length,
      passed: results.filter(r => r.status === 'pass').length,
      failed: results.filter(r => r.status === 'fail').length,
      notApplicable: results.filter(r => r.status === 'not_applicable').length,
      manualReview: results.filter(r => r.status === 'manual_review').length,
      complianceScore: 0
    };

    const applicableControls = summary.totalControls - summary.notApplicable;
    if (applicableControls > 0) {
      summary.complianceScore = Math.round((summary.passed / applicableControls) * 100);
    }

    const recommendations: string[] = [];
    if (summary.failed > 0) {
      recommendations.push(`🚨 Address ${summary.failed} failed ASVS controls immediately`);
    }
    if (summary.manualReview > 0) {
      recommendations.push(`👀 ${summary.manualReview} controls require manual review`);
    }
    if (summary.complianceScore >= 80) {
      recommendations.push(`✅ Good ASVS Level ${level} compliance (${summary.complianceScore}%)`);
    } else {
      recommendations.push(`⚠️ ASVS Level ${level} compliance needs improvement (${summary.complianceScore}%)`);
    }

    const nextSteps: string[] = [];
    if (summary.failed > 0) {
      nextSteps.push('Prioritize fixing failed controls based on risk assessment');
    }
    if (summary.manualReview > 0) {
      nextSteps.push('Conduct manual assessment of controls requiring review');
    }
    if (level < 3) {
      nextSteps.push(`Consider progressing to ASVS Level ${level + 1} after achieving compliance`);
    }

    return {
      projectPath,
      timestamp: new Date().toISOString(),
      level,
      summary,
      results,
      recommendations,
      nextSteps
    };
  }

  // Helper methods
  private isAssessableFile(fileName: string): boolean {
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    return extensions.some(ext => fileName.endsWith(ext));
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

  private isAPIEndpoint(node: TSESTree.FunctionDeclaration | TSESTree.ArrowFunctionExpression, filePath: string): boolean {
    const functionName = node.type === AST_NODE_TYPES.FunctionDeclaration ? node.id?.name : undefined;
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    return httpMethods.includes(functionName?.toUpperCase() || '') && 
           (filePath.includes('/api/') || filePath.includes('/route.'));
  }

  private isDatabaseOperation(code: string): boolean {
    const dbOperations = ['select', 'insert', 'update', 'delete', 'find', 'query'];
    return dbOperations.some(op => code.toLowerCase().includes(op));
  }

  private hasUserInput(node: TSESTree.Node, sourceCode: string): boolean {
    const code = this.getNodeCode(node, sourceCode);
    const userInputPatterns = ['req.', 'params', 'body', 'query', 'input'];
    return userInputPatterns.some(pattern => code.includes(pattern));
  }

  public getControlById(id: string): ASVSControl | undefined {
    return this.controls.get(id);
  }

  public getControlsByLevel(level: 1 | 2 | 3): ASVSControl[] {
    return Array.from(this.controls.values()).filter(control => control.level <= level);
  }

  public getControlsByCategory(category: string): ASVSControl[] {
    return Array.from(this.controls.values()).filter(control => control.category === category);
  }
}