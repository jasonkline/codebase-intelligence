export const securityTemplate = {
  name: 'Security Best Practices',
  category: 'security',
  
  overview: `
# Security Framework

The security framework implements defense-in-depth with multiple layers of protection:
authentication, authorization, data isolation, input validation, and monitoring. 
All security controls are designed to prevent common vulnerabilities while maintaining
usability and performance.
`,

  securityLayers: [
    {
      name: 'Authentication Layer',
      description: 'Verifies user identity using JWT tokens',
      controls: [
        'JWT token validation with secure signatures',
        'Token expiration and refresh mechanisms',
        'Multi-factor authentication support',
        'Session management and invalidation'
      ],
      threats: [
        'Token theft and replay attacks',
        'Weak token generation',
        'Session fixation',
        'Brute force attacks'
      ]
    },
    {
      name: 'Authorization Layer', 
      description: 'Enforces access control based on user roles and permissions',
      controls: [
        'Role-Based Access Control (RBAC)',
        'Organization-scoped permissions',
        'Resource-level access control',
        'Dynamic permission evaluation'
      ],
      threats: [
        'Privilege escalation',
        'Unauthorized resource access',
        'Missing access controls',
        'Insecure direct object references'
      ]
    },
    {
      name: 'Data Protection Layer',
      description: 'Protects data confidentiality and integrity',
      controls: [
        'Row Level Security (RLS) policies',
        'Data encryption at rest and in transit',
        'Organization data isolation',
        'Secure database connections'
      ],
      threats: [
        'Data breaches and leakage',
        'Cross-tenant data access',
        'SQL injection attacks',
        'Unencrypted sensitive data'
      ]
    }
  ],

  vulnerabilityCategories: [
    {
      category: 'Authentication Vulnerabilities',
      risks: [
        {
          name: 'Missing Authentication',
          description: 'API endpoints accessible without authentication',
          severity: 'CRITICAL',
          cweId: 'CWE-306',
          detection: 'Look for API routes without requireAuthWithTenant()',
          remediation: 'Add authentication middleware to all protected endpoints'
        },
        {
          name: 'Weak JWT Implementation',
          description: 'JWT tokens with weak secrets or algorithms',
          severity: 'HIGH',
          cweId: 'CWE-327',
          detection: 'Check JWT configuration and secret strength',
          remediation: 'Use strong secrets, secure algorithms, and proper validation'
        }
      ]
    },
    {
      category: 'Authorization Vulnerabilities',
      risks: [
        {
          name: 'Missing Authorization Checks',
          description: 'Authenticated endpoints without proper permission checks',
          severity: 'HIGH',
          cweId: 'CWE-285',
          detection: 'Look for endpoints missing hasPermission() calls',
          remediation: 'Implement role-based permission checks'
        },
        {
          name: 'Insecure Direct Object References',
          description: 'Direct access to objects without ownership validation',
          severity: 'HIGH',
          cweId: 'CWE-639',
          detection: 'Check for direct ID-based object access',
          remediation: 'Validate object ownership and permissions'
        }
      ]
    },
    {
      category: 'Data Security Vulnerabilities',
      risks: [
        {
          name: 'RLS Policy Bypass',
          description: 'Database access without proper RLS enforcement',
          severity: 'CRITICAL',
          cweId: 'CWE-284',
          detection: 'Look for direct database connections',
          remediation: 'Use getOrgDatabaseWithAuth() for all database access'
        },
        {
          name: 'SQL Injection',
          description: 'Unsanitized user input in database queries',
          severity: 'CRITICAL',
          cweId: 'CWE-89',
          detection: 'Check for string concatenation in queries',
          remediation: 'Use parameterized queries and input validation'
        }
      ]
    }
  ],

  securityPatterns: [
    {
      name: 'Secure API Endpoint',
      pattern: `
export async function POST() {
  try {
    // 1. Authentication check
    const { user, orgSlug, role } = await requireAuthWithTenant()
    
    // 2. Input validation
    const validatedData = await validateInput(request.body, schema)
    
    // 3. Authorization check
    if (!hasPermission(role, 'create:resource')) {
      return new Response('Forbidden', { status: 403 })
    }
    
    // 4. Secure database access
    const db = await getOrgDatabaseWithAuth()
    
    // 5. Business logic with sanitized input
    const result = await createResource(db, validatedData)
    
    // 6. Secure response
    return Response.json({ 
      success: true, 
      data: sanitizeOutput(result) 
    })
    
  } catch (error) {
    // 7. Secure error handling
    logger.error('API error:', error)
    return new Response('Internal Server Error', { status: 500 })
  }
}
`,
      description: 'Complete secure API endpoint pattern with all security controls',
      securityFeatures: [
        'Authentication verification',
        'Input validation and sanitization',
        'Authorization checks',
        'Secure database access',
        'Error handling without information leakage'
      ]
    },
    {
      name: 'Secure Data Query',
      pattern: `
export async function getUserProjects(userId: string) {
  // Validate input
  if (!isValidUUID(userId)) {
    throw new ValidationError('Invalid user ID')
  }
  
  // Get authenticated database connection
  const db = await getOrgDatabaseWithAuth()
  
  // Query with RLS enforcement
  const projects = await db
    .select({
      id: projects.id,
      name: projects.name,
      description: projects.description,
      // Exclude sensitive fields from selection
    })
    .from(projects)
    .where(eq(projects.userId, userId))
    .limit(100) // Prevent large result sets
  
  return projects
}
`,
      description: 'Secure data access pattern with input validation and RLS',
      securityFeatures: [
        'Input validation',
        'Authenticated database connection',
        'RLS policy enforcement',
        'Field filtering',
        'Result set limiting'
      ]
    }
  ],

  securityChecklist: [
    {
      category: 'Authentication',
      checks: [
        '✅ All protected endpoints use requireAuthWithTenant()',
        '✅ JWT tokens have strong secrets and secure algorithms',
        '✅ Token expiration is properly configured',
        '✅ Session invalidation works correctly',
        '✅ Password policies are enforced',
        '✅ Rate limiting is implemented on auth endpoints'
      ]
    },
    {
      category: 'Authorization',
      checks: [
        '✅ All endpoints have appropriate permission checks',
        '✅ RBAC roles and permissions are properly defined',
        '✅ Organization isolation is enforced',
        '✅ Resource ownership is validated',
        '✅ Admin functions require admin privileges',
        '✅ Default permissions are restrictive'
      ]
    },
    {
      category: 'Data Security',
      checks: [
        '✅ All database access uses getOrgDatabaseWithAuth()',
        '✅ RLS policies are enabled on all tables',
        '✅ Sensitive data is encrypted at rest',
        '✅ Database connections use SSL/TLS',
        '✅ Input validation prevents injection attacks',
        '✅ Output is sanitized to prevent XSS'
      ]
    },
    {
      category: 'Infrastructure',
      checks: [
        '✅ HTTPS is enforced for all communications',
        '✅ Security headers are properly configured',
        '✅ Secrets are managed securely',
        '✅ Logging captures security events',
        '✅ Error messages don\'t leak sensitive information',
        '✅ Dependencies are regularly updated'
      ]
    }
  ],

  incidentResponse: [
    {
      scenario: 'Authentication Bypass Detected',
      immediateActions: [
        'Identify and block the attack vector',
        'Invalidate potentially compromised sessions',
        'Review authentication logs for similar attempts',
        'Notify security team and stakeholders'
      ],
      investigation: [
        'Analyze attack patterns and techniques used',
        'Identify affected accounts and data',
        'Review code for authentication vulnerabilities',
        'Assess potential data exposure'
      ],
      remediation: [
        'Fix identified authentication vulnerabilities',
        'Strengthen authentication controls',
        'Update monitoring and detection rules',
        'Conduct security review of related systems'
      ]
    },
    {
      scenario: 'Data Breach or Unauthorized Access',
      immediateActions: [
        'Contain the breach and prevent further access',
        'Preserve evidence and logs',
        'Assess scope of compromised data',
        'Notify affected users and regulatory authorities'
      ],
      investigation: [
        'Determine how unauthorized access occurred',
        'Identify all affected data and systems',
        'Review access logs and user activities',
        'Assess compliance and legal implications'
      ],
      remediation: [
        'Fix security vulnerabilities that enabled breach',
        'Implement additional monitoring and controls',
        'Provide identity protection services to affected users',
        'Update security policies and procedures'
      ]
    }
  ],

  monitoringAndAlerting: [
    {
      metric: 'Authentication Failures',
      threshold: '>10 failures per user per minute',
      alert: 'Potential brute force attack',
      response: 'Temporarily block IP/user and investigate'
    },
    {
      metric: 'Privilege Escalation Attempts',
      threshold: 'Any attempt to access unauthorized resources',
      alert: 'Unauthorized access attempt',
      response: 'Block user and conduct security review'
    },
    {
      metric: 'Database Query Anomalies',
      threshold: 'Unusual query patterns or volumes',
      alert: 'Potential SQL injection or data exfiltration',
      response: 'Block suspicious queries and investigate'
    },
    {
      metric: 'Cross-Organization Data Access',
      threshold: 'Any successful cross-org data access',
      alert: 'Data isolation breach',
      response: 'Immediate investigation and system lockdown'
    }
  ],

  complianceConsiderations: [
    {
      framework: 'GDPR',
      requirements: [
        'Data protection by design and by default',
        'User consent and data minimization',
        'Right to access, rectify, and delete data',
        'Data breach notification within 72 hours',
        'Privacy impact assessments for high-risk processing'
      ],
      implementation: [
        'Implement privacy-first design patterns',
        'Provide user data export and deletion features',
        'Maintain audit logs for data processing activities',
        'Implement automated breach detection and notification',
        'Conduct regular privacy impact assessments'
      ]
    },
    {
      framework: 'SOC 2',
      requirements: [
        'Security controls for data protection',
        'Access controls and user provisioning',
        'System operations and monitoring',
        'Risk management and incident response',
        'Vendor management and due diligence'
      ],
      implementation: [
        'Document and test security controls regularly',
        'Implement automated access provisioning and deprovisioning',
        'Maintain comprehensive system monitoring and logging',
        'Establish formal incident response procedures',
        'Conduct vendor security assessments'
      ]
    }
  ]
};

export default securityTemplate;