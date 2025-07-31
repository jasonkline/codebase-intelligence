export const databaseTemplate = {
  name: 'Database Architecture',
  category: 'database',
  
  overview: `
# Multi-Tenant Database Architecture

The database architecture implements complete data isolation between organizations 
using separate database instances per tenant, combined with Row Level Security (RLS) 
for additional protection. This ensures maximum security and regulatory compliance.
`,

  components: [
    {
      name: 'Database Connection Management',
      description: 'Manages authenticated database connections with organization context',
      implementation: `
export async function getOrgDatabaseWithAuth(): Promise<Database> {
  // Get current auth context (must be called within authenticated request)
  const authContext = getCurrentAuthContext()
  
  if (!authContext) {
    throw new Error('No authentication context available')
  }
  
  // Get organization-specific database connection
  const connectionString = await getOrgDatabaseConnection(authContext.orgSlug)
  
  // Create database client with RLS context
  const db = drizzle(connectionString, {
    schema,
    logger: true
  })
  
  // Set RLS context for this connection
  await setRLSContext(db, authContext)
  
  return db
}

async function setRLSContext(db: Database, context: AuthContext) {
  // Set organization context for RLS policies
  await db.execute(sql\`SET app.current_organization = \${context.orgSlug}\`)
  await db.execute(sql\`SET app.current_user_id = \${context.user.id}\`)
  await db.execute(sql\`SET app.current_user_role = \${context.role}\`)
}
`,
      securityNotes: [
        'Never use direct database connections without auth',
        'Always set RLS context before queries',
        'Validate organization access before connection',
        'Use connection pooling for performance'
      ]
    },
    {
      name: 'Row Level Security Policies',
      description: 'Database-level security policies that enforce organization isolation',
      implementation: `
-- Example RLS policy for organization isolation
CREATE POLICY org_isolation_policy ON users
  FOR ALL
  TO authenticated
  USING (
    organization_id = current_setting('app.current_organization')::uuid
  )
  WITH CHECK (
    organization_id = current_setting('app.current_organization')::uuid
  );

-- Role-based access policy
CREATE POLICY role_based_access ON sensitive_data
  FOR SELECT
  TO authenticated
  USING (
    CASE current_setting('app.current_user_role')
      WHEN 'admin' THEN true
      WHEN 'manager' THEN department_id = get_user_department()
      ELSE user_id = current_setting('app.current_user_id')::uuid
    END
  );
`,
      securityNotes: [
        'Enable RLS on all tables with sensitive data',
        'Test policies thoroughly with different roles',
        'Use database functions for complex access logic',
        'Monitor RLS policy performance'
      ]
    }
  ],

  flows: [
    {
      name: 'Secure Data Access Flow',
      steps: [
        'Authentication middleware validates user and extracts org context',
        'getOrgDatabaseWithAuth() called to get database connection',
        'Organization-specific connection string retrieved',
        'Database client created with RLS configuration',
        'RLS context set with organization and user information',
        'Query executed with automatic policy enforcement',
        'Results filtered by RLS policies before return'
      ],
      securityCheckpoints: [
        'Authentication context validation',
        'Organization access verification',
        'RLS context configuration',
        'Policy enforcement verification'
      ]
    },
    {
      name: 'Multi-Tenant Query Execution',
      steps: [
        'Application code calls database query method',
        'RLS policies automatically applied based on context',
        'Database filters results to organization scope',
        'Additional role-based filtering applied if configured',
        'Filtered results returned to application',
        'Application processes organization-scoped data'
      ],
      securityCheckpoints: [
        'Organization context verification',
        'RLS policy application',
        'Role-based access control',
        'Data scope validation'
      ]
    }
  ],

  securityConsiderations: [
    'All tables containing user data must have RLS enabled',
    'Never bypass RLS policies in application code',
    'Use database-level encryption for sensitive data',
    'Implement audit logging for all data access',
    'Regular security reviews of RLS policies',
    'Monitor for policy bypass attempts',
    'Backup and recovery procedures must maintain isolation'
  ],

  commonPatterns: [
    {
      name: 'Secure Database Query',
      pattern: `
export async function getUserData(userId: string) {
  // Get authenticated database connection
  const db = await getOrgDatabaseWithAuth()
  
  // Query will automatically apply RLS policies
  const userData = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1)
  
  return userData[0]
}
`,
      description: 'Standard pattern for secure database queries',
      whenToUse: 'For all database operations that access user or organization data'
    },
    {
      name: 'Organization-Scoped List Query',
      pattern: `
export async function getOrganizationProjects() {
  const db = await getOrgDatabaseWithAuth()
  
  // RLS automatically filters to current organization
  const projects = await db
    .select()
    .from(projects)
    .orderBy(desc(projects.created_at))
  
  return projects
}
`,
      description: 'Pattern for retrieving organization-scoped lists',
      whenToUse: 'When fetching lists of data that should be filtered by organization'
    },
    {
      name: 'Role-Based Data Access',
      pattern: `
export async function getSensitiveData() {
  const db = await getOrgDatabaseWithAuth()
  
  // This query will only return data the user's role allows
  const data = await db
    .select()
    .from(sensitive_table)
    .where(/* additional filters if needed */)
  
  return data
}
`,
      description: 'Pattern for role-based data access with RLS',
      whenToUse: 'When different user roles should see different subsets of data'
    }
  ],

  antiPatterns: [
    {
      name: 'Direct Database Connection',
      pattern: `
// ❌ NEVER DO THIS
const db = drizzle(DATABASE_URL)
const data = await db.select().from(users)
`,
      whyBad: 'Bypasses all security policies and organization isolation',
      correctApproach: 'Always use getOrgDatabaseWithAuth()'
    },
    {
      name: 'Hardcoded Organization Filter',
      pattern: `
// ❌ AVOID THIS
const data = await db
  .select()
  .from(users)
  .where(eq(users.org_id, 'hardcoded-org'))
`,
      whyBad: 'Breaks multi-tenancy and creates security vulnerabilities',
      correctApproach: 'Let RLS policies handle organization filtering automatically'
    }
  ],

  troubleshootingGuide: [
    {
      issue: 'Empty Query Results',
      symptoms: ['Queries return no data when data exists', 'Users cannot see their own data'],
      solutions: [
        'Verify RLS context is set correctly',
        'Check organization ID in auth context',
        'Validate RLS policies are not too restrictive',
        'Ensure user belongs to the organization'
      ]
    },
    {
      issue: 'Cross-Organization Data Leakage',
      symptoms: ['Users see data from other organizations', 'Data isolation is broken'],
      solutions: [
        'Review and test RLS policies',
        'Verify organization context is set properly',
        'Check for policy bypass in application code',
        'Audit database access patterns'
      ]
    },
    {
      issue: 'Performance Issues with RLS',
      symptoms: ['Slow query performance', 'Database timeouts'],
      solutions: [
        'Add indexes on organization_id columns',
        'Optimize RLS policy conditions',
        'Use database query analysis tools',
        'Consider denormalization for frequently accessed data'
      ]
    }
  ],

  testingGuidelines: [
    'Test data isolation between organizations',
    'Verify RLS policies with different user roles',
    'Test edge cases like deleted organizations',
    'Validate performance with realistic data volumes',
    'Test backup and restore procedures maintain isolation',
    'Verify audit logging captures all access attempts'
  ],

  migrationConsiderations: [
    'All migrations must maintain RLS policy compatibility',
    'Test migrations on copy of production data',
    'Verify schema changes don\'t break existing policies',
    'Update RLS policies when adding new columns',
    'Coordinate migrations across all tenant databases'
  ]
};

export default databaseTemplate;