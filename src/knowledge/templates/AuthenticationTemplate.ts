export const authenticationTemplate = {
  name: 'Authentication System',
  category: 'auth',
  
  overview: `
# Authentication System

The authentication system provides secure user authentication and session management 
using JWT tokens with organization context. It ensures proper security boundaries 
and multi-tenant isolation.
`,

  components: [
    {
      name: 'Authentication Middleware',
      description: 'Validates JWT tokens and extracts user context',
      implementation: `
export async function requireAuthWithTenant() {
  // Extract JWT token from request
  const token = extractTokenFromRequest()
  
  // Validate token signature and expiration
  const decoded = await verifyJWT(token)
  
  // Extract user context
  const { user, orgSlug, role } = decoded
  
  // Validate organization membership
  await validateOrganizationMembership(user.id, orgSlug)
  
  return { user, orgSlug, role }
}
`,
      securityNotes: [
        'Always validate token signature',
        'Check token expiration',
        'Verify organization membership',
        'Use secure JWT secrets'
      ]
    },
    {
      name: 'Session Management',
      description: 'Handles JWT token lifecycle and refresh',
      implementation: `
export class SessionManager {
  async createSession(user: User, organization: string): Promise<string> {
    const payload = {
      userId: user.id,
      email: user.email,
      orgSlug: organization,
      role: await getUserRole(user.id, organization),
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 24 hours
    }
    
    return jwt.sign(payload, JWT_SECRET)
  }
  
  async refreshToken(token: string): Promise<string> {
    const decoded = await verifyJWT(token)
    
    // Check if token is eligible for refresh
    if (!isEligibleForRefresh(decoded)) {
      throw new Error('Token not eligible for refresh')
    }
    
    return this.createSession(decoded.user, decoded.orgSlug)
  }
}
`,
      securityNotes: [
        'Implement token refresh mechanism',
        'Set appropriate expiration times',
        'Validate refresh eligibility',
        'Log session events for audit'
      ]
    }
  ],

  flows: [
    {
      name: 'User Login Flow',
      steps: [
        'User submits credentials to login endpoint',
        'Validate credentials against auth provider (Supabase)',
        'Check user organization membership',
        'Generate JWT token with user claims and org context',
        'Return token to client',
        'Client stores token for subsequent requests'
      ],
      securityCheckpoints: [
        'Credential validation',
        'Organization membership verification',
        'JWT token generation with proper claims',
        'Secure token transmission'
      ]
    },
    {
      name: 'API Request Authentication',
      steps: [
        'Client includes JWT token in Authorization header',
        'Middleware extracts and validates token',
        'Extract user, organization, and role from token',
        'Verify organization membership is still valid',
        'Attach auth context to request',
        'Proceed with request processing'
      ],
      securityCheckpoints: [
        'Token extraction and validation',
        'Organization membership check',
        'Role-based access verification',
        'Context attachment for downstream processing'
      ]
    }
  ],

  securityConsiderations: [
    'Use strong JWT secrets and rotate regularly',
    'Implement proper token expiration and refresh',
    'Validate organization membership on every request',
    'Log authentication events for security monitoring',
    'Use HTTPS for all authentication-related communications',
    'Implement rate limiting on authentication endpoints',
    'Consider implementing JWT blacklisting for logout'
  ],

  commonPatterns: [
    {
      name: 'Protected API Route',
      pattern: `
export async function GET() {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant()
    
    // Your API logic here
    const data = await getDataForOrganization(orgSlug)
    
    return Response.json({ data })
  } catch (error) {
    if (error.name === 'AuthenticationError') {
      return new Response('Unauthorized', { status: 401 })
    }
    return new Response('Internal Error', { status: 500 })
  }
}
`,
      description: 'Standard pattern for protected API endpoints',
      whenToUse: 'For any API endpoint that requires user authentication'
    },
    {
      name: 'Role-based Access Control',
      pattern: `
export async function POST() {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant()
    
    // Check if user has required permission
    if (!hasPermission(role, 'create:resource')) {
      return new Response('Forbidden', { status: 403 })
    }
    
    // Proceed with protected operation
    const result = await createResource(data, orgSlug)
    
    return Response.json({ result })
  } catch (error) {
    return handleAPIError(error)
  }
}
`,
      description: 'Pattern for endpoints requiring specific permissions',
      whenToUse: 'When different user roles have different access levels'
    }
  ],

  troubleshootingGuide: [
    {
      issue: 'JWT Token Validation Errors',
      symptoms: ['401 Unauthorized responses', 'Token signature verification failed'],
      solutions: [
        'Verify JWT_SECRET environment variable is set correctly',
        'Check token expiration times',
        'Ensure token format is correct',
        'Validate token signature algorithm matches'
      ]
    },
    {
      issue: 'Organization Context Missing',
      symptoms: ['Cannot determine user organization', 'Multi-tenant data access issues'],
      solutions: [
        'Ensure orgSlug is included in JWT payload',
        'Verify organization membership validation',
        'Check database RLS policies include organization context',
        'Validate token extraction logic'
      ]
    }
  ],

  testingGuidelines: [
    'Test authentication with valid and invalid tokens',
    'Verify token expiration handling',
    'Test organization isolation',
    'Validate role-based access controls',
    'Test token refresh mechanism',
    'Verify error handling for authentication failures'
  ]
};

export default authenticationTemplate;