/**
 * Authentication utilities for the application
 */

export interface User {
  id: string;
  email: string;
  role: 'admin' | 'member' | 'approver';
  orgSlug: string;
}

export interface AuthContext {
  user: User;
  orgSlug: string;
  role: string;
}

/**
 * Requires authentication with tenant context
 * This is the main auth function used throughout the app
 * @throws {Error} When authentication fails
 */
export async function requireAuthWithTenant(): Promise<AuthContext> {
  try {
    // Mock authentication logic
    const token = getAuthToken();
    if (!token) {
      throw new Error('No authentication token');
    }
    
    const user = await validateToken(token);
    if (!user) {
      throw new Error('Invalid token');
    }
    
    return {
      user,
      orgSlug: user.orgSlug,
      role: user.role
    };
  } catch (error) {
    console.error('Authentication failed:', error);
    throw new Error('Authentication required');
  }
}

/**
 * Get authentication token from request headers
 */
function getAuthToken(): string | null {
  // Mock implementation
  return 'mock-token';
}

/**
 * Validate JWT token and return user
 */
async function validateToken(token: string): Promise<User | null> {
  // Mock validation
  if (token === 'mock-token') {
    return {
      id: '123',
      email: 'user@example.com',
      role: 'member',
      orgSlug: 'test-org'
    };
  }
  return null;
}

/**
 * Check if user has specific permission
 */
export function hasPermission(role: string, permission: string): boolean {
  const permissions = {
    admin: ['read', 'write', 'delete', 'approve'],
    approver: ['read', 'write', 'approve'],
    member: ['read', 'write']
  };
  
  return permissions[role as keyof typeof permissions]?.includes(permission) || false;
}

/**
 * Require specific role for access
 */
export function requireRole(userRole: string, requiredRole: string): boolean {
  const hierarchy = {
    admin: 3,
    approver: 2,
    member: 1
  };
  
  const userLevel = hierarchy[userRole as keyof typeof hierarchy] || 0;
  const requiredLevel = hierarchy[requiredRole as keyof typeof hierarchy] || 0;
  
  return userLevel >= requiredLevel;
}