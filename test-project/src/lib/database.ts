/**
 * Database access utilities with organization isolation
 */

import { AuthContext } from './auth';

export interface DatabaseConnection {
  query: (sql: string, params?: any[]) => Promise<any[]>;
  close: () => Promise<void>;
}

/**
 * Get authenticated database connection with organization context
 * This ensures Row Level Security is applied
 */
export async function getOrgDatabaseWithAuth(): Promise<DatabaseConnection> {
  try {
    // Mock secure database connection
    return {
      query: async (sql: string, params?: any[]) => {
        console.log('Executing secure query:', sql);
        return [];
      },
      close: async () => {
        console.log('Closing secure connection');
      }
    };
  } catch (error) {
    console.error('Failed to get authenticated database connection:', error);
    throw error;
  }
}

/**
 * DANGEROUS: Direct database access without auth context
 * This bypasses RLS and should not be used
 */
export function getDirectDatabaseConnection(): DatabaseConnection {
  // This is a security risk - no auth context
  return {
    query: async (sql: string, params?: any[]) => {
      console.log('DANGER: Direct query without RLS:', sql);
      return [];
    },
    close: async () => {
      console.log('Closing direct connection');
    }
  };
}

/**
 * Secure data access with RLS
 */
export async function getSupabaseRLS(): Promise<DatabaseConnection> {
  return {
    query: async (sql: string, params?: any[]) => {
      console.log('RLS query:', sql);
      return [];
    },
    close: async () => {
      console.log('Closing RLS connection');
    }
  };
}

/**
 * Get user data for current organization
 */
export async function getUserData(authContext: AuthContext, userId: string) {
  const db = await getOrgDatabaseWithAuth();
  try {
    const result = await db.query(
      'SELECT * FROM users WHERE id = ? AND org_slug = ?',
      [userId, authContext.orgSlug]
    );
    return result[0];
  } finally {
    await db.close();
  }
}

/**
 * SECURITY ISSUE: Hardcoded organization access
 */
export async function getHardcodedOrgData() {
  const db = await getOrgDatabaseWithAuth();
  try {
    // This is bad - hardcoded org breaks multi-tenancy
    const result = await db.query(
      'SELECT * FROM data WHERE org_slug = ?',
      ['hardcoded-org']
    );
    return result;
  } finally {
    await db.close();
  }
}