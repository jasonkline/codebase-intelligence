// Vulnerable code examples for testing RLS bypass detection

import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';

// VULNERABLE: Direct database client creation
export function vulnerableDirectClient() {
  const connectionString = process.env.DATABASE_URL!;
  const client = drizzle(connectionString);
  return client;
}

// VULNERABLE: Raw postgres client
export function vulnerableRawClient() {
  const client = postgres(process.env.DATABASE_URL!);
  return client;
}

// VULNERABLE: Hardcoded organization ID
export async function vulnerableHardcodedOrg() {
  const orgId = 'acme-corp'; // VULNERABLE: Hardcoded org
  const db = await getOrgDatabase();
  return db.select().from('users').where('org_id', orgId);
}

// VULNERABLE: Missing org filter in raw query
export async function vulnerableRawQuery(client: any) {
  const result = await client.query(`
    SELECT * FROM users 
    WHERE status = 'active'
  `); // Missing org filter
  return result;
}

// VULNERABLE: Cross-tenant access attempt
export async function vulnerableCrossTenant(targetOrgId: string) {
  const db = await getDatabase();
  // VULNERABLE: Accessing different org's data
  return db.select().from('users').where('org_id', '!=', targetOrgId);
}

// VULNERABLE: Bypassing RLS with direct connection
export async function vulnerableBypassRLS() {
  const client = new postgres.Client({
    connectionString: process.env.DATABASE_URL
  });
  await client.connect();
  
  // Direct query bypasses RLS
  const result = await client.query('SELECT * FROM users');
  return result;
}

// VULNERABLE: Admin override without proper checks
export async function vulnerableAdminOverride(userId: string) {
  const adminDb = drizzle(process.env.ADMIN_DATABASE_URL!);
  // VULNERABLE: Direct admin access without verification
  return adminDb.select().from('users').where('id', userId);
}

// SECURE: Proper RLS-enabled access
export async function secureRLSAccess() {
  const db = await getSupabaseRLS(); // Uses RLS
  return db.from('users').select('*');
}

// SECURE: Authenticated database with org context
export async function secureAuthenticatedAccess() {
  const { user, orgSlug } = await requireAuthWithTenant();
  const db = await getOrgDatabaseWithAuth();
  return db.select().from('users'); // Org context automatically applied
}

// SECURE: Manual org filtering (fallback pattern)
export async function secureManualFiltering() {
  const { user, orgSlug } = await requireAuthWithTenant();
  const db = await getDatabase();
  return db.select().from('users').where('org_slug', orgSlug);
}