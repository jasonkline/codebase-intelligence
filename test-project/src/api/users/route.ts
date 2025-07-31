/**
 * API route for user management
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAuthWithTenant, hasPermission } from '../../lib/auth';
import { getOrgDatabaseWithAuth, getUserData } from '../../lib/database';

/**
 * GET /api/users - List users in organization
 */
export async function GET(request: NextRequest) {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant();
    
    // Check permissions
    if (!hasPermission(role, 'read')) {
      return new NextResponse('Forbidden', { status: 403 });
    }
    
    const db = await getOrgDatabaseWithAuth();
    const users = await db.query(
      'SELECT id, email, role FROM users WHERE org_slug = ?',
      [orgSlug]
    );
    
    await db.close();
    
    return NextResponse.json({ users });
  } catch (error) {
    console.error('GET /api/users error:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}

/**
 * POST /api/users - Create new user
 */
export async function POST(request: NextRequest) {
  try {
    const { user, orgSlug, role } = await requireAuthWithTenant();
    
    // Only admins can create users
    if (!hasPermission(role, 'write') || role !== 'admin') {
      return new NextResponse('Forbidden', { status: 403 });
    }
    
    const body = await request.json();
    // TODO: Add input validation here
    
    const db = await getOrgDatabaseWithAuth();
    const result = await db.query(
      'INSERT INTO users (email, role, org_slug) VALUES (?, ?, ?)',
      [body.email, body.role, orgSlug]
    );
    
    await db.close();
    
    return NextResponse.json({ success: true, id: result.insertId });
  } catch (error) {
    console.error('POST /api/users error:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}

/**
 * DELETE /api/users/[id] - Delete user
 * SECURITY ISSUE: Missing auth check
 */
export async function DELETE(request: NextRequest) {
  try {
    // MISSING: Authentication check
    // const { user, orgSlug, role } = await requireAuthWithTenant();
    
    const url = new URL(request.url);
    const userId = url.pathname.split('/').pop();
    
    const db = await getOrgDatabaseWithAuth();
    await db.query('DELETE FROM users WHERE id = ?', [userId]);
    await db.close();
    
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('DELETE /api/users error:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}