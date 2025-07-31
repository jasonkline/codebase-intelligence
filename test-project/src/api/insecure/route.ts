/**
 * INSECURE API route - demonstrates security issues
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDirectDatabaseConnection } from '../../lib/database';

/**
 * CRITICAL SECURITY ISSUE: No authentication
 */
export async function GET(request: NextRequest) {
  try {
    // NO AUTH CHECK - anyone can access this
    const db = getDirectDatabaseConnection(); // Direct DB access bypasses RLS
    
    const data = await db.query('SELECT * FROM sensitive_data'); // No org filtering
    
    return NextResponse.json({ data });
  } catch (error) {
    console.log(error); // Logging sensitive errors
    return new NextResponse('Error', { status: 500 });
  }
}

/**
 * SQL Injection vulnerability
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const db = getDirectDatabaseConnection();
    
    // SQL injection vulnerability - direct string interpolation
    const query = `SELECT * FROM users WHERE name = '${body.name}'`;
    const result = await db.query(query);
    
    return NextResponse.json({ result });
  } catch (error) {
    return new NextResponse('Error', { status: 500 });
  }
}

/**
 * Missing input validation
 */
export async function PUT(request: NextRequest) {
  const body = await request.json();
  
  // No validation of input
  // No auth check
  // Direct database access
  
  const db = getDirectDatabaseConnection();
  await db.query(
    'UPDATE users SET admin = ? WHERE id = ?',
    [body.isAdmin, body.userId] // Privilege escalation possible
  );
  
  return NextResponse.json({ success: true });
}