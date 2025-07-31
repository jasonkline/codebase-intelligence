// Vulnerable code examples for testing authentication bypass detection

// VULNERABLE: API route without authentication
export async function GET() {
  const users = await db.select().from('users');
  return Response.json({ users });
}

// VULNERABLE: Commented out auth check
export async function POST(request: Request) {
  // TODO: Add authentication later
  // const { user } = await requireAuthWithTenant();
  
  const body = await request.json();
  const result = await db.insert('users').values(body);
  return Response.json({ result });
}

// VULNERABLE: Early return bypassing auth
export async function DELETE(request: Request) {
  if (process.env.NODE_ENV === 'development') {
    // Skip auth in development
    return Response.json({ message: 'Deleted' });
  }
  
  const { user } = await requireAuthWithTenant();
  // ... deletion logic
}

// VULNERABLE: Admin backdoor
export async function PATCH(request: Request) {
  const { user } = await requireAuthWithTenant();
  
  // VULNERABLE: Hardcoded admin bypass
  if (user.email === 'admin@backdoor.com') {
    return Response.json({ message: 'Admin access granted' });
  }
  
  if (!hasPermission(user.role, 'update:users')) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }
  
  // ... update logic
}

// VULNERABLE: Missing role check
export async function PUT(request: Request) {
  const { user } = await requireAuthWithTenant(); // Has auth but no authorization
  
  // Any authenticated user can delete anything
  const { id } = await request.json();
  await db.delete('users').where('id', id);
  
  return Response.json({ message: 'User deleted' });
}

// SECURE: Proper authentication and authorization
export async function securePOST(request: Request) {
  const { user, orgSlug, role } = await requireAuthWithTenant();
  
  if (!hasPermission(role, 'create:users')) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }
  
  const body = await request.json();
  const result = await db.insert('users').values({ ...body, orgSlug });
  
  return Response.json({ result });
}