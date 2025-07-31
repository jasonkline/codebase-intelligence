// Vulnerable code examples for testing SQL injection detection

export function vulnerableQuery1(userId: string) {
  // VULNERABLE: Direct template literal with user input
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return query;
}

export function vulnerableQuery2(searchTerm: string) {
  // VULNERABLE: String concatenation
  const query = "SELECT * FROM products WHERE name = '" + searchTerm + "'";
  return query;
}

export function vulnerableQuery3(req: any) {
  // VULNERABLE: Using request parameters directly
  const query = `
    SELECT u.*, p.* 
    FROM users u 
    JOIN profiles p ON u.id = p.user_id 
    WHERE u.email = '${req.body.email}' 
    AND u.password = '${req.body.password}'
  `;
  return query;
}

export function vulnerableStoredProcedure(orgId: string, status: string) {
  // VULNERABLE: Dynamic stored procedure call
  const query = `EXEC GetOrdersByStatus @orgId = ${orgId}, @status = '${status}'`;
  return query;
}

// SECURE: Proper parameterized query (should not be flagged)
export function secureQuery(userId: string, db: any) {
  const query = db.prepare("SELECT * FROM users WHERE id = ?");
  return query.get(userId);
}

// SECURE: Using query builder (should not be flagged)
export function secureQueryBuilder(userId: string, db: any) {
  return db.select().from('users').where('id', userId);
}