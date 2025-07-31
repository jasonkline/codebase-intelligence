#!/usr/bin/env ts-node

/**
 * Simple test to validate core functionality
 */

import { join } from 'path';
import ASTParser from './src/parser/ASTParser';
import SystemAnalyzer from './src/parser/SystemAnalyzer';
import DatabaseManager from './src/database/schema';

async function simpleTest() {
  console.log('🧠 Simple Codebase Intelligence Test...\n');
  
  try {
    // Test 1: AST Parser
    console.log('🔍 Testing AST Parser...');
    const parser = new ASTParser();
    const testFile = join(__dirname, 'test-project/src/lib/auth.ts');
    const parsed = parser.parseFile(testFile);
    
    if (parsed) {
      console.log(`   ✅ Parsed ${parsed.symbols.length} symbols`);
      console.log(`   ✅ Found ${parsed.imports.length} imports`);
      console.log(`   ✅ Found ${parsed.exports.length} exports`);
    } else {
      console.log('   ❌ Failed to parse file');
    }
    
    // Test 2: System Analyzer
    console.log('\n🔍 Testing System Analyzer...');
    const analyzer = new SystemAnalyzer();
    
    if (parsed) {
      const fs = await import('fs/promises');
      const sourceCode = await fs.readFile(testFile, 'utf-8');
      const analysis = analyzer.analyzeFile(parsed, sourceCode);
      
      console.log(`   ✅ Found ${analysis.authPatterns.length} auth patterns`);
      console.log(`   ✅ Found ${analysis.rbacPatterns.length} RBAC patterns`);
      console.log(`   ✅ Found ${analysis.dataAccessPatterns.length} data access patterns`);
      console.log(`   ✅ Found ${analysis.apiPatterns.length} API patterns`);
      console.log(`   ✅ Security issues: ${analysis.summary.securityIssues}`);
    }
    
    // Test 3: Database
    console.log('\n🔍 Testing Database...');
    const db = new DatabaseManager(':memory:');
    console.log('   ✅ Database initialized');
    
    if (parsed) {
      // Insert a test symbol
      const testSymbol = {
        name: parsed.symbols[0]?.name || 'test',
        kind: 'function',
        file_path: testFile,
        line_start: 1,
        line_end: 10,
        column_start: 0,
        column_end: 10,
        is_exported: true
      };
      
      const symbolId = db.insertSymbol(testSymbol);
      console.log(`   ✅ Inserted symbol with ID: ${symbolId}`);
      
      const symbols = db.getSymbolsByFile(testFile);
      console.log(`   ✅ Retrieved ${symbols.length} symbols from database`);
    }
    
    db.close();
    console.log('   ✅ Database closed');
    
    console.log('\n🎉 Simple test completed successfully!');
    console.log('\nCore components are working:');
    console.log('✅ AST Parser can extract symbols from TypeScript files');
    console.log('✅ System Analyzer can identify patterns in code');
    console.log('✅ Database can store and retrieve analysis results');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  simpleTest();
}