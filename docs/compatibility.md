# Compatibility Guide

Codebase Intelligence is designed to work with any TypeScript/JavaScript codebase. This guide details what's supported and how to configure it for different project types.

## Supported Languages

### ✅ **Fully Supported**
- **TypeScript** (.ts, .tsx files)
- **JavaScript** (ES6+, .js, .jsx files)
- **JSON** configuration files
- **Markdown** documentation files

### ⚠️ **Limited Support**
- **Other languages** - Basic file scanning only, no AST analysis

## Supported Frameworks & Libraries

### ✅ **Frontend Frameworks**
- **Next.js** - Full support including App Router, API routes, middleware
- **React** - Component analysis, hooks patterns, state management
- **Vue.js** - Component structure, composition API, options API
- **Angular** - Component analysis, services, dependency injection
- **Svelte/SvelteKit** - Component patterns, stores
- **Nuxt.js** - Server-side rendering patterns, plugins
- **Gatsby** - Static site patterns, GraphQL queries

### ✅ **Backend Frameworks**
- **Express.js** - Route analysis, middleware patterns, error handling
- **NestJS** - Decorator patterns, modules, dependency injection
- **Fastify** - Route handlers, plugins, hooks
- **Koa.js** - Middleware composition, context handling
- **Hapi.js** - Route configurations, plugins
- **Node.js** native - HTTP servers, utilities

### ✅ **Full-Stack Frameworks**
- **Next.js** - API routes, server actions, middleware
- **SvelteKit** - Server-side routing, load functions
- **Nuxt.js** - Server API, middleware
- **Remix** - Loader/action patterns, forms

## Supported Databases & ORMs

### ✅ **Databases**
- **PostgreSQL** - RLS analysis, security patterns
- **MySQL** - Query analysis, injection detection
- **SQLite** - Local database patterns
- **MongoDB** - Document patterns, aggregation
- **Supabase** - RLS policies, auth patterns
- **PlanetScale** - Schema analysis
- **Any SQL database** - Generic query analysis

### ✅ **ORMs & Query Builders**
- **Prisma** - Schema analysis, type safety patterns
- **TypeORM** - Entity patterns, relationships
- **Sequelize** - Model definitions, associations
- **Drizzle** - Schema patterns, type safety
- **Knex.js** - Query builder patterns
- **Mongoose** - Schema definitions, middleware
- **Raw SQL** - Query analysis, injection detection

## Supported Authentication Systems

### ✅ **Authentication Providers**
- **Supabase Auth** - RLS integration, JWT patterns
- **Auth0** - Token validation, role patterns
- **Firebase Auth** - User management, custom claims
- **NextAuth.js** - Provider patterns, session handling
- **Passport.js** - Strategy patterns, middleware
- **Custom JWT** - Token validation, middleware patterns
- **Session-based** - Cookie handling, session management

### ✅ **Authorization Patterns**
- **Role-Based Access Control (RBAC)** - Role/permission mappings
- **Attribute-Based Access Control (ABAC)** - Dynamic permissions
- **Row Level Security (RLS)** - Database-level security
- **Custom middleware** - Route protection patterns

## Project Structure Compatibility

### ✅ **Supported Project Types**
- **Monorepos** - Multi-package analysis, shared patterns
- **Microservices** - Service boundaries, communication patterns
- **Serverless** - Function patterns, event handling
- **JAMstack** - Static generation, API integration
- **Progressive Web Apps** - Service workers, offline patterns
- **Electron Apps** - Main/renderer processes, IPC patterns

### ✅ **Package Managers**
- **npm** - package.json analysis, scripts
- **yarn** - Workspace patterns, version resolution
- **pnpm** - Workspace analysis, peer dependencies
- **Bun** - Fast runtime, package management

### ✅ **Build Tools**
- **Webpack** - Bundle analysis, optimization patterns
- **Vite** - ESM patterns, dev server configuration
- **Rollup** - Library bundling patterns
- **esbuild** - Fast compilation patterns
- **Turbopack** - Next.js bundling
- **Parcel** - Zero-config bundling

## Testing Framework Support

### ✅ **Testing Frameworks**
- **Jest** - Test patterns, mocking strategies
- **Vitest** - Modern testing patterns
- **Cypress** - E2E test patterns
- **Playwright** - Cross-browser testing
- **Testing Library** - Component testing patterns
- **Mocha/Chai** - Traditional testing patterns

## Configuration File Support

### ✅ **Automatically Detected**
- **package.json** - Dependencies, scripts, metadata
- **tsconfig.json** - TypeScript configuration
- **next.config.js** - Next.js configuration
- **vite.config.ts** - Vite configuration
- **jest.config.js** - Test configuration
- **.env files** - Environment variables (security scanning)
- **docker-compose.yml** - Container patterns
- **Dockerfile** - Container security analysis

## System Requirements

### ✅ **Operating Systems**
- **macOS** - Intel and Apple Silicon
- **Linux** - Ubuntu, CentOS, Alpine, etc.
- **Windows** - WSL2 recommended for best performance

### ✅ **Node.js Versions**
- **Node.js 16.x** - Minimum supported version
- **Node.js 18.x** - Recommended (LTS)
- **Node.js 20.x** - Latest supported
- **Node.js 21.x+** - May work but not officially tested

### ✅ **Memory Requirements**
- **Small projects** (<1000 files) - 512MB RAM
- **Medium projects** (1000-5000 files) - 1GB RAM
- **Large projects** (5000+ files) - 2GB+ RAM
- **Monorepos** - 4GB+ RAM recommended

## Framework-Specific Features

### **Next.js**
- ✅ App Router analysis
- ✅ API route security scanning
- ✅ Server component patterns
- ✅ Middleware analysis
- ✅ Server actions security

### **React**
- ✅ Hook patterns analysis
- ✅ Component composition
- ✅ State management patterns
- ✅ Context usage analysis
- ✅ Performance anti-patterns

### **Express.js**
- ✅ Route security analysis
- ✅ Middleware ordering
- ✅ Error handling patterns
- ✅ CORS configuration
- ✅ Rate limiting patterns

### **Prisma**
- ✅ Schema analysis
- ✅ RLS pattern detection
- ✅ Query optimization
- ✅ Migration patterns
- ✅ Type safety validation

## Configuration Examples

### Next.js Project
```json
{
  "projectConfig": {
    "name": "my-nextjs-app",
    "type": "nextjs",
    "language": "typescript",
    "framework": "next.js",
    "database": "postgresql",
    "authentication": "supabase-auth",
    "includePaths": [
      "app/**/*.{ts,tsx}",
      "components/**/*.{ts,tsx}",
      "lib/**/*.ts"
    ],
    "excludePaths": [
      "node_modules/**",
      ".next/**",
      "**/*.test.ts"
    ]
  }
}
```

### Express API
```json
{
  "projectConfig": {
    "name": "my-api",
    "type": "backend",
    "language": "typescript",
    "framework": "express",
    "database": "mongodb",
    "authentication": "jwt",
    "includePaths": [
      "src/**/*.ts",
      "routes/**/*.ts",
      "middleware/**/*.ts"
    ]
  }
}
```

### React SPA
```json
{
  "projectConfig": {
    "name": "my-react-app",
    "type": "spa",
    "language": "typescript",
    "framework": "react",
    "authentication": "auth0",
    "includePaths": [
      "src/**/*.{ts,tsx}",
      "components/**/*.{ts,tsx}"
    ]
  }
}
```

## Limitations

### ❌ **Not Supported**
- **Python, Java, C#** - No AST analysis (basic file scanning only)
- **PHP, Ruby** - No AST analysis
- **Binary files** - No analysis capabilities
- **Proprietary frameworks** - May have limited pattern recognition

### ⚠️ **Limited Support**
- **Very old JavaScript** (ES5 and below) - Basic analysis only
- **Non-standard file extensions** - May not be detected
- **Heavily obfuscated code** - Reduced analysis quality

## Getting Help

If your framework or setup isn't working as expected:

1. **Check file extensions** - Ensure TypeScript/JavaScript files use standard extensions
2. **Verify paths** - Make sure `includePaths` covers your source code
3. **Review logs** - Check `logs/combined.log` for analysis errors
4. **Report issues** - [GitHub Issues](https://github.com/jasonkline/codebase-intelligence/issues) with your setup details

## Framework Detection

The system automatically detects your framework by analyzing:
- **package.json dependencies**
- **File structure patterns**
- **Configuration files**
- **Import patterns**
- **Code conventions**

No manual framework specification is required in most cases.

---

**The system is designed to be framework-agnostic and will work with any TypeScript/JavaScript codebase. Framework-specific features enhance the analysis but are not required for basic functionality.**