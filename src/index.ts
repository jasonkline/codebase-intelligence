#!/usr/bin/env node

import { mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import CodebaseIntelligenceMCPServer from './mcp/server';
import logger from './utils/logger';

async function main(): Promise<void> {
  try {
    // Ensure logs directory exists
    if (!existsSync('logs')) {
      await mkdir('logs', { recursive: true });
    }

    logger.info('Starting Codebase Intelligence MCP Server...');

    const server = new CodebaseIntelligenceMCPServer();
    await server.start();

    // Keep the process running
    process.stdin.resume();
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

if (require.main === module) {
  main().catch((error) => {
    logger.error('Unhandled error in main:', error);
    process.exit(1);
  });
}