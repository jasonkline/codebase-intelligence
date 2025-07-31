# Multi-stage Docker build for Codebase Intelligence MCP Server
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++ sqlite-dev

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache sqlite tini && \
    addgroup -g 1001 -S codebase && \
    adduser -S codebase -u 1001 -G codebase

# Set working directory
WORKDIR /app

# Copy built application and node_modules from builder
COPY --from=builder --chown=codebase:codebase /app/node_modules ./node_modules
COPY --from=builder --chown=codebase:codebase /app/dist ./dist
COPY --chown=codebase:codebase package*.json ./

# Create required directories
RUN mkdir -p /app/data /app/logs /app/config /app/temp && \
    chown -R codebase:codebase /app

# Switch to non-root user
USER codebase

# Set environment variables
ENV NODE_ENV=production \
    CI_LOG_LEVEL=info \
    CI_DATABASE_PATH=/app/data/analysis.db \
    CI_ENABLE_TELEMETRY=true \
    CI_TEMP_DIR=/app/temp

# Expose health check port (optional)
EXPOSE 7346

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD node -e "
        const http = require('http');
        const options = {
            hostname: 'localhost',
            port: 7346,
            path: '/health',
            timeout: 5000
        };
        const req = http.request(options, (res) => {
            process.exit(res.statusCode === 200 ? 0 : 1);
        });
        req.on('error', () => process.exit(1));
        req.end();
    " || exit 1

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["node", "dist/index.js"]

# Metadata
LABEL maintainer="Jason Kline" \
      version="1.0.0" \
      description="Intelligent codebase analysis, pattern recognition, and security scanning MCP server" \
      org.opencontainers.image.source="https://github.com/jasonkline/codebase-intelligence" \
      org.opencontainers.image.documentation="https://github.com/jasonkline/codebase-intelligence/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT"