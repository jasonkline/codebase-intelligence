# Production Deployment Guide

Comprehensive guide for deploying Codebase Intelligence to production environments.

## Deployment Overview

This guide covers production deployment strategies including containerized deployments, cloud services, and enterprise installations. Choose the deployment method that best fits your infrastructure and requirements.

## Deployment Options

### 1. Docker Deployment (Recommended)
### 2. Kubernetes Deployment
### 3. Cloud Service Deployment (AWS, GCP, Azure)
### 4. Bare Metal Installation
### 5. Enterprise On-Premises

## Docker Deployment

### Basic Docker Setup

#### Dockerfile
```dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine AS production

# Install security updates and SQLite
RUN apk update && apk upgrade && \
    apk add --no-cache sqlite tini && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S codebase && \
    adduser -S codebase -u 1001

WORKDIR /app

# Copy application
COPY --from=builder /app/node_modules ./node_modules
COPY --chown=codebase:codebase . .

# Create data directory
RUN mkdir -p /app/data && chown -R codebase:codebase /app/data

USER codebase

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:7345/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

EXPOSE 7345

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  codebase-intelligence:
    build: .
    container_name: codebase-intelligence
    restart: unless-stopped
    ports:
      - "7345:7345"
    environment:
      - NODE_ENV=production
      - CI_PROJECT_PATH=/projects
      - CI_DATABASE_PATH=/app/data/analysis.db
      - CI_LOG_LEVEL=info
      - CI_MEMORY_LIMIT=4GB
      - CI_MAX_CONCURRENCY=4
    volumes:
      - ./project:/projects:ro
      - codebase-data:/app/data
      - codebase-logs:/app/logs
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
        reservations:
          cpus: '2.0'
          memory: 2G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7345/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  # Optional: Web UI for monitoring
  codebase-ui:
    image: codebase-intelligence-ui:latest
    container_name: codebase-ui
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://codebase-intelligence:7345
    depends_on:
      - codebase-intelligence

volumes:
  codebase-data:
    driver: local
  codebase-logs:
    driver: local

networks:
  default:
    name: codebase-intelligence
```

### Multi-Stage Production Build

```dockerfile
# Multi-stage build for optimized production image
FROM node:18-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine AS runner
WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache sqlite tini curl

# Create user
RUN addgroup --system --gid 1001 codebase && \
    adduser --system --uid 1001 codebase

# Copy built application
COPY --from=builder --chown=codebase:codebase /app/dist ./dist
COPY --from=deps --chown=codebase:codebase /app/node_modules ./node_modules
COPY --chown=codebase:codebase package*.json ./

USER codebase

EXPOSE 7345

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
```

## Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: codebase-intelligence

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: codebase-config
  namespace: codebase-intelligence
data:
  NODE_ENV: "production"
  CI_LOG_LEVEL: "info"
  CI_MEMORY_LIMIT: "4GB"
  CI_MAX_CONCURRENCY: "4"
  CI_DATABASE_PATH: "/app/data/analysis.db"
```

### Persistent Volume Claims

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: codebase-data-pvc
  namespace: codebase-intelligence
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
  storageClassName: fast-ssd

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: codebase-projects-pvc
  namespace: codebase-intelligence
spec:
  accessModes:
    - ReadOnlyMany
  resources:
    requests:
      storage: 100Gi
  storageClassName: standard
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: codebase-intelligence
  namespace: codebase-intelligence
  labels:
    app: codebase-intelligence
spec:
  replicas: 3
  selector:
    matchLabels:
      app: codebase-intelligence
  template:
    metadata:
      labels:
        app: codebase-intelligence
    spec:
      containers:
      - name: codebase-intelligence
        image: codebase-intelligence:latest
        ports:
        - containerPort: 7345
        envFrom:
        - configMapRef:
            name: codebase-config
        env:
        - name: CI_PROJECT_PATH
          value: "/projects"
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "6Gi"
            cpu: "4"
        volumeMounts:
        - name: data-volume
          mountPath: /app/data
        - name: projects-volume
          mountPath: /projects
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 7345
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 7345
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
      volumes:
      - name: data-volume
        persistentVolumeClaim:
          claimName: codebase-data-pvc
      - name: projects-volume
        persistentVolumeClaim:
          claimName: codebase-projects-pvc

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: codebase-intelligence-service
  namespace: codebase-intelligence
spec:
  selector:
    app: codebase-intelligence
  ports:
    - protocol: TCP
      port: 80
      targetPort: 7345
  type: ClusterIP

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: codebase-intelligence-ingress
  namespace: codebase-intelligence
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - codebase.yourdomain.com
    secretName: codebase-tls
  rules:
  - host: codebase.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: codebase-intelligence-service
            port:
              number: 80
```

### HorizontalPodAutoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: codebase-intelligence-hpa
  namespace: codebase-intelligence
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: codebase-intelligence
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60
```

## Cloud Deployments

### AWS ECS Deployment

```json
{
  "family": "codebase-intelligence",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "codebase-intelligence",
      "image": "your-account.dkr.ecr.region.amazonaws.com/codebase-intelligence:latest",
      "portMappings": [
        {
          "containerPort": 7345,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        },
        {
          "name": "CI_PROJECT_PATH",
          "value": "/projects"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:codebase-db-url"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "efs-storage",
          "containerPath": "/app/data"
        }
      ],
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:7345/health || exit 1"
        ],
        "interval": 30,
        "timeout": 10,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/codebase-intelligence",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ],
  "volumes": [
    {
      "name": "efs-storage",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-12345678",
        "transitEncryption": "ENABLED"
      }
    }
  ]
}
```

### GCP Cloud Run Deployment

```yaml
# cloud-run.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: codebase-intelligence
  annotations:
    run.googleapis.com/ingress: all
    run.googleapis.com/execution-environment: gen2
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/memory: "4Gi"
        run.googleapis.com/cpu: "2"
        run.googleapis.com/max-instances: "10"
        run.googleapis.com/min-instances: "1"
    spec:
      serviceAccountName: codebase-intelligence@PROJECT.iam.gserviceaccount.com
      containers:
      - image: gcr.io/PROJECT/codebase-intelligence:latest
        ports:
        - containerPort: 7345
        env:
        - name: NODE_ENV
          value: production
        - name: CI_PROJECT_PATH
          value: /projects
        - name: CI_DATABASE_PATH
          value: /mnt/data/analysis.db
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
        volumeMounts:
        - name: data-volume
          mountPath: /mnt/data
        startupProbe:
          httpGet:
            path: /health
            port: 7345
          initialDelaySeconds: 60
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 10
        livenessProbe:
          httpGet:
            path: /health
            port: 7345
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
      volumes:
      - name: data-volume
        nfs:
          server: FILESTORE_IP
          path: /data
```

### Azure Container Instances

```yaml
# azure-aci.yaml
apiVersion: 2021-03-01
location: eastus
name: codebase-intelligence
properties:
  containers:
  - name: codebase-intelligence
    properties:
      image: your-registry.azurecr.io/codebase-intelligence:latest
      resources:
        requests:
          cpu: 2
          memoryInGb: 4
      ports:
      - port: 7345
        protocol: TCP
      environmentVariables:
      - name: NODE_ENV
        value: production
      - name: CI_PROJECT_PATH
        value: /projects
      volumeMounts:
      - name: data-volume
        mountPath: /app/data
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: tcp
      port: 7345
  volumes:
  - name: data-volume
    azureFile:
      shareName: codebase-data
      storageAccountName: yourStorageAccount
      storageAccountKey: yourStorageKey
```

## Production Configuration

### Environment Variables

```bash
# Production environment variables
export NODE_ENV="production"
export CI_PROJECT_PATH="/app/projects"
export CI_DATABASE_PATH="/app/data/analysis.db"
export CI_LOG_LEVEL="info"
export CI_LOG_FILE="/app/logs/codebase-intelligence.log"

# Performance settings
export CI_MEMORY_LIMIT="4GB"
export CI_MAX_CONCURRENCY="4"
export CI_ANALYSIS_TIMEOUT="600000"

# Security settings
export CI_ENABLE_TELEMETRY="false"
export CI_SECURITY_STRICT_MODE="true"
export CI_BLOCK_CRITICAL_ISSUES="true"

# Database settings
export CI_DATABASE_CACHE_SIZE="512MB"
export CI_DATABASE_CONNECTION_POOL_SIZE="10"

# Monitoring
export CI_HEALTH_CHECK_PORT="7345"
export CI_METRICS_ENABLED="true"
export CI_METRICS_PORT="9090"
```

### Production Configuration File

```json
{
  "version": "1.0",
  "environment": "production",
  "logging": {
    "level": "info",
    "file": "/app/logs/codebase-intelligence.log",
    "maxSize": "100MB",
    "maxFiles": 5,
    "format": "json"
  },
  "analysis": {
    "parallel": true,
    "maxConcurrency": 8,
    "timeout": 900000,
    "memoryLimit": "6GB",
    "exclude": [
      "node_modules/**",
      "dist/**",
      "build/**",
      ".git/**",
      "**/*.min.js",
      "**/*.d.ts"
    ]
  },
  "database": {
    "path": "/app/data/analysis.db",
    "memoryLimit": "1GB",
    "cacheSize": "512MB",
    "walMode": true,
    "connectionPool": {
      "min": 2,
      "max": 20,
      "acquireTimeoutMillis": 30000
    },
    "backup": {
      "enabled": true,
      "frequency": "daily",
      "retention": 30,
      "path": "/app/backups/"
    }
  },
  "security": {
    "enabled": true,
    "strictMode": true,
    "blockCritical": true,
    "scanOnSave": false,
    "minSeverity": "medium"
  },
  "telemetry": {
    "enabled": false,
    "endpoint": "",
    "anonymizeData": true
  },
  "monitoring": {
    "healthCheck": {
      "enabled": true,
      "port": 7345,
      "path": "/health"
    },
    "metrics": {
      "enabled": true,
      "port": 9090,
      "path": "/metrics"
    }
  }
}
```

## Monitoring and Observability

### Health Checks

```typescript
// Health check endpoint implementation
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version,
    uptime: process.uptime(),
    checks: {
      database: checkDatabase(),
      memory: checkMemory(),
      disk: checkDisk()
    }
  };
  
  const allHealthy = Object.values(health.checks).every(check => check.status === 'healthy');
  
  res.status(allHealthy ? 200 : 503).json(health);
});

app.get('/ready', (req, res) => {
  // Readiness check for Kubernetes
  const ready = {
    status: 'ready',
    timestamp: new Date().toISOString(),
    checks: {
      database: checkDatabaseConnection(),
      initialization: checkInitialization()
    }
  };
  
  const allReady = Object.values(ready.checks).every(check => check.status === 'ready');
  
  res.status(allReady ? 200 : 503).json(ready);
});
```

### Prometheus Metrics

```typescript
// Prometheus metrics endpoint
const promClient = require('prom-client');

const register = new promClient.Registry();

// Custom metrics
const analysisTime = new promClient.Histogram({
  name: 'codebase_analysis_duration_seconds',
  help: 'Time spent analyzing codebase',
  buckets: [1, 5, 10, 30, 60, 300, 600]
});

const memoryUsage = new promClient.Gauge({
  name: 'codebase_memory_usage_bytes',
  help: 'Current memory usage'
});

const securityIssues = new promClient.Counter({
  name: 'codebase_security_issues_total',
  help: 'Total security issues found',
  labelNames: ['severity']
});

register.registerMetric(analysisTime);
register.registerMetric(memoryUsage);
register.registerMetric(securityIssues);

app.get('/metrics', (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(register.metrics());
});
```

### Logging Configuration

```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "transports": [
      {
        "type": "file",
        "filename": "/app/logs/app.log",
        "maxSize": "100MB",
        "maxFiles": 5,
        "tailable": true
      },
      {
        "type": "file",
        "level": "error",
        "filename": "/app/logs/error.log",
        "maxSize": "50MB",
        "maxFiles": 5
      },
      {
        "type": "console",
        "level": "info",
        "format": "simple"
      }
    ]
  }
}
```

## Security Hardening

### Container Security

```dockerfile
# Security-hardened Dockerfile
FROM node:18-alpine AS production

# Install security updates
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init sqlite && \
    rm -rf /var/cache/apk/*

# Create non-root user with specific UID/GID
RUN addgroup -g 10001 -S codebase && \
    adduser -S -D -H -u 10001 -s /sbin/nologin codebase

WORKDIR /app

# Copy application with correct ownership
COPY --chown=codebase:codebase . .

# Set file permissions
RUN chmod -R 755 /app && \
    chmod -R 644 /app/package*.json

# Drop privileges
USER codebase

# Use dumb-init as PID 1
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]

# Security labels
LABEL security.non-root=true
LABEL security.no-new-privileges=true
```

### Kubernetes Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: codebase-intelligence
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: codebase-intelligence
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: data-volume
          mountPath: /app/data
      volumes:
      - name: tmp-volume
        emptyDir: {}
```

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: codebase-intelligence-network-policy
  namespace: codebase-intelligence
spec:
  podSelector:
    matchLabels:
      app: codebase-intelligence
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 7345
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
```

## Backup and Disaster Recovery

### Database Backup Script

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/app/backups"
DB_PATH="/app/data/analysis.db"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/analysis_$DATE.db"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

# Compress backup
gzip "$BACKUP_FILE"

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "analysis_*.db.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

### Automated Backup with Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: codebase-backup
  namespace: codebase-intelligence
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache sqlite
              DATE=$(date +%Y%m%d_%H%M%S)
              sqlite3 /app/data/analysis.db ".backup /backup/analysis_$DATE.db"
              gzip /backup/analysis_$DATE.db
              find /backup -name "analysis_*.db.gz" -mtime +30 -delete
            volumeMounts:
            - name: data-volume
              mountPath: /app/data
              readOnly: true
            - name: backup-volume
              mountPath: /backup
          volumes:
          - name: data-volume
            persistentVolumeClaim:
              claimName: codebase-data-pvc
          - name: backup-volume
            persistentVolumeClaim:
              claimName: codebase-backup-pvc
          restartPolicy: OnFailure
```

## Production Checklist

### Pre-Deployment

- [ ] Security scan completed
- [ ] Performance testing completed
- [ ] Configuration validated
- [ ] SSL certificates configured
- [ ] Backup strategy implemented
- [ ] Monitoring configured
- [ ] Log aggregation set up
- [ ] Health checks implemented
- [ ] Resource limits defined
- [ ] Network policies configured

### Post-Deployment

- [ ] Health checks passing
- [ ] Metrics being collected
- [ ] Logs being aggregated
- [ ] Backups running successfully
- [ ] Performance within acceptable limits
- [ ] Security monitoring active
- [ ] Alerts configured
- [ ] Documentation updated
- [ ] Team trained on operations
- [ ] Runbooks created

---

*For advanced enterprise deployment scenarios, see our [Enterprise Deployment Guide](../enterprise/deployment.md) and [High Availability Setup](./high-availability.md).*