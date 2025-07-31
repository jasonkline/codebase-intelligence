# Performance Optimization Guide

Comprehensive guide to optimizing the performance of Codebase Intelligence for various project sizes and use cases.

## Performance Overview

Codebase Intelligence is designed to handle projects of various sizes, from small applications to enterprise codebases with hundreds of thousands of files. This guide covers optimization strategies, performance monitoring, and scaling considerations.

## Performance Characteristics

### Baseline Performance

| Project Size | Files | Analysis Time | Memory Usage | Database Size |
|--------------|-------|---------------|--------------|---------------|
| Small        | <1K   | 5-15s        | 256MB        | 10-50MB       |
| Medium       | 1K-10K| 30-120s      | 512MB-2GB    | 50-500MB      |
| Large        | 10K-50K| 2-10min     | 2-8GB        | 500MB-2GB     |
| Enterprise   | 50K+  | 10-60min     | 8-32GB       | 2-10GB        |

### Performance Factors

#### Analysis Performance
- **File Count**: Linear relationship with processing time
- **File Size**: Large files increase memory usage exponentially
- **AST Complexity**: Complex nested structures slow parsing
- **Concurrency**: Parallel processing improves performance significantly

#### Real-time Performance
- **File Watching**: Sub-100ms response for single file changes
- **Pattern Matching**: ~10ms for pattern compliance checking
- **Security Scanning**: ~50ms for security rule evaluation
- **Knowledge Queries**: 100-500ms depending on complexity

## Configuration Optimization

### Analysis Performance Settings

```json
{
  "analysis": {
    "parallel": true,
    "maxConcurrency": 8,
    "timeout": 600000,
    "maxFileSize": "5MB",
    "chunkSize": 1000,
    "memoryLimit": "8GB",
    "excludePatterns": [
      "node_modules/**",
      "dist/**",
      "build/**",
      ".next/**",
      "coverage/**",
      "**/*.min.js",
      "**/*.d.ts"
    ]
  }
}
```

### Database Performance Settings

```json
{
  "database": {
    "memoryLimit": "2GB",
    "cacheSize": "512MB",
    "walMode": true,
    "busyTimeout": 30000,
    "connectionPool": {
      "min": 1,
      "max": 10,
      "acquireTimeoutMillis": 30000,
      "idleTimeoutMillis": 600000
    },
    "vacuum": {
      "enabled": true,
      "frequency": "daily",
      "analyze": true
    }
  }
}
```

### Memory Management Settings

```json
{
  "memory": {
    "maxHeapSize": "8GB",
    "gcStrategy": "adaptive",
    "cacheSize": {
      "ast": "1GB",
      "patterns": "256MB",
      "security": "128MB",
      "knowledge": "512MB"
    },
    "monitoring": {
      "enabled": true,
      "warningThreshold": 0.8,
      "criticalThreshold": 0.95
    }
  }
}
```

## Environment Variables for Performance

```bash
# Core performance settings
export CI_MAX_CONCURRENCY="8"
export CI_MEMORY_LIMIT="8GB"
export CI_ANALYSIS_TIMEOUT="600000"
export CI_FILE_SIZE_LIMIT="5MB"

# Database performance
export CI_DATABASE_CACHE_SIZE="512MB"
export CI_DATABASE_CONNECTION_POOL_SIZE="10"
export CI_DATABASE_WAL_MODE="true"

# Memory management
export CI_HEAP_SIZE="8GB"
export CI_GC_STRATEGY="adaptive"
export CI_CACHE_SIZE="1GB"

# Real-time performance
export CI_WATCH_DEBOUNCE="100"
export CI_VALIDATION_DELAY="50"
export CI_SUGGESTION_DELAY="200"
```

## Hardware Recommendations

### CPU Recommendations

```bash
# Small Projects (<1K files)
CPU: 2+ cores, 2.5GHz+
Example: MacBook Air M1, Intel i5-8250U

# Medium Projects (1K-10K files)  
CPU: 4+ cores, 3.0GHz+
Example: MacBook Pro M1 Pro, Intel i7-9700K

# Large Projects (10K-50K files)
CPU: 8+ cores, 3.5GHz+
Example: MacBook Pro M1 Max, Intel i9-9900K

# Enterprise Projects (50K+ files)
CPU: 16+ cores, 4.0GHz+
Example: Mac Studio M1 Ultra, Intel Xeon W-2295
```

### Memory Recommendations

```bash
# Small Projects
RAM: 4GB minimum, 8GB recommended

# Medium Projects
RAM: 8GB minimum, 16GB recommended

# Large Projects
RAM: 16GB minimum, 32GB recommended

# Enterprise Projects
RAM: 32GB minimum, 64GB+ recommended
```

### Storage Recommendations

```bash
# All Project Sizes
Type: SSD required (NVMe preferred)
Space: 10GB + (2x project size)
IOPS: 1000+ for database performance

# Enterprise Projects
Type: NVMe SSD required
Space: 100GB + (5x project size)
IOPS: 5000+ for optimal performance
```

## Performance Monitoring

### Built-in Performance Metrics

```typescript
// Access performance metrics via MCP tool
{
  "name": "get_performance_metrics",
  "arguments": {}
}

// Response includes:
{
  "analysis": {
    "avgProcessingTime": 1250,
    "filesPerSecond": 12.5,
    "memoryUsage": "2.1GB",
    "cacheHitRate": 89.2
  },
  "database": {
    "queryTime": 15.7,
    "connectionPool": {
      "active": 3,
      "idle": 2,
      "waiting": 0
    },
    "cacheHitRate": 94.1
  },
  "realtime": {
    "avgValidationTime": 45,
    "avgPatternMatchTime": 12,
    "watcherLatency": 23
  }
}
```

### System Monitoring

```bash
# Monitor Codebase Intelligence processes
ps aux | grep codebase-intelligence

# Monitor memory usage
watch -n 1 'free -h && echo && ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem | head'

# Monitor disk I/O
iostat -x 1

# Monitor database performance
sqlite3 .codeintel/analysis.db "PRAGMA compile_options;"
```

### Custom Performance Logging

```json
{
  "performance": {
    "logging": {
      "enabled": true,
      "level": "info",
      "metrics": [
        "analysis_time",
        "memory_usage", 
        "database_queries",
        "cache_performance"
      ],
      "outputPath": "logs/performance.log",
      "format": "json"
    },
    "profiling": {
      "enabled": false,
      "samplingRate": 0.1,
      "outputPath": "profiles/"
    }
  }
}
```

## Optimization Strategies

### Large Codebase Optimization

#### 1. Selective Analysis
```json
{
  "analysis": {
    "include": [
      "src/**/*.ts",
      "lib/**/*.ts"
    ],
    "exclude": [
      "node_modules/**",
      "dist/**",
      "**/*.test.ts",
      "**/*.spec.ts",
      "**/*.d.ts",
      "generated/**",
      "vendor/**"
    ],
    "maxFileSize": "2MB",
    "skipBinaryFiles": true
  }
}
```

#### 2. Incremental Analysis
```json
{
  "incremental": {
    "enabled": true,
    "trackFileHashes": true,
    "skipUnchanged": true,
    "dependencyTracking": true,
    "maxAge": 86400
  }
}
```

#### 3. Batched Processing
```json
{
  "processing": {
    "batchSize": 100,
    "batchDelay": 10,
    "maxBatches": 50,
    "prioritizeChanged": true
  }
}
```

### Memory Optimization

#### 1. Garbage Collection Tuning
```bash
# Node.js GC optimization
export NODE_OPTIONS="--max-old-space-size=8192 --gc-global"

# V8 GC tuning for large heaps
export NODE_OPTIONS="--max-old-space-size=16384 --optimize-for-size"
```

#### 2. Memory-Mapped Files
```json
{
  "database": {
    "mmapSize": "1GB",
    "cacheSpill": false,
    "lockingMode": "exclusive"
  }
}
```

#### 3. Streaming Processing
```json
{
  "streaming": {
    "enabled": true,
    "chunkSize": "10MB",
    "backpressure": true,
    "maxConcurrent": 4
  }
}
```

### Database Optimization

#### 1. Index Optimization
```sql
-- Create performance indexes
CREATE INDEX IF NOT EXISTS idx_symbols_file_path ON symbols(file_path);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_patterns_category ON patterns(category);
CREATE INDEX IF NOT EXISTS idx_security_issues_severity ON security_issues(severity);

-- Analyze tables for query optimization
ANALYZE symbols;
ANALYZE patterns;
ANALYZE security_issues;
```

#### 2. Query Optimization
```sql
-- Use prepared statements
PREPARE search_symbols AS 
SELECT * FROM symbols WHERE name LIKE ? AND file_path LIKE ?;

-- Enable query planner debugging
PRAGMA query_only = ON;
EXPLAIN QUERY PLAN SELECT * FROM symbols WHERE name = 'functionName';
```

#### 3. Database Maintenance
```bash
# Regular database maintenance script
#!/bin/bash
DB_PATH=".codeintel/analysis.db"

# Vacuum database
sqlite3 "$DB_PATH" "VACUUM;"

# Analyze statistics
sqlite3 "$DB_PATH" "ANALYZE;"

# Check integrity
sqlite3 "$DB_PATH" "PRAGMA integrity_check;"

# Optimize database
sqlite3 "$DB_PATH" "PRAGMA optimize;"
```

## Real-time Performance Optimization

### File Watching Optimization

```json
{
  "watching": {
    "debounceMs": 100,
    "batchChanges": true,
    "maxBatchSize": 50,
    "ignorePatterns": [
      "**/.git/**",
      "**/node_modules/**",
      "**/*.log",
      "**/dist/**"
    ],
    "usePolling": false,
    "followSymlinks": false
  }
}
```

### Validation Performance

```json
{
  "validation": {
    "async": true,
    "timeout": 5000,
    "cacheResults": true,
    "cacheTTL": 300,
    "maxConcurrent": 4,
    "priorityQueue": true
  }
}
```

### Pattern Matching Performance

```json
{
  "patterns": {
    "precompiled": true,
    "cacheMatches": true,
    "fuzzyThreshold": 0.8,
    "maxPatterns": 1000,
    "indexingStrategy": "btree"
  }
}
```

## Scaling Strategies

### Horizontal Scaling

#### Multi-Instance Deployment
```yaml
# docker-compose.yml for multiple instances
version: '3.8'
services:
  codebase-intelligence-1:
    image: codebase-intelligence:latest
    environment:
      - CI_INSTANCE_ID=1
      - CI_SHARD_COUNT=3
      - CI_SHARD_INDEX=0
    volumes:
      - ./shard-0:/app/data

  codebase-intelligence-2:
    image: codebase-intelligence:latest
    environment:
      - CI_INSTANCE_ID=2
      - CI_SHARD_COUNT=3
      - CI_SHARD_INDEX=1
    volumes:
      - ./shard-1:/app/data

  codebase-intelligence-3:
    image: codebase-intelligence:latest
    environment:
      - CI_INSTANCE_ID=3
      - CI_SHARD_COUNT=3
      - CI_SHARD_INDEX=2
    volumes:
      - ./shard-2:/app/data
```

#### Load Balancing
```nginx
# nginx.conf for load balancing
upstream codebase_intelligence {
    least_conn;
    server localhost:7345 weight=1;
    server localhost:7346 weight=1;
    server localhost:7347 weight=1;
}

server {
    listen 80;
    location / {
        proxy_pass http://codebase_intelligence;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Vertical Scaling

#### Container Resource Limits
```yaml
# docker-compose.yml with resource limits
services:
  codebase-intelligence:
    image: codebase-intelligence:latest
    deploy:
      resources:
        limits:
          cpus: '8.0'
          memory: 16G
        reservations:
          cpus: '4.0'
          memory: 8G
    environment:
      - CI_MAX_CONCURRENCY=16
      - CI_MEMORY_LIMIT=12GB
```

#### Kubernetes Scaling
```yaml
# kubernetes deployment with auto-scaling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: codebase-intelligence
spec:
  replicas: 3
  selector:
    matchLabels:
      app: codebase-intelligence
  template:
    spec:
      containers:
      - name: codebase-intelligence
        image: codebase-intelligence:latest
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "16Gi"
            cpu: "8"
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: codebase-intelligence-hpa
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
```

## Performance Testing

### Benchmarking Script

```bash
#!/bin/bash
# performance-test.sh

echo "Starting Codebase Intelligence Performance Test"
echo "=============================================="

# Test project paths
SMALL_PROJECT="/path/to/small-project"    # <1K files
MEDIUM_PROJECT="/path/to/medium-project"  # 1K-10K files
LARGE_PROJECT="/path/to/large-project"    # 10K+ files

# Test configurations
CONFIGS=("default" "optimized" "high-memory")

for config in "${CONFIGS[@]}"; do
    echo "Testing configuration: $config"
    
    # Load configuration
    export CI_CONFIG_PATH="configs/$config.json"
    
    for project in "$SMALL_PROJECT" "$MEDIUM_PROJECT" "$LARGE_PROJECT"; do
        if [ -d "$project" ]; then
            echo "Analyzing $project with $config configuration"
            
            # Clear caches
            rm -rf .codeintel/cache/
            
            # Time the analysis
            start_time=$(date +%s.%N)
            codebase-intelligence analyze --project "$project" --quiet
            end_time=$(date +%s.%N)
            
            # Calculate duration
            duration=$(echo "$end_time - $start_time" | bc)
            
            # Count files
            file_count=$(find "$project" -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" | wc -l)
            
            # Log results
            echo "$config,$project,$file_count,$duration" >> performance-results.csv
            
            echo "  Files: $file_count, Time: ${duration}s"
        fi
    done
    echo ""
done

echo "Performance testing complete. Results saved to performance-results.csv"
```

### Memory Profiling

```bash
# Enable memory profiling
export CI_PROFILER_ENABLED="true"
export CI_MEMORY_PROFILING="true"

# Run analysis with profiling
codebase-intelligence analyze --profile

# Generate heap snapshot
kill -USR2 $(pgrep -f codebase-intelligence)

# Analyze with Node.js tools
node --inspect-brk codebase-intelligence analyze
```

### Performance Regression Testing

```javascript
// performance-regression.js
const { performance } = require('perf_hooks');
const { execSync } = require('child_process');

const testCases = [
  { name: 'small-project', path: '/path/to/small', expectedTime: 10000 },
  { name: 'medium-project', path: '/path/to/medium', expectedTime: 60000 },
  { name: 'large-project', path: '/path/to/large', expectedTime: 300000 }
];

async function runPerformanceTests() {
  const results = [];
  
  for (const testCase of testCases) {
    console.log(`Testing ${testCase.name}...`);
    
    const start = performance.now();
    try {
      execSync(`codebase-intelligence analyze --project ${testCase.path}`, {
        stdio: 'pipe',
        timeout: testCase.expectedTime * 2
      });
    } catch (error) {
      console.error(`Test failed for ${testCase.name}:`, error.message);
      continue;
    }
    const end = performance.now();
    
    const actualTime = end - start;
    const regression = ((actualTime - testCase.expectedTime) / testCase.expectedTime) * 100;
    
    results.push({
      name: testCase.name,
      expectedTime: testCase.expectedTime,
      actualTime,
      regression: regression.toFixed(2)
    });
    
    console.log(`  Expected: ${testCase.expectedTime}ms, Actual: ${actualTime.toFixed(0)}ms, Regression: ${regression.toFixed(2)}%`);
  }
  
  // Alert on significant regressions
  const significantRegressions = results.filter(r => r.regression > 20);
  if (significantRegressions.length > 0) {
    console.error('PERFORMANCE REGRESSION DETECTED:');
    significantRegressions.forEach(r => {
      console.error(`  ${r.name}: ${r.regression}% slower than expected`);
    });
    process.exit(1);
  }
  
  console.log('All performance tests passed!');
}

runPerformanceTests().catch(console.error);
```

## Troubleshooting Performance Issues

### Common Performance Problems

#### 1. High Memory Usage
```bash
# Symptoms
- System becomes unresponsive
- Out of memory errors
- High swap usage

# Diagnosis
ps aux | grep codebase-intelligence
free -h
top -p $(pgrep codebase-intelligence)

# Solutions
export CI_MEMORY_LIMIT="4GB"
export CI_MAX_CONCURRENCY="4"
export NODE_OPTIONS="--max-old-space-size=4096"
```

#### 2. Slow Analysis
```bash
# Symptoms
- Analysis takes hours to complete
- High CPU usage with no progress
- Timeout errors

# Diagnosis
time codebase-intelligence analyze --verbose
strace -p $(pgrep codebase-intelligence)

# Solutions
# Exclude unnecessary files
{
  "analysis": {
    "exclude": ["node_modules/**", "**/*.min.js", "dist/**"]
  }
}

# Increase timeout
export CI_ANALYSIS_TIMEOUT="1800000"  # 30 minutes
```

#### 3. Database Lock Issues
```bash
# Symptoms
- "Database is locked" errors
- Analysis hangs indefinitely
- Multiple processes accessing database

# Diagnosis
lsof .codeintel/analysis.db
ps aux | grep codebase-intelligence

# Solutions
pkill -f codebase-intelligence
rm -f .codeintel/analysis.db-wal .codeintel/analysis.db-shm
```

### Performance Debugging

```bash
# Enable debug logging
export CI_LOG_LEVEL="debug"
export CI_DEBUG_PERFORMANCE="true"

# Run with verbose output
codebase-intelligence analyze --verbose --debug

# Profile memory usage
valgrind --tool=massif node codebase-intelligence analyze

# Profile CPU usage
perf record -g node codebase-intelligence analyze
perf report
```

---

*For enterprise-level performance optimization, see our [Enterprise Performance Guide](./enterprise/performance.md) and [Scaling Architecture](./architecture.md#scaling).*