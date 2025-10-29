# NACF Monitoring & Observability Guide

Comprehensive monitoring, alerting, and observability setup for the Neural Authentication Control Framework (NACF).

## 📋 Table of Contents

- [Monitoring Overview](#monitoring-overview)
- [Metrics Collection](#metrics-collection)
- [Logging Architecture](#logging-architecture)
- [Alerting System](#alerting-system)
- [Dashboards & Visualization](#dashboards--visualization)
- [Tracing & Performance](#tracing--performance)
- [Health Checks](#health-checks)
- [Incident Response](#incident-response)
- [Best Practices](#best-practices)

## 📊 Monitoring Overview

### Monitoring Stack

NACF uses a comprehensive monitoring stack:

```
Metrics:     Prometheus → VictoriaMetrics → Grafana
Logs:        Fluent Bit → Elasticsearch → Kibana
Traces:      Jaeger → Elasticsearch → Jaeger UI
Alerts:      Prometheus → AlertManager → Multiple Channels
Health:      Custom Health Checks → Prometheus
```

### Key Monitoring Areas

1. **Application Performance**: Response times, throughput, error rates
2. **Neural Processing**: Signal quality, model accuracy, processing latency
3. **Security**: Failed authentications, suspicious activities, compliance
4. **Infrastructure**: CPU, memory, disk, network utilization
5. **Business Metrics**: User registrations, authentication success rates

## 📈 Metrics Collection

### Application Metrics

#### Core Metrics

```python
from prometheus_client import Counter, Histogram, Gauge, Summary
import time

# Authentication metrics
AUTH_REQUESTS_TOTAL = Counter(
    'nacfauth_auth_requests_total',
    'Total number of authentication requests',
    ['method', 'status', 'user_type']
)

AUTH_DURATION = Histogram(
    'nacfauth_auth_duration_seconds',
    'Authentication request duration',
    ['method', 'status'],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
)

AUTH_SUCCESS_RATE = Gauge(
    'nacfauth_auth_success_rate',
    'Current authentication success rate (last 5 minutes)',
    ['method']
)

# Neural processing metrics
SIGNAL_PROCESSING_DURATION = Histogram(
    'nacfauth_signal_processing_duration_seconds',
    'Neural signal processing duration',
    ['signal_type', 'quality'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0]
)

SIGNAL_QUALITY_SCORE = Histogram(
    'nacfauth_signal_quality_score',
    'Neural signal quality distribution',
    ['signal_type'],
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)

MODEL_ACCURACY = Gauge(
    'nacfauth_model_accuracy',
    'Current model accuracy scores',
    ['user_id', 'model_version']
)

# Session metrics
ACTIVE_SESSIONS = Gauge(
    'nacfauth_active_sessions',
    'Number of currently active sessions'
)

SESSION_DURATION = Histogram(
    'nacfauth_session_duration_hours',
    'Session duration distribution',
    buckets=[1, 2, 4, 8, 12, 24, 48, 168]  # Hours
)

# Security metrics
FAILED_AUTH_ATTEMPTS = Counter(
    'nacfauth_failed_auth_attempts_total',
    'Total number of failed authentication attempts',
    ['reason', 'ip_address']
)

SUSPICIOUS_ACTIVITIES = Counter(
    'nacfauth_suspicious_activities_total',
    'Total number of suspicious activities detected',
    ['activity_type', 'severity']
)

# Business metrics
USER_REGISTRATIONS_TOTAL = Counter(
    'nacfauth_user_registrations_total',
    'Total number of user registrations',
    ['registration_method', 'status']
)

DAILY_ACTIVE_USERS = Gauge(
    'nacfauth_daily_active_users',
    'Number of daily active users'
)
```

#### Metrics Middleware

```python
import time
from functools import wraps
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

class MetricsMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        start_time = time.time()
        method = scope['method']
        path = scope['path']

        # Create response wrapper to capture status
        response_status = [200]  # Default

        async def wrapped_send(message):
            if message['type'] == 'http.response.start':
                response_status[0] = message['status']
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)

            # Record metrics
            duration = time.time() - start_time
            status = str(response_status[0])

            AUTH_REQUESTS_TOTAL.labels(
                method=method,
                status=status,
                user_type=self._get_user_type(scope)
            ).inc()

            AUTH_DURATION.labels(
                method=method,
                status=status
            ).observe(duration)

            # Update success rate gauge
            self._update_success_rate()

        except Exception as e:
            # Record error metrics
            AUTH_REQUESTS_TOTAL.labels(
                method=method,
                status='500',
                user_type='unknown'
            ).inc()

            raise

    def _get_user_type(self, scope) -> str:
        # Extract user type from request headers/tokens
        # Implementation depends on your auth system
        return 'authenticated'  # Placeholder

    def _update_success_rate(self):
        # Calculate and update success rate
        # This would typically query Prometheus or maintain local counters
        pass

# Metrics endpoint
@app.get('/metrics')
async def metrics():
    return Response(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
```

### Infrastructure Metrics

#### System Metrics

```yaml
# Prometheus node exporter configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'nacfauth-api'
    static_configs:
      - targets: ['nacfauth-api:8000']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 15s

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']
    scrape_interval: 30s

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']
    scrape_interval: 30s
```

#### Database Metrics

```sql
-- PostgreSQL custom metrics
CREATE OR REPLACE FUNCTION get_auth_stats()
RETURNS TABLE (
    total_users bigint,
    active_users_today bigint,
    auth_attempts_today bigint,
    success_rate_today numeric
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM user_profiles WHERE status = 'active') as total_users,
        (SELECT COUNT(DISTINCT user_id) FROM auth_attempts
         WHERE timestamp >= CURRENT_DATE) as active_users_today,
        (SELECT COUNT(*) FROM auth_attempts
         WHERE timestamp >= CURRENT_DATE) as auth_attempts_today,
        (SELECT ROUND(
            COUNT(*) FILTER (WHERE success) * 100.0 / NULLIF(COUNT(*), 0), 2
         ) FROM auth_attempts WHERE timestamp >= CURRENT_DATE) as success_rate_today;
END;
$$ LANGUAGE plpgsql;
```

## 📝 Logging Architecture

### Structured Logging

#### Logging Configuration

```python
import logging
import json
import sys
from pythonjsonlogger import jsonlogger

class StructuredLogger:
    def __init__(self, service_name: str, log_level: str = 'INFO'):
        self.service_name = service_name
        self.logger = logging.getLogger(service_name)
        self.logger.setLevel(getattr(logging, log_level))

        # Remove existing handlers
        self.logger.handlers.clear()

        # Create structured formatter
        formatter = jsonlogger.JsonFormatter(
            fmt='%(asctime)s %(name)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S%z'
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            f'logs/{service_name}.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log_auth_attempt(self, user_id: str, success: bool,
                        confidence: float = None, duration: float = None,
                        ip_address: str = None, user_agent: str = None):
        self.logger.info('Authentication attempt', extra={
            'event_type': 'auth_attempt',
            'user_id': user_id,
            'success': success,
            'confidence': confidence,
            'duration_ms': duration,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'service': self.service_name
        })

    def log_security_event(self, event_type: str, severity: str,
                          details: dict, user_id: str = None):
        self.logger.warning('Security event detected', extra={
            'event_type': 'security_event',
            'security_event_type': event_type,
            'severity': severity,
            'details': details,
            'user_id': user_id,
            'service': self.service_name
        })

    def log_performance_metric(self, operation: str, duration: float,
                              metadata: dict = None):
        self.logger.info('Performance metric', extra={
            'event_type': 'performance',
            'operation': operation,
            'duration_ms': duration,
            'metadata': metadata or {},
            'service': self.service_name
        })

# Global logger instance
logger = StructuredLogger('nacfauth-api')
```

#### Log Levels and Usage

| Level | Usage | Examples |
|-------|-------|----------|
| DEBUG | Detailed debugging info | Variable values, function calls |
| INFO | General information | User actions, system events |
| WARNING | Warning conditions | Deprecated features, unusual events |
| ERROR | Error conditions | Failed operations, exceptions |
| CRITICAL | Critical errors | System failures, security breaches |

### Log Aggregation

#### Fluent Bit Configuration

```ini
# fluent-bit.conf
[INPUT]
    Name              tail
    Path              /var/log/nacf/*.log
    Parser            json
    Tag               nacf.*
    Refresh_Interval  5

[INPUT]
    Name              prometheus_scrape
    Host              0.0.0.0
    Port              9090
    Tag               prometheus.*
    Metrics_Path      /metrics

[FILTER]
    Name              grep
    Match             nacf.*
    Exclude           log_level debug

[FILTER]
    Name              record_modifier
    Match             nacf.*
    Record            service_name nacfauth
    Record            cluster production

[OUTPUT]
    Name              elasticsearch
    Match             nacf.*
    Host              elasticsearch
    Port              9200
    Index             nacf-logs
    Type              log

[OUTPUT]
    Name              prometheus_remote_write
    Match             prometheus.*
    Host              prometheus
    Port              9090
    Uri               /api/v1/write
```

## 🚨 Alerting System

### Alert Definitions

#### Critical Alerts

```yaml
# Prometheus alerting rules
groups:
  - name: nacfauth.critical
    rules:
      - alert: NACFHighErrorRate
        expr: rate(nacfauth_auth_requests_total{status=~"5.."}[5m]) / rate(nacfauth_auth_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
          service: nacfauth
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | printf \"%.2f\" }}% over the last 5 minutes"
          runbook_url: "https://docs.nacf.dev/runbooks/high-error-rate"

      - alert: NACFServiceDown
        expr: up{job="nacfauth-api"} == 0
        for: 2m
        labels:
          severity: critical
          service: nacfauth
        annotations:
          summary: "NACF API service is down"
          description: "NACF API has been down for more than 2 minutes"
          runbook_url: "https://docs.nacf.dev/runbooks/service-down"

      - alert: NACFDatabaseDown
        expr: pg_up == 0
        for: 1m
        labels:
          severity: critical
          service: nacfauth
        annotations:
          summary: "Database is down"
          description: "PostgreSQL database is not responding"
          runbook_url: "https://docs.nacf.dev/runbooks/database-down"
```

#### Warning Alerts

```yaml
  - name: nacfauth.warning
    rules:
      - alert: NACFLowSuccessRate
        expr: nacfauth_auth_success_rate < 0.95
        for: 10m
        labels:
          severity: warning
          service: nacfauth
        annotations:
          summary: "Low authentication success rate"
          description: "Authentication success rate dropped to {{ $value | printf \"%.2f\" }}%"
          runbook_url: "https://docs.nacf.dev/runbooks/low-success-rate"

      - alert: NACFHighLatency
        expr: histogram_quantile(0.95, rate(nacfauth_auth_duration_seconds_bucket[5m])) > 2.0
        for: 5m
        labels:
          severity: warning
          service: nacfauth
        annotations:
          summary: "High authentication latency"
          description: "95th percentile latency is {{ $value | printf \"%.2f\" }}s"
          runbook_url: "https://docs.nacf.dev/runbooks/high-latency"

      - alert: NACFSignalQualityDegraded
        expr: nacfauth_signal_quality_score < 0.7
        for: 5m
        labels:
          severity: warning
          service: nacfauth
        annotations:
          summary: "Degraded signal quality"
          description: "Average signal quality dropped to {{ $value | printf \"%.2f\" }}"
          runbook_url: "https://docs.nacf.dev/runbooks/signal-quality"
```

#### Security Alerts

```yaml
  - name: nacfauth.security
    rules:
      - alert: NACFBruteForceDetected
        expr: rate(nacfauth_failed_auth_attempts_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
          service: nacfauth
          alert_type: security
        annotations:
          summary: "Brute force attack detected"
          description: "High rate of failed authentication attempts: {{ $value | printf \"%.0f\" }}/5min"
          runbook_url: "https://docs.nacf.dev/runbooks/brute-force"

      - alert: NACFSuspiciousActivity
        expr: increase(nacfauth_suspicious_activities_total[1h]) > 5
        for: 5m
        labels:
          severity: warning
          service: nacfauth
          alert_type: security
        annotations:
          summary: "Suspicious activity detected"
          description: "{{ $value | printf \"%.0f\" }} suspicious activities in the last hour"
          runbook_url: "https://docs.nacf.dev/runbooks/suspicious-activity"
```

### Alert Manager Configuration

```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@nacf.dev'
  smtp_auth_username: 'alerts@nacf.dev'
  smtp_auth_password: 'your-smtp-password'

route:
  group_by: ['alertname', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'nacfauth-team'
  routes:
    - match:
        severity: critical
      receiver: 'nacfauth-critical'
    - match:
        alert_type: security
      receiver: 'nacfauth-security'

receivers:
  - name: 'nacfauth-team'
    email_configs:
      - to: 'team@nacf.dev'
        send_resolved: true
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#alerts'
        send_resolved: true

  - name: 'nacfauth-critical'
    pagerduty_configs:
      - service_key: 'your-pagerduty-service-key'
    email_configs:
      - to: 'oncall@nacf.dev'
        send_resolved: true

  - name: 'nacfauth-security'
    email_configs:
      - to: 'security@nacf.dev'
        send_resolved: true
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SECURITY/WEBHOOK'
        channel: '#security-alerts'
        send_resolved: true
```

## 📊 Dashboards & Visualization

### Grafana Dashboards

#### Main NACF Dashboard

```json
{
  "dashboard": {
    "title": "NACF Overview",
    "tags": ["nacfauth", "authentication"],
    "timezone": "UTC",
    "panels": [
      {
        "title": "Authentication Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(nacfauth_auth_requests_total{status=~\"2..\"}[5m]) / rate(nacfauth_auth_requests_total[5m]) * 100",
            "legendFormat": "Success Rate %"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "red", "value": null },
                { "color": "orange", "value": 90 },
                { "color": "green", "value": 95 }
              ]
            }
          }
        }
      },
      {
        "title": "Authentication Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(nacfauth_auth_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(nacfauth_auth_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Active Sessions",
        "type": "singlestat",
        "targets": [
          {
            "expr": "nacfauth_active_sessions",
            "legendFormat": "Active Sessions"
          }
        ]
      },
      {
        "title": "Signal Quality Distribution",
        "type": "heatmap",
        "targets": [
          {
            "expr": "nacfauth_signal_quality_score",
            "legendFormat": "Signal Quality"
          }
        ]
      }
    ]
  }
}
```

#### Security Dashboard

```json
{
  "dashboard": {
    "title": "NACF Security",
    "tags": ["nacfauth", "security"],
    "panels": [
      {
        "title": "Failed Authentication Attempts",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(nacfauth_failed_auth_attempts_total[5m])",
            "legendFormat": "Failed Attempts/5min"
          }
        ]
      },
      {
        "title": "Suspicious Activities",
        "type": "table",
        "targets": [
          {
            "expr": "increase(nacfauth_suspicious_activities_total[1h])",
            "legendFormat": "Suspicious Activities"
          }
        ]
      },
      {
        "title": "Top Failed IPs",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, rate(nacfauth_failed_auth_attempts_total[1h])) by (ip_address)",
            "legendFormat": "{{ ip_address }}"
          }
        ]
      }
    ]
  }
}
```

### Kibana Dashboards

#### Log Analysis Dashboard

```json
{
  "title": "NACF Logs Analysis",
  "visState": {
    "title": "Error Logs Over Time",
    "type": "histogram",
    "params": {
      "type": "histogram",
      "grid": {
        "categoryLines": false
      },
      "categoryAxes": [
        {
          "id": "CategoryAxis-1",
          "type": "category",
          "position": "bottom",
          "show": true,
          "style": {},
          "scale": {
            "type": "linear"
          },
          "labels": {
            "show": true,
            "truncate": 100
          },
          "title": {}
        }
      ],
      "valueAxes": [
        {
          "id": "ValueAxis-1",
          "name": "LeftAxis-1",
          "type": "value",
          "position": "left",
          "show": true,
          "style": {},
          "scale": {
            "type": "linear",
            "mode": "normal"
          },
          "labels": {
            "show": true,
            "rotate": 0,
            "filter": false,
            "truncate": 100
          },
          "title": {
            "text": "Count"
          }
        }
      ],
      "seriesParams": [
        {
          "show": "true",
          "type": "histogram",
          "mode": "stacked",
          "data": {
            "label": "Count",
            "id": "1"
          },
          "valueAxis": "ValueAxis-1",
          "drawLinesBetweenPoints": true,
          "showCircles": true
        }
      ]
    },
    "aggs": [
      {
        "id": "1",
        "enabled": true,
        "type": "date_histogram",
        "schema": "segment",
        "params": {
          "field": "@timestamp",
          "interval": "auto",
          "customInterval": "2h",
          "min_doc_count": 1,
          "extended_bounds": {},
          "customLabel": "Time"
        }
      },
      {
        "id": "2",
        "enabled": true,
        "type": "terms",
        "schema": "group",
        "params": {
          "field": "level",
          "size": 5,
          "order": "desc",
          "orderBy": "_count",
          "customLabel": "Log Level"
        }
      }
    ]
  }
}
```

## 🔍 Tracing & Performance

### Distributed Tracing

#### Jaeger Integration

```python
from jaeger_client import Config
from flask_opentracing import FlaskTracing
from opentracing_instrumentation.client_hooks import install_all_patches

def init_tracing(service_name: str):
    config = Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1,
            },
            'local_agent': {
                'reporting_host': 'jaeger-agent',
                'reporting_port': 6831,
            },
            'logging': True,
        },
        service_name=service_name,
    )

    # Initialize tracer
    tracer = config.initialize_tracer()

    # Install instrumentation
    install_all_patches()

    return tracer

# Initialize in Flask app
tracer = init_tracing('nacfauth-api')
tracing = FlaskTracing(tracer, True, app)
```

#### Custom Tracing

```python
from opentracing import tags
import time

class TracingMiddleware:
    def __init__(self, app, tracer):
        self.app = app
        self.tracer = tracer

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        # Start span
        with self.tracer.start_active_span(
            f"{scope['method']} {scope['path']}",
            tags={
                tags.SPAN_KIND: tags.SPAN_KIND_RPC_SERVER,
                tags.HTTP_METHOD: scope['method'],
                tags.HTTP_URL: scope['path'],
            }
        ) as scope_span:
            span = scope_span.span

            try:
                # Add custom tags
                span.set_tag('user_id', self._extract_user_id(scope))
                span.set_tag('request_id', self._generate_request_id())

                start_time = time.time()
                await self.app(scope, receive, wrapped_send)
                duration = time.time() - start_time

                # Record success
                span.set_tag(tags.HTTP_STATUS_CODE, response_status[0])
                span.set_tag('duration_ms', duration * 1000)
                span.log_kv({'event': 'request_completed'})

            except Exception as e:
                # Record error
                span.set_tag(tags.ERROR, True)
                span.log_kv({
                    'event': 'error',
                    'error': str(e),
                    'stack': traceback.format_exc()
                })
                raise
```

### Performance Profiling

#### Application Profiling

```python
import cProfile
import pstats
from functools import wraps
import io

def profile_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        pr = cProfile.Profile()
        pr.enable()

        result = func(*args, **kwargs)

        pr.disable()
        s = io.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()

        # Log profiling results
        logger.info(f"Profile for {func.__name__}", extra={
            'profile_data': s.getvalue(),
            'function': func.__name__
        })

        return result
    return wrapper

# Apply to critical functions
@profile_function
def authenticate_user(user_id: str, signals):
    # Authentication logic
    pass
```

#### Memory Profiling

```python
import tracemalloc
from functools import wraps

def memory_profile(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        tracemalloc.start()

        result = func(*args, **kwargs)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        logger.info(f"Memory usage for {func.__name__}", extra={
            'current_memory_mb': current / 1024 / 1024,
            'peak_memory_mb': peak / 1024 / 1024,
            'function': func.__name__
        })

        return result
    return wrapper
```

## 🏥 Health Checks

### Application Health Checks

```python
from fastapi import APIRouter, HTTPException
import asyncpg
import redis.asyncio as redis
import aiohttp

router = APIRouter()

class HealthChecker:
    def __init__(self, db_url: str, redis_url: str):
        self.db_url = db_url
        self.redis_url = redis_url

    async def check_database(self) -> dict:
        try:
            conn = await asyncpg.connect(self.db_url)
            result = await conn.fetchval("SELECT 1")
            await conn.close()

            return {
                'status': 'healthy',
                'response_time_ms': 0,  # Would measure actual time
                'details': {'connection': 'successful'}
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'details': {'connection': 'failed'}
            }

    async def check_redis(self) -> dict:
        try:
            r = redis.from_url(self.redis_url)
            await r.ping()
            await r.close()

            return {
                'status': 'healthy',
                'response_time_ms': 0,
                'details': {'ping': 'successful'}
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'details': {'ping': 'failed'}
            }

    async def check_external_services(self) -> dict:
        services = {
            'neural_model': 'http://model-service:8001/health',
            'signal_processor': 'http://signal-processor:8002/health'
        }

        results = {}
        async with aiohttp.ClientSession() as session:
            for name, url in services.items():
                try:
                    async with session.get(url, timeout=5) as response:
                        results[name] = {
                            'status': 'healthy' if response.status == 200 else 'degraded',
                            'response_time_ms': 0,
                            'http_status': response.status
                        }
                except Exception as e:
                    results[name] = {
                        'status': 'unhealthy',
                        'error': str(e)
                    }

        return results

health_checker = HealthChecker(
    db_url="postgresql://...",
    redis_url="redis://..."
)

@router.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""

    # Check all components
    db_health = await health_checker.check_database()
    redis_health = await health_checker.check_redis()
    services_health = await health_checker.check_external_services()

    # Determine overall health
    all_checks = [db_health, redis_health] + list(services_health.values())
    overall_status = 'healthy'

    if any(check.get('status') == 'unhealthy' for check in all_checks):
        overall_status = 'unhealthy'
    elif any(check.get('status') == 'degraded' for check in all_checks):
        overall_status = 'degraded'

    return {
        'status': overall_status,
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'checks': {
            'database': db_health,
            'redis': redis_health,
            'external_services': services_health
        }
    }

@router.get("/health/live")
async def liveness_check():
    """Simple liveness probe"""
    return {"status": "alive"}

@router.get("/health/ready")
async def readiness_check():
    """Readiness probe - checks if service can accept traffic"""
    db_health = await health_checker.check_database()

    if db_health['status'] == 'healthy':
        return {"status": "ready"}
    else:
        raise HTTPException(status_code=503, detail="Service not ready")
```

### Kubernetes Health Checks

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nacf-api
spec:
  containers:
  - name: nacf-api
    image: nacf-api:latest
    ports:
    - containerPort: 8000
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8000
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8000
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 3
      failureThreshold: 3
    startupProbe:
      httpGet:
        path: /health/live
        port: 8000
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 30
```

## 🚨 Incident Response

### Automated Response

```python
class IncidentResponder:
    def __init__(self, alertmanager_client, slack_client):
        self.alertmanager = alertmanager_client
        self.slack = slack_client
        self.incident_thresholds = {
            'error_rate': 0.05,  # 5%
            'latency_p95': 5.0,  # 5 seconds
            'failed_auth_rate': 0.10  # 10%
        }

    async def handle_alert(self, alert: dict):
        """Handle incoming alerts and trigger automated responses"""

        alert_name = alert['labels']['alertname']
        severity = alert['labels']['severity']

        if alert_name == 'NACFHighErrorRate':
            await self.handle_high_error_rate(alert, severity)
        elif alert_name == 'NACFHighLatency':
            await self.handle_high_latency(alert, severity)
        elif alert_name == 'NACFBruteForceDetected':
            await self.handle_brute_force(alert, severity)

    async def handle_high_error_rate(self, alert: dict, severity: str):
        """Handle high error rate incidents"""

        # Scale up application
        if severity == 'critical':
            await self.scale_application(replicas=150)  # Emergency scaling

        # Enable circuit breaker
        await self.enable_circuit_breaker()

        # Notify team
        await self.notify_team(
            "High error rate detected",
            f"Error rate: {alert['value']}%",
            severity
        )

    async def handle_brute_force(self, alert: dict, severity: str):
        """Handle brute force attack detection"""

        # Enable stricter rate limiting
        await self.enable_strict_rate_limiting()

        # Block suspicious IPs
        suspicious_ips = await self.get_suspicious_ips()
        await self.block_ips(suspicious_ips)

        # Notify security team
        await self.notify_security_team(
            "Brute force attack detected",
            f"Attack details: {alert}",
            severity
        )

    async def scale_application(self, replicas: int):
        """Scale application pods"""
        # Kubernetes API call to scale deployment
        pass

    async def enable_circuit_breaker(self):
        """Enable circuit breaker pattern"""
        # Implementation to enable circuit breaker
        pass

    async def notify_team(self, title: str, message: str, severity: str):
        """Send notifications to team"""
        # Send to Slack, email, PagerDuty, etc.
        pass
```

### Runbooks

#### High Error Rate Runbook

```markdown
# High Error Rate Runbook

## Detection
- Alert: NACFHighErrorRate
- Threshold: Error rate > 5% for 5 minutes

## Initial Assessment
1. Check application logs for error patterns
2. Verify database connectivity
3. Check Redis availability
4. Monitor system resources (CPU, memory, disk)

## Immediate Actions
1. **Scale up**: Increase pod replicas if CPU/memory high
2. **Circuit breaker**: Enable if downstream services failing
3. **Rate limiting**: Increase limits if under attack
4. **Restart services**: If memory leaks suspected

## Investigation Steps
1. Analyze error logs in Kibana
2. Check recent deployments
3. Review recent code changes
4. Monitor external dependencies

## Recovery
1. Identify root cause
2. Apply fix
3. Scale back to normal levels
4. Monitor for recurrence

## Prevention
1. Add more comprehensive error handling
2. Implement gradual rollout for deployments
3. Add chaos engineering tests
4. Improve monitoring coverage
```

## 📋 Best Practices

### Monitoring Best Practices

1. **Define SLOs/SLIs**: Set clear service level objectives
2. **Use the Four Golden Signals**: Latency, traffic, errors, saturation
3. **Monitor from user perspective**: Synthetic monitoring
4. **Alert on symptoms, not causes**: Alert when users are affected
5. **Keep alerts actionable**: Each alert should have a clear owner and runbook

### Logging Best Practices

1. **Structured logging**: Use JSON format with consistent fields
2. **Log levels appropriately**: Don't log sensitive data
3. **Include context**: Request IDs, user IDs, session IDs
4. **Log security events**: All authentication attempts, suspicious activities
5. **Retention policies**: Define how long to keep different log types

### Alerting Best Practices

1. **Avoid alert fatigue**: Only alert on actionable issues
2. **Escalation policies**: Different notification methods for different severities
3. **On-call rotation**: Ensure 24/7 coverage
4. **Alert dependencies**: Don't alert on issues caused by known outages
5. **Regular review**: Review and tune alert thresholds regularly

### Observability Culture

1. **Shared ownership**: Everyone responsible for monitoring
2. **Blame-free culture**: Focus on learning from incidents
3. **Regular reviews**: Post-mortem all incidents
4. **Tool literacy**: Train team on monitoring tools
5. **Automation**: Automate as much monitoring as possible

---

This monitoring guide provides comprehensive coverage of NACF's observability setup. For specific implementation details, refer to the [Installation Guide](INSTALL.md) and [Architecture Guide](ARCHITECTURE.md). 🚀