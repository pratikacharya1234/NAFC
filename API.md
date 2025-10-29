# NACF API Documentation

Complete API reference for the Neural Authentication Control Framework (NACF), including REST endpoints, WebSocket streams, and SDK methods.

## 📋 Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [REST API](#rest-api)
- [WebSocket API](#websocket-api)
- [Python SDK](#python-sdk)
- [Web SDK](#web-sdk)
- [Mobile SDKs](#mobile-sdks)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Versioning](#versioning)

## 📖 Overview

### API Architecture

NACF provides multiple API interfaces:

- **REST API**: HTTP-based endpoints for authentication operations
- **WebSocket API**: Real-time streaming for continuous authentication
- **Python SDK**: Native Python library for server-side integration
- **Web SDK**: JavaScript library for browser-based authentication
- **Mobile SDKs**: Native libraries for iOS and Android

### Base URLs

- **Production**: `https://api.nacf.dev/v1`
- **Staging**: `https://api-staging.nacf.dev/v1`
- **Development**: `http://localhost:8000/api/v1`

### Content Types

- **Request**: `application/json`
- **Response**: `application/json`
- **File Upload**: `multipart/form-data`

## 🔐 Authentication

### API Key Authentication

```bash
# Include in request headers
Authorization: Bearer your-api-key-here

# Or as query parameter
GET /api/v1/users?api_key=your-api-key-here
```

### JWT Token Authentication

```bash
# For authenticated user operations
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### Session-Based Authentication

```javascript
// Web SDK handles session automatically
const client = new NACF.Client({ apiKey: 'your-key' });
await client.authenticate({ userId: 'user123' });
```

## 🌐 REST API

### Core Endpoints

#### POST /api/v1/auth/register

Register a new user with neural profile.

**Headers:**
```
Authorization: Bearer your-api-key
Content-Type: application/json
```

**Request Body:**
```json
{
  "user_id": "string (required)",
  "neural_profile": {
    "signals": {
      "eeg_data": "array of arrays (required)",
      "sampling_rate": "number (default: 1000)",
      "channels": "array of strings (required)",
      "duration_seconds": "number (optional)"
    },
    "quality_score": "number (0.0-1.0, optional)",
    "metadata": {
      "device": "string (optional)",
      "session_date": "ISO 8601 string (optional)",
      "environmental_conditions": "object (optional)"
    }
  },
  "options": {
    "model_type": "string (default: 'default')",
    "training_params": "object (optional)"
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "user_id": "string",
  "registration_id": "string",
  "model_accuracy": "number",
  "quality_metrics": {
    "signal_quality": "number",
    "training_score": "number",
    "feature_count": "number"
  },
  "timestamp": "ISO 8601 string",
  "processing_time_ms": "number"
}
```

**Error Responses:**
- `400 Bad Request`: Invalid request data
- `409 Conflict`: User already exists
- `422 Unprocessable Entity`: Invalid neural data
- `429 Too Many Requests`: Rate limit exceeded

**Example:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "john_doe",
    "neural_profile": {
      "signals": {
        "eeg_data": [[0.1, 0.2, 0.3, 0.4], [0.2, 0.3, 0.4, 0.5]],
        "sampling_rate": 1000,
        "channels": ["Fp1", "Fp2", "F3", "F4"]
      },
      "quality_score": 0.95
    }
  }'
```

#### POST /api/v1/auth/authenticate

Authenticate a user with neural signals.

**Request Body:**
```json
{
  "user_id": "string (required)",
  "signals": {
    "eeg_data": "array of arrays (required)",
    "sampling_rate": "number (default: 1000)",
    "channels": "array of strings (required)"
  },
  "session_id": "string (optional)",
  "options": {
    "confidence_threshold": "number (default: 0.85)",
    "include_features": "boolean (default: false)",
    "model_version": "string (optional)"
  }
}
```

**Response (200 OK):**
```json
{
  "authenticated": true,
  "user_id": "string",
  "confidence": "number (0.0-1.0)",
  "session_id": "string",
  "quality_score": "number",
  "processing_time_ms": "number",
  "timestamp": "ISO 8601 string",
  "model_version": "string",
  "features": "object (optional)"
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/authenticate \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "john_doe",
    "signals": {
      "eeg_data": [[0.1, 0.2, 0.3, 0.4]],
      "sampling_rate": 1000,
      "channels": ["Fp1", "Fp2", "F3", "F4"]
    }
  }'
```

#### POST /api/v1/auth/verify-session

Verify ongoing session authentication.

**Request Body:**
```json
{
  "session_id": "string (required)",
  "signals": {
    "eeg_data": "array of arrays (required)",
    "sampling_rate": "number (default: 1000)",
    "channels": "array of strings (required)"
  },
  "options": {
    "update_session": "boolean (default: true)",
    "extend_session": "boolean (default: false)"
  }
}
```

**Response (200 OK):**
```json
{
  "session_valid": true,
  "user_id": "string",
  "confidence": "number",
  "session_expires_at": "ISO 8601 string",
  "last_activity": "ISO 8601 string",
  "continuous_auth_score": "number"
}
```

### User Management

#### GET /api/v1/users/{user_id}

Get user information and status.

**Response (200 OK):**
```json
{
  "user_id": "string",
  "status": "active|inactive|suspended",
  "registration_date": "ISO 8601 string",
  "last_authentication": "ISO 8601 string",
  "model_version": "string",
  "auth_attempts_today": "number",
  "total_auth_attempts": "number",
  "success_rate": "number",
  "device_info": {
    "primary_device": "string",
    "device_history": "array"
  }
}
```

#### PUT /api/v1/users/{user_id}/profile

Update user neural profile.

**Request Body:**
```json
{
  "neural_profile": {
    "signals": "object (required)",
    "quality_score": "number (optional)"
  },
  "update_reason": "retraining|drift_correction|device_change",
  "options": {
    "merge_with_existing": "boolean (default: false)",
    "backup_existing": "boolean (default: true)"
  }
}
```

#### DELETE /api/v1/users/{user_id}

Delete user and all associated data.

**Query Parameters:**
- `confirm_deletion`: `true` (required for safety)

**Response (204 No Content)**

### Analytics and Monitoring

#### GET /api/v1/analytics/auth-stats

Get authentication statistics.

**Query Parameters:**
- `user_id`: Filter by specific user
- `start_date`: ISO 8601 start date
- `end_date`: ISO 8601 end date
- `granularity`: `hour|day|week|month`
- `metrics`: Comma-separated list of metrics

**Response (200 OK):**
```json
{
  "period": {
    "start": "ISO 8601 string",
    "end": "ISO 8601 string",
    "granularity": "string"
  },
  "summary": {
    "total_authentications": "number",
    "successful_authentications": "number",
    "success_rate": "number",
    "average_confidence": "number",
    "average_response_time_ms": "number"
  },
  "time_series": [
    {
      "timestamp": "ISO 8601 string",
      "authentications": "number",
      "success_rate": "number",
      "average_confidence": "number",
      "p95_response_time_ms": "number"
    }
  ],
  "user_breakdown": [
    {
      "user_id": "string",
      "authentications": "number",
      "success_rate": "number"
    }
  ]
}
```

#### GET /api/v1/analytics/signal-quality

Get signal quality analytics.

**Response (200 OK):**
```json
{
  "overall_quality": {
    "average": "number",
    "median": "number",
    "p95": "number",
    "distribution": {
      "excellent": "number (count)",
      "good": "number (count)",
      "fair": "number (count)",
      "poor": "number (count)"
    }
  },
  "by_device": [
    {
      "device_type": "string",
      "count": "number",
      "average_quality": "number",
      "quality_trend": "improving|stable|declining"
    }
  ],
  "by_channel": [
    {
      "channel": "string",
      "average_quality": "number",
      "failure_rate": "number"
    }
  ]
}
```

#### GET /api/v1/health

System health check.

**Response (200 OK):**
```json
{
  "status": "healthy|degraded|unhealthy",
  "version": "string",
  "uptime_seconds": "number",
  "checks": {
    "database": {
      "status": "pass|fail",
      "response_time_ms": "number",
      "details": "object"
    },
    "redis": {
      "status": "pass|fail",
      "response_time_ms": "number"
    },
    "kafka": {
      "status": "pass|fail|not_configured",
      "response_time_ms": "number"
    },
    "neural_engine": {
      "status": "pass|fail",
      "model_loaded": "boolean",
      "last_training": "ISO 8601 string"
    }
  },
  "timestamp": "ISO 8601 string"
}
```

### Batch Operations

#### POST /api/v1/batch/authenticate

Batch authenticate multiple users.

**Request Body:**
```json
{
  "requests": [
    {
      "request_id": "string (optional)",
      "user_id": "string (required)",
      "signals": "object (required)"
    }
  ],
  "options": {
    "parallel_processing": "boolean (default: true)",
    "fail_fast": "boolean (default: false)",
    "timeout_seconds": "number (default: 30)"
  }
}
```

**Response (200 OK):**
```json
{
  "results": [
    {
      "request_id": "string",
      "user_id": "string",
      "authenticated": "boolean",
      "confidence": "number",
      "error": "string (optional)"
    }
  ],
  "summary": {
    "total_requests": "number",
    "successful_authentications": "number",
    "failed_authentications": "number",
    "average_confidence": "number",
    "processing_time_ms": "number"
  }
}
```

## 🔌 WebSocket API

### Connection

```javascript
// Connect to WebSocket endpoint
const ws = new WebSocket('ws://localhost:8000/ws/auth');

// Handle connection
ws.onopen = () => {
  console.log('Connected to NACF WebSocket');
};

// Handle messages
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  handleAuthUpdate(data);
};

// Handle errors
ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};
```

### Message Types

#### Authentication Stream

**Subscribe:**
```json
{
  "type": "subscribe",
  "channel": "auth",
  "user_id": "string",
  "session_id": "string (optional)"
}
```

**Stream Messages:**
```json
{
  "type": "auth_update",
  "user_id": "string",
  "session_id": "string",
  "authenticated": true,
  "confidence": 0.92,
  "quality_score": 0.88,
  "timestamp": "ISO 8601 string"
}
```

#### Continuous Monitoring

**Subscribe:**
```json
{
  "type": "subscribe",
  "channel": "continuous_auth",
  "user_id": "string",
  "config": {
    "update_interval_ms": 1000,
    "confidence_threshold": 0.8,
    "quality_threshold": 0.7
  }
}
```

**Stream Messages:**
```json
{
  "type": "continuous_update",
  "user_id": "string",
  "status": "active|warning|alert",
  "confidence": 0.85,
  "quality_score": 0.82,
  "alerts": [
    {
      "type": "low_confidence",
      "severity": "warning",
      "message": "Authentication confidence dropped below threshold"
    }
  ],
  "timestamp": "ISO 8601 string"
}
```

#### Signal Quality Monitoring

**Subscribe:**
```json
{
  "type": "subscribe",
  "channel": "signal_quality",
  "user_id": "string"
}
```

**Stream Messages:**
```json
{
  "type": "quality_update",
  "user_id": "string",
  "overall_quality": 0.87,
  "channel_quality": {
    "Fp1": 0.91,
    "Fp2": 0.85,
    "F3": 0.89,
    "F4": 0.82
  },
  "issues": [
    {
      "channel": "F4",
      "issue": "noise",
      "severity": "minor"
    }
  ],
  "timestamp": "ISO 8601 string"
}
```

## 🐍 Python SDK

### Installation

```bash
pip install nacf-sdk
```

### Basic Usage

```python
from nacf import NeuralAuthClient
import numpy as np

# Initialize client
client = NeuralAuthClient(
    api_key='your-api-key',
    base_url='http://localhost:8000/api/v1'
)

# Register user
neural_data = np.random.randn(1000, 4)  # 1000 samples, 4 channels
result = client.register_user(
    user_id='john_doe',
    neural_signals=neural_data,
    sampling_rate=1000,
    channels=['Fp1', 'Fp2', 'F3', 'F4'],
    quality_score=0.95
)
print(f"Registration: {result.success}")

# Authenticate user
auth_signals = np.random.randn(500, 4)
auth_result = client.authenticate_user(
    user_id='john_doe',
    neural_signals=auth_signals,
    sampling_rate=1000,
    channels=['Fp1', 'Fp2', 'F3', 'F4']
)
print(f"Authenticated: {auth_result.authenticated}")
print(f"Confidence: {auth_result.confidence:.2%}")
```

### Advanced Features

```python
# Batch operations
batch_requests = [
    {
        'user_id': 'user1',
        'signals': np.random.randn(500, 4),
        'channels': ['Fp1', 'Fp2', 'F3', 'F4']
    },
    {
        'user_id': 'user2',
        'signals': np.random.randn(500, 4),
        'channels': ['Fp1', 'Fp2', 'F3', 'F4']
    }
]

batch_results = client.batch_authenticate(batch_requests)
for result in batch_results:
    print(f"{result.user_id}: {result.authenticated} ({result.confidence:.2%})")

# Session management
session = client.create_session('john_doe')
print(f"Session created: {session.session_id}")

# Continuous authentication
def on_auth_update(update):
    print(f"Auth update: {update.confidence:.2%}")

client.start_continuous_auth(
    session_id=session.session_id,
    callback=on_auth_update,
    update_interval=1.0  # seconds
)

# Real-time signal processing
processor = client.create_realtime_processor(
    buffer_size=1000,
    processing_interval=0.1
)

@processor.on_processed
def handle_processed_signals(features):
    result = client.authenticate_realtime('john_doe', features)
    print(f"Real-time auth: {result.authenticated}")

# Start processing
processor.start()
# Feed real-time data...
processor.process_chunk(new_signal_chunk)
```

### Configuration

```python
from nacf import NeuralAuthConfig

config = NeuralAuthConfig(
    api_key='your-api-key',
    base_url='https://api.nacf.dev/v1',
    timeout=30,
    retry_attempts=3,
    retry_delay=1.0,
    enable_compression=True,
    ssl_verify=True
)

client = NeuralAuthClient(config)
```

## 🌐 Web SDK

### Installation

```bash
npm install nacf-sdk
```

```html
<script src="https://cdn.jsdelivr.net/npm/nacf-sdk@latest/dist/nacf-sdk.min.js"></script>
```

### Basic Usage

```javascript
import { NACFClient } from 'nacf-sdk';

// Initialize client
const client = new NACFClient({
  apiKey: 'your-api-key',
  baseURL: 'http://localhost:8000/api/v1',
  timeout: 10000
});

// Register user
const registration = await client.registerUser({
  userId: 'john_doe',
  signalConfig: {
    samplingRate: 1000,
    channels: ['Fp1', 'Fp2', 'F3', 'F4'],
    qualityThreshold: 0.85,
    collectionDuration: 300000  // 5 minutes
  }
});

registration.onProgress((progress) => {
  console.log(`Registration: ${progress.percentage}%`);
});

const result = await registration.start();
console.log('Registration complete:', result.success);

// Authenticate user
const authentication = client.createAuthentication({
  userId: 'john_doe',
  continuousMode: true,
  confidenceThreshold: 0.85
});

authentication.on('auth-success', (result) => {
  console.log('Authentication successful:', result.confidence);
});

authentication.on('auth-failure', (result) => {
  console.log('Authentication failed:', result.reason);
});

await authentication.start();
```

### Advanced Features

```javascript
// Multi-modal authentication
const multiModalAuth = client.createMultiModalAuthentication({
  userId: 'john_doe',
  modalities: {
    eeg: {
      channels: ['Fp1', 'Fp2', 'F3', 'F4'],
      weight: 0.7
    },
    ecg: {
      channels: ['Lead1', 'Lead2'],
      weight: 0.3
    }
  },
  fusionStrategy: 'weighted_average'
});

// Device management
const deviceManager = client.getDeviceManager();

// List available devices
const devices = await deviceManager.getDevices();
console.log('Available devices:', devices);

// Connect to specific device
await deviceManager.connectDevice('eeg_headset_v2');

// Real-time processing
const realtimeProcessor = client.createRealtimeProcessor({
  bufferSize: 1000,
  processingInterval: 100  // ms
});

realtimeProcessor.onProcessed((features) => {
  const result = client.authenticateRealtime('john_doe', features);
  updateAuthStatus(result);
});

// Session management
const sessionManager = client.getSessionManager();

const session = await sessionManager.createSession('john_doe', {
  duration: 3600000,  // 1 hour
  continuousVerification: true,
  reauthThreshold: 0.8
});

sessionManager.on('session-expiring', () => {
  showReauthPrompt();
});
```

## 📱 Mobile SDKs

### Android SDK

```kotlin
// Initialize client
val nacfClient = NACFClient.Builder()
    .apiKey("your-api-key")
    .baseUrl("https://api.nacf.dev/v1")
    .timeout(10000)
    .build()

// Register user
val registrationConfig = RegistrationConfig.Builder()
    .userId("john_doe")
    .signalConfig(SignalConfig.Builder()
        .samplingRate(1000)
        .channels(listOf("Fp1", "Fp2", "F3", "F4"))
        .qualityThreshold(0.85)
        .collectionDuration(300000)
        .build())
    .build()

nacfauth.registerUser(registrationConfig, object : RegistrationCallback {
    override fun onProgress(progress: RegistrationProgress) {
        updateProgress(progress.percentage)
    }

    override fun onQualityCheck(quality: SignalQuality) {
        if (quality.score < 0.8) {
            showQualityWarning()
        }
    }

    override fun onSuccess(result: RegistrationResult) {
        showSuccess("Registration completed!")
    }

    override fun onFailure(error: NACFError) {
        showError("Registration failed: ${error.message}")
    }
})

// Authenticate user
val authConfig = AuthenticationConfig.Builder()
    .userId("john_doe")
    .continuousMode(true)
    .confidenceThreshold(0.85)
    .build()

nacfauth.authenticateUser(authConfig, object : AuthenticationCallback {
    override fun onSuccess(result: AuthResult) {
        updateUI("authenticated", result.confidence)
    }

    override fun onFailure(result: AuthResult) {
        updateUI("failed", result.confidence)
    }

    override fun onQualityWarning(quality: SignalQuality) {
        showQualityWarning(quality.score)
    }
})
```

### iOS SDK

```swift
// Initialize client
let nacfClient = NACFClient(
    apiKey: "your-api-key",
    baseUrl: "https://api.nacf.dev/v1"
)

// Register user
let registrationConfig = RegistrationConfig(
    userId: "john_doe",
    signalConfig: SignalConfig(
        samplingRate: 1000,
        channels: ["Fp1", "Fp2", "F3", "F4"],
        qualityThreshold: 0.85,
        collectionDuration: 300000
    )
)

nacfauth.registerUser(config: registrationConfig) { result in
    switch result {
    case .success(let registrationResult):
        self.showSuccess("Registration completed!")
    case .failure(let error):
        self.showError("Registration failed: \(error.localizedDescription)")
    }
}

// Monitor progress
nacfauth.registrationProgress = { progress in
    self.updateProgress(progress.percentage)
}

nacfauth.qualityCheck = { quality in
    if quality.score < 0.8 {
        self.showQualityWarning()
    }
}

// Authenticate user
let authConfig = AuthenticationConfig(
    userId: "john_doe",
    continuousMode: true,
    confidenceThreshold: 0.85
)

nacfauth.authenticateUser(config: authConfig) { result in
    switch result {
    case .success(let authResult):
        self.updateUI(state: "authenticated", confidence: authResult.confidence)
    case .failure(let authResult):
        self.updateUI(state: "failed", confidence: authResult.confidence)
    }
}
```

## ⚠️ Error Handling

### HTTP Status Codes

- `200 OK`: Success
- `201 Created`: Resource created
- `204 No Content`: Success, no content returned
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `422 Unprocessable Entity`: Validation error
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### Error Response Format

```json
{
  "error": {
    "code": "string",
    "message": "string",
    "details": "object (optional)",
    "timestamp": "ISO 8601 string",
    "request_id": "string (optional)"
  }
}
```

### Common Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `INVALID_REQUEST` | Malformed request | Check request format and required fields |
| `INVALID_CREDENTIALS` | Wrong API key | Verify API key is correct |
| `USER_NOT_FOUND` | User doesn't exist | Check user_id spelling |
| `INSUFFICIENT_QUALITY` | Signal quality too low | Improve signal quality or adjust threshold |
| `MODEL_NOT_TRAINED` | User model not ready | Complete registration first |
| `RATE_LIMIT_EXCEEDED` | Too many requests | Wait and retry, or upgrade plan |
| `SERVICE_UNAVAILABLE` | Service down | Check service status, retry later |

### SDK Error Handling

```javascript
// Web SDK
try {
  const result = await client.authenticateUser(userData);
} catch (error) {
  if (error.code === 'NETWORK_ERROR') {
    // Handle network issues
    retryWithBackoff();
  } else if (error.code === 'AUTH_FAILED') {
    // Handle authentication failure
    showAuthFailure(error.details);
  } else {
    // Handle other errors
    showGenericError(error.message);
  }
}
```

```python
# Python SDK
from nacf.exceptions import NACFError, NetworkError, AuthenticationError

try:
    result = client.authenticate_user(user_id, signals)
except NetworkError as e:
    # Handle network issues
    retry_with_backoff()
except AuthenticationError as e:
    # Handle auth failures
    log_auth_failure(user_id, e.details)
except NACFError as e:
    # Handle other NACF errors
    log_error(f"NACF error: {e.code} - {e.message}")
```

## 🚦 Rate Limiting

### Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| Authentication | 100/minute | Per user |
| Registration | 10/minute | Per user |
| Analytics | 60/minute | Per API key |
| Health checks | 1000/minute | Per IP |

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1634567890
X-RateLimit-Retry-After: 60
```

### Handling Rate Limits

```javascript
// Automatic retry with backoff
async function makeAPICall(apiCall, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await apiCall();
    } catch (error) {
      if (error.status === 429) {
        const retryAfter = error.headers['retry-after'] || Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      throw error;
    }
  }
}

// Usage
const result = await makeAPICall(() =>
  client.authenticateUser(userData)
);
```

## 📋 Versioning

### API Versioning

- **Current Version**: v1
- **Version Format**: `/api/v{version}/`
- **Backward Compatibility**: Maintained for 2 years
- **Deprecation Notice**: 6 months advance notice

### SDK Versioning

- **Semantic Versioning**: `MAJOR.MINOR.PATCH`
- **Breaking Changes**: Major version bump
- **New Features**: Minor version bump
- **Bug Fixes**: Patch version bump

### Version Headers

```http
Accept: application/vnd.nacf.v1+json
X-API-Version: 1.2.3
```

### Migration Guide

When upgrading between major versions:

1. **Review Breaking Changes**: Check changelog
2. **Update SDK**: Install latest compatible version
3. **Test Integration**: Run full test suite
4. **Gradual Rollout**: Deploy to staging first
5. **Monitor Metrics**: Watch for errors and performance

---

For more detailed examples and advanced usage patterns, visit our [GitHub repository](https://github.com/pratikacharya1234/NAFC) or [documentation site](https://docs.nacf.dev). 🚀