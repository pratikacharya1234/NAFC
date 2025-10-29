# Getting Started with NACF

Welcome to the Neural Authentication Control Framework (NACF)! This guide will help you get up and running quickly with NACF for development, testing, or production deployment.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation Options](#installation-options)
- [Configuration](#configuration)
- [First Steps](#first-steps)
- [Development Environment](#development-environment)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended for beginners)

```bash
# Clone the repository
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC

# Start all services with Docker Compose
docker-compose up -d

# Wait for services to be ready (about 2-3 minutes)
# Then open your browser to http://localhost:8000
```

### Option 2: Local Development Setup

```bash
# Clone and setup
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC

# Create virtual environment
python -m venv nacf-env
source nacf-env/bin/activate  # Windows: nacf-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Start the API server
python -m nacf.api.main

# In another terminal, start the web interface
cd web_sdk && npm install && npm run dev
```

### Option 3: Kubernetes Deployment

```bash
# Deploy to Kubernetes cluster
kubectl create namespace nacf
kubectl apply -k infra/kubernetes/base/

# Wait for deployment
kubectl wait --for=condition=available --timeout=300s deployment --all -n nacf

# Get service URL
kubectl get svc -n nacf
```

## 📋 Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows 10/11
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 20GB free space

### Software Dependencies

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.8+ | Core NACF engine |
| Node.js | 16+ | Web SDK development |
| Docker | 20.10+ | Containerized deployment |
| kubectl | 1.19+ | Kubernetes management |
| PostgreSQL | 13+ | Data persistence |
| Redis | 6+ | Caching and sessions |
| Kafka | 2.8+ | Message queuing |

### Installing Prerequisites

#### Python 3.8+

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.8 python3.8-venv python3-pip

# macOS
brew install python@3.8

# Windows
# Download from https://python.org
```

#### Node.js 16+

```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS
brew install node

# Windows
# Download from https://nodejs.org
```

#### Docker

```bash
# Ubuntu/Debian
sudo apt install docker.io docker-compose
sudo systemctl start docker
sudo usermod -aG docker $USER

# macOS
# Download Docker Desktop from https://docker.com

# Windows
# Download Docker Desktop from https://docker.com
```

#### kubectl

```bash
# Ubuntu/Debian
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# macOS
brew install kubectl

# Windows
# Download from https://kubernetes.io/docs/tasks/tools/
```

## 🛠️ Installation Options

### 1. Docker Compose (Easiest)

Perfect for development and testing.

```bash
# Clone repository
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**What's included:**
- NACF API server
- PostgreSQL database
- Redis cache
- Kafka message queue
- Kong API gateway
- Monitoring stack (Prometheus + Grafana)

### 2. Local Development Installation

Best for active development and debugging.

```bash
# Clone repository
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC

# Create virtual environment
python -m venv nacf-env
source nacf-env/bin/activate

# Install NACF
pip install -r requirements.txt
pip install -e .

# Install additional development dependencies
pip install -r requirements-dev.txt

# Start PostgreSQL (if not using Docker)
# On Ubuntu: sudo apt install postgresql
# On macOS: brew install postgresql

# Start Redis (if not using Docker)
# On Ubuntu: sudo apt install redis-server
# On macOS: brew install redis

# Start Kafka (if not using Docker)
# Download from https://kafka.apache.org/downloads
```

### 3. Kubernetes Installation

For production or advanced development.

```bash
# Ensure kubectl is configured for your cluster
kubectl cluster-info

# Create namespace
kubectl create namespace nacf

# Deploy NACF
kubectl apply -k infra/kubernetes/base/

# Wait for deployment
kubectl wait --for=condition=available --timeout=300s deployment --all -n nacf

# Check status
kubectl get pods -n nacf
kubectl get svc -n nacf
```

### 4. Web SDK Installation

For integrating NACF into web applications.

```bash
# Navigate to web SDK
cd web_sdk

# Install dependencies
npm install

# Build for production
npm run build

# Or start development server
npm run dev
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database Configuration
DATABASE_URL=postgresql://nacfauth:nacfpass@localhost:5432/nacfdb
REDIS_URL=redis://localhost:6379/0

# Kafka Configuration
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPIC_NEURAL_SIGNALS=neural-signals
KAFKA_TOPIC_AUTH_EVENTS=auth-events

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_SECRET_KEY=your-secret-key-here

# Neural Engine Configuration
NEURAL_MODEL_PATH=models/
NEURAL_SIGNAL_QUALITY_THRESHOLD=0.85
NEURAL_AUTH_CONFIDENCE_THRESHOLD=0.90

# Security Configuration
JWT_SECRET_KEY=your-jwt-secret-here
JWT_EXPIRATION_HOURS=24
ENCRYPTION_KEY=your-encryption-key-here

# Monitoring
PROMETHEUS_METRICS_ENABLED=true
LOG_LEVEL=INFO
```

### Configuration Files

#### NACF Core Configuration (`nacf/core/config.py`)

```python
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql://nacfauth:nacfpass@localhost:5432/nacfdb"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Neural Engine
    neural_model_path: str = "models/"
    signal_quality_threshold: float = 0.85
    auth_confidence_threshold: float = 0.90

    # Security
    jwt_secret_key: str = "your-jwt-secret"
    jwt_expiration_hours: int = 24
    encryption_key: str = "your-encryption-key"

    class Config:
        env_file = ".env"
```

#### Web SDK Configuration

```javascript
// config.js
const nacfConfig = {
  baseURL: 'http://localhost:8000/api/v1',
  apiKey: 'your-api-key',
  timeout: 5000,
  retryAttempts: 3,
  neuralSignalConfig: {
    samplingRate: 1000,
    channels: ['EEG_Fpz', 'EEG_Fz', 'EEG_Cz'],
    qualityThreshold: 0.85
  }
};

export default nacfConfig;
```

## 🎯 First Steps

### 1. Verify Installation

```bash
# Check NACF API
curl http://localhost:8000/health

# Check database connection
python -c "from nacf.core.config import get_settings; print('Config loaded successfully')"

# Check web SDK
cd web_sdk && npm test
```

### 2. Create Your First User

```python
from nacf.core.neural_auth_service import NeuralAuthService

# Initialize service
auth_service = NeuralAuthService()

# Register a user with neural profile
user_id = "test_user"
neural_profile = {
    "eeg_signals": [...],  # Your neural signal data
    "quality_score": 0.95,
    "metadata": {
        "device": "EEG_headset_v2",
        "session_date": "2024-01-01"
    }
}

result = auth_service.register_user(user_id, neural_profile)
print(f"User registered: {result.success}")
```

### 3. Test Authentication

```python
# Authenticate user
auth_signals = {
    "eeg_signals": [...],  # Real-time neural signals
    "quality_score": 0.92
}

auth_result = auth_service.authenticate_user(user_id, auth_signals)
print(f"Authenticated: {auth_result.authenticated}")
print(f"Confidence: {auth_result.confidence}")
```

### 4. Web SDK Integration

```html
<!DOCTYPE html>
<html>
<head>
    <title>NACF Demo</title>
    <script src="dist/nacf-sdk.js"></script>
</head>
<body>
    <div id="nacfauth-container"></div>

    <script>
        const nacfClient = new NACF.Client({
            baseURL: 'http://localhost:8000/api/v1',
            apiKey: 'your-api-key'
        });

        // Initialize authentication
        nacfClient.initializeAuth('#nacfauth-container', {
            onSuccess: (result) => {
                console.log('Authentication successful:', result);
            },
            onError: (error) => {
                console.error('Authentication failed:', error);
            }
        });
    </script>
</body>
</html>
```

## 🛠️ Development Environment

### Setting Up IDE

#### VS Code (Recommended)

1. Install VS Code extensions:
   - Python
   - Pylance
   - Docker
   - Kubernetes
   - GitLens

2. Configure Python interpreter:
   - Open command palette: `Ctrl+Shift+P`
   - Select "Python: Select Interpreter"
   - Choose the NACF virtual environment

3. Configure debugging:
   ```json
   // .vscode/launch.json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "NACF API",
         "type": "python",
         "request": "launch",
         "module": "nacf.api.main",
         "console": "integratedTerminal"
       }
     ]
   }
   ```

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_auth_engine.py -v

# Run with coverage
python -m pytest --cov=nacf --cov-report=html

# Run integration tests
python -m pytest tests/integration/ -v
```

### Debugging

```bash
# Start API server in debug mode
python -m debugpy --listen 0.0.0.0:5678 -m nacf.api.main

# Attach debugger in VS Code
# Use the debug configuration above
```

## 🚀 Production Deployment

### Kubernetes Production Setup

1. **Configure production overlays:**

```bash
# Create production overlay
mkdir -p infra/kubernetes/overlays/production

# Copy base configuration
cp -r infra/kubernetes/base/* infra/kubernetes/overlays/production/

# Edit production configurations
# - Increase resource limits
# - Configure external databases
# - Set up ingress
# - Configure secrets
```

2. **Deploy to production:**

```bash
# Apply production overlay
kubectl apply -k infra/kubernetes/overlays/production/

# Set up ingress
kubectl apply -f infra/kubernetes/base/ingress/

# Configure SSL certificates
kubectl create secret tls nacf-tls --cert=cert.pem --key=key.pem -n nacf
```

### Docker Production Setup

```bash
# Build production images
docker build -t nacf-api:latest -f Dockerfile.api .
docker build -t nacf-web:latest -f Dockerfile.web .

# Push to registry
docker tag nacf-api:latest your-registry/nacf-api:latest
docker push your-registry/nacf-api:latest

# Deploy with docker-compose.prod.yml
docker-compose -f docker-compose.prod.yml up -d
```

### Monitoring Setup

```bash
# Deploy monitoring stack
kubectl apply -f infra/monitoring/

# Access Grafana
kubectl port-forward svc/grafana 3000:3000 -n nacf

# Open http://localhost:3000 (admin/admin)
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Database Connection Failed

**Error:** `psycopg2.OperationalError: could not connect to server`

**Solutions:**
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Check connection
psql -h localhost -U nacfauth -d nacfdb

# Reset database
python -m nacf.core.data_pipeline reset-db
```

#### 2. Redis Connection Failed

**Error:** `redis.ConnectionError: Connection refused`

**Solutions:**
```bash
# Check if Redis is running
redis-cli ping

# Start Redis service
sudo systemctl start redis-server

# Check Redis logs
sudo journalctl -u redis-server -f
```

#### 3. Kafka Connection Failed

**Error:** `kafka.errors.NoBrokersAvailable`

**Solutions:**
```bash
# Check Kafka status
sudo systemctl status kafka

# Check Zookeeper
sudo systemctl status zookeeper

# Reset Kafka topics
kafka-topics.sh --delete --topic neural-signals --bootstrap-server localhost:9092
kafka-topics.sh --create --topic neural-signals --bootstrap-server localhost:9092
```

#### 4. API Server Won't Start

**Error:** `ModuleNotFoundError: No module named 'nacfauth'`

**Solutions:**
```bash
# Activate virtual environment
source nacf-env/bin/activate

# Reinstall NACF
pip install -e .

# Check Python path
python -c "import nacf; print(nacf.__file__)"
```

#### 5. Web SDK Build Failed

**Error:** `npm ERR! code ENOTFOUND`

**Solutions:**
```bash
# Clear npm cache
npm cache clean --force

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Check Node.js version
node --version
npm --version
```

### Getting Help

1. **Check the logs:**
```bash
# API logs
docker-compose logs nacf-api

# Kubernetes logs
kubectl logs -f deployment/nacf-api -n nacf

# Web SDK logs
cd web_sdk && npm run dev
```

2. **Enable debug logging:**
```bash
export LOG_LEVEL=DEBUG
python -m nacf.api.main
```

3. **Check system resources:**
```bash
# Memory usage
free -h

# Disk space
df -h

# CPU usage
top
```

## 🎯 Next Steps

### Learn More

- 📖 [API Documentation](API.md) - Complete API reference
- 🏗️ [Architecture Guide](ARCHITECTURE.md) - System design details
- 🔒 [Security Guide](SECURITY.md) - Security best practices
- 📊 [Monitoring Guide](MONITORING.md) - Observability setup

### Advanced Topics

- **Custom Neural Models**: Train your own authentication models
- **Multi-tenant Setup**: Configure for multiple organizations
- **High Availability**: Set up clustering and failover
- **Performance Tuning**: Optimize for high throughput
- **Integration**: Connect with existing authentication systems

### Community Resources

- 🐛 [GitHub Issues](https://github.com/pratikacharya1234/NAFC/issues) - Report bugs
- 💬 [GitHub Discussions](https://github.com/pratikacharya1234/NAFC/discussions) - Ask questions
- 📧 [Mailing List](mailto:nacf-users@googlegroups.com) - Stay updated
- 🏢 [Slack Community](https://nacfauth.slack.com) - Real-time chat

### Contributing

Ready to contribute? Check out our [Contributing Guide](CONTRIBUTING.md) to get started!

---

🎉 **Congratulations!** You've successfully set up NACF. Start building secure neural authentication into your applications!

Need help? Don't hesitate to [open an issue](https://github.com/pratikacharya1234/NAFC/issues) or ask in our [community discussions](https://github.com/pratikacharya1234/NAFC/discussions). 🚀