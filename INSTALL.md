# NACF Installation Guide

This guide covers all available installation methods for the Neural Authentication Control Framework (NACF), from quick Docker setups to full production deployments.

## 📋 Table of Contents

- [Quick Install](#quick-install)
- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Post-Installation](#post-installation)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

## 🚀 Quick Install

### One-Command Docker Install

```bash
# Download and run NACF with all dependencies
curl -fsSL https://get.nacf.dev | bash

# Or manually:
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC
docker-compose up -d
```

### Python Package Install

```bash
# Install NACF via pip
pip install nacf

# Or from source
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC
pip install -e .
```

### Web SDK Install

```bash
# Install via npm
npm install nacf-sdk

# Or include via CDN
<script src="https://cdn.jsdelivr.net/npm/nacf-sdk@latest/dist/nacf-sdk.min.js"></script>
```

## 💻 System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux, macOS 10.15+, Windows 10+ |
| **CPU** | 2 cores, x86_64 or ARM64 |
| **RAM** | 4GB |
| **Storage** | 10GB free space |
| **Network** | 100Mbps internet connection |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Ubuntu 20.04+, CentOS 8+, RHEL 8+ |
| **CPU** | 4+ cores, modern x86_64 |
| **RAM** | 8GB+ |
| **Storage** | 50GB+ SSD |
| **Network** | 1Gbps connection |
| **GPU** | NVIDIA GPU with CUDA 11+ (optional, for ML acceleration) |

### Supported Platforms

- **Linux**: Ubuntu, CentOS, RHEL, Debian, Fedora, SUSE
- **macOS**: 10.15+ (Intel), 11.0+ (Apple Silicon)
- **Windows**: 10 Pro/Enterprise (via WSL2), Windows Server 2019+
- **Containers**: Docker, Podman, Kubernetes
- **Cloud**: AWS, GCP, Azure, DigitalOcean

## 🛠️ Installation Methods

### Method 1: Docker Compose (Recommended)

Perfect for development, testing, and small-scale production.

#### Prerequisites

```bash
# Install Docker and Docker Compose
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose

# macOS (using Homebrew)
brew install docker docker-compose

# Windows
# Download Docker Desktop from https://docker.com
```

#### Installation

```bash
# Clone repository
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC

# Start all services
docker-compose up -d

# View status
docker-compose ps

# View logs
docker-compose logs -f
```

#### What's Included

- NACF API server (Python/FastAPI)
- PostgreSQL database
- Redis cache
- Kafka message queue + Zookeeper
- Kong API gateway
- Monitoring stack (Prometheus + Grafana)

#### Access Points

- **API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Grafana**: http://localhost:3000 (admin/admin)
- **Kong Admin**: http://localhost:8001

### Method 2: Kubernetes Deployment

For production deployments and scalable environments.

#### Prerequisites

```bash
# Install kubectl
# Ubuntu/Debian
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm (optional, for advanced deployments)
curl https://get.helm.sh/helm-v3.9.0-linux-amd64.tar.gz -o helm.tar.gz
tar -zxvf helm.tar.gz
sudo mv linux-amd64/helm /usr/local/bin/helm
```

#### Local Kubernetes (Kind/Minikube)

```bash
# Using kind
kind create cluster --name nacf-dev

# Using minikube
minikube start --memory=4096 --cpus=2

# Deploy NACF
kubectl create namespace nacf
kubectl apply -k infra/kubernetes/base/

# Wait for deployment
kubectl wait --for=condition=available --timeout=300s deployment --all -n nacf
```

#### Cloud Kubernetes

```bash
# AWS EKS
aws eks update-kubeconfig --region us-east-1 --name nacf-cluster

# GCP GKE
gcloud container clusters get-credentials nacf-cluster --region us-central1

# Azure AKS
az aks get-credentials --resource-group nacf-rg --name nacf-cluster

# Deploy NACF
kubectl create namespace nacf
kubectl apply -k infra/kubernetes/base/
```

#### Helm Deployment

```bash
# Add NACF Helm repository
helm repo add nacf https://charts.nacf.dev
helm repo update

# Install NACF
helm install nacf nacf/nacf \
  --namespace nacf \
  --create-namespace \
  --set postgresql.auth.password=mypassword \
  --set redis.auth.password=myredispassword
```

### Method 3: Local Python Installation

For development and integration into existing Python applications.

#### Prerequisites

```bash
# Install Python 3.8+
# Ubuntu/Debian
sudo apt install python3.8 python3.8-venv python3-pip

# macOS
brew install python@3.8

# Windows
# Download from https://python.org
```

#### Installation

```bash
# Create virtual environment
python3 -m venv nacf-env
source nacf-env/bin/activate  # Windows: nacf-env\Scripts\activate

# Install NACF
pip install nacf

# Or install from source with development dependencies
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC
pip install -r requirements.txt
pip install -e .
```

#### External Dependencies Setup

```bash
# PostgreSQL
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo -u postgres createuser nacfauth
sudo -u postgres createdb nacfdb
sudo -u postgres psql -c "ALTER USER nacfauth PASSWORD 'nacfauth';"

# Redis
sudo apt install redis-server
sudo systemctl start redis-server

# Kafka (optional, for advanced features)
# Download from https://kafka.apache.org/downloads
# Start Zookeeper and Kafka services
```

### Method 4: Ansible Automation

For automated deployment across multiple servers.

#### Prerequisites

```bash
# Install Ansible
# Ubuntu/Debian
sudo apt install ansible

# macOS
brew install ansible

# Windows (via WSL)
sudo apt install ansible
```

#### Deployment

```bash
# Clone repository
git clone https://github.com/pratikacharya1234/NAFC.git
cd NAFC/infra/ansible

# Configure inventory
cp inventory.ini.example inventory.ini
# Edit inventory.ini with your server details

# Run deployment playbook
ansible-playbook -i inventory.ini deploy.yml

# Or for development environment
ansible-playbook -i inventory.ini deploy-dev.yml
```

### Method 5: Web SDK Installation

For integrating NACF into web applications.

#### NPM Installation

```bash
# Install via npm
npm install nacf-sdk

# Install via yarn
yarn add nacf-sdk

# Install specific version
npm install nacf-sdk@1.2.3
```

#### CDN Installation

```html
<!-- Latest version -->
<script src="https://cdn.jsdelivr.net/npm/nacf-sdk@latest/dist/nacf-sdk.min.js"></script>

<!-- Specific version -->
<script src="https://cdn.jsdelivr.net/npm/nacf-sdk@1.2.3/dist/nacf-sdk.min.js"></script>

<!-- ES modules -->
<script type="module">
  import { NACFClient } from 'https://cdn.jsdelivr.net/npm/nacf-sdk@latest/dist/nacf-sdk.esm.js';
</script>
```

#### Manual Download

```bash
# Download latest release
wget https://github.com/pratikacharya1234/NAFC/releases/latest/download/nacf-sdk.min.js

# Or download specific version
wget https://github.com/pratikacharya1234/NAFC/releases/download/v1.2.3/nacf-sdk.min.js
```

### Method 6: Mobile SDK Installation

#### Android

```gradle
// build.gradle (Project level)
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
        google()
        mavenCentral()
    }
}

// build.gradle (App level)
dependencies {
    implementation 'com.github.pratikacharya1234:NAFC:1.2.3'
}
```

#### iOS (Swift Package Manager)

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/pratikacharya1234/NAFC.git", from: "1.2.3")
]

// Xcode Project
// File > Swift Packages > Add Package Dependency
// https://github.com/pratikacharya1234/NAFC.git
```

#### iOS (CocoaPods)

```ruby
# Podfile
pod 'NACF', '~> 1.2.3'
```

### Method 7: Cloud Marketplace

#### AWS Marketplace

```bash
# Launch NACF from AWS Marketplace
# Search for "NACF Neural Authentication"
# Follow AWS deployment wizard

# Or using CloudFormation
aws cloudformation create-stack \
  --stack-name nacf-stack \
  --template-url https://nacfauth.s3.amazonaws.com/cloudformation/nacf-template.yaml \
  --parameters ParameterKey=InstanceType,ParameterValue=t3.medium
```

#### GCP Marketplace

```bash
# Deploy from GCP Marketplace
gcloud deployment-manager deployments create nacf-deployment \
  --template nacf-template.py \
  --properties zone=us-central1-a,machineType=n1-standard-2
```

#### Azure Marketplace

```bash
# Deploy from Azure Marketplace
az group create --name nacf-rg --location eastus
az deployment group create \
  --resource-group nacf-rg \
  --template-uri https://nacfauth.blob.core.windows.net/templates/nacf-template.json \
  --parameters adminUsername=nacfadmin vmSize=Standard_D2s_v3
```

## 🔧 Post-Installation

### Initialize Database

```bash
# For Docker installation
docker-compose exec nacf-api python -m nacf.core.data_pipeline init-db

# For local installation
python -m nacf.core.data_pipeline init-db

# For Kubernetes
kubectl exec -n nacf deployment/nacf-api -- python -m nacf.core.data_pipeline init-db
```

### Create Admin User

```bash
# Create initial admin user
python -c "
from nacf.core.neural_auth_service import NeuralAuthService
service = NeuralAuthService()
# Create admin user with mock neural data for testing
import numpy as np
mock_signals = np.random.randn(1000, 4)
service.register_user('admin', {'signals': mock_signals, 'quality_score': 0.95})
"
```

### Configure API Gateway

```bash
# For Kong (Docker)
curl -X POST http://localhost:8001/services \
  -d name=nacf-api \
  -d url=http://nacfauth:8000

curl -X POST http://localhost:8001/services/nacf-api/routes \
  -d paths[]=/api/v1
```

### Set Up Monitoring

```bash
# Access Grafana
open http://localhost:3000

# Default credentials: admin/admin
# Add NACF data source and import dashboards from infra/monitoring/
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database
DATABASE_URL=postgresql://nacfauth:nacfpass@localhost:5432/nacfdb
REDIS_URL=redis://localhost:6379/0

# API
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key-here

# Neural Engine
NEURAL_MODEL_PATH=models/
SIGNAL_QUALITY_THRESHOLD=0.85
AUTH_CONFIDENCE_THRESHOLD=0.90

# Security
JWT_SECRET_KEY=your-jwt-secret
ENCRYPTION_KEY=your-encryption-key

# External Services
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
PROMETHEUS_METRICS_ENABLED=true
```

### Docker Compose Override

Create `docker-compose.override.yml`:

```yaml
version: '3.8'
services:
  nacf-api:
    environment:
      - DATABASE_URL=postgresql://nacfauth:nacfpass@db:5432/nacfdb
      - REDIS_URL=redis://redis:6379/0
      - API_DEBUG=true
    volumes:
      - ./models:/app/models
      - ./logs:/app/logs

  db:
    environment:
      - POSTGRES_PASSWORD=mypassword
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Kubernetes ConfigMaps

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nacf-config
  namespace: nacf
data:
  DATABASE_URL: "postgresql://nacfauth:nacfpass@postgres:5432/nacfdb"
  REDIS_URL: "redis://redis:6379/0"
  NEURAL_MODEL_PATH: "/models"
  LOG_LEVEL: "INFO"
```

## ✅ Verification

### Health Checks

```bash
# API health check
curl http://localhost:8000/health

# Database connectivity
curl http://localhost:8000/health/db

# Redis connectivity
curl http://localhost:8000/health/redis

# Kafka connectivity (if enabled)
curl http://localhost:8000/health/kafka
```

### Functional Tests

```bash
# Run unit tests
python -m pytest tests/unit/ -v

# Run integration tests
python -m pytest tests/integration/ -v

# Run end-to-end tests
python -m pytest tests/e2e/ -v

# For Docker installation
docker-compose exec nacf-api python -m pytest tests/ -v
```

### Performance Benchmark

```bash
# Run performance tests
python -m pytest tests/benchmark/ -v --benchmark-only

# Load testing with locust
pip install locust
locust -f tests/load/locustfile.py --host=http://localhost:8000
```

### Web SDK Verification

```html
<!DOCTYPE html>
<html>
<head>
    <title>NACF Test</title>
    <script src="dist/nacf-sdk.js"></script>
</head>
<body>
    <script>
        // Test SDK loading
        console.log('NACF SDK version:', NACF.version);

        // Test client initialization
        const client = new NACF.Client({
            baseURL: 'http://localhost:8000/api/v1'
        });

        // Test API connectivity
        client.healthCheck().then(result => {
            console.log('API health:', result);
        });
    </script>
</body>
</html>
```

## 🔧 Troubleshooting

### Common Installation Issues

#### Docker Issues

```bash
# Check Docker service status
sudo systemctl status docker

# Check Docker version
docker --version
docker-compose --version

# Clean up Docker resources
docker system prune -a

# Check container logs
docker-compose logs nacf-api
```

#### Python Issues

```bash
# Check Python version
python --version

# Check pip version
pip --version

# Upgrade pip
pip install --upgrade pip

# Check virtual environment
which python
which pip

# Reinstall requirements
pip uninstall nacf
pip install -r requirements.txt
pip install -e .
```

#### Database Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database connectivity
psql -h localhost -U nacfauth -d nacfdb

# Reset database
python -m nacf.core.data_pipeline reset-db

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

#### Network Issues

```bash
# Check port availability
netstat -tlnp | grep :8000

# Check firewall rules
sudo ufw status
sudo iptables -L

# Test connectivity
curl -v http://localhost:8000/health

# DNS resolution
nslookup localhost
```

#### Permission Issues

```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
newgrp docker

# Fix file permissions
sudo chown -R $USER:$USER /path/to/nacf
chmod +x scripts/*.sh

# Fix virtual environment permissions
sudo chown -R $USER:$USER nacf-env/
```

### Performance Issues

```bash
# Check system resources
top
htop
free -h
df -h

# Check NACF performance metrics
curl http://localhost:8000/metrics

# Profile Python code
python -m cProfile -s time nacf/core/auth_engine.py

# Check database performance
# Connect to PostgreSQL and run:
# SELECT * FROM pg_stat_activity;
# SELECT * FROM pg_stat_user_tables;
```

### Logging and Debugging

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
export PYTHONPATH=/path/to/nacf

# View application logs
tail -f logs/nacf.log

# View Docker logs
docker-compose logs -f nacf-api

# View Kubernetes logs
kubectl logs -f deployment/nacf-api -n nacf

# Enable Python debugging
python -m pdb nacf/api/main.py
```

## 🗑️ Uninstallation

### Docker Compose

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Clean up networks
docker network prune
```

### Kubernetes

```bash
# Delete NACF deployment
kubectl delete -k infra/kubernetes/base/

# Delete namespace (WARNING: deletes all data)
kubectl delete namespace nacf

# Clean up persistent volumes
kubectl delete pvc --all -n nacf
```

### Local Python Installation

```bash
# Remove virtual environment
rm -rf nacf-env/

# Uninstall NACF package
pip uninstall nacf

# Remove source code
rm -rf NAFC/

# Clean up Python cache
find . -type d -name __pycache__ -exec rm -rf {} +
find . -name "*.pyc" -delete
```

### System Cleanup

```bash
# Remove external dependencies (be careful!)
sudo apt remove postgresql redis-server kafka
sudo apt autoremove

# Remove Docker images and volumes
docker system prune -a
docker volume prune

# Remove configuration files
rm -f ~/.nacfrc
rm -rf ~/.config/nacf/
```

### Database Cleanup

```bash
# Drop NACF database
sudo -u postgres psql -c "DROP DATABASE nacfdb;"
sudo -u postgres psql -c "DROP USER nacfauth;"

# Remove Redis data
redis-cli FLUSHALL

# Remove Kafka topics
kafka-topics.sh --delete --topic neural-signals --bootstrap-server localhost:9092
kafka-topics.sh --delete --topic auth-events --bootstrap-server localhost:9092
```

---

## 📞 Support

If you encounter issues during installation:

1. **Check the troubleshooting section above**
2. **Review the logs** for error messages
3. **Verify system requirements** are met
4. **Open an issue** on GitHub with:
   - Installation method used
   - OS and version
   - Error messages and logs
   - Steps to reproduce

For additional help, visit our [community forum](https://community.nacf.dev) or [documentation](https://docs.nacf.dev). 🚀