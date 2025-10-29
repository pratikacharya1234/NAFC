# Contributing to NACF

Thank you for your interest in contributing to the Neural Authentication Control Framework (NACF)! We welcome contributions from the community and are grateful for your help in making NACF better.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Community](#community)

## 🤝 Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have:

- **Python**: 3.8 or higher
- **Git**: 2.25 or higher
- **Docker**: 20.10 or higher (for containerized development)
- **kubectl**: 1.19 or higher (for Kubernetes development)
- **Node.js**: 16 or higher (for web SDK development)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/your-username/NAFC.git
cd NAFC
```

3. Set up the upstream remote:

```bash
git remote add upstream https://github.com/pratikacharya1234/NAFC.git
```

## 🛠️ Development Setup

### Local Development Environment

1. **Create a virtual environment:**

```bash
python -m venv nacf-env
source nacf-env/bin/activate  # On Windows: nacf-env\Scripts\activate
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

3. **Install NACF in development mode:**

```bash
pip install -e .
```

### Kubernetes Development Environment

1. **Start local Kubernetes cluster:**

```bash
# Using kind
kind create cluster --name nacf-dev

# Or using minikube
minikube start
```

2. **Deploy NACF for development:**

```bash
kubectl create namespace nacf-dev
kubectl apply -k infra/kubernetes/base/
```

### Web SDK Development

1. **Navigate to web SDK directory:**

```bash
cd web_sdk
```

2. **Install dependencies:**

```bash
npm install
```

3. **Start development server:**

```bash
npm run dev
```

## 🤝 How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **🐛 Bug Fixes**: Identify and fix issues
- **✨ New Features**: Implement new functionality
- **📚 Documentation**: Improve docs, tutorials, examples
- **🧪 Tests**: Write tests for existing code
- **🔧 Tools**: Development tools, CI/CD improvements
- **🎨 UI/UX**: Improve user interfaces
- **🌐 Translations**: Add support for new languages

### Finding Issues to Work On

- Check [GitHub Issues](https://github.com/pratikacharya1234/NAFC/issues) for open tasks
- Look for issues labeled `good first issue` or `help wanted`
- Check the [Roadmap](https://github.com/pratikacharya1234/NAFC/projects) for planned features

## 🔄 Development Workflow

### 1. Choose an Issue

- Select an issue from GitHub or create a new one
- Comment on the issue to indicate you're working on it
- Wait for maintainer approval if it's a significant change

### 2. Create a Branch

```bash
# Create and switch to a new branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

Branch naming conventions:
- `feature/description` for new features
- `fix/description` for bug fixes
- `docs/description` for documentation
- `refactor/description` for code refactoring

### 3. Make Changes

- Write clear, focused commits
- Test your changes thoroughly
- Follow the coding standards below
- Update documentation as needed

### 4. Test Your Changes

```bash
# Run unit tests
python -m pytest tests/ -v

# Run integration tests
python -m pytest tests/integration/ -v

# Run linting
flake8 nacf/
black nacf/

# For web SDK
cd web_sdk
npm test
npm run lint
```

### 5. Update Documentation

- Update README.md if needed
- Add docstrings to new functions
- Update API documentation
- Add examples for new features

### 6. Commit Your Changes

```bash
# Stage your changes
git add .

# Commit with a clear message
git commit -m "feat: add neural signal quality validation

- Add signal quality assessment algorithm
- Implement quality thresholds configuration
- Add unit tests for quality validation
- Update API documentation

Closes #123"
```

Commit message format:
```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### 7. Push and Create Pull Request

```bash
# Push your branch
git push origin feature/your-feature-name

# Create a Pull Request on GitHub
```

## 📝 Coding Standards

### Python Code Style

We follow PEP 8 with some modifications:

```python
# Good: Clear variable names, type hints, docstrings
def authenticate_user(user_id: str, neural_signals: NeuralSignals) -> AuthResult:
    """
    Authenticate a user using neural signals.

    Args:
        user_id: Unique identifier for the user
        neural_signals: Neural signal data for authentication

    Returns:
        Authentication result with confidence score

    Raises:
        AuthenticationError: If authentication fails
    """
    # Implementation here
    pass

# Bad: Unclear names, no type hints
def auth(u, ns):
    # Implementation here
    pass
```

### Key Guidelines

- **Type Hints**: Use type hints for all function parameters and return values
- **Docstrings**: Write comprehensive docstrings using Google style
- **Naming**: Use descriptive names (e.g., `user_id` not `uid`)
- **Imports**: Group imports (standard library, third-party, local)
- **Line Length**: Maximum 88 characters (Black formatter default)
- **Error Handling**: Use custom exceptions, don't catch generic Exception

### JavaScript/TypeScript (Web SDK)

```javascript
/**
 * NACF Web SDK Client
 * @class
 */
class NACFClient {
  /**
   * Creates a new NACF client instance
   * @param {Object} config - Configuration object
   * @param {string} config.baseURL - API base URL
   * @param {string} config.apiKey - API key
   */
  constructor(config) {
    // Implementation
  }

  /**
   * Registers a user with neural profile
   * @param {string} userId - User identifier
   * @param {Object} neuralData - Neural profile data
   * @returns {Promise<Object>} Registration result
   */
  async registerUser(userId, neuralData) {
    // Implementation
  }
}
```

### Kubernetes Manifests

- Use consistent labeling
- Include resource limits and requests
- Add health checks and readiness probes
- Use ConfigMaps and Secrets appropriately
- Document complex configurations

## 🧪 Testing

### Unit Tests

```python
# tests/test_auth_engine.py
import pytest
from nacf.core.auth_engine import AuthEngine

class TestAuthEngine:
    def test_user_registration(self):
        engine = AuthEngine()
        result = engine.register_user("test_user", mock_neural_data)
        assert result.success is True
        assert result.user_id == "test_user"

    def test_authentication_success(self):
        engine = AuthEngine()
        # Setup user first
        engine.register_user("test_user", mock_neural_data)

        # Test authentication
        result = engine.authenticate_user("test_user", mock_auth_signals)
        assert result.authenticated is True
        assert result.confidence > 0.8
```

### Integration Tests

```python
# tests/integration/test_api_endpoints.py
import pytest
from nacf.api.client import NACFAPIClient

class TestAPIEndpoints:
    def test_register_user_api(self, api_client):
        response = api_client.post('/api/v1/auth', json={
            'action': 'register',
            'user_id': 'test_user',
            'neural_profile': mock_neural_data
        })
        assert response.status_code == 200
        assert response.json()['success'] is True
```

### Test Coverage

Aim for >80% code coverage:

```bash
# Run tests with coverage
python -m pytest --cov=nacf --cov-report=html --cov-report=term

# View coverage report
open htmlcov/index.html
```

## 📚 Documentation

### Code Documentation

- Use docstrings for all public functions, classes, and modules
- Include type hints for parameters and return values
- Document exceptions that may be raised
- Provide usage examples in docstrings

### API Documentation

- Update API documentation for new endpoints
- Include request/response examples
- Document error codes and messages
- Update OpenAPI/Swagger specifications

### User Documentation

- Update README.md for new features
- Add examples and tutorials
- Update installation instructions
- Document configuration options

## 🔄 Submitting Changes

### Pull Request Process

1. **Ensure your PR meets these requirements:**
   - All tests pass
   - Code follows style guidelines
   - Documentation is updated
   - No merge conflicts

2. **Create a descriptive PR:**
   - Clear title describing the change
   - Detailed description of what was changed and why
   - Link to related issues
   - Screenshots for UI changes

3. **PR Template:**
   ```markdown
   ## Description
   Brief description of the changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Unit tests added/updated
   - [ ] Integration tests added/updated
   - [ ] Manual testing completed

   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Documentation updated
   - [ ] Tests pass
   - [ ] No breaking changes

   Closes #123
   ```

### Review Process

1. **Automated Checks:**
   - CI/CD pipeline runs tests and linting
   - Code coverage requirements met
   - Security scans pass

2. **Code Review:**
   - At least one maintainer reviews the code
   - Review focuses on code quality, security, and functionality
   - Constructive feedback provided

3. **Approval and Merge:**
   - PR approved by required reviewers
   - Squash and merge to maintain clean history
   - Delete feature branch after merge

## 🌐 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussion
- **Slack**: Real-time community chat (invite link in discussions)

### Getting Help

- Check existing issues and documentation first
- Use clear, descriptive titles for new issues
- Provide code examples and error messages
- Be patient and respectful

### Recognition

Contributors are recognized through:
- GitHub contributor statistics
- Mention in release notes
- Contributor spotlight in newsletters
- Invitation to become a maintainer

## 🎯 Best Practices

### Commit Best Practices

- Write clear, concise commit messages
- Make small, focused commits
- Use present tense in commit messages
- Reference issue numbers when applicable

### Code Review Best Practices

- Review code, not the person
- Provide constructive feedback
- Suggest improvements, don't demand changes
- Acknowledge good practices
- Be patient and respectful

### Security Considerations

- Never commit sensitive information
- Use environment variables for secrets
- Follow secure coding practices
- Report security issues privately

## 📄 License

By contributing to NACF, you agree that your contributions will be licensed under the Apache License 2.0.

## 🙏 Recognition

We appreciate all contributions, big and small! Contributors are listed in our [CONTRIBUTORS.md](CONTRIBUTORS.md) file and recognized in release notes.

---

Thank you for contributing to NACF! Your help makes neural authentication more secure and accessible for everyone. 🚀