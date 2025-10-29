# NACF Web SDK

A JavaScript SDK for integrating NACF (Neural Authentication Control Framework) into web applications.

## Features

- 🔐 Neural-based user authentication
- 🛡️ Secure API key authentication
- 📊 Real-time signal processing
- 🎯 Easy-to-use JavaScript API
- 📱 Browser-compatible

## Quick Start

### 1. Include the SDK

```html
<script src="path/to/nacf-sdk.js"></script>
```

### 2. Initialize the Client

```javascript
const nacf = new NACFClient({
    baseURL: 'https://your-nacf-gateway.com',
    apiKey: 'your-api-key'
});
```

### 3. Register a User

```javascript
const neuralProfile = {
    signal_type: 'EEG',
    data: [0.1, 0.2, 0.3, ...],
    timestamp: new Date().toISOString()
};

const result = await nacf.registerUser('user123', neuralProfile);
```

### 4. Authenticate a User

```javascript
const authSignals = {
    signal_type: 'EEG',
    data: [0.15, 0.25, 0.35, ...],
    timestamp: new Date().toISOString()
};

const result = await nacf.authenticateUser('user123', authSignals);
```

## API Reference

### NACFClient

#### Constructor

```javascript
new NACFClient(config)
```

**Parameters:**
- `config.baseURL` (string): NACF API gateway URL
- `config.apiKey` (string): API key for authentication

#### Methods

##### registerUser(userId, neuralData)

Registers a new user with their neural profile.

**Parameters:**
- `userId` (string): Unique user identifier
- `neuralData` (object): Neural profile data

**Returns:** Promise resolving to registration result

##### authenticateUser(userId, neuralData)

Authenticates a user using neural signals.

**Parameters:**
- `userId` (string): User identifier
- `neuralData` (object): Authentication neural signals

**Returns:** Promise resolving to authentication result

##### processSignals(signals)

Processes neural signals for analysis.

**Parameters:**
- `signals` (object): Neural signals to process

**Returns:** Promise resolving to processing result

## Neural Data Format

```javascript
{
    signal_type: 'EEG', // or 'ECG', 'EMG', etc.
    data: [0.1, 0.2, 0.3, ...], // Array of signal values
    timestamp: '2025-10-28T12:00:00Z', // ISO timestamp
    metadata: { // Optional additional data
        device: 'Muse2',
        sampling_rate: 256
    }
}
```

## Setup Instructions

### 1. Deploy NACF System

```bash
# Clone the repository
git clone https://github.com/your-org/nacf.git
cd nacf

# Deploy to Kubernetes
kubectl apply -k infra/kubernetes/base/
```

### 2. Configure API Gateway

Update your Kong configuration with the correct domain and SSL certificates.

### 3. Generate API Keys

Use the NACF admin interface to generate API keys for your application.

### 4. Update Configuration

```javascript
const NACF_CONFIG = {
    baseURL: 'https://your-nacf-gateway.com',
    apiKey: 'your-generated-api-key'
};
```

## Browser Support

- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

## Security Considerations

- Always use HTTPS in production
- Store API keys securely (never in client-side code)
- Implement proper error handling
- Validate neural data before transmission

## Examples

### Complete Authentication Flow

```javascript
// Initialize client
const nacf = new NACFClient({
    baseURL: 'https://api.nacf.com',
    apiKey: process.env.NACF_API_KEY
});

// Register user
async function registerUser(userId, neuralData) {
    try {
        const result = await nacf.registerUser(userId, neuralData);
        console.log('User registered:', result);
        return result;
    } catch (error) {
        console.error('Registration failed:', error);
        throw error;
    }
}

// Authenticate user
async function authenticateUser(userId, neuralData) {
    try {
        const result = await nacf.authenticateUser(userId, neuralData);
        if (result.authenticated) {
            console.log('Authentication successful');
            return true;
        } else {
            console.log('Authentication failed');
            return false;
        }
    } catch (error) {
        console.error('Authentication error:', error);
        throw error;
    }
}
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check your API key
2. **404 Not Found**: Verify the API endpoint URL
3. **429 Too Many Requests**: You've exceeded rate limits
4. **413 Payload Too Large**: Neural data exceeds size limits

### Debug Mode

Enable debug logging:

```javascript
const nacf = new NACFClient({
    baseURL: 'https://api.nacf.com',
    apiKey: 'your-key',
    debug: true
});
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- 📧 Email: support@nacf.com
- 📖 Documentation: https://docs.nacf.com
- 🐛 Issues: https://github.com/your-org/nacf/issues