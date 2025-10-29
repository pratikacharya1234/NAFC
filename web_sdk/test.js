// NACF Web SDK Test Suite
// Run with: node test.js

const { NACFClient, NACFError } = require('./src/nacf-sdk.js');

// Mock fetch for testing
global.fetch = async (url, options) => {
  console.log(`Mock fetch: ${options.method} ${url}`);

  // Simulate API responses
  if (url.includes('/api/v1/auth') && options.method === 'POST') {
    const body = JSON.parse(options.body);
    if (body.action === 'register') {
      return {
        ok: true,
        json: async () => ({
          success: true,
          user_id: body.user_id,
          message: 'User registered successfully'
        })
      };
    } else if (body.action === 'authenticate') {
      return {
        ok: true,
        json: async () => ({
          authenticated: true,
          user_id: body.user_id,
          confidence: 0.95,
          message: 'Authentication successful'
        })
      };
    }
  }

  return {
    ok: false,
    status: 404,
    statusText: 'Not Found',
    text: async () => 'Endpoint not found'
  };
};

async function runTests() {
  console.log('🧪 Running NACF Web SDK Tests...\n');

  // Test 1: Client initialization
  console.log('Test 1: Client Initialization');
  try {
    const client = new NACFClient({
      baseURL: 'http://localhost:8080',
      apiKey: 'test-key',
      debug: true
    });
    console.log('✅ Client initialized successfully');
  } catch (error) {
    console.log('❌ Client initialization failed:', error.message);
  }

  // Test 2: User registration
  console.log('\nTest 2: User Registration');
  try {
    const client = new NACFClient({
      baseURL: 'http://localhost:8080',
      apiKey: 'test-key'
    });

    const neuralProfile = {
      signal_type: 'EEG',
      data: [0.1, 0.2, 0.3],
      timestamp: '2025-10-28T12:00:00Z'
    };

    const result = await client.registerUser('test-user', neuralProfile);
    console.log('✅ User registration successful:', result);
  } catch (error) {
    console.log('❌ User registration failed:', error.message);
  }

  // Test 3: User authentication
  console.log('\nTest 3: User Authentication');
  try {
    const client = new NACFClient({
      baseURL: 'http://localhost:8080',
      apiKey: 'test-key'
    });

    const neuralSignals = {
      signal_type: 'EEG',
      data: [0.15, 0.25, 0.35],
      timestamp: '2025-10-28T12:01:00Z'
    };

    const result = await client.authenticateUser('test-user', neuralSignals);
    console.log('✅ User authentication successful:', result);
  } catch (error) {
    console.log('❌ User authentication failed:', error.message);
  }

  // Test 4: Validation errors
  console.log('\nTest 4: Input Validation');
  try {
    const client = new NACFClient({
      baseURL: 'http://localhost:8080',
      apiKey: 'test-key'
    });

    // Invalid user ID
    await client.registerUser('', {});
    console.log('❌ Should have failed with invalid user ID');
  } catch (error) {
    console.log('✅ Correctly caught validation error:', error.message);
  }

  console.log('\n🎉 All tests completed!');
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests };