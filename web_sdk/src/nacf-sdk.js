/**
 * NACF Web SDK - Neural Authentication Control Framework
 * JavaScript SDK for integrating neural-based authentication into web applications
 *
 * @version 1.0.0
 * @author NACF Team
 * @license MIT
 */

class NACFClient {
    /**
     * Creates a new NACF client instance
     *
     * @param {Object} config - Configuration object
     * @param {string} config.baseURL - NACF API gateway base URL
     * @param {string} config.apiKey - API key for authentication
     * @param {boolean} [config.debug=false] - Enable debug logging
     * @param {number} [config.timeout=10000] - Request timeout in milliseconds
     */
    constructor(config) {
        if (!config.baseURL || !config.apiKey) {
            throw new Error('baseURL and apiKey are required');
        }

        this.baseURL = config.baseURL.replace(/\/$/, ''); // Remove trailing slash
        this.apiKey = config.apiKey;
        this.debug = config.debug || false;
        this.timeout = config.timeout || 10000;

        this._log('NACF Client initialized', { baseURL: this.baseURL });
    }

    /**
     * Registers a new user with their neural profile
     *
     * @param {string} userId - Unique user identifier
     * @param {Object} neuralProfile - Neural profile data
     * @param {string} neuralProfile.signal_type - Type of neural signal (EEG, ECG, EMG, etc.)
     * @param {Array<number>} neuralProfile.data - Array of signal values
     * @param {string} neuralProfile.timestamp - ISO timestamp
     * @param {Object} [neuralProfile.metadata] - Optional metadata
     * @returns {Promise<Object>} Registration result
     */
    async registerUser(userId, neuralProfile) {
        this._validateUserId(userId);
        this._validateNeuralData(neuralProfile);

        const payload = {
            action: 'register',
            user_id: userId,
            neural_profile: neuralProfile
        };

        return this._makeRequest('/api/v1/auth', 'POST', payload);
    }

    /**
     * Authenticates a user using neural signals
     *
     * @param {string} userId - User identifier
     * @param {Object} neuralSignals - Authentication neural signals
     * @param {string} neuralSignals.signal_type - Type of neural signal
     * @param {Array<number>} neuralSignals.data - Array of signal values
     * @param {string} neuralSignals.timestamp - ISO timestamp
     * @param {Object} [neuralSignals.metadata] - Optional metadata
     * @returns {Promise<Object>} Authentication result
     */
    async authenticateUser(userId, neuralSignals) {
        this._validateUserId(userId);
        this._validateNeuralData(neuralSignals);

        const payload = {
            action: 'authenticate',
            user_id: userId,
            neural_signals: neuralSignals
        };

        return this._makeRequest('/api/v1/auth', 'POST', payload);
    }

    /**
     * Processes neural signals for analysis
     *
     * @param {Object} signals - Neural signals to process
     * @param {string} signals.signal_type - Type of neural signal
     * @param {Array<number>} signals.data - Array of signal values
     * @param {string} signals.timestamp - ISO timestamp
     * @param {Object} [signals.metadata] - Optional metadata
     * @returns {Promise<Object>} Processing result
     */
    async processSignals(signals) {
        this._validateNeuralData(signals);

        const payload = {
            signals: signals
        };

        return this._makeRequest('/api/v1/process', 'POST', payload);
    }

    /**
     * Gets user profile information
     *
     * @param {string} userId - User identifier
     * @returns {Promise<Object>} User profile data
     */
    async getUserProfile(userId) {
        this._validateUserId(userId);

        return this._makeRequest(`/api/v1/auth?user_id=${encodeURIComponent(userId)}`, 'GET');
    }

    /**
     * Updates user neural profile
     *
     * @param {string} userId - User identifier
     * @param {Object} neuralProfile - Updated neural profile
     * @returns {Promise<Object>} Update result
     */
    async updateUserProfile(userId, neuralProfile) {
        this._validateUserId(userId);
        this._validateNeuralData(neuralProfile);

        const payload = {
            action: 'update',
            user_id: userId,
            neural_profile: neuralProfile
        };

        return this._makeRequest('/api/v1/auth', 'PUT', payload);
    }

    /**
     * Deletes a user profile
     *
     * @param {string} userId - User identifier
     * @returns {Promise<Object>} Deletion result
     */
    async deleteUser(userId) {
        this._validateUserId(userId);

        const payload = {
            action: 'delete',
            user_id: userId
        };

        return this._makeRequest('/api/v1/auth', 'DELETE', payload);
    }

    /**
     * Makes an HTTP request to the NACF API
     *
     * @private
     * @param {string} endpoint - API endpoint
     * @param {string} method - HTTP method
     * @param {Object} [data] - Request payload
     * @returns {Promise<Object>} Response data
     */
    async _makeRequest(endpoint, method, data = null) {
        const url = `${this.baseURL}${endpoint}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'apikey': this.apiKey,
                'User-Agent': 'NACF-Web-SDK/1.0.0'
            },
            signal: controller.signal
        };

        if (data) {
            config.body = JSON.stringify(data);
        }

        this._log(`Making ${method} request to ${url}`, data);

        try {
            const response = await fetch(url, config);
            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorText = await response.text();
                throw new NACFError(
                    `HTTP ${response.status}: ${response.statusText}`,
                    response.status,
                    errorText
                );
            }

            const result = await response.json();
            this._log('Request successful', result);
            return result;

        } catch (error) {
            clearTimeout(timeoutId);

            if (error.name === 'AbortError') {
                throw new NACFError('Request timeout', 408, 'Request timed out');
            }

            this._log('Request failed', error);
            throw error;
        }
    }

    /**
     * Validates user ID format
     *
     * @private
     * @param {string} userId - User identifier to validate
     */
    _validateUserId(userId) {
        if (!userId || typeof userId !== 'string') {
            throw new NACFError('Invalid user ID: must be a non-empty string', 400);
        }

        if (userId.length > 255) {
            throw new NACFError('Invalid user ID: must be less than 256 characters', 400);
        }

        // Basic validation for allowed characters
        if (!/^[a-zA-Z0-9_-]+$/.test(userId)) {
            throw new NACFError('Invalid user ID: only alphanumeric characters, hyphens, and underscores allowed', 400);
        }
    }

    /**
     * Validates neural data structure
     *
     * @private
     * @param {Object} data - Neural data to validate
     */
    _validateNeuralData(data) {
        if (!data || typeof data !== 'object') {
            throw new NACFError('Invalid neural data: must be an object', 400);
        }

        if (!data.signal_type || typeof data.signal_type !== 'string') {
            throw new NACFError('Invalid neural data: signal_type is required and must be a string', 400);
        }

        if (!Array.isArray(data.data) || data.data.length === 0) {
            throw new NACFError('Invalid neural data: data must be a non-empty array of numbers', 400);
        }

        // Validate that all data points are numbers
        if (!data.data.every(point => typeof point === 'number' && !isNaN(point))) {
            throw new NACFError('Invalid neural data: all data points must be valid numbers', 400);
        }

        if (!data.timestamp || typeof data.timestamp !== 'string') {
            throw new NACFError('Invalid neural data: timestamp is required and must be a string', 400);
        }

        // Validate timestamp format (basic ISO check)
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(data.timestamp)) {
            throw new NACFError('Invalid neural data: timestamp must be in ISO format', 400);
        }
    }

    /**
     * Logs debug information if debug mode is enabled
     *
     * @private
     * @param {string} message - Log message
     * @param {*} [data] - Additional data to log
     */
    _log(message, data) {
        if (this.debug) {
            console.log(`[NACF] ${message}`, data || '');
        }
    }
}

/**
 * Custom error class for NACF operations
 */
class NACFError extends Error {
    /**
     * @param {string} message - Error message
     * @param {number} [statusCode] - HTTP status code
     * @param {*} [details] - Additional error details
     */
    constructor(message, statusCode = 500, details = null) {
        super(message);
        this.name = 'NACFError';
        this.statusCode = statusCode;
        this.details = details;
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    // CommonJS
    module.exports = { NACFClient, NACFError };
} else if (typeof define === 'function' && define.amd) {
    // AMD
    define([], function() {
        return { NACFClient, NACFError };
    });
} else if (typeof window !== 'undefined') {
    // Browser global
    window.NACFClient = NACFClient;
    window.NACFError = NACFError;
}

// ES6 export (if supported)
if (typeof exports !== 'undefined') {
    exports.NACFClient = NACFClient;
    exports.NACFError = NACFError;
}