const express = require('express');
const router = express.Router();
const { logError, LogLevel } = require('../lib/error-logger');

/**
 * Handle client-side error logs from the frontend
 */
router.post('/client-error', async (req, res) => {
  try {
    const errorData = req.body;
    
    // Basic validation
    if (!errorData || !errorData.message) {
      return res.status(400).json({ error: 'Invalid error data' });
    }

    // Extract client IP and user info
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const userId = req.user?.id;

    // Map frontend log level to backend log level
    let logLevel;
    switch (errorData.level) {
      case 'debug': logLevel = LogLevel.DEBUG; break;
      case 'info': logLevel = LogLevel.INFO; break;
      case 'warn': logLevel = LogLevel.WARN; break;
      case 'error': logLevel = LogLevel.ERROR; break;
      case 'critical': logLevel = LogLevel.CRITICAL; break;
      default: logLevel = LogLevel.ERROR;
    }

    // Create a meaningful error object
    const error = new Error(`Client Error: ${errorData.message}`);
    error.name = errorData.name || 'ClientError';
    error.stack = errorData.stack;

    // Log the client error
    await logError(error, {
      source: 'client',
      clientInfo: {
        ip: clientIp,
        userAgent,
        userId,
        url: errorData.url,
        componentStack: errorData.componentStack,
        errorSource: errorData.source,
        clientMetadata: errorData.metadata || {},
        receivedAt: errorData.receivedAt || new Date()
      }
    }, logLevel);

    // Return success
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error handling client error logging:', error);
    
    // Log the meta-error (error in error handling)
    logError(error, {
      context: 'client_error_endpoint',
      requestBody: req.body
    });
    
    return res.status(500).json({ error: 'Error processing error log' });
  }
});

module.exports = router; 