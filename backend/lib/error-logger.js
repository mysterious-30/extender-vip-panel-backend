// Error Logger Module
const fs = require('fs');
const path = require('path');
const { connectToDatabase } = require('./mongodb');

// Log levels
const LogLevel = {
  DEBUG: 'debug',
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error',
  CRITICAL: 'critical'
};

// Ensure error logs directory exists
const LOG_DIR = path.join(__dirname, '../logs');
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Error log file paths
const ERROR_LOG_FILE = path.join(LOG_DIR, 'error.log');
const APPLICATION_LOG_FILE = path.join(LOG_DIR, 'application.log');

/**
 * Formats an error object for logging
 * @param {Error} error - The error object
 * @param {Object} additionalInfo - Additional context information
 * @returns {Object} Formatted error object
 */
function formatError(error, additionalInfo = {}) {
  const baseError = {
    timestamp: new Date(),
    message: error.message || 'Unknown error',
    name: error.name || 'Error',
    stack: error.stack,
    ...additionalInfo
  };

  // Handle non-standard error properties
  if (error.code) baseError.code = error.code;
  if (error.statusCode) baseError.statusCode = error.statusCode;
  if (error.errno) baseError.errno = error.errno;
  if (error.syscall) baseError.syscall = error.syscall;
  if (error.path) baseError.path = error.path;
  if (error.address) baseError.address = error.address;
  if (error.port) baseError.port = error.port;

  return baseError;
}

/**
 * Logs an error to file system
 * @param {Object} errorData - Formatted error data
 * @param {string} logFile - Path to log file
 */
function logToFile(errorData, logFile) {
  const logEntry = `[${errorData.timestamp.toISOString()}] [${errorData.name}] ${errorData.message}\n${
    errorData.stack ? `Stack: ${errorData.stack}\n` : ''
  }Context: ${JSON.stringify(omitSensitiveData(errorData))}\n\n`;

  fs.appendFile(logFile, logEntry, (err) => {
    if (err) {
      console.error('Failed to write to log file:', err);
    }
  });
}

/**
 * Logs an error to database
 * @param {Object} errorData - Formatted error data
 */
async function logToDatabase(errorData) {
  try {
    const { db } = await connectToDatabase();
    if (!db) {
      throw new Error('No database connection available');
    }
    await db.collection('error_logs').insertOne(omitSensitiveData(errorData));
  } catch (dbError) {
    console.error('Failed to log to database:', dbError);
    // Fallback to file logging if database fails
    logToFile(
      formatError(dbError, { 
        originalError: errorData,
        context: 'Failed to log original error to database'
      }), 
      ERROR_LOG_FILE
    );
  }
}

/**
 * Remove sensitive data from logs
 * @param {Object} data - Data to sanitize
 * @returns {Object} Sanitized data
 */
function omitSensitiveData(data) {
  const sensitiveFields = ['password', 'token', 'secret', 'authorization', 'cookie'];
  const sanitized = { ...data };
  
  const sanitizeObj = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    
    Object.keys(obj).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (sensitiveFields.some(field => lowerKey.includes(field))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        sanitizeObj(obj[key]);
      }
    });
  };
  
  sanitizeObj(sanitized);
  return sanitized;
}

/**
 * Main error logging function
 * @param {Error} error - Error object
 * @param {Object} contextInfo - Additional context information
 * @param {string} level - Log level (default: 'error')
 */
async function logError(error, contextInfo = {}, level = LogLevel.ERROR) {
  if (!error) {
    error = new Error('Unknown error (no error object provided)');
  }

  // Convert string errors to Error objects
  if (typeof error === 'string') {
    error = new Error(error);
  }

  const errorData = formatError(error, {
    ...contextInfo,
    level,
    environment: process.env.NODE_ENV || 'development',
    processInfo: {
      pid: process.pid,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime()
    }
  });

  // Always log to console in development
  if (process.env.NODE_ENV !== 'production' || level === LogLevel.CRITICAL) {
    console.error(`[${level.toUpperCase()}]`, error.message, { 
      stack: error.stack,
      context: contextInfo
    });
  }

  // Log to file
  logToFile(errorData, ERROR_LOG_FILE);
  
  // Log to database (async)
  try {
    await logToDatabase(errorData);
  } catch (e) {
    console.error('Error logging to database:', e);
  }
}

/**
 * Log an application event (non-error)
 * @param {string} message - Event message
 * @param {Object} data - Additional data
 * @param {string} level - Log level
 */
function logAppEvent(message, data = {}, level = LogLevel.INFO) {
  const logEntry = {
    timestamp: new Date(),
    message,
    level,
    data: omitSensitiveData(data),
    environment: process.env.NODE_ENV || 'development'
  };

  // Log to console in development
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[${level.toUpperCase()}] ${message}`, data);
  }

  // Log to application log file
  const fileEntry = `[${logEntry.timestamp.toISOString()}] [${level.toUpperCase()}] ${message}\n${
    Object.keys(data).length ? `Data: ${JSON.stringify(omitSensitiveData(data))}\n` : ''
  }\n`;

  fs.appendFile(APPLICATION_LOG_FILE, fileEntry, (err) => {
    if (err) {
      console.error('Failed to write to application log file:', err);
    }
  });

  // Log to database as well
  logToDatabase(logEntry).catch(err => {
    console.error('Failed to log app event to database:', err);
  });
}

/**
 * Express middleware for error logging
 */
function errorLoggerMiddleware(err, req, res, next) {
  const contextInfo = {
    url: req.originalUrl || req.url,
    method: req.method,
    body: omitSensitiveData(req.body),
    params: req.params,
    query: req.query,
    ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    userId: req.user?.id,
    requestId: req.id || req.headers['x-request-id']
  };

  const level = err.statusCode >= 500 ? LogLevel.ERROR : LogLevel.WARN;
  logError(err, contextInfo, level);

  // Pass to next error handler
  next(err);
}

/**
 * Request logger middleware
 */
function requestLoggerMiddleware(req, res, next) {
  const startTime = Date.now();

  // Log when response is sent
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const level = res.statusCode >= 400 
      ? (res.statusCode >= 500 ? LogLevel.ERROR : LogLevel.WARN) 
      : LogLevel.INFO;

    logAppEvent(`HTTP ${req.method} ${req.originalUrl || req.url}`, {
      statusCode: res.statusCode,
      duration,
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      userId: req.user?.id,
      responseSize: parseInt(res.getHeader('content-length') || '0'),
      requestId: req.id || req.headers['x-request-id']
    }, level);
  });

  next();
}

module.exports = {
  logError,
  logAppEvent,
  errorLoggerMiddleware,
  requestLoggerMiddleware,
  LogLevel
}; 