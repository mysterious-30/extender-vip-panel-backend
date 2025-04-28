/**
 * System Monitoring Module
 * 
 * Provides functionality to monitor system health, resource usage, and abnormal activities.
 * This module works alongside other logging modules to provide a comprehensive monitoring solution.
 */

const os = require('os');
const { logError, logAppEvent, LogLevel } = require('./error-logger');
const { connectToDatabase } = require('./mongodb');
const { logAuditEvent } = require('./audit-logger');

// Collection names
const SYSTEM_HEALTH_COLLECTION = 'system_health';
const ABNORMAL_ACTIVITIES_COLLECTION = 'abnormal_activities';

// Resource usage thresholds
const THRESHOLDS = {
  CPU_LOAD: 0.8, // 80% CPU usage
  MEMORY_USAGE: 0.9, // 90% memory usage
  API_RESPONSE_TIME: 2000, // 2 seconds
  REQUEST_RATE: 100, // requests per minute
  ERROR_RATE: 0.1 // 10% error rate
};

// Activity tracking
const lastMonitorTimestamp = Date.now();
const requestCounts = {
  total: 0,
  errors: 0,
  lastResetTime: Date.now()
};

/**
 * Log system health metrics to database
 * @param {boolean} [logToConsole=false] - Whether to log to console
 * @returns {Promise<void>}
 */
async function logSystemHealth(logToConsole = false) {
  try {
    const cpus = os.cpus();
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const loadAvg = os.loadavg();
    
    const healthData = {
      timestamp: new Date(),
      cpuUsage: {
        load: loadAvg[0],
        loadAvg: loadAvg,
        cpuCount: cpus.length,
        model: cpus[0].model,
        speed: cpus[0].speed
      },
      memoryUsage: {
        total: totalMemory,
        free: freeMemory,
        used: totalMemory - freeMemory,
        usagePercentage: (1 - freeMemory / totalMemory) * 100
      },
      os: {
        platform: os.platform(),
        release: os.release(),
        hostname: os.hostname(),
        uptime: os.uptime()
      },
      process: {
        pid: process.pid,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        version: process.version
      },
      requests: {
        ...requestCounts,
        requestsPerMinute: calculateRequestsPerMinute()
      }
    };
    
    // Check if any metrics exceed thresholds
    const cpuAlert = loadAvg[0] / cpus.length > THRESHOLDS.CPU_LOAD;
    const memoryAlert = (totalMemory - freeMemory) / totalMemory > THRESHOLDS.MEMORY_USAGE;
    const requestRateAlert = calculateRequestsPerMinute() > THRESHOLDS.REQUEST_RATE;
    const errorRateAlert = (requestCounts.errors / requestCounts.total) > THRESHOLDS.ERROR_RATE;
    
    if (cpuAlert || memoryAlert || requestRateAlert || errorRateAlert) {
      healthData.alerts = {
        cpuAlert,
        memoryAlert,
        requestRateAlert,
        errorRateAlert
      };
      
      // Log an alert if any threshold is exceeded
      logAppEvent("System health threshold exceeded", healthData, LogLevel.WARN);
      
      // If multiple thresholds are exceeded, this might be more serious
      if ((cpuAlert && memoryAlert) || (requestRateAlert && errorRateAlert)) {
        logAbnormalActivity("multiple_system_thresholds_exceeded", "High system load detected across multiple metrics", healthData);
      }
    }
    
    // Log to console if requested
    if (logToConsole) {
      console.log("System Health Report:", JSON.stringify(healthData, null, 2));
    }
    
    // Store in database
    const { db } = await connectToDatabase();
    await db.collection(SYSTEM_HEALTH_COLLECTION).insertOne(healthData);
    
    // Reset counters every hour
    const now = Date.now();
    if (now - requestCounts.lastResetTime > 3600000) {
      requestCounts.total = 0;
      requestCounts.errors = 0;
      requestCounts.lastResetTime = now;
    }
    
    return healthData;
  } catch (error) {
    console.error("Error logging system health:", error);
    logError(error, { context: "system_health_logging" });
  }
}

/**
 * Calculate requests per minute based on request counts
 * @returns {number} Requests per minute
 */
function calculateRequestsPerMinute() {
  const now = Date.now();
  const minutesElapsed = (now - requestCounts.lastResetTime) / 60000;
  return minutesElapsed > 0 ? requestCounts.total / minutesElapsed : 0;
}

/**
 * Track a new request for metrics
 * @param {boolean} [isError=false] - Whether the request resulted in an error
 */
function trackRequest(isError = false) {
  requestCounts.total++;
  if (isError) {
    requestCounts.errors++;
  }
}

/**
 * Log abnormal system activity
 * @param {string} type - Type of abnormal activity
 * @param {string} description - Description of the activity
 * @param {Object} data - Additional data about the activity
 * @returns {Promise<void>}
 */
async function logAbnormalActivity(type, description, data = {}) {
  try {
    const activity = {
      timestamp: new Date(),
      type,
      description,
      data,
      severity: determineSeverity(type, data)
    };
    
    // Log to application log
    logAppEvent(`Abnormal activity detected: ${type}`, { description, ...data }, LogLevel.WARN);
    
    // Also log high severity events as audit events instead of security events
    if (activity.severity === 'high' || activity.severity === 'critical') {
      logAuditEvent({
        action: `abnormal_activity_${type}`,
        category: 'security',
        status: activity.severity === 'critical' ? 'critical' : 'error',
        details: {
          description: description,
          ...data
        },
        clientInfo: {
          userId: data.userId || 'system',
          ip: data.ip || null
        }
      }).catch(err => console.error('Error logging audit event:', err));
    }
    
    // Store in database
    const { db } = await connectToDatabase();
    await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).insertOne(activity);
    
    return activity;
  } catch (error) {
    console.error("Error logging abnormal activity:", error);
    logError(error, { context: "abnormal_activity_logging", originalData: { type, description, data } });
  }
}

/**
 * Determine severity of an abnormal activity
 * @param {string} type - Type of abnormal activity
 * @param {Object} data - Activity data
 * @returns {string} Severity level (low, medium, high, critical)
 */
function determineSeverity(type, data) {
  // Define severity based on activity type and data
  const highSeverityTypes = [
    'brute_force_attempt',
    'multiple_auth_failures',
    'api_abuse',
    'injection_attempt',
    'multiple_system_thresholds_exceeded'
  ];
  
  const criticalSeverityTypes = [
    'suspicious_admin_access',
    'data_exfiltration',
    'security_breach',
    'malicious_code_execution'
  ];
  
  if (criticalSeverityTypes.includes(type)) return 'critical';
  if (highSeverityTypes.includes(type)) return 'high';
  
  // Check rate-based severity
  if (data.rate && data.rate > 50) return 'high';
  if (data.rate && data.rate > 20) return 'medium';
  
  // Check error-rate severity
  if (data.errorRate && data.errorRate > 0.5) return 'high';
  if (data.errorRate && data.errorRate > 0.2) return 'medium';
  
  return 'low';
}

/**
 * Detect and log brute force attempts
 * @param {string} userId - User ID or identifier
 * @param {string} ip - IP address
 * @param {string} action - The action being attempted (login, api access, etc.)
 * @returns {Promise<boolean>} True if brute force detected
 */
async function detectBruteForce(userId, ip, action) {
  try {
    const { db } = await connectToDatabase();
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    
    // Query recent failed attempts
    const query = {
      timestamp: { $gte: fiveMinutesAgo },
      "data.action": action,
      $or: [
        { "data.userId": userId },
        { "data.ip": ip }
      ]
    };
    
    const count = await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).countDocuments(query);
    
    // If more than 5 failed attempts in 5 minutes, consider it a brute force attempt
    if (count >= 5) {
      await logAbnormalActivity('brute_force_attempt', `Possible brute force ${action} attempt detected`, {
        userId,
        ip,
        action,
        attemptCount: count + 1,
        timeWindow: '5 minutes'
      });
      return true;
    }
    
    return false;
  } catch (error) {
    console.error("Error detecting brute force:", error);
    logError(error, { context: "brute_force_detection", data: { userId, ip, action } });
    return false;
  }
}

/**
 * Monitor API endpoint for abnormal usage patterns
 * @param {string} endpoint - API endpoint
 * @param {string} method - HTTP method
 * @param {string} userId - User ID
 * @param {string} ip - IP address
 * @param {number} responseTime - Response time in ms
 * @returns {Promise<void>}
 */
async function monitorApiEndpoint(endpoint, method, userId, ip, responseTime) {
  try {
    trackRequest(false);
    
    // Check for abnormally high response time
    if (responseTime > THRESHOLDS.API_RESPONSE_TIME) {
      await logAbnormalActivity('slow_api_response', `Slow API response detected for ${method} ${endpoint}`, {
        endpoint,
        method,
        userId,
        ip,
        responseTime,
        threshold: THRESHOLDS.API_RESPONSE_TIME
      });
    }
    
    // Aggregate endpoint usage per minute for this user/IP
    const { db } = await connectToDatabase();
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
    
    const query = {
      timestamp: { $gte: oneMinuteAgo },
      "data.endpoint": endpoint,
      "data.method": method,
      $or: [
        { "data.userId": userId },
        { "data.ip": ip }
      ]
    };
    
    const count = await db.collection(SYSTEM_HEALTH_COLLECTION).countDocuments(query);
    
    // If user/IP is making too many requests to the same endpoint
    if (count > 30) { // More than 30 requests per minute to the same endpoint
      await logAbnormalActivity('api_abuse', `Possible API abuse detected for ${method} ${endpoint}`, {
        endpoint,
        method,
        userId,
        ip,
        requestCount: count,
        timeWindow: '1 minute',
        rate: count
      });
      
      // Log API abuse as an audit event instead of security event
      logAuditEvent({
        action: 'api_abuse',
        category: 'security',
        status: 'warning',
        details: {
          description: `High rate of API calls to ${method} ${endpoint}`,
          endpoint,
          method,
          requestCount: count,
          timeWindow: '1 minute'
        },
        clientInfo: {
          userId,
          ip
        }
      }).catch(err => console.error('Error logging audit event:', err));
    }
  } catch (error) {
    console.error("Error monitoring API endpoint:", error);
    logError(error, { context: "api_monitoring", data: { endpoint, method, userId, ip } });
  }
}

/**
 * Initialize database indexes for the monitoring collections
 * @returns {Promise<void>}
 */
async function initSystemMonitor() {
  try {
    const { db } = await connectToDatabase();
    
    // Create indexes for system health collection
    await db.collection(SYSTEM_HEALTH_COLLECTION).createIndex({ timestamp: -1 });
    await db.collection(SYSTEM_HEALTH_COLLECTION).createIndex({ "cpuUsage.load": 1 });
    await db.collection(SYSTEM_HEALTH_COLLECTION).createIndex({ "memoryUsage.usagePercentage": 1 });
    
    // Create indexes for abnormal activities collection
    await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).createIndex({ timestamp: -1 });
    await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).createIndex({ type: 1 });
    await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).createIndex({ severity: 1 });
    await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).createIndex({ "data.userId": 1 });
    await db.collection(ABNORMAL_ACTIVITIES_COLLECTION).createIndex({ "data.ip": 1 });
    
    console.log("System monitoring initialized with indexes");
    
    // Schedule periodic health checks
    setInterval(() => {
      logSystemHealth().catch(err => {
        console.error("Error in scheduled system health check:", err);
      });
    }, 60000); // Run every minute
    
  } catch (error) {
    console.error("Error initializing system monitor:", error);
    logError(error, { context: "system_monitor_initialization" });
  }
}

// Middleware to track request metrics
function monitorRequestMiddleware(req, res, next) {
  const startTime = Date.now();
  
  // Add monitoring data to request object
  req.monitoringData = {
    startTime
  };
  
  // Track request
  trackRequest(false);
  
  // Log when response is sent
  res.on('finish', async () => {
    const responseTime = Date.now() - startTime;
    const isError = res.statusCode >= 400;
    
    // Track error if status code indicates error
    if (isError) {
      trackRequest(true);
    }
    
    // Monitor API usage patterns for potential abuse
    if (req.originalUrl.startsWith('/api/')) {
      await monitorApiEndpoint(
        req.originalUrl,
        req.method,
        req.user?.id || 'anonymous',
        req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        responseTime
      );
    }
    
    // Detect slow responses
    if (responseTime > THRESHOLDS.API_RESPONSE_TIME) {
      logAppEvent(`Slow response detected: ${req.method} ${req.originalUrl}`, {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        responseTime,
        ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        userId: req.user?.id || 'anonymous'
      }, LogLevel.WARN);
    }
  });
  
  next();
}

module.exports = {
  logSystemHealth,
  detectBruteForce,
  logAbnormalActivity,
  monitorApiEndpoint,
  monitorRequestMiddleware,
  trackRequest,
  initSystemMonitor
}; 