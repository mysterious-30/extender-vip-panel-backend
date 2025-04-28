/**
 * Security Logger Module
 * 
 * Provides functionality to log and query security events.
 * This module is used to track security-related activities and potential threats.
 */

const { connectToDatabase } = require('./mongodb');

// Collection name for security logs
const COLLECTION_NAME = 'securityLogs';

/**
 * Log a security event to the database
 * 
 * @param {Object} eventData - The security event data
 * @param {string} eventData.type - The type of security event (required)
 * @param {string} eventData.severity - Severity level of the event (required: 'low', 'medium', 'high', 'critical')
 * @param {Object} eventData.clientInfo - Information about the client (required)
 * @param {string} [eventData.clientInfo.userId] - ID of the user associated with the event
 * @param {string} [eventData.clientInfo.ip] - IP address of the client
 * @param {string} [eventData.clientInfo.userAgent] - User agent string of the client
 * @param {string} [eventData.source='system'] - Source of the event ('system', 'user', 'api', 'client')
 * @param {string} [eventData.description] - Description of the security event
 * @param {Object} [eventData.metadata] - Additional metadata about the event
 * @returns {Promise<Object>} The created security log document
 * @throws {Error} If required fields are missing or if the database operation fails
 */
async function logSecurityEvent(eventData) {
  // Validate required fields
  if (!eventData) {
    throw new Error('Event data is required');
  }
  
  if (!eventData.type) {
    throw new Error('Event type is required');
  }
  
  if (!eventData.severity) {
    throw new Error('Severity is required');
  }
  
  if (!eventData.clientInfo) {
    throw new Error('Client info is required');
  }
  
  // Create the security log document
  const securityLog = {
    timestamp: new Date(),
    type: eventData.type,
    severity: eventData.severity,
    source: eventData.source || 'system',
    description: eventData.description || '',
    clientInfo: {
      userId: eventData.clientInfo.userId || null,
      ip: eventData.clientInfo.ip || null,
      userAgent: eventData.clientInfo.userAgent || null,
      url: eventData.clientInfo.url || null
    },
    metadata: eventData.metadata || {}
  };
  
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    
    // Insert the security log
    const result = await collection.insertOne(securityLog);
    
    // Return the created document with the generated _id
    return { ...securityLog, _id: result.insertedId };
  } catch (error) {
    console.error('Error logging security event:', error);
    throw new Error(`Failed to log security event: ${error.message}`);
  }
}

/**
 * Query security logs with filtering options
 * 
 * @param {Object} [options={}] - Query options
 * @param {string} [options.type] - Filter by event type
 * @param {string} [options.severity] - Filter by severity level
 * @param {string} [options.source] - Filter by source
 * @param {string} [options.userId] - Filter by user ID
 * @param {string} [options.ip] - Filter by IP address
 * @param {Date|string} [options.startDate] - Filter events after this date
 * @param {Date|string} [options.endDate] - Filter events before this date
 * @param {number} [options.limit=100] - Maximum number of results to return
 * @param {number} [options.skip=0] - Number of results to skip (for pagination)
 * @param {Object} [options.sort={ timestamp: -1 }] - Sort criteria
 * @returns {Promise<Array>} Array of matching security logs
 * @throws {Error} If the database operation fails
 */
async function querySecurityLogs(options = {}) {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    
    // Build the filter
    const filter = buildFilter(options);
    
    // Set default pagination and sorting
    const limit = options.limit || 100;
    const skip = options.skip || 0;
    const sort = options.sort || { timestamp: -1 };
    
    // Query the database
    const result = await collection.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .toArray();
    
    return result;
  } catch (error) {
    console.error('Error querying security logs:', error);
    throw new Error(`Failed to query security logs: ${error.message}`);
  }
}

/**
 * Count security logs matching the filter criteria
 * 
 * @param {Object} [options={}] - Filter options (same as querySecurityLogs)
 * @returns {Promise<number>} The count of matching security logs
 * @throws {Error} If the database operation fails
 */
async function countSecurityLogs(options = {}) {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    
    // Build the filter
    const filter = buildFilter(options);
    
    // Count the documents
    const count = await collection.countDocuments(filter);
    
    return count;
  } catch (error) {
    console.error('Error counting security logs:', error);
    throw new Error(`Failed to count security logs: ${error.message}`);
  }
}

/**
 * Build a filter object from the provided options
 * 
 * @private
 * @param {Object} options - Filter options
 * @returns {Object} MongoDB filter object
 */
function buildFilter(options) {
  const filter = {};
  
  // Add type filter
  if (options.type) {
    filter.type = options.type;
  }
  
  // Add severity filter
  if (options.severity) {
    filter.severity = options.severity;
  }
  
  // Add source filter
  if (options.source) {
    filter.source = options.source;
  }
  
  // Add user ID filter
  if (options.userId) {
    filter['clientInfo.userId'] = options.userId;
  }
  
  // Add IP address filter
  if (options.ip) {
    filter['clientInfo.ip'] = options.ip;
  }
  
  // Add date range filters
  if (options.startDate || options.endDate) {
    filter.timestamp = {};
    
    if (options.startDate) {
      filter.timestamp.$gte = new Date(options.startDate);
    }
    
    if (options.endDate) {
      filter.timestamp.$lte = new Date(options.endDate);
    }
  }
  
  return filter;
}

/**
 * Initialize the security logger module
 * This creates necessary indexes for efficient querying
 * 
 * @returns {Promise<void>}
 */
async function initSecurityLogger() {
  try {
    const { db } = await connectToDatabase();
    const collection = db.collection(COLLECTION_NAME);
    
    // Create indexes for common query patterns
    await Promise.all([
      collection.createIndex({ timestamp: -1 }),
      collection.createIndex({ type: 1 }),
      collection.createIndex({ severity: 1 }),
      collection.createIndex({ source: 1 }),
      collection.createIndex({ 'clientInfo.userId': 1 }),
      collection.createIndex({ 'clientInfo.ip': 1 })
    ]);
    
    console.log('Security logger initialized with indexes');
  } catch (error) {
    console.error('Error initializing security logger:', error);
    throw new Error(`Failed to initialize security logger: ${error.message}`);
  }
}

module.exports = {
  logSecurityEvent,
  querySecurityLogs,
  countSecurityLogs,
  initSecurityLogger
}; 