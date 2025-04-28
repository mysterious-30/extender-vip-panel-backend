/**
 * Audit Logger Module
 * 
 * Provides functionality to log and query audit events.
 * This module is used to track user actions and system events.
 */

const { getDB } = require('./db');

// Collection name for audit logs
const COLLECTION_NAME = 'auditLogs';

/**
 * Log an audit event to the database
 * 
 * @param {Object} eventData - The audit event data
 * @param {string} eventData.action - The action being performed (required)
 * @param {string} eventData.category - The category of the action (required)
 * @param {Object} eventData.clientInfo - Information about the client (required)
 * @param {string} eventData.clientInfo.userId - ID of the user performing the action (required)
 * @param {string} [eventData.clientInfo.ip] - IP address of the client
 * @param {string} [eventData.clientInfo.userAgent] - User agent string of the client
 * @param {Object} [eventData.details] - Additional details about the action
 * @param {string} [eventData.status='success'] - Status of the action ('success', 'failure', 'error')
 * @param {string} [eventData.resourceId] - ID of the resource being acted upon
 * @param {string} [eventData.resourceType] - Type of the resource being acted upon
 * @returns {Promise<Object>} The created audit log document
 * @throws {Error} If required fields are missing or if the database operation fails
 */
async function logAuditEvent(eventData) {
  // Validate required fields
  if (!eventData) {
    throw new Error('Event data is required');
  }
  
  if (!eventData.action) {
    throw new Error('Action is required');
  }
  
  if (!eventData.category) {
    throw new Error('Category is required');
  }
  
  if (!eventData.clientInfo || !eventData.clientInfo.userId) {
    throw new Error('Client info with userId is required');
  }
  
  // Create the audit log document
  const auditLog = {
    timestamp: new Date(),
    action: eventData.action,
    category: eventData.category,
    clientInfo: {
      userId: eventData.clientInfo.userId,
      ip: eventData.clientInfo.ip || null,
      userAgent: eventData.clientInfo.userAgent || null
    },
    details: eventData.details || {},
    status: eventData.status || 'success',
    resourceId: eventData.resourceId || null,
    resourceType: eventData.resourceType || null
  };
  
  try {
    const db = getDB();
    const collection = db.collection(COLLECTION_NAME);
    
    // Insert the audit log
    const result = await collection.insertOne(auditLog);
    
    // Return the created document with the generated _id
    return { ...auditLog, _id: result.insertedId };
  } catch (error) {
    console.error('Error logging audit event:', error);
    throw new Error(`Failed to log audit event: ${error.message}`);
  }
}

/**
 * Query audit logs with filtering options
 * 
 * @param {Object} [options={}] - Query options
 * @param {string} [options.userId] - Filter by user ID
 * @param {string} [options.category] - Filter by category
 * @param {string} [options.action] - Filter by action
 * @param {string} [options.status] - Filter by status
 * @param {string} [options.resourceId] - Filter by resource ID
 * @param {string} [options.resourceType] - Filter by resource type
 * @param {Date|string} [options.startDate] - Filter events after this date
 * @param {Date|string} [options.endDate] - Filter events before this date
 * @param {number} [options.limit=100] - Maximum number of results to return
 * @param {number} [options.skip=0] - Number of results to skip (for pagination)
 * @param {Object} [options.sort={ timestamp: -1 }] - Sort criteria
 * @returns {Promise<Array>} Array of matching audit logs
 * @throws {Error} If the database operation fails
 */
async function queryAuditLogs(options = {}) {
  try {
    const db = getDB();
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
    console.error('Error querying audit logs:', error);
    throw new Error(`Failed to query audit logs: ${error.message}`);
  }
}

/**
 * Count audit logs matching the filter criteria
 * 
 * @param {Object} [options={}] - Filter options (same as queryAuditLogs)
 * @returns {Promise<number>} The count of matching audit logs
 * @throws {Error} If the database operation fails
 */
async function countAuditLogs(options = {}) {
  try {
    const db = getDB();
    const collection = db.collection(COLLECTION_NAME);
    
    // Build the filter
    const filter = buildFilter(options);
    
    // Count the documents
    const count = await collection.countDocuments(filter);
    
    return count;
  } catch (error) {
    console.error('Error counting audit logs:', error);
    throw new Error(`Failed to count audit logs: ${error.message}`);
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
  
  // Add user ID filter
  if (options.userId) {
    filter['clientInfo.userId'] = options.userId;
  }
  
  // Add category filter
  if (options.category) {
    filter.category = options.category;
  }
  
  // Add action filter
  if (options.action) {
    filter.action = options.action;
  }
  
  // Add status filter
  if (options.status) {
    filter.status = options.status;
  }
  
  // Add resource filters
  if (options.resourceId) {
    filter.resourceId = options.resourceId;
  }
  
  if (options.resourceType) {
    filter.resourceType = options.resourceType;
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
 * Initialize the audit logger module
 * This creates necessary indexes for efficient querying
 * 
 * @returns {Promise<void>}
 */
async function initAuditLogger() {
  try {
    const db = getDB();
    const collection = db.collection(COLLECTION_NAME);
    
    // Create indexes for common query patterns
    await Promise.all([
      collection.createIndex({ timestamp: -1 }),
      collection.createIndex({ 'clientInfo.userId': 1 }),
      collection.createIndex({ category: 1 }),
      collection.createIndex({ action: 1 }),
      collection.createIndex({ status: 1 }),
      collection.createIndex({ resourceId: 1 }),
      collection.createIndex({ resourceType: 1 })
    ]);
    
    console.log('Audit logger initialized with indexes');
  } catch (error) {
    console.error('Error initializing audit logger:', error);
    throw new Error(`Failed to initialize audit logger: ${error.message}`);
  }
}

module.exports = {
  logAuditEvent,
  queryAuditLogs,
  countAuditLogs,
  initAuditLogger
}; 