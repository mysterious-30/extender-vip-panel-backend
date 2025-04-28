/**
 * Database Module
 * 
 * Provides functionality to connect to and interact with MongoDB.
 */

const { MongoClient } = require('mongodb');

// Connection variables
let client = null;
let db = null;
let isConnected = false;

// Default connection options
const DEFAULT_DB_NAME = 'auditLoggerDB';
const DEFAULT_MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';

/**
 * Initialize the database connection
 * 
 * @param {Object} options - Connection options
 * @param {string} [options.uri=process.env.MONGO_URI || 'mongodb://localhost:27017'] - MongoDB connection URI
 * @param {string} [options.dbName=DEFAULT_DB_NAME] - Database name
 * @returns {Promise<Object>} The database connection
 */
async function connect(options = {}) {
  if (isConnected) {
    return { client, db };
  }

  try {
    const uri = options.uri || DEFAULT_MONGO_URI;
    const dbName = options.dbName || DEFAULT_DB_NAME;
    
    // Create a new MongoClient
    client = new MongoClient(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    // Connect to the MongoDB server
    await client.connect();
    console.log('Connected to MongoDB');
    
    // Get the database
    db = client.db(dbName);
    isConnected = true;
    
    return { client, db };
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    throw new Error(`Database connection failed: ${error.message}`);
  }
}

/**
 * Get the database instance
 * 
 * @returns {Object} The database instance
 * @throws {Error} If the database is not connected
 */
function getDB() {
  if (!isConnected || !db) {
    throw new Error('Database not connected. Call connect() first.');
  }
  return db;
}

/**
 * Get the MongoDB client
 * 
 * @returns {MongoClient} The MongoDB client
 * @throws {Error} If the client is not connected
 */
function getClient() {
  if (!isConnected || !client) {
    throw new Error('Database not connected. Call connect() first.');
  }
  return client;
}

/**
 * Close the database connection
 * 
 * @returns {Promise<void>}
 */
async function close() {
  if (client && isConnected) {
    await client.close();
    isConnected = false;
    client = null;
    db = null;
    console.log('Disconnected from MongoDB');
  }
}

module.exports = {
  connect,
  getDB,
  getClient,
  close
}; 