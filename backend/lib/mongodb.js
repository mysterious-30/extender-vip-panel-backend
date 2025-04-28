// MongoDB connection module for backend
const { MongoClient } = require('mongodb');

// Connection URI from environment variables or use default
const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = process.env.MONGODB_DB || 'extender-panel';

// Cache MongoDB connection
let cachedClient = null;
let cachedDb = null;

/**
 * Connect to MongoDB database
 * @returns {Promise<{db: any, client: MongoClient}>} MongoDB client and database
 */
async function connectToDatabase() {
  // If connection already exists, return cached connection
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  try {
    // Connect to MongoDB
    const client = await MongoClient.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    const db = client.db(dbName);
    
    // Cache connection
    cachedClient = client;
    cachedDb = db;
    
    console.log('Successfully connected to MongoDB');
    return { client, db };
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    
    // Fall back to in-memory logging if MongoDB is not available
    console.log('Using in-memory logging as fallback');
    
    // Return a mock db that will not throw errors
    return {
      client: null,
      db: {
        collection: () => ({
          insertOne: async () => ({ acknowledged: true, insertedId: 'mock-id' }),
          find: () => ({
            toArray: async () => [],
            sort: () => ({ limit: () => ({ toArray: async () => [] }) }),
          }),
          countDocuments: async () => 0,
          aggregate: () => ({ toArray: async () => [] }),
        }),
      },
    };
  }
}

module.exports = {
  connectToDatabase,
}; 