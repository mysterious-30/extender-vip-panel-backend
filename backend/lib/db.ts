import mongoose from 'mongoose';

// Cache the mongoose connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/extender-vip';

let cachedConnection: typeof mongoose | null = null;
let connectionPromise: Promise<typeof mongoose> | null = null;

// Connection options optimized for performance
const connectionOptions: mongoose.ConnectOptions = {
  maxPoolSize: 100, // Increase connection pool for better concurrency
  minPoolSize: 5,   // Keep minimum connections ready
  socketTimeoutMS: 45000, // Longer timeout for operations
  serverSelectionTimeoutMS: 5000, // Faster server selection
  heartbeatFrequencyMS: 10000, // Regular heartbeat
  maxIdleTimeMS: 30000, // Release unused connections after this period
};

/**
 * Global function to connect to MongoDB database
 * This uses connection pooling and caching for better performance
 */
export async function connectToDatabase() {
  // If we have a cached connection, return it
  if (cachedConnection) {
    return cachedConnection;
  }

  // If we're already connecting, return the existing promise
  if (connectionPromise) {
    return connectionPromise;
  }

  // Set mongoose options for better performance
  mongoose.set('bufferCommands', true);
  mongoose.set('autoIndex', false); // Don't build indexes in production

  try {
    // Create new connection promise
    connectionPromise = mongoose.connect(MONGODB_URI, connectionOptions)
      .then((mongoose) => {
        console.log('Connected to MongoDB');
        cachedConnection = mongoose;
        return mongoose;
      })
      .catch((err) => {
        console.error('MongoDB connection error:', err);
        connectionPromise = null;
        throw err;
      });

    return connectionPromise;
  } catch (error) {
    console.error('Error initiating MongoDB connection:', error);
    throw error;
  }
}

// Connection events for monitoring
mongoose.connection.on('connected', () => {
  console.log('MongoDB connection established');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB connection disconnected');
});

// Gracefully close connection when process ends
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
}); 