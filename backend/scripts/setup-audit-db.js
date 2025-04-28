#!/usr/bin/env node

/**
 * Database setup script for audit logging
 * This script creates the necessary collections and indexes for audit logging
 */

const { connectDB, closeDB } = require('../lib/db');

async function setupAuditDatabase() {
  try {
    console.log('Setting up audit logging database...');
    
    // Connect to database
    const db = await connectDB();
    
    // Create auditLogs collection if it doesn't exist
    const collections = await db.listCollections({ name: 'auditLogs' }).toArray();
    
    if (collections.length === 0) {
      console.log('Creating auditLogs collection...');
      await db.createCollection('auditLogs');
    } else {
      console.log('auditLogs collection already exists');
    }
    
    // Create indexes for efficient querying
    console.log('Creating indexes on auditLogs collection...');
    const collection = db.collection('auditLogs');
    
    // Index for timestamp-based queries
    await collection.createIndex({ timestamp: 1 });
    
    // Index for user-based queries
    await collection.createIndex({ 'clientInfo.userId': 1 });
    
    // Index for action-based queries
    await collection.createIndex({ action: 1 });
    
    // Index for category-based queries
    await collection.createIndex({ category: 1 });
    
    // Combined index for common reporting queries
    await collection.createIndex({ 
      timestamp: 1, 
      action: 1, 
      'clientInfo.userId': 1 
    });
    
    // TTL index if audit logs should expire after a certain period (e.g., 1 year)
    // Uncomment the following line and adjust the expireAfterSeconds value as needed
    // await collection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 31536000 });
    
    console.log('Database setup completed successfully');
  } catch (error) {
    console.error('Error setting up audit database:', error);
    process.exit(1);
  } finally {
    await closeDB();
  }
}

// Run the setup function
setupAuditDatabase(); 