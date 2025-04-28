const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const fs = require('fs');

// Initialize data directory for any local files
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// MongoDB Connection URL - typically would be in an environment variable
const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';
const DB_NAME = 'extender_panel';

// Create a MongoDB client with better options
const client = new MongoClient(MONGO_URL, {
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 10000,
  maxPoolSize: 50,
  retryWrites: true
});

let db;
let dbConnected = false;

// Collections
let usersCollection;
let keysCollection;
let apiTokensCollection;
let bulkKeysCollection;
let referralsCollection;

// Connect to MongoDB
async function connectToDatabase() {
  if (dbConnected) return db;
  
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    dbConnected = true;
    
    // Get reference to database
    db = client.db(DB_NAME);
    
    // Get references to collections
    usersCollection = db.collection('users');
    keysCollection = db.collection('keys');
    apiTokensCollection = db.collection('api_tokens');
    bulkKeysCollection = db.collection('bulk_keys');
    
    // Ensure referrals collection exists
    try {
      await db.createCollection('referrals');
      console.log('Created referrals collection');
    } catch (collectionError) {
      // Collection might already exist, which is fine
      console.log('Referrals collection already exists or error creating:', collectionError.message);
    }
    
    referralsCollection = db.collection('referrals');
    console.log('Referrals collection initialized:', !!referralsCollection);
    
    // Initialize collections with indexes
    await initializeCollections();
    
    // Initialize default users if none exist
    await initDefaultUsers();
    
    return db;
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    dbConnected = false;
    
    // Try to restart the connection after a delay
    setTimeout(() => {
      console.log('Attempting to reconnect to MongoDB...');
      connectToDatabase().catch(err => {
        console.error('Failed to reconnect to MongoDB:', err);
      });
    }, 5000);
    
    throw error;
  }
}

// Ensure database is connected
async function ensureDbConnected() {
  if (!dbConnected) {
    console.log('Database not connected, connecting now...');
    await connectToDatabase();
  }
  return dbConnected;
}

// Initialize collections with indexes
async function initializeCollections() {
  try {
    // Create unique indexes
    await usersCollection.createIndex({ userId: 1 }, { unique: true });
    await keysCollection.createIndex({ key: 1 }, { unique: true });
    await apiTokensCollection.createIndex({ token: 1 }, { unique: true });
    await referralsCollection.createIndex({ code: 1 }, { unique: true });
    
    console.log('Collections initialized with indexes');
  } catch (error) {
    console.error('Error initializing collections:', error);
  }
}

// Initialize default users if none exist
async function initDefaultUsers() {
  try {
    const count = await usersCollection.countDocuments();
    
    if (count === 0) {
      console.log('Creating default users...');
      
      const defaultUsers = [
        {
          id: 'owner1',
          userId: 'owner',
          password: 'owner123',
          name: 'Owner User',
          role: 'owner',
          balance: 1000,
          expiryDate: null,
          createdAt: new Date().toISOString()
        }
      ];
      
      await usersCollection.insertMany(defaultUsers);
      console.log('Default users created');
    }
  } catch (error) {
    console.error('Error initializing default users:', error);
  }
}

// User database operations
const userDB = {
  getUserByCredentials: async (userId, password) => {
    try {
      console.log(`Looking up user with credentials, userId: ${userId}`);
      
      // First find the user by userId only (don't check password yet)
      const user = await usersCollection.findOne({ userId });
      
      if (!user) {
        console.log(`No user found with userId: ${userId}`);
        return null;
      }
      
      console.log(`Found user: ${user.userId}, role: ${user.role}`);
      
      // Check if it's a default user with plaintext password (for backward compatibility)
      if (user.password === password) {
        console.log('Authenticated with plaintext password');
        return user;
      }
      
      // If password is hashed (bcrypt), we need to verify differently
      // Default users may have plaintext passwords, while new users have hashed passwords
      try {
        // If using bcrypt, the password would be hashed during registration
        const bcrypt = require('bcrypt');
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (passwordMatch) {
          console.log('Authenticated with hashed password');
          return user;
        }
      } catch (e) {
        console.error('Error comparing passwords:', e);
      }
      
      console.log('Password does not match');
      return null;
    } catch (error) {
      console.error(`Error in getUserByCredentials:`, error);
      return null;
    }
  },
  
  getUserById: async (id) => {
    try {
      let user = null;

      // First try to find by MongoDB _id
      if (ObjectId.isValid(id)) {
        user = await usersCollection.findOne({ _id: new ObjectId(id) });
      }

      // If not found and it's a string, try to find by userId or id field
      if (!user && typeof id === 'string') {
        user = await usersCollection.findOne({ 
          $or: [{ userId: id }, { id: id }]
        });
      }

      return user;
    } catch (error) {
      console.error('Error getting user by ID:', error);
      return null;
    }
  },
  
  findUserByUserId: async (userId) => {
    try {
      console.log(`Looking up user by userId: ${userId}`);
      return await usersCollection.findOne({ userId });
    } catch (error) {
      console.error(`Error in findUserByUserId for userId ${userId}:`, error);
      return null;
    }
  },
  
  getAllUsers: async () => {
    return await usersCollection.find({}).toArray();
  },
  
  createUser: async (userData) => {
    try {
      console.log(`Creating user with userId: ${userData.userId}`);
      const result = await usersCollection.insertOne(userData);
      
      if (result && result.acknowledged) {
        console.log(`User created successfully with ID: ${result.insertedId}`);
        return {
          success: true,
          message: 'User created successfully',
          userId: userData.userId,
          insertedId: result.insertedId
        };
      } else {
        console.log(`Failed to create user: ${userData.userId}`);
        return {
          success: false,
          message: 'Database operation failed to create user'
        };
      }
    } catch (error) {
      console.error(`Error creating user ${userData.userId}:`, error);
      return {
        success: false,
        message: error.message || 'Error during user creation'
      };
    }
  },
  
  updateUserBalance: async (userId, cost) => {
    // First check if this is an owner account
    const user = await usersCollection.findOne({ id: userId });
    if (user && user.role === 'owner') {
      console.log('Skipping balance update for owner account');
      return { acknowledged: true, matchedCount: 1, modifiedCount: 0 };
    }
    
    // Only update balance for non-owner accounts
    return await usersCollection.updateOne(
      { id: userId },
      { $inc: { balance: -cost } }
    );
  },
  
  updateAdminBalance: async (admin, amount) => {
    console.log('Updating admin balance in database.js', { admin, amount });
    
    // Ensure admin object exists
    if (!admin) {
      console.error('Admin object is null or undefined');
      throw new Error('Invalid admin object');
    }
    
    // Ensure amount is a number
    const numAmount = Number(amount);
    if (isNaN(numAmount)) {
      console.error('Invalid amount:', amount);
      throw new Error('Amount must be a valid number');
    }
    
    let updateSuccess = false;
    let errorMessages = [];
    
    // Method 1: Try updating by MongoDB _id if available
    if (admin._id) {
      try {
        console.log('Method 1: Updating by _id:', admin._id);
        let idToUse = admin._id;
        
        // If _id is a string but looks like an ObjectId, convert it
        if (typeof idToUse === 'string' && ObjectId.isValid(idToUse)) {
          idToUse = new ObjectId(idToUse);
          console.log('Converted string _id to ObjectId:', idToUse);
        }
        
        const result = await usersCollection.updateOne(
          { _id: idToUse },
          { $set: { balance: numAmount } }
        );
        
        console.log('Result of update by _id:', result);
        
        if (result && result.matchedCount > 0) {
          console.log('Successfully updated by _id');
          updateSuccess = true;
          return result;
        }
      } catch (error) {
        console.error('Error updating by _id:', error);
        errorMessages.push(`_id method failed: ${error.message}`);
      }
    }
    
    // Method 2: Try updating by regular id field
    if (!updateSuccess && admin.id) {
      try {
        console.log('Method 2: Updating by id:', admin.id);
        const result = await usersCollection.updateOne(
          { id: admin.id },
          { $set: { balance: numAmount } }
        );
        
        console.log('Result of update by id:', result);
        
        if (result && result.matchedCount > 0) {
          console.log('Successfully updated by id');
          updateSuccess = true;
          return result;
        }
      } catch (error) {
        console.error('Error updating by id:', error);
        errorMessages.push(`id method failed: ${error.message}`);
      }
    }
    
    // Method 3: Try updating by userId field
    if (!updateSuccess && admin.userId) {
      try {
        console.log('Method 3: Updating by userId:', admin.userId);
        const result = await usersCollection.updateOne(
          { userId: admin.userId },
          { $set: { balance: numAmount } }
        );
        
        console.log('Result of update by userId:', result);
        
        if (result && result.matchedCount > 0) {
          console.log('Successfully updated by userId');
          updateSuccess = true;
          return result;
        }
      } catch (error) {
        console.error('Error updating by userId:', error);
        errorMessages.push(`userId method failed: ${error.message}`);
      }
    }
    
    // Method 4: Try a more general query as last resort
    if (!updateSuccess) {
      try {
        // Create a query that matches any of the identifiers
        const query = {};
        if (admin._id && ObjectId.isValid(admin._id)) {
          query._id = new ObjectId(admin._id.toString());
        } else if (admin.id) {
          query.id = admin.id;
        } else if (admin.userId) {
          query.userId = admin.userId;
        } else {
          throw new Error('No valid identifier fields found');
        }
        
        console.log('Method 4: Last resort update with query:', query);
        
        // Dump the entire users collection to see what's available
        const allUsers = await usersCollection.find({}).toArray();
        console.log('Available users in collection:', allUsers.map(u => ({ 
          _id: u._id, 
          id: u.id, 
          userId: u.userId,
          role: u.role
        })));
        
        const result = await usersCollection.updateOne(
          query,
          { $set: { balance: numAmount } }
        );
        
        console.log('Result of last resort update:', result);
        
        if (result && result.matchedCount > 0) {
          console.log('Successfully updated with general query');
          updateSuccess = true;
          return result;
        }
      } catch (error) {
        console.error('Error with last resort update:', error);
        errorMessages.push(`General query method failed: ${error.message}`);
      }
    }
    
    // If we get here, all update methods failed
    const errorMessage = `All update methods failed: ${errorMessages.join('; ')}`;
    console.error(errorMessage);
    throw new Error(errorMessage);
  },
  
  updateAdminExpiry: async (admin, expiryDate) => {
    console.log(`updateAdminExpiry: Attempting to update admin expiry for:`, admin);
    
    if (!admin) {
      throw new Error('Admin object is required');
    }
    
    // Validate expiryDate
    const date = new Date(expiryDate);
    if (isNaN(date.getTime())) {
      throw new Error('Invalid expiry date format');
    }
    
    // Track success of methods
    const results = {
      method1: false,
      method2: false,
      method3: false,
      method4: false
    };
    
    try {
      // Method 1: Try to update by MongoDB _id
      if (admin._id) {
        console.log(`Method 1: Updating by MongoDB _id: ${admin._id}`);
        try {
          const result = await usersCollection.updateOne(
            { _id: admin._id },
            { $set: { expiryDate: expiryDate } }
          );
          
          if (result.modifiedCount > 0) {
            console.log(`Method 1: Successfully updated admin expiry by _id`);
            results.method1 = true;
            return { success: true, method: 'MongoDB _id' };
          }
        } catch (error) {
          console.error(`Method 1 failed:`, error);
        }
      }
      
      // Method 2: Try to update by regular id
      if (admin.id) {
        console.log(`Method 2: Updating by regular id: ${admin.id}`);
        try {
          const result = await usersCollection.updateOne(
            { id: admin.id },
            { $set: { expiryDate: expiryDate } }
          );
          
          if (result.modifiedCount > 0) {
            console.log(`Method 2: Successfully updated admin expiry by id`);
            results.method2 = true;
            return { success: true, method: 'regular id' };
          }
        } catch (error) {
          console.error(`Method 2 failed:`, error);
        }
      }
      
      // Method 3: Try to update by userId
      if (admin.userId) {
        console.log(`Method 3: Updating by userId: ${admin.userId}`);
        try {
          const result = await usersCollection.updateOne(
            { userId: admin.userId },
            { $set: { expiryDate: expiryDate } }
          );
          
          if (result.modifiedCount > 0) {
            console.log(`Method 3: Successfully updated admin expiry by userId`);
            results.method3 = true;
            return { success: true, method: 'userId' };
          }
        } catch (error) {
          console.error(`Method 3 failed:`, error);
        }
      }
      
      // Method 4: Last resort - try a more general query to match any of the identifiers
      console.log(`Method 4: Attempting general query with multiple identifiers`);
      try {
        const query = { $or: [] };
        
        if (admin._id) query.$or.push({ _id: admin._id });
        if (admin.id) query.$or.push({ id: admin.id });
        if (admin.userId) query.$or.push({ userId: admin.userId });
        
        if (query.$or.length > 0) {
          const result = await usersCollection.updateOne(
            query,
            { $set: { expiryDate: expiryDate } }
          );
          
          if (result.modifiedCount > 0) {
            console.log(`Method 4: Successfully updated admin expiry using general query`);
            results.method4 = true;
            return { success: true, method: 'general query' };
          }
        }
      } catch (error) {
        console.error(`Method 4 failed:`, error);
      }
      
      // If we get here, all methods failed
      console.error(`All update methods failed for admin:`, admin);
      throw new Error('All update methods failed');
    } catch (error) {
      console.error(`Error in updateAdminExpiry:`, error);
      throw error;
    }
  },
  
  deleteUser: async (id) => {
    try {
      console.log(`Deleting user with id: ${id}`);
      
      // Try to delete by regular id field first
      let result = await usersCollection.deleteOne({ id });
      
      // If no document was deleted and it's a valid ObjectId, try deleting by _id
      if (result.deletedCount === 0 && ObjectId.isValid(id)) {
        console.log(`No user found with id field ${id}, trying with _id (ObjectId)`);
        result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
      }
      
      console.log(`Delete result: ${result.deletedCount} document(s) deleted`);
      return result;
    } catch (error) {
      console.error(`Error in deleteUser for id ${id}:`, error);
      throw error;
    }
  },
  
  updateAdminStatus: async (adminId, isActive) => {
    try {
      console.log(`Updating admin status: adminId=${adminId}, isActive=${isActive}`);
      
      // Convert isActive to boolean
      const boolIsActive = Boolean(isActive);
      
      // Try to update by MongoDB _id if it's a valid ObjectId
      if (ObjectId.isValid(adminId)) {
        console.log('Updating by MongoDB _id');
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(adminId) },
          { $set: { isActive: boolIsActive } }
        );
        
        if (result.matchedCount > 0) {
          console.log('Admin status updated successfully by _id');
          return { success: true, method: '_id' };
        }
      }
      
      // Try to update by regular id field
      console.log('Updating by regular id field');
      const result = await usersCollection.updateOne(
        { id: adminId },
        { $set: { isActive: boolIsActive } }
      );
      
      if (result.matchedCount > 0) {
        console.log('Admin status updated successfully by id field');
        return { success: true, method: 'id' };
      }
      
      // If still not found, try by userId field as last resort
      console.log('Updating by userId field');
      const resultByUserId = await usersCollection.updateOne(
        { userId: adminId },
        { $set: { isActive: boolIsActive } }
      );
      
      if (resultByUserId.matchedCount > 0) {
        console.log('Admin status updated successfully by userId field');
        return { success: true, method: 'userId' };
      }
      
      console.log('Admin not found with any identifier method');
      return { success: false, message: 'Admin not found' };
    } catch (error) {
      console.error('Error updating admin status:', error);
      throw error;
    }
  },

  // Update user password
  async updateUserPassword(userId, newPassword) {
    try {
      if (ObjectId.isValid(userId)) {
        // Update by MongoDB _id
        await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { password: newPassword } }
        );
      } else {
        // Update by userId or id field
        await usersCollection.updateOne(
          { $or: [{ userId: userId }, { id: userId }] },
          { $set: { password: newPassword } }
        );
      }
      return true;
    } catch (error) {
      console.error('Error updating user password:', error);
      throw error;
    }
  }
};

// Keys database operations
const keysDB = {
  getAllKeys: async (includeBulkKeys = false) => {
    try {
      const keysCollection = db.collection('keys');
      
      // Only add the filter if we're not including bulk keys
      const query = includeBulkKeys ? {} : { bulkKeyId: { $exists: false } };
      
      return await keysCollection.find(query).sort({ createdAt: -1 }).toArray();
    } catch (error) {
      console.error('Error in getAllKeys:', error);
      return [];
    }
  },
  
  getKeysByUser: async (userId) => {
    try {
      console.log(`Looking up keys for user ID: ${userId}`);
      let query = {
        bulkKeyId: { $exists: false }
      };
      
      // Create an array of possible createdBy values
      const possibleCreatedByValues = [];
      
      // Add userId directly
      possibleCreatedByValues.push(userId);
      
      // If it looks like an ObjectId, try that too
      if (ObjectId.isValid(userId)) {
        possibleCreatedByValues.push(new ObjectId(userId));
      }
      
      // Add to query with $or condition for all possible admin identifiers
      query.$or = [
        ...possibleCreatedByValues.map(value => ({ createdBy: value })),
        ...possibleCreatedByValues.map(value => ({ 'generatedBy._id': value })),
        ...possibleCreatedByValues.map(value => ({ 'generatedBy.id': value })),
        ...possibleCreatedByValues.map(value => ({ 'generatedBy.userId': value }))
      ];
      
      console.log(`Query for getKeysByUser: ${JSON.stringify(query)}`);
      
      const keys = await keysCollection.find(query)
        .sort({ createdAt: -1 })
        .toArray();
        
      console.log(`Found ${keys.length} keys for user ${userId}`);
      return keys;
    } catch (error) {
      console.error(`Error in getKeysByUser for userId ${userId}:`, error);
      return [];
    }
  },
  
  getAllBulkKeys: async (folderId) => {
    return await keysCollection.find({ 
      bulkKeyId: folderId 
    })
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getKeyById: async (keyId) => {
    try {
      console.log(`Looking up key with id: ${keyId}`);
      
      // Try to find by regular id field first
      let key = await keysCollection.findOne({ id: keyId });
      
      // If not found, try to find by MongoDB _id (ObjectId)
      if (!key && ObjectId.isValid(keyId)) {
        console.log(`No key found with id field ${keyId}, trying with _id (ObjectId)`);
        key = await keysCollection.findOne({ _id: new ObjectId(keyId) });
      }
      
      return key;
    } catch (error) {
      console.error(`Error in getKeyById for id ${keyId}:`, error);
      return null;
    }
  },
  
  createKey: async (keyData) => {
    return await keysCollection.insertOne(keyData);
  },
  
  deleteKey: async (keyId) => {
    try {
      console.log(`Attempting to delete key with id: ${keyId}`);
      
      // Try to delete by regular id field first
      let result = await keysCollection.deleteOne({ id: keyId });
      console.log(`Delete by id field result: ${result.deletedCount} document(s) deleted`);
      
      // If no document was deleted and it's a valid ObjectId, try deleting by _id
      if (result.deletedCount === 0 && ObjectId.isValid(keyId)) {
        console.log(`No key found with id field ${keyId}, trying with _id (ObjectId)`);
        result = await keysCollection.deleteOne({ _id: new ObjectId(keyId) });
        console.log(`Delete by _id field result: ${result.deletedCount} document(s) deleted`);
      }
      
      return result;
    } catch (error) {
      console.error(`Error in deleteKey for keyId ${keyId}:`, error);
      throw error;
    }
  },
  
  resetKey: async (keyId) => {
    return await keysCollection.updateOne(
      { id: keyId },
      { $set: { usageCount: 0 } }
    );
  },
  
  incrementKeyUsage: async (keyId) => {
    try {
      console.log(`Incrementing usage count for key with ID: ${keyId}`);
      
      // Find the key to increment
      const keysCollection = db.collection('keys');
      
      // Try to update by id first
      let updateResult = await keysCollection.updateOne(
        { id: keyId }, 
        { $inc: { usageCount: 1 } }
      );
      
      if (updateResult.modifiedCount === 0) {
        // If no documents were modified, try by MongoDB _id
        if (ObjectId.isValid(keyId)) {
          updateResult = await keysCollection.updateOne(
            { _id: new ObjectId(keyId) }, 
            { $inc: { usageCount: 1 } }
          );
        }
      }
      
      console.log(`Key usage increment result: ${JSON.stringify(updateResult)}`);
      return updateResult;
    } catch (error) {
      console.error(`Error incrementing key usage count:`, error);
      throw error;
    }
  },

  // Add new function to track device IDs for keys
  addDeviceToKey: async (keyId, deviceId) => {
    try {
      console.log(`Adding device ${deviceId} to key with ID: ${keyId}`);
      
      const keysCollection = db.collection('keys');
      
      // Try to update by id first
      let updateResult = await keysCollection.updateOne(
        { id: keyId }, 
        { 
          $addToSet: { deviceIds: deviceId },  // Add to deviceIds array without duplicates
          $inc: { usageCount: 1 }              // Increment usage count
        }
      );
      
      if (updateResult.modifiedCount === 0) {
        // If no documents were modified, try by MongoDB _id
        if (ObjectId.isValid(keyId)) {
          updateResult = await keysCollection.updateOne(
            { _id: new ObjectId(keyId) }, 
            { 
              $addToSet: { deviceIds: deviceId },
              $inc: { usageCount: 1 }
            }
          );
        }
      }
      
      console.log(`Device registration result: ${JSON.stringify(updateResult)}`);
      return updateResult;
    } catch (error) {
      console.error(`Error adding device to key:`, error);
      throw error;
    }
  }
};

// API tokens database operations
const apiTokensDB = {
  getAllTokens: async () => {
    return await apiTokensCollection.find({})
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getTokensByUser: async (userId) => {
    return await apiTokensCollection.find({ userId })
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getTokenById: async (tokenId) => {
    return await apiTokensCollection.findOne({ id: tokenId });
  },
  
  createToken: async (tokenData) => {
    return await apiTokensCollection.insertOne(tokenData);
  },
  
  deleteToken: async (tokenId) => {
    return await apiTokensCollection.deleteOne({ id: tokenId });
  }
};

// Bulk keys database operations
const bulkKeysDB = {
  getAllBulkKeys: async () => {
    return await bulkKeysCollection.find({})
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getBulkKeysByUser: async (userId) => {
    return await bulkKeysCollection.find({ userId })
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getBulkKeyById: async (bulkKeyId) => {
    return await bulkKeysCollection.findOne({ id: bulkKeyId });
  },
  
  createBulkKey: async (bulkKeyData) => {
    return await bulkKeysCollection.insertOne(bulkKeyData);
  },
  
  deleteBulkKey: async (bulkKeyId) => {
    return await bulkKeysCollection.deleteOne({ id: bulkKeyId });
  }
};

// Referrals database operations
const referralsDB = {
  getAllReferrals: async () => {
    await ensureDbConnected();
    return await referralsCollection.find({})
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getReferralByCode: async (code) => {
    try {
      console.log(`Looking up referral code: ${code}`);
      await ensureDbConnected();
      const referral = await referralsCollection.findOne({ code });
      console.log('Referral lookup result:', referral ? JSON.stringify(referral) : 'not found');
      return referral;
    } catch (error) {
      console.error('Error getting referral by code:', error);
      return null;
    }
  },
  
  incrementReferralUsage: async (referralId) => {
    await ensureDbConnected();
    return await referralsCollection.updateOne(
      { id: referralId },
      { $inc: { usageCount: 1 } }
    );
  },
  
  updateReferralUsage: async (referralId) => {
    await ensureDbConnected();
    return await referralsCollection.updateOne(
      { id: referralId },
      { 
        $inc: { usageCount: 1 },
        $set: { lastUsed: new Date().toISOString() }
      }
    );
  },
  
  getReferralsByUser: async (userId) => {
    return await referralsCollection.find({ userId })
      .sort({ createdAt: -1 })
      .toArray();
  },
  
  getReferralById: async (referralId) => {
    await ensureDbConnected();
    return await referralsCollection.findOne({ id: referralId });
  },
  
  createReferral: async (referralData) => {
    try {
      await ensureDbConnected();
      const result = await referralsCollection.insertOne(referralData);
      console.log('Referral created:', result);
      return result;
    } catch (error) {
      console.error('Error creating referral:', error);
      throw error;
    }
  },
  
  markReferralAsUsed: async (code, usedBy) => {
    try {
      console.log(`Marking referral code ${code} as used by ${usedBy}`);
      await ensureDbConnected();
      const result = await referralsCollection.updateOne(
        { code },
        { 
          $set: { 
            used: true, 
            usedBy,
            usedAt: new Date().toISOString()
          },
          $inc: { usageCount: 1 }
        }
      );
      
      console.log('Mark referral as used result:', result);
      return {
        success: result.modifiedCount > 0,
        message: result.modifiedCount > 0 ? 'Referral marked as used' : 'Failed to update referral'
      };
    } catch (error) {
      console.error('Error marking referral as used:', error);
      return {
        success: false,
        message: error.message
      };
    }
  },
  
  deleteReferral: async (referralId) => {
    await ensureDbConnected();
    return await referralsCollection.deleteOne({ id: referralId });
  }
};

// Connect to MongoDB when module is loaded
connectToDatabase().catch(console.error);

// Close database connection when application exits
process.on('SIGINT', async () => {
  try {
    await client.close();
    console.log('MongoDB connection closed');
    process.exit(0);
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
    process.exit(1);
  }
});

// Export the database functions so they can be used by server.js
module.exports = {
  connectToDatabase,
  ensureDbConnected,
  userDB,
  keysDB,
  apiTokensDB,
  bulkKeysDB,
  referralsDB
}; 


