import { connectToDatabase } from './mongodb';
import { ObjectId } from 'mongodb';
import crypto from 'crypto';

// User Operations
export const UserOperations = {
  // Find user by ID
  findById: async (userId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('users').findOne({ _id: new ObjectId(userId) });
  },
  
  // Find user by user ID field
  findByUserId: async (userIdField: string) => {
    const { db } = await connectToDatabase();
    return db.collection('users').findOne({ userId: userIdField });
  },
  
  // Create a new user
  createUser: async (userData: any) => {
    const { db } = await connectToDatabase();
    return db.collection('users').insertOne(userData);
  },
  
  // Update user
  updateUser: async (userId: string, updateData: any) => {
    const { db } = await connectToDatabase();
    return db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateData }
    );
  },
  
  // Update user balance (increment/decrement)
  updateBalance: async (userId: string, amount: number) => {
    const { db } = await connectToDatabase();
    return db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $inc: { balance: amount } }
    );
  },
  
  // Delete user
  deleteUser: async (userId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('users').deleteOne({ _id: new ObjectId(userId) });
  },
  
  // Get paginated list of admins
  getAdmins: async (page: number, limit: number) => {
    const { db } = await connectToDatabase();
    const skip = (page - 1) * limit;
    
    const query = { role: 'admin' };
    const totalCount = await db.collection('users').countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);
    
    const admins = await db.collection('users')
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .project({
        userId: 1,
        name: 1,
        balance: 1,
        expiryDate: 1,
        createdAt: 1,
      })
      .toArray();
    
    return { admins, totalPages, currentPage: page };
  },
  
  // Get admin stats
  getAdminStats: async () => {
    const { db } = await connectToDatabase();
    
    const totalAdmins = await db.collection('users').countDocuments({ role: 'admin' });
    
    // Sum admin balances
    const balanceResult = await db.collection('users').aggregate([
      { $match: { role: 'admin' } },
      { $group: { _id: null, total: { $sum: '$balance' } } }
    ]).toArray();
    
    const totalBalance = balanceResult.length > 0 ? balanceResult[0].total : 0;
    
    return { totalAdmins, totalBalance };
  }
};

// Key Operations
export const KeyOperations = {
  // Find key by ID
  findById: async (keyId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('keys').findOne({ _id: new ObjectId(keyId) });
  },
  
  // Find key by key string
  findByKey: async (keyString: string) => {
    const { db } = await connectToDatabase();
    return db.collection('keys').findOne({ key: keyString });
  },
  
  // Create a new key
  createKey: async (keyData: any) => {
    const { db } = await connectToDatabase();
    return db.collection('keys').insertOne(keyData);
  },
  
  // Update key
  updateKey: async (keyId: string, updateData: any) => {
    const { db } = await connectToDatabase();
    return db.collection('keys').updateOne(
      { _id: new ObjectId(keyId) },
      { $set: updateData }
    );
  },
  
  // Reset key (set active)
  resetKey: async (keyId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('keys').updateOne(
      { _id: new ObjectId(keyId) },
      { $set: { isActive: true } }
    );
  },
  
  // Delete key
  deleteKey: async (keyId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('keys').deleteOne({ _id: new ObjectId(keyId) });
  },
  
  // Get paginated list of keys (with filter by user if needed)
  getKeys: async (page: number, limit: number, userId?: string) => {
    const { db } = await connectToDatabase();
    const skip = (page - 1) * limit;
    
    let query = {};
    if (userId) {
      query = { 'generatedBy._id': new ObjectId(userId) };
    }
    
    const totalCount = await db.collection('keys').countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);
    
    const keys = await db.collection('keys')
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();
    
    // Get active device count for each key
    const keysWithDeviceCounts = await Promise.all(keys.map(async (key) => {
      const activeDevices = await db.collection('deviceUsage').countDocuments({ 
        keyId: key._id.toString(),
        active: true
      });
      
      return {
        ...key,
        activeDeviceCount: activeDevices
      };
    }));
    
    return { keys: keysWithDeviceCounts, totalPages, currentPage: page };
  },
  
  // Get key stats
  getKeyStats: async (userId?: string) => {
    const { db } = await connectToDatabase();
    const now = new Date();
    
    let query = {};
    let activeQuery = { expiryDate: { $gt: now }, isActive: true };
    
    if (userId) {
      query = { 'generatedBy._id': new ObjectId(userId) };
      activeQuery = { ...activeQuery, 'generatedBy._id': new ObjectId(userId) };
    }
    
    const totalKeys = await db.collection('keys').countDocuments(query);
    const activeKeys = await db.collection('keys').countDocuments(activeQuery);
    
    return { totalKeys, activeKeys };
  },
  
  // Get active devices for a key
  getActiveDevices: async (keyId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('deviceUsage')
      .find({ keyId, active: true })
      .toArray();
  }
};

// Referral Code Operations
export const ReferralOperations = {
  // Find referral by code
  findByCode: async (code: string) => {
    const { db } = await connectToDatabase();
    return db.collection('referralCodes').findOne({ code });
  },
  
  // Create a new referral code
  createReferral: async (referralData: any) => {
    const { db } = await connectToDatabase();
    return db.collection('referralCodes').insertOne(referralData);
  },
  
  // Mark referral code as used
  useReferral: async (code: string, userId: string) => {
    const { db } = await connectToDatabase();
    return db.collection('referralCodes').updateOne(
      { code },
      { 
        $set: { 
          isUsed: true,
          usedBy: userId,
          usedAt: new Date()
        } 
      }
    );
  },
  
  // Get all referral codes
  getReferralCodes: async () => {
    const { db } = await connectToDatabase();
    return db.collection('referralCodes')
      .find()
      .sort({ createdAt: -1 })
      .toArray();
  }
};

// API Token Operations
export const APITokenOperations = {
  // Generate a new API token
  generateToken: async (userId: string, expiryDays: number = 30, name: string = 'iOS App Token') => {
    try {
      const { db } = await connectToDatabase();
      
      console.log('Connected to database, generating token for userId:', userId);
      
      // Generate a secure random token
      const token = crypto.randomBytes(32).toString('hex');
      
      // Set expiry date
      const expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + expiryDays);
      
      // Check if userId is valid ObjectId
      let userIdObj;
      try {
        userIdObj = new ObjectId(userId);
      } catch (err) {
        console.error('Invalid userId format:', userId);
        throw new Error('Invalid user ID format');
      }
      
      // Create token record
      const tokenData = {
        userId: userIdObj,
        token,
        name,
        expiryDate,
        createdAt: new Date(),
        lastUsed: null,
        isActive: true
      };
      
      console.log('Inserting token data into database');
      
      // Insert into database
      const result = await db.collection('apiTokens').insertOne(tokenData);
      
      console.log('Token inserted with _id:', result.insertedId);
      
      return {
        _id: result.insertedId,
        token,
        expiryDate,
        name
      };
    } catch (error) {
      console.error('Error in generateToken:', error);
      throw error;
    }
  },
  
  // Verify an API token
  verifyToken: async (token: string) => {
    const { db } = await connectToDatabase();
    
    // Find the token
    const tokenData = await db.collection('apiTokens').findOne({ 
      token, 
      isActive: true,
      expiryDate: { $gt: new Date() }
    });
    
    if (!tokenData) {
      return null;
    }
    
    // Update last used timestamp
    await db.collection('apiTokens').updateOne(
      { _id: tokenData._id },
      { $set: { lastUsed: new Date() } }
    );
    
    // Get the user associated with this token
    const user = await db.collection('users').findOne({
      _id: tokenData.userId
    });
    
    return user;
  },
  
  // Get all tokens for a user
  getUserTokens: async (userId: string) => {
    try {
      const { db } = await connectToDatabase();
      
      let userIdObj;
      try {
        userIdObj = new ObjectId(userId);
      } catch (err) {
        console.error('Invalid userId format in getUserTokens:', userId);
        return [];
      }
      
      return db.collection('apiTokens')
        .find({ userId: userIdObj })
        .sort({ createdAt: -1 })
        .toArray();
    } catch (error) {
      console.error('Error in getUserTokens:', error);
      return [];
    }
  },
  
  // Revoke a token
  revokeToken: async (tokenId: string, userId: string) => {
    try {
      const { db } = await connectToDatabase();
      
      let tokenIdObj, userIdObj;
      
      try {
        tokenIdObj = new ObjectId(tokenId);
        userIdObj = new ObjectId(userId);
      } catch (err) {
        console.error('Invalid ID format in revokeToken:', { tokenId, userId });
        throw new Error('Invalid ID format');
      }
      
      // Only allow users to revoke their own tokens
      return db.collection('apiTokens').updateOne(
        { 
          _id: tokenIdObj,
          userId: userIdObj
        },
        { $set: { isActive: false } }
      );
    } catch (error) {
      console.error('Error in revokeToken:', error);
      throw error;
    }
  }
}; 