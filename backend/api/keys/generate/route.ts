// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { verifyAuth } from '@/lib/auth';
import { ObjectId } from 'mongodb';
import { randomBytes } from 'crypto';

export async function POST(req: NextRequest) {
  console.log('Generate Key API: POST request received');
  
  try {
    // Verify authentication
    const authResult = await verifyAuth(req);
    
    if (!authResult.authorized) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const { db, client } = await connectToDatabase();
    console.log('Generate Key API: Connected to MongoDB');
    
    // Get user info
    const { userId, role } = authResult;
    console.log(`Generate Key API: User authenticated: ${userId} (${role})`);
    
    // Only owner and admin can generate keys
    if (role !== 'owner' && role !== 'admin') {
      return NextResponse.json({ error: 'Unauthorized. Only owner and admin can generate keys.' }, { status: 403 });
    }
    
    // Get user from database
    let user = null;
    if (role === 'admin') {
      try {
        // First try by ObjectId
        user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
        console.log(`Generate Key API: Found user by userId ${userId}: ${user ? 'Yes' : 'No'}`);
        
        // If not found and we have userIdField, try that instead
        if (!user && authResult.userIdField) {
          user = await db.collection('users').findOne({ userId: authResult.userIdField });
          console.log(`Generate Key API: Found user by userIdField ${authResult.userIdField}: ${user ? 'Yes' : 'No'}`);
        }
      } catch (error) {
        console.error(`Generate Key API: Error finding admin user:`, error);
      }
    } else if (role === 'owner') {
      user = await db.collection('users').findOne({ role: 'owner' });
      console.log(`Generate Key API: Found user by role 'owner': ${user ? 'Yes' : 'No'}`);
    }
    
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    // Parse request body
    const requestData = await req.json();
    
    const {
      app = 'BGMI',
      duration,
      devices,
      price = 0,
      totalCost = 0,
      customKey,
      bulk = false,
      numberOfKeys = 1,
      folderName,
      folderId,
      bulkKeyType = 'multi_device', // 'multi_device' or 'single_device'
    } = requestData;
    
    console.log(`Generate Key API: Request - duration: ${duration}, devices: ${devices}, customKey: ${customKey ? 'yes' : 'no'}`);
    console.log(`Generate Key API: Bulk generation: ${bulk ? 'yes' : 'no'}, numberOfKeys: ${numberOfKeys}`);
    console.log(`Generate Key API: Price: ${price}, Total Cost from request: ${totalCost}`);
    if (bulk) {
      console.log(`Generate Key API: Folder name: ${folderName}, Folder ID: ${folderId}`);
      console.log(`Generate Key API: Bulk key type: ${bulkKeyType}`);
    }
    
    // Validate request
    if (!duration) {
      return NextResponse.json({ error: 'Duration is required' }, { status: 400 });
    }
    
    if (!devices || devices < 1) {
      return NextResponse.json({ error: 'Number of devices must be at least 1' }, { status: 400 });
    }
    
    if (bulk && (!numberOfKeys || numberOfKeys < 1 || numberOfKeys > 50)) {
      return NextResponse.json({ error: 'For bulk generation, number of keys must be between 1 and 50' }, { status: 400 });
    }
    
    if (bulk && (!folderName || !folderId)) {
      return NextResponse.json({ error: 'Folder name and ID are required for bulk generation' }, { status: 400 });
    }
    
    // Check if the custom key already exists
    if (customKey) {
      // Validate custom key length (for both numeric and alphabetic keys)
      if (customKey.length < 6 || customKey.length > 12) {
        return NextResponse.json({ 
          error: 'Custom key must be between 6 and 12 characters (letters or numbers)' 
        }, { status: 400 });
      }
      
      // Ensure the key contains only alphanumeric characters
      if (!/^[a-zA-Z0-9]+$/.test(customKey)) {
        return NextResponse.json({ 
          error: 'Custom key must contain only letters and numbers' 
        }, { status: 400 });
      }
      
      const existingKey = await db.collection('keys').findOne({ key: customKey });
      if (existingKey) {
        return NextResponse.json({ error: 'Custom key already exists' }, { status: 400 });
      }
    }
    
    // Store the exact totalCost from request that will be used for deduction
    // This ensures we use exactly what was shown to the user
    const deductionAmount = Math.abs(Number(totalCost)) || 0;
    console.log(`Generate Key API: Amount to be deducted: ${deductionAmount}`);
    
    // For admin users, check if they have sufficient balance
    if (role === 'admin') {
      if (!user.balance || user.balance < deductionAmount) {
        const availableBalance = user.balance || 0;
        return NextResponse.json({ 
          error: `Insufficient balance. Required: ₹${deductionAmount}, Available: ₹${availableBalance}` 
        }, { status: 400 });
      }
    }
    
    // Calculate expiry date
    let expiryDate = new Date();
    const durationUnit = duration.match(/(\d+)(\w+)/);
    
    if (durationUnit) {
      const value = parseInt(durationUnit[1]);
      const unit = durationUnit[2].toLowerCase();
      
      if (unit === 'hour' || unit === 'hours') {
        expiryDate.setHours(expiryDate.getHours() + value);
      } else if (unit === 'day' || unit === 'days') {
        expiryDate.setDate(expiryDate.getDate() + value);
      }
    }
    
    console.log(`Generate Key API: Confirmed deduction amount: ${deductionAmount}, Expiry: ${expiryDate}`);
    
    try {
      // For admin users, update balance with exactly the amount shown to user
      if (role === 'admin') {
        const balanceBeforeUpdate = user.balance || 0;
        const updateResult = await db.collection('users').updateOne(
          { _id: new ObjectId(userId) },
          { $inc: { balance: -deductionAmount } }
        );
        
        if (updateResult.modifiedCount === 1) {
          console.log(`Generate Key API: Successfully deducted ₹${deductionAmount} from admin balance (previous: ₹${balanceBeforeUpdate})`);
          
          // Verify the new balance
          const updatedUser = await db.collection('users').findOne({ _id: new ObjectId(userId) });
          const newBalance = updatedUser?.balance || 0;
          console.log(`Generate Key API: Admin balance after deduction: ₹${newBalance} (expected: ₹${balanceBeforeUpdate - deductionAmount})`);
        } else {
          console.warn(`Generate Key API: Failed to update admin balance!`);
        }
      }
      
      if (bulk) {
        // Bulk generation
        const generatedKeys = [];
        
        // Get userId in consistent ObjectId format for storage
        let createdById;
        try {
          if (typeof userId === 'string') {
            createdById = new ObjectId(userId);
          } else {
            createdById = userId;
          }
          console.log(`Generate Key API: Using createdBy ID for bulk: ${createdById}`);
        } catch (error) {
          // If ObjectId conversion fails, use original value
          console.error(`Generate Key API: Error converting userId to ObjectId:`, error);
          createdById = userId;
        }
        
        // Create a standardized generatedBy object to ensure consistent lookup later
        const generatedBy = {
          _id: createdById,
          userId: user.userId || userId,
          name: user.name || user.userId,
          role: role
        };
        
        // Create folder entry first
        const folderData = {
          _id: new ObjectId(),
          folderId,
          folderName,
          bulkKeyType,
          createdAt: new Date(),
          maxDevices: devices,
          duration,
          totalKeys: numberOfKeys,
          activeKeys: numberOfKeys,
          expiredKeys: 0,
          createdBy: createdById,
          creatorName: user.name || user.userId,
          generatedBy: generatedBy, // Add the detailed user info
        };
        
        await db.collection('bulkKeyFolders').insertOne(folderData);
        
        // Generate and insert keys
        for (let i = 0; i < numberOfKeys; i++) {
          const keyValue = generateRandomKey();
          
          const keyData = {
            _id: new ObjectId(),
            key: keyValue,
            app,
            duration,
            maxDevices: bulkKeyType === 'single_device' ? 1 : devices, // Force 1 device for single_device type
            usedDevices: 0,
            devices: [],
            expiry: expiryDate,
            isBlocked: false,
            isExpired: false,
            createdAt: new Date(),
            createdBy: createdById,
            folderId, // Link to the bulk folder
            bulkKeyType,
            generatedBy: generatedBy, // Add the detailed user info
          };
          
          await db.collection('keys').insertOne(keyData);
          generatedKeys.push(keyValue);
        }
        
        console.log(`Generate Key API: Created ${numberOfKeys} bulk keys with createdBy: ${createdById}`);
        
        return NextResponse.json({ 
          success: true, 
          keys: generatedKeys,
          folderId,
          folderName 
        }, { status: 200 });
      } else {
        // Single key generation
        const keyValue = customKey || generateRandomKey();
        
        // Get userId in consistent ObjectId format for storage
        let createdById;
        try {
          if (typeof userId === 'string') {
            createdById = new ObjectId(userId);
          } else {
            createdById = userId;
          }
          console.log(`Generate Key API: Using createdBy ID: ${createdById}`);
        } catch (error) {
          // If ObjectId conversion fails, use original value
          console.error(`Generate Key API: Error converting userId to ObjectId:`, error);
          createdById = userId;
        }
        
        // Create a standardized generatedBy object to ensure consistent lookup later
        const generatedBy = {
          _id: createdById,
          userId: user.userId || userId,
          name: user.name || user.userId,
          role: role
        };
        
        const keyData = {
          _id: new ObjectId(),
          key: keyValue,
          app,
          duration,
          maxDevices: devices,
          usedDevices: 0,
          devices: [],
          expiry: expiryDate,
          isBlocked: false,
          isExpired: false,
          createdAt: new Date(),
          createdBy: createdById,
          generatedBy: generatedBy, // Add the detailed user info who generated the key
        };
        
        const result = await db.collection('keys').insertOne(keyData);
        console.log(`Generate Key API: Key created with ID: ${result.insertedId}, createdBy: ${createdById}, generatedBy: ${JSON.stringify(generatedBy)}`);
        
        return NextResponse.json({ success: true, key: keyValue }, { status: 200 });
      }
    } catch (error) {
      console.error('Generate Key API Error:', error);
      return NextResponse.json({ error: 'Failed to generate key' }, { status: 500 });
    }
  } catch (error) {
    console.error('Generate Key API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

// Helper function to generate a random key
function generateRandomKey(length = 16) {
  // For owner and admin accounts, enforce key length between 6 and 12 characters
  const minKeyLength = 6;
  const maxKeyLength = 12;
  
  // Generate key using crypto for better randomness
  // This will still generate a hex string that's twice the byte length,
  // so we divide the desired character length by 2 (rounded up)
  const bytesNeeded = Math.ceil(maxKeyLength / 2);
  const hexString = randomBytes(bytesNeeded).toString('hex').toUpperCase();
  
  // Ensure key is at least minKeyLength characters
  if (hexString.length < minKeyLength) {
    // In the unlikely case it's too short, pad it
    return hexString.padEnd(minKeyLength, '0');
  }
  
  // Trim to maxKeyLength if needed
  return hexString.substring(0, maxKeyLength);
}

