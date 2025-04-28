// @ts-ignore - Ignore missing type declarations
// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
// @ts-ignore
import { connectDB } from '@/lib/mongodb-connect';
// @ts-ignore
import Key from '@/models/Key';
// @ts-ignore
import User from '@/models/User';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';

const ITEMS_PER_PAGE = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Export API functions
export async function GET(req: NextRequest) {
  // Track time for debugging performance issues
  const requestStartTime = Date.now();
  // Initialize timeouts object with proper typing
  const timeouts: Record<string, number> = {};
  
  try {
    console.log("Keys API request started");
    
    // Parse query parameters
    const { searchParams } = new URL(req.url);
    const page = parseInt(searchParams.get('page') || '1');
    
    console.log(`Processing keys request for page ${page}`);
    
    // Direct auth check from cookie
    const cookieStore = req.cookies;
    const token = cookieStore.get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
    }
    
    timeouts.auth = Date.now() - requestStartTime;
    
    // Manually decode and verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as {
        userId: string;
        role: string;
        id?: string;
        _id?: string;
        name?: string;
        userIdField?: string;
      };
    } catch (error) {
      return NextResponse.json({ message: 'Invalid token' }, { status: 401 });
    }
    
    // Set a timeout to prevent hanging requests
    const apiTimeout = setTimeout(() => {
      console.error(`API TIMEOUT: Keys request exceeded 10 seconds for user ${decoded.userId}, role ${decoded.role}`);
    }, 10000);
    
    timeouts.decode = Date.now() - requestStartTime;
    // Connect to database
    try {
      await connectDB();
      timeouts.dbConnect = Date.now() - requestStartTime;
    } catch (dbError) {
      clearTimeout(apiTimeout);
      console.error('Database connection error:', dbError);
      return NextResponse.json({ 
        message: 'Database connection failed',
        error: dbError.message
      }, { status: 500 });
    }
    
    // Find user from token info
    let user;
    const userId = decoded.userId;
    const isOwner = decoded.role === 'owner';
    const isAdmin = decoded.role === 'admin';
    
    // If owner role, no need to query for the user
    if (!isOwner) {
      try {
        // First try as regular userId (most common case)
        // @ts-ignore - Ignore MongoDB model typing issues
        user = await User.findOne({ userId: decoded.userId }).lean();
        
        // If not found, try by ObjectId
        if (!user && decoded.userId) {
          try {
            const objectId = new mongoose.Types.ObjectId(decoded.userId);
            // @ts-ignore - Ignore MongoDB model typing issues
            user = await User.findById(objectId).lean();
          } catch (error) {
            // Not a valid ObjectId, which is ok
          }
        }
        
        // Last resort options
        if (!user) {
          if (decoded.name) {
            // @ts-ignore - Ignore MongoDB model typing issues
            user = await User.findOne({ userId: decoded.name }).lean();
          }
          
          if (!user && (decoded.id || decoded._id)) {
            const idToUse = decoded.id || decoded._id;
            try {
              // @ts-ignore - Ignore MongoDB model typing issues
              user = await User.findById(idToUse).lean();
            } catch (err) {
              // Not a valid ObjectId
            }
          }
        }
      } catch (error) {
        clearTimeout(apiTimeout);
        console.error('Error looking up user:', error);
        return NextResponse.json({ 
          message: 'Error looking up user',
          error: error.message
        }, { status: 500 });
      }
    } else {
      // For owner, just create a minimal user object
      user = { role: 'owner', userId: 'owner' };
    }
    
    timeouts.userLookup = Date.now() - requestStartTime;
    
    if (!user && !isOwner) {
      clearTimeout(apiTimeout);
      console.error(`User not found. Token data: ${JSON.stringify(decoded)}`);
      return NextResponse.json({ 
        message: 'User not found',
        details: 'Could not find user with the provided credentials'
      }, { status: 404 });
    }
    
    // Skip calculation
    const skip = (page - 1) * ITEMS_PER_PAGE;
    
    // Query conditions - default showing only user's own keys
    let query = {};
    
    // Create an array of possible createdBy values
    const possibleCreatedByValues = [];
    
    // Always add the userId string
    possibleCreatedByValues.push(userId);
    
    // If user._id exists, add both the ObjectId and string versions
    if (user._id) {
      try {
        // Try to convert to ObjectId if it's a string
        if (typeof user._id === 'string') {
          possibleCreatedByValues.push(new mongoose.Types.ObjectId(user._id));
        } else {
          possibleCreatedByValues.push(user._id);
        }
        possibleCreatedByValues.push(user._id.toString());
      } catch (error) {
        // If conversion fails, just use the string
        possibleCreatedByValues.push(String(user._id));
      }
    }
    
    // Add user.userId as well
    if (user.userId && user.userId !== userId) {
      possibleCreatedByValues.push(user.userId);
    }
    
    // Make sure we have at least one value
    if (possibleCreatedByValues.length === 0) {
      possibleCreatedByValues.push(userId);
    }
    
    try {
      // Different query based on user role
      if (isOwner) {
        // Owner sees all keys (no additional filters needed)
        query = { 
          $and: [
            { folderId: { $exists: false } },
            { $or: [
                { isBulkKey: { $exists: false } },
                { isBulkKey: false }
              ]
            }
          ]
        };
        console.log("Owner account: Using full key query");
      } else {
        // Both admin and regular users only see their own keys
        query = {
          $and: [
            { folderId: { $exists: false } },
            { $or: [
                { isBulkKey: { $exists: false } },
                { isBulkKey: false }
              ] 
            },
            { $or: possibleCreatedByValues.map(value => ({ createdBy: value })) }
          ]
        };
        console.log(`${isAdmin ? 'Admin' : 'Regular user'} account: Filtering keys to show only those created by user`);
      }
    } catch (error) {
      console.error('Error creating key query:', error);
      return NextResponse.json({ 
        message: 'Error creating key query',
        error: error.message
      }, { status: 500 });
    }
    
    // Find keys with pagination - use lean() for better performance
    let keys;
    let totalCount = 0; // Declare totalCount at a higher scope
    try {
      // Special handling for owner accounts only
      if (isOwner) {
        console.log('Owner account detected: Fetching all keys');
        
        // For owner users, limit the number of keys to prevent performance issues
        const ADMIN_MAX_KEYS = 100; // Maximum keys to process for admin to prevent timeouts
        
        // For owner users, filter out bulk keys (those with folderId)
        // Also exclude keys where isBulkKey is true
        // @ts-ignore - Ignore MongoDB model typing issues
        keys = await Key.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(ITEMS_PER_PAGE)
          .lean();
          
        console.log(`Found ${keys.length} keys for owner user`);
        
        // For owners, limit the total count to avoid expensive count queries
        if (isOwner) {
          // Use countDocuments with a limit to prevent full collection scans
          const countPipeline = [
            { $match: query },
            { $limit: ADMIN_MAX_KEYS },
            { $count: "total" }
          ];
          
          // Use aggregation for counting to improve performance
          // @ts-ignore - Ignore MongoDB model typing issues
          const countResult = await Key.aggregate(countPipeline);
          totalCount = countResult.length > 0 ? countResult[0].total : 0;
          
          // If we got the maximum, indicate there might be more
          if (totalCount >= ADMIN_MAX_KEYS) {
            console.log(`Owner view: Count limited to ${ADMIN_MAX_KEYS}`);
            totalCount = ADMIN_MAX_KEYS;
          }
        }
      } else {
        // For regular users and admins, get their own keys
        // @ts-ignore - Ignore MongoDB model typing issues
        keys = await Key.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(ITEMS_PER_PAGE)
          .lean();
          
        console.log(`Found ${keys.length} keys for ${isAdmin ? 'admin' : 'user'} ${user.userId || userId}`);
        
        // Get total count more efficiently for regular users
        try {
          const countPipeline = [
            { $match: query },
            { $count: "total" }
          ];
          
          // @ts-ignore - Ignore MongoDB model typing issues
          const countResult = await Key.aggregate(countPipeline);
          totalCount = countResult.length > 0 ? countResult[0].total : 0;
        } catch (countError) {
          console.error('Error getting key count:', countError);
          // Fallback to just showing the number of keys we retrieved
          totalCount = keys.length;
        }
      }
      
      // Calculate total pages
      const totalPages = Math.ceil(totalCount / ITEMS_PER_PAGE) || 1;
      
      // Format response - don't send all the internal data
      const formattedKeys = await Promise.all(keys.map(async key => {
        try {
          // Format the key for the response
          const formattedKey = {
            ...key,
            isExpired: key.expiresAt < new Date(),
            generatedBy: 'Unknown',
            generatedByRole: 'Unknown'
          };
          
          // Get creator info
          if (key.createdBy) {
            try {
              // Try to look up the creator 
              let creator = null;
              
              // Try with ObjectId
              try {
                if (typeof key.createdBy === 'string') {
                  // @ts-ignore - Ignore MongoDB model typing issues
                  creator = await User.findById(new mongoose.Types.ObjectId(key.createdBy)).lean();
                } else {
                  // @ts-ignore - Ignore MongoDB model typing issues
                  creator = await User.findById(key.createdBy).lean();
                }
              } catch (err) {
                // Not a valid ObjectId, try with userId
                // @ts-ignore - Ignore MongoDB model typing issues
                creator = await User.findOne({ userId: key.createdBy }).lean();
              }
              
              if (creator) {
                formattedKey.generatedBy = creator.name || creator.userId || 'Unknown';
                formattedKey.generatedByRole = creator.role || 'user';
              }
            } catch (error) {
              console.error('Error getting creator info:', error);
              // Use default values set above
            }
          }
          
          return formattedKey;
        } catch (keyError) {
          console.error('Error formatting key:', keyError);
          return key; // Return original key if formatting fails
        }
      }));
      
      clearTimeout(apiTimeout);
      
      // Return keys with pagination info
      const response = {
        keys: formattedKeys,
        pagination: {
          currentPage: page,
          totalPages,
          totalCount
        },
        timeouts
      };
      
      return NextResponse.json(response);
      
    } catch (error) {
      clearTimeout(apiTimeout);
      console.error('Error fetching keys:', error);
      return NextResponse.json({ 
        message: 'Error fetching keys',
        error: error.message
      }, { status: 500 });
    }
  } catch (outerError) {
    console.error('Unhandled error in keys API:', outerError);
    return NextResponse.json({ 
      message: 'Internal server error',
      error: outerError.message
    }, { status: 500 });
  }
}

// For deleting keys
export async function DELETE(req: NextRequest) {
  try {
    // Extract key ID from URL
    const url = new URL(req.url);
    const pathParts = url.pathname.split('/');
    const keyId = pathParts[pathParts.length - 1]; // Last path segment should be ID
    
    console.log(`Deleting key: ${keyId}`);
    
    // Direct auth check from cookie
    const cookieStore = req.cookies;
    const token = cookieStore.get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
    }
    
    // Manually decode and verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as {
        userId: string;
        role: string;
        id?: string;
        _id?: string;
      };
    } catch (error) {
      return NextResponse.json({ message: 'Invalid token' }, { status: 401 });
    }
    
    // Connect to database
    await connectDB();
    
    // Find user from token info
    let user;
    
    // Try to find the user by their userId (username)
    if (decoded.userId) {
      user = await User.findOne({ userId: decoded.userId }).lean();
    }
    
    // If still no user, check if we have an owner user (there should be one)
    if (!user && decoded.role === 'owner') {
      user = await User.findOne({ role: 'owner' }).lean();
    }
    
    // Last resort, try to find by ID if provided
    if (!user && (decoded.id || decoded._id)) {
      const idToUse = decoded.id || decoded._id;
      try {
        user = await User.findById(idToUse).lean();
      } catch (err) {
        // Continue to next check
      }
    }
    
    if (!user) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 });
    }
    
    // Find key
    try {
      var key = await Key.findById(keyId).lean();
    } catch (error) {
      console.error(`Error finding key ${keyId}:`, error);
      return NextResponse.json({
        message: `Error finding key: ${error.message}`
      }, { status: 500 });
    }
    
    if (!key) {
      return NextResponse.json({ message: 'Key not found' }, { status: 404 });
    }
    
    // Check if user has permission to delete this key
    const isOwner = user.role === 'owner';
    let hasPermission = isOwner;
    
    if (!isOwner && key.createdBy) {
      // Compare createdBy with user._id and userId, handling string and ObjectId formats
      const keyCreatedBy = String(key.createdBy);
      
      // Check against user._id if it exists
      if (user._id) {
        const userId = String(user._id);
        hasPermission = keyCreatedBy === userId;
      }
      
      // Also check against user.userId
      if (!hasPermission && user.userId) {
        hasPermission = keyCreatedBy === user.userId;
      }
      
      // Finally check against decoded.userId
      if (!hasPermission) {
        hasPermission = keyCreatedBy === decoded.userId;
      }
    }
    
    if (!hasPermission) {
      console.log(`Permission denied: User ${decoded.userId} (role: ${decoded.role}) tried to delete key created by ${key.createdBy}`);
      return NextResponse.json(
        { message: 'You do not have permission to delete this key' },
        { status: 403 }
      );
    }
    
    // Delete key
    try {
      await Key.findByIdAndDelete(keyId);
      console.log(`Successfully deleted key ${keyId}`);
    } catch (error) {
      console.error(`Error deleting key ${keyId}:`, error);
      return NextResponse.json({
        message: `Error deleting key: ${error.message}`
      }, { status: 500 });
    }
    
    return NextResponse.json({ success: true, message: 'Key deleted successfully' });
  } catch (error) {
    console.error('Key deletion error:', error);
    return NextResponse.json(
      { message: 'Internal server error', error: error.message },
      { status: 500 }
    );
  }
}


