// @ts-ignore
// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
// @ts-ignore
import { connectDB } from "@/lib/mongodb-connect";
// @ts-ignore
import Key from "@/models/Key";
// @ts-ignore
import User from "@/models/User";
// @ts-ignore
import mongoose from "mongoose";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

export async function GET(req: NextRequest) {
  console.log("My Keys API request started");
  
  try {
    // Parse query parameters
    const { searchParams } = new URL(req.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '20');
    const skip = (page - 1) * limit;
    
    // Get token from cookies
    const token = req.cookies.get('auth_token')?.value;
    if (!token) {
      return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
    }
    
    // Verify token
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
    
    // Connect to DB
    await connectDB();
    
    // Find user
    const userId = decoded.userId;
    const isOwner = decoded.role === 'owner';
    const isAdmin = decoded.role === 'admin';
    // @ts-ignore - Ignore MongoDB model typing issues
    const user = await User.findOne({ userId }).lean();
    
    if (!user && !isOwner) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 });
    }
    
    // Create array of possible user identifiers
    const possibleCreatedByValues = [userId];
    
    // If user._id exists, add it to possible values
    if (user && user._id) {
      try {
        if (typeof user._id === 'string') {
          possibleCreatedByValues.push(new mongoose.Types.ObjectId(user._id));
          possibleCreatedByValues.push(user._id);
        } else {
          possibleCreatedByValues.push(user._id);
          possibleCreatedByValues.push(user._id.toString());
        }
      } catch (error) {
        // If conversion fails, just use the string
        possibleCreatedByValues.push(String(user._id));
      }
    }
    
    // Add user.userId if different from userId
    if (user && user.userId && user.userId !== userId) {
      possibleCreatedByValues.push(user.userId);
    }
    
    // Query to find keys created by this user
    const query = {
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
    
    console.log(`My Keys query: ${JSON.stringify(query)}`);
    
    // Get keys and count
    // @ts-ignore - Ignore MongoDB model typing issues
    const keys = await Key.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    // @ts-ignore - Ignore MongoDB model typing issues
    const totalCount = await Key.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit) || 1;
    
    console.log(`Found ${keys.length} keys for user ${userId}, total: ${totalCount}`);
    
    // Format keys with user info
    const formattedKeys = keys.map(key => {
      // Handle both deviceId and deviceIds for backward compatibility
      const deviceCount = key.deviceId 
        ? (Array.isArray(key.deviceId) ? key.deviceId.length : 1)
        : 0;
      
      return {
        ...key,
        devices: deviceCount,
        usedDevices: deviceCount,
        status: key.status || 'active',
        generatedBy: {
          _id: key.createdBy || (user ? user._id : null) || userId,
          userId: user ? user.userId : userId,
          role: user ? user.role : (isOwner ? 'owner' : (isAdmin ? 'admin' : 'user'))
        }
      };
    });
    
    // Return response
    return NextResponse.json({
      keys: formattedKeys,
      totalPages,
      currentPage: page,
      totalCount
    });
    
  } catch (error) {
    console.error('My Keys API error:', error);
    return NextResponse.json(
      { message: 'Internal server error', error: error.message },
      { status: 500 }
    );
  }
}

