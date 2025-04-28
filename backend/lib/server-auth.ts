import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';
import { connectDB } from './mongodb-connect';
import User from '@/models/User';
import mongoose from 'mongoose';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export interface Session {
  user: {
    id: string;
    userId: string;
    role: 'owner';
  };
}

export async function getServerSession(): Promise<Session | null> {
  try {
    console.log('getServerSession: Checking for auth_token cookie');
    
    // Get auth token from cookies
    const cookieStore = cookies();
    const token = cookieStore.get('auth_token')?.value;
    
    if (!token) {
      console.log('getServerSession: No auth_token cookie found');
      return null;
    }
    
    console.log('getServerSession: Auth token found, verifying...');
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET) as {
      userId: string;
      role: 'owner';
      id?: string;
      _id?: string;
      name?: string;
    };
    
    console.log('getServerSession: Token verified:', decoded);
    
    // Connect to database
    await connectDB();
    
    // The decoded token might contain either id or userId, so we need to handle both
    let userId: string | null = null;
    
    if (decoded.id) {
      userId = decoded.id;
    } else if (decoded._id) {
      userId = decoded._id;
    } else if (decoded.userId) {
      // Search by userId field
      console.log(`getServerSession: Searching for user with userId: ${decoded.userId}`);
      const user = await User.findOne({ userId: decoded.userId });
      
      if (user) {
        console.log(`getServerSession: User found by userId: ${user._id}`);
        userId = user._id.toString();
      }
    }
    
    if (!userId) {
      console.log('getServerSession: Could not determine user ID from token');
      return null;
    }
    
    console.log(`getServerSession: Looking up user with ID: ${userId}`);
    
    // Find user by ID - try to convert to ObjectId if string
    let userObjectId: mongoose.Types.ObjectId;
    try {
      userObjectId = new mongoose.Types.ObjectId(userId);
    } catch (e) {
      console.log('getServerSession: Invalid user ID format');
      return null;
    }
    
    const user = await User.findById(userObjectId);
    
    if (!user) {
      console.log(`getServerSession: User with ID ${userId} not found`);
      return null;
    }
    
    console.log(`getServerSession: Found user ${user.userId} with role ${user.role}`);
    
    // Return session
    return {
      user: {
        id: user._id.toString(),
        userId: user.userId,
        role: user.role
      }
    };
  } catch (error) {
    console.error('getServerSession error:', error);
    return null;
  }
} 
