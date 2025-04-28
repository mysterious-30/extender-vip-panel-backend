// @ts-ignore - Ignore missing type declarations
// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
// @ts-ignore - Ignore missing type declarations
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

export async function GET(request: Request) {
  try {
    // Authentication check
    const token = cookies().get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    try {
      // Verify the token
      const decoded = verify(token, process.env.JWT_SECRET || 'fallback_secret') as {
        userId: string;
        username: string;
        role: string;
      };
      
      const { db } = await connectToDatabase();
      
      // Check if user is owner or admin
      if (decoded.role !== 'owner' && decoded.role !== 'admin') {
        return NextResponse.json(
          { success: false, message: 'Only owners and admins can view admin list' },
          { status: 403 }
        );
      }
      
      // Get query parameters
      const { searchParams } = new URL(request.url);
      const page = parseInt(searchParams.get('page') || '1', 10);
      const limit = parseInt(searchParams.get('limit') || '10', 10);
      const skip = (page - 1) * limit;
      
      // Fetch admin users with pagination
      const query = { role: 'admin' };
      const totalAdmins = await db.collection('users').countDocuments(query);
      const admins = await db
        .collection('users')
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .project({
          _id: 1,
          username: 1,
          role: 1,
          balance: 1,
          expiryDate: 1,
          createdAt: 1,
          lastLogin: 1,
          isBanned: 1,
          // Omit password and other sensitive fields
        })
        .toArray();
      
      // Return the admin list with pagination info
      return NextResponse.json({
        success: true,
        admins,
        pagination: {
          total: totalAdmins,
          page,
          limit,
          pages: Math.ceil(totalAdmins / limit),
        },
      });
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Admin listing error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 
