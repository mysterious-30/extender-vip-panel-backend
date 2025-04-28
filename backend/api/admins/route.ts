// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

export async function GET(request: Request) {
  try {
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
        userIdField: string;
        role: string;
      };
      
      // Allow both owner and admin to access admin list
      if (decoded.role !== 'owner' && decoded.role !== 'admin') {
        return NextResponse.json(
          { success: false, message: 'Access denied. Owner or Admin privileges required.' },
          { status: 403 }
        );
      }
      
      const { db } = await connectToDatabase();
      
      // Get pagination parameters
      const { searchParams } = new URL(request.url);
      const page = parseInt(searchParams.get('page') || '1');
      const limit = 10; // Items per page
      const skip = (page - 1) * limit;
      
      // Get admins with role = 'admin'
      const query = { role: 'admin' };
      
      // Get total count for pagination
      const totalCount = await db.collection('users').countDocuments(query);
      const totalPages = Math.ceil(totalCount / limit);
      
      // Get admins with pagination
      const admins = await db.collection('users')
        .find(query)
        .sort({ createdAt: -1 }) // Newest first
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
      
      return NextResponse.json({
        success: true,
        admins,
        totalPages,
        currentPage: page,
      });
      
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Fetch admins error:', error);
    return NextResponse.json(
      { success: false, message: 'An error occurred while fetching admins' },
      { status: 500 }
    );
  }
} 
