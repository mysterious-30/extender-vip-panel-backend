// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
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
      
      // Check if user is owner
      if (decoded.role !== 'owner') {
        return NextResponse.json(
          { success: false, message: 'Only owner can view referral codes' },
          { status: 403 }
        );
      }
      
      // Fetch all referral codes
      const codes = await db
        .collection('referralCodes')
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      
      // Return the codes
      return NextResponse.json({
        success: true,
        codes,
      });
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Referral code listing error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 
