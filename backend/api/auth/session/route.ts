// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

export async function GET(request: Request) {
  try {
    // Get the token from cookies
    const token = cookies().get('auth_token')?.value;
    
    if (!token) {
      // Return a NextAuth compatible response for no session
      return NextResponse.json({
        user: null,
        expires: new Date(Date.now()).toISOString()
      });
    }
    
    try {
      // Verify the token
      const decoded = verify(token, process.env.JWT_SECRET || 'fallback_secret') as {
        userId: string;
        name: string;
        role: string;
      };
      
      const { db } = await connectToDatabase();
      
      // Get the user from database to check if they're still valid
      const user = await db.collection('users').findOne({
        _id: new ObjectId(decoded.userId)
      });
      
      if (!user) {
        cookies().delete('auth_token');
        // Return a NextAuth compatible response for invalid session
        return NextResponse.json({
          user: null,
          expires: new Date(Date.now()).toISOString()
        });
      }
      
      // Check if user is banned
      if (user.isBanned) {
        cookies().delete('auth_token');
        // Return a NextAuth compatible response for banned user
        return NextResponse.json({
          user: null,
          expires: new Date(Date.now()).toISOString()
        });
      }
      
      // Check expiry date for admins
      if (user.role === 'admin' && user.expiryDate) {
        const expiryDate = new Date(user.expiryDate);
        if (expiryDate < new Date()) {
          cookies().delete('auth_token');
          // Return a NextAuth compatible response for expired account
          return NextResponse.json({
            user: null,
            expires: new Date(Date.now()).toISOString()
          });
        }
      }
      
      // Calculate token expiry (7 days from now, matching login route)
      const expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + 7);
      
      // Return the user data in a NextAuth compatible format
      return NextResponse.json({
        user: {
          id: user._id.toString(),
          userId: user.userId,
          name: user.name || user.userId,
          role: user.role,
          balance: user.balance || 0,
          expiryDate: user.expiryDate || null,
        },
        expires: expiryDate.toISOString()
      });
    } catch (error) {
      console.error('Token verification error:', error);
      // Invalid token
      cookies().delete('auth_token');
      // Return a NextAuth compatible response for invalid token
      return NextResponse.json({
        user: null,
        expires: new Date(Date.now()).toISOString()
      });
    }
  } catch (error) {
    console.error('Session check error:', error);
    // Return a NextAuth compatible response for server error
    return NextResponse.json({
      user: null,
      expires: new Date(Date.now()).toISOString()
    });
  }
}
