// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { sign } from 'jsonwebtoken';
import { connectToDatabase } from '@/lib/mongodb';
import { compare } from 'bcryptjs';
import { addCorsHeaders } from '../../_security';

export async function POST(request: Request) {
  try {
    const { userId, password } = await request.json();

    if (!userId || !password) {
      const response = NextResponse.json(
        { success: false, message: 'User ID and password are required' },
        { status: 400 }
      );
      return addCorsHeaders(response);
    }

    console.log('Login attempt for user:', userId);

    // Connect to the database
    const { db } = await connectToDatabase();
    
    // Find the user in the database
    const user = await db.collection('users').findOne({ userId });
    
    if (!user) {
      console.log('User not found:', userId);
      const response = NextResponse.json(
        { success: false, message: 'Invalid credentials' },
        { status: 401 }
      );
      return addCorsHeaders(response);
    }
    
    // Compare the provided password with the stored hash
    const isPasswordValid = await compare(password, user.password);
    
    if (!isPasswordValid) {
      console.log('Invalid password for user:', userId);
      const response = NextResponse.json(
        { success: false, message: 'Invalid credentials' },
        { status: 401 }
      );
      return addCorsHeaders(response);
    }
    
    // Create JWT token
    const jwtSecret = process.env.JWT_SECRET || 'fallback-jwt-secret-for-development-only';
    
    const token = sign(
      {
        userId: user._id,
        name: user.name || user.userId,
        role: user.role,
      },
      jwtSecret,
      { expiresIn: '7d' }
    );
    
    // Create response object
    const response = NextResponse.json({
      success: true,
      user: {
        id: user._id.toString(),
        userId: user.userId,
        name: user.name || user.userId,
        role: user.role,
        balance: user.balance || 0,
        expiryDate: user.expiryDate || null,
      }
    });
    
    // Set the cookie on the response
    response.cookies.set('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // Using 'lax' for better compatibility
      maxAge: 60 * 60 * 24 * 7, // 1 week
      path: '/',
    });
    
    console.log('Login successful for user:', userId, 'with role:', user.role);
    
    // Add CORS headers to response
    return addCorsHeaders(response);
  } catch (error) {
    console.error('Login error:', error);
    const response = NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
    return addCorsHeaders(response);
  }
}

// Handle OPTIONS requests for CORS preflight
export function OPTIONS() {
  const response = new NextResponse(null, { status: 204 });
  return addCorsHeaders(response);
}
