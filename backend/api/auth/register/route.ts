// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { hash } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { ObjectId } from 'mongodb';

export async function POST(request: Request) {
  try {
    const { name, userId, password, referralCode } = await request.json();

    if (!userId || !password) {
      return NextResponse.json(
        { success: false, message: 'User ID and password are required' },
        { status: 400 }
      );
    }

    // Validate user ID
    if (userId.length < 3 || userId.length > 20) {
      return NextResponse.json(
        { success: false, message: 'User ID must be between 3 and 20 characters' },
        { status: 400 }
      );
    }

    // Validate password
    if (password.length < 6) {
      return NextResponse.json(
        { success: false, message: 'Password must be at least 6 characters' },
        { status: 400 }
      );
    }

    const { db } = await connectToDatabase();
    
    // Check if user ID is already taken
    const existingUser = await db.collection('users').findOne({ userId });
    if (existingUser) {
      return NextResponse.json(
        { success: false, message: 'User ID is already taken' },
        { status: 400 }
      );
    }

    // Hash the password
    const hashedPassword = await hash(password, 10);
    
    let role = 'user';
    let initialBalance = 0;
    let expiryDate = null;
    
    // If referral code is provided, validate it
    if (referralCode) {
      const code = await db.collection('referralCodes').findOne({ 
        code: referralCode,
        isUsed: false,
        expiryDate: { $gt: new Date() }
      });
      
      if (!code) {
        return NextResponse.json(
          { success: false, message: 'Invalid or expired referral code' },
          { status: 400 }
        );
      }
      
      // Check if code is already being used in another registration process
      // This prevents race conditions where multiple users try to use the same code simultaneously
      const codeBeingUsed = await db.collection('referralCodes').findOneAndUpdate(
        { _id: code._id, isUsed: false },
        { 
          $set: { 
            isUsed: true, 
            usedBy: userId, 
            usedAt: new Date() 
          } 
        },
        { returnDocument: 'after' }
      );
      
      if (!codeBeingUsed.value || codeBeingUsed.value.isUsed !== true) {
        return NextResponse.json(
          { success: false, message: 'This referral code has already been used. Please try another code.' },
          { status: 400 }
        );
      }
      
      // Set admin role and balance from the referral code
      role = 'admin';
      initialBalance = code.initialBalance || 0;
      expiryDate = code.expiryDate;
    }
    
    // Create new user
    const result = await db.collection('users').insertOne({
      userId,
      name: name || userId,
      password: hashedPassword,
      role,
      balance: initialBalance,
      expiryDate,
      createdAt: new Date(),
      lastLogin: new Date(),
      isBanned: false,
    });
    
    // Create JWT token
    const token = sign(
      {
        userId: result.insertedId.toString(),
        userIdField: userId,
        role,
      },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '7d' }
    );
    
    // Set HTTP-only cookie
    cookies().set({
      name: 'auth_token',
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 24 * 7, // 1 week
      path: '/',
    });
    
    return NextResponse.json({
      success: true,
      user: {
        id: result.insertedId.toString(),
        userId: userId,
        name: name || userId,
        role,
        balance: initialBalance,
        expiryDate,
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 
