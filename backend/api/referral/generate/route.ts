// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { connectDB } from '@/lib/mongodb-connect'; // Add backup connection method
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';
import crypto from 'crypto';
import mongoose from 'mongoose';

// Helper function to generate a unique code
function generateUniqueCode(): string {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

export async function POST(request: Request) {
  try {
    // Authentication check
    const token = cookies().get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
    console.log('Referral Generate API: Processing request');
    
    try {
      // Verify the token
      const decoded = verify(token, JWT_SECRET) as {
        userId: string;
        role: string;
        username?: string;
        name?: string;
      };
      
      console.log('Referral Generate API: Token decoded', decoded);
      
      // Try to connect to MongoDB using both connection methods for reliability
      let db;
      try {
        const connection = await connectToDatabase();
        db = connection.db;
        console.log('Referral Generate API: Connected to MongoDB using primary connection');
      } catch (mongoError) {
        console.error('Referral Generate API: Primary connection failed, trying backup', mongoError);
        await connectDB();
        const backupDb = mongoose.connection.db;
        if (!backupDb) {
          throw new Error('Failed to connect to MongoDB using both methods');
        }
        db = backupDb;
        console.log('Referral Generate API: Connected to MongoDB using backup connection');
      }
      
      // Check if user is owner
      if (decoded.role !== 'owner') {
        console.log(`Referral Generate API: Permission denied for role ${decoded.role}`);
        return NextResponse.json(
          { success: false, message: 'Only owner can generate referral codes' },
          { status: 403 }
        );
      }
      
      // Get the request body
      const requestBody = await request.json();
      console.log('Referral Generate API: Request body', requestBody);
      
      const { expiryDate, initialBalance } = requestBody;
      
      if (!expiryDate) {
        return NextResponse.json(
          { success: false, message: 'Expiry date is required' },
          { status: 400 }
        );
      }
      
      if (!initialBalance || initialBalance <= 0) {
        return NextResponse.json(
          { success: false, message: 'Initial balance must be greater than 0' },
          { status: 400 }
        );
      }
      
      // Generate a unique code
      let code = generateUniqueCode();
      let isUnique = false;
      
      console.log('Referral Generate API: Generated initial code', code);
      
      // Make sure the code is unique
      while (!isUnique) {
        const existingCode = await db.collection('referralCodes').findOne({ code });
        if (!existingCode) {
          isUnique = true;
        } else {
          console.log('Referral Generate API: Code already exists, generating new one');
          code = generateUniqueCode();
        }
      }
      
      // Prepare document to insert
      const referralDocument = {
        code,
        initialBalance,
        expiryDate: new Date(expiryDate),
        createdBy: decoded.userId,
        createdAt: new Date(),
        isUsed: false,
        usedBy: null,
        usedAt: null,
      };
      
      console.log('Referral Generate API: Saving code to database', referralDocument);
      
      // Save the code to the database
      const result = await db.collection('referralCodes').insertOne(referralDocument);
      
      if (!result.acknowledged || !result.insertedId) {
        throw new Error('Failed to insert referral code into database');
      }
      
      console.log('Referral Generate API: Code saved successfully', result);
      
      // Return the generated code
      return NextResponse.json({
        success: true,
        code,
        _id: result.insertedId.toString(),
        message: 'Referral code generated successfully'
      });
    } catch (error) {
      console.error('Referral Generate API: Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Referral Generate API: Unexpected error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error', error: error.message },
      { status: 500 }
    );
  }
} 
