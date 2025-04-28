// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectDB } from '@/lib/mongodb-connect';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';
import Key from '@/models/Key';

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    console.log(`Key deletion API: Processing request for key ID ${params.id}`);
    const token = cookies().get('auth_token')?.value;
    
    if (!token) {
      console.log('Key deletion API: No auth token provided');
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    const keyId = params.id;
    
    if (!keyId) {
      console.log('Key deletion API: No key ID provided');
      return NextResponse.json(
        { success: false, message: 'Key ID is required' },
        { status: 400 }
      );
    }
    
    try {
      // Connect to the database
      await connectDB();
      console.log('Key deletion API: Connected to database');
      
      // Verify the token
      const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
      const decoded = verify(token, JWT_SECRET) as {
        userId: string;
        name: string;
        role: string;
      };
      
      console.log(`Key deletion API: Token verified for user ${decoded.userId} with role ${decoded.role}`);
      
      // Find the key first to check ownership
      let key = null;
      let client = await connectDB();
      let db = client.db;
      
      try {
        // First try to find using Mongoose
        key = await Key.findById(keyId);
        
        // If not found, try direct MongoDB
        if (!key && db && db.collection) {
          const result = await db.collection('keys').findOne({
            _id: new ObjectId(keyId)
          });
          key = result;
        }
        
        if (!key) {
          console.log(`Key deletion API: Key ${keyId} not found`);
          return NextResponse.json(
            { success: false, message: 'Key not found' },
            { status: 404 }
          );
        }
        
        console.log(`Key deletion API: Found key ${keyId}, created by ${key.createdBy}`);
      } catch (error) {
        console.error('Key deletion API: Error finding key:', error);
        return NextResponse.json(
          { success: false, message: 'Error finding key' },
          { status: 500 }
        );
      }
      
      // Check permissions - owner can delete any key, admin can only delete their own keys
      let hasPermission = false;
      
      if (decoded.role === 'owner') {
        hasPermission = true;
      } else if (decoded.role === 'admin') {
        // Check if the key was created by this admin
        if (key.createdBy) {
          // Compare createdBy with userId, handling ObjectId case
          if (key.createdBy instanceof ObjectId) {
            try {
              hasPermission = key.createdBy.equals(new ObjectId(decoded.userId)) || 
                              key.createdBy.toString() === decoded.userId;
            } catch (error) {
              console.error('Key deletion API: Error comparing ObjectIds:', error);
            }
          } else if (typeof key.createdBy === 'string') {
            hasPermission = key.createdBy === decoded.userId;
          }
        }
      }
      
      if (!hasPermission) {
        console.log(`Key deletion API: User ${decoded.userId} with role ${decoded.role} is not allowed to delete key created by ${key.createdBy}`);
        return NextResponse.json(
          { success: false, message: 'You do not have permission to delete this key' },
          { status: 403 }
        );
      }
      
      // Delete the key
      let keyDeleted = false;
      
      try {
        console.log(`Key deletion API: Attempting to delete key ${keyId} using Mongoose`);
        const result = await Key.findByIdAndDelete(keyId);
        if (result) {
          console.log(`Key deletion API: Successfully deleted key ${keyId} using Mongoose`);
          keyDeleted = true;
        } else {
          console.log(`Key deletion API: Key ${keyId} not found using Mongoose`);
        }
      } catch (mongooseError) {
        console.error('Key deletion API: Mongoose deletion error:', mongooseError);
        // We'll fallback to direct MongoDB access below
      }
      
      // If not deleted yet, try direct MongoDB access
      if (!keyDeleted) {
        try {
          console.log(`Key deletion API: Attempting to delete key ${keyId} using direct MongoDB`);
          
          if (!db || !db.collection) {
            throw new Error('Database connection not available');
          }
          
          // Delete the key
          const result = await db.collection('keys').deleteOne({
            _id: new ObjectId(keyId)
          });
          
          if (result.deletedCount === 0) {
            console.log(`Key deletion API: Key ${keyId} not found in MongoDB`);
            return NextResponse.json(
              { success: false, message: 'Key not found' },
              { status: 404 }
            );
          }
          
          console.log(`Key deletion API: Successfully deleted key ${keyId} using direct MongoDB`);
          keyDeleted = true;
        } catch (mongoDbError) {
          console.error('Key deletion API: MongoDB deletion error:', mongoDbError);
          throw mongoDbError; // Re-throw to be caught by outer catch
        }
      }
      
      if (!keyDeleted) {
        return NextResponse.json(
          { success: false, message: 'Key not found' },
          { status: 404 }
        );
      }
      
      console.log(`Key deletion API: Successfully deleted key ${keyId}`);
      return NextResponse.json({
        success: true,
        message: 'Key deleted successfully'
      });
      
    } catch (error) {
      console.error('Key deletion API: Token verification or database error:', error);
      return NextResponse.json(
        { success: false, message: error.message || 'Invalid token or database error' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Key deletion API: Unhandled error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error', details: error.message },
      { status: 500 }
    );
  }
} 