// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

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
          { success: false, message: 'Only owners and admins can update admin expiry' },
          { status: 403 }
        );
      }
      
      // Get request body
      const { adminId, expiryDate } = await request.json();
      
      if (!adminId || !expiryDate) {
        return NextResponse.json(
          { success: false, message: 'Admin ID and expiry date are required' },
          { status: 400 }
        );
      }
      
      // Validate expiry date
      const newExpiryDate = new Date(expiryDate);
      if (isNaN(newExpiryDate.getTime())) {
        return NextResponse.json(
          { success: false, message: 'Invalid expiry date format' },
          { status: 400 }
        );
      }
      
      // Find the admin
      const admin = await db.collection('users').findOne({
        _id: new ObjectId(adminId),
        role: 'admin',
      });
      
      if (!admin) {
        return NextResponse.json(
          { success: false, message: 'Admin not found' },
          { status: 404 }
        );
      }
      
      // Update admin's expiry date and set to active
      await db.collection('users').updateOne(
        { _id: new ObjectId(adminId) },
        { $set: { 
          expiryDate: newExpiryDate,
          isActive: true // Always set to active when expiry date is updated
        }}
      );
      
      // Log the update
      await db.collection('expiryUpdates').insertOne({
        adminId,
        previousExpiryDate: admin.expiryDate || null,
        newExpiryDate,
        performedBy: decoded.userId,
        performedAt: new Date(),
      });
      
      return NextResponse.json({
        success: true,
        message: 'Admin expiry date updated successfully',
        expiryDate: newExpiryDate,
      });
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Admin expiry update error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 
