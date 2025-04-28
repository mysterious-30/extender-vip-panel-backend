// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const token = cookies().get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    const adminId = params.id;
    
    if (!adminId) {
      return NextResponse.json(
        { success: false, message: 'Admin ID is required' },
        { status: 400 }
      );
    }
    
    const { expiryDate } = await request.json();
    
    if (!expiryDate) {
      return NextResponse.json(
        { success: false, message: 'Expiry date is required' },
        { status: 400 }
      );
    }
    
    // Validate expiry date is a valid date
    const newExpiryDate = new Date(expiryDate);
    
    if (isNaN(newExpiryDate.getTime())) {
      return NextResponse.json(
        { success: false, message: 'Invalid expiry date format' },
        { status: 400 }
      );
    }
    
    try {
      // Verify the token
      const decoded = verify(token, process.env.JWT_SECRET || 'fallback_secret') as {
        userId: string;
        userIdField: string;
        role: string;
      };
      
      // Only owner can update admin expiry
      if (decoded.role !== 'owner') {
        return NextResponse.json(
          { success: false, message: 'Only owners can update admin expiry' },
          { status: 403 }
        );
      }
      
      const { db } = await connectToDatabase();
      
      // Get the admin
      const admin = await db.collection('users').findOne({
        _id: new ObjectId(adminId),
        role: 'admin'
      });
      
      if (!admin) {
        return NextResponse.json(
          { success: false, message: 'Admin not found' },
          { status: 404 }
        );
      }
      
      // Update the admin's expiry date and always set them to active
      await db.collection('users').updateOne(
        { _id: new ObjectId(adminId) },
        { $set: { 
          expiryDate: newExpiryDate,
          isActive: true // Always set to active when expiry date is updated
        }}
      );
      
      return NextResponse.json({
        success: true,
        message: 'Expiry date updated successfully'
      });
      
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Update admin expiry error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 