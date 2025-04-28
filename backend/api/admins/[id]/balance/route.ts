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
    
    const { amount } = await request.json();
    
    if (!amount || isNaN(amount) || amount <= 0) {
      return NextResponse.json(
        { success: false, message: 'Valid amount is required' },
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
      
      // Both owner and admin can update admin balance
      if (decoded.role !== 'owner' && decoded.role !== 'admin') {
        return NextResponse.json(
          { success: false, message: 'Only owners and admins can update admin balance' },
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
      
      // Update the admin's balance
      await db.collection('users').updateOne(
        { _id: new ObjectId(adminId) },
        { $inc: { balance: amount } }
      );
      
      return NextResponse.json({
        success: true,
        message: `Balance updated successfully, added ₹${amount}`
      });
      
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Update admin balance error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 