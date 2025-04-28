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
          { success: false, message: 'Only owners and admins can update admin balance' },
          { status: 403 }
        );
      }
      
      // Get request body
      const { adminId, amount, action } = await request.json();
      
      if (!adminId || !amount || !action) {
        return NextResponse.json(
          { success: false, message: 'Admin ID, amount, and action are required' },
          { status: 400 }
        );
      }
      
      if (isNaN(amount) || amount <= 0) {
        return NextResponse.json(
          { success: false, message: 'Amount must be a positive number' },
          { status: 400 }
        );
      }
      
      if (action !== 'add' && action !== 'subtract') {
        return NextResponse.json(
          { success: false, message: 'Action must be either "add" or "subtract"' },
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
      
      // Calculate new balance
      let newBalance = admin.balance || 0;
      
      if (action === 'add') {
        newBalance += amount;
      } else {
        // Don't allow negative balance
        if (newBalance < amount) {
          return NextResponse.json(
            { success: false, message: 'Admin does not have enough balance' },
            { status: 400 }
          );
        }
        newBalance -= amount;
      }
      
      // Update admin's balance
      await db.collection('users').updateOne(
        { _id: new ObjectId(adminId) },
        { $set: { balance: newBalance } }
      );
      
      // Log the transaction
      await db.collection('balanceTransactions').insertOne({
        adminId,
        amount,
        action,
        previousBalance: admin.balance || 0,
        newBalance,
        performedBy: decoded.userId,
        performedAt: new Date(),
      });
      
      return NextResponse.json({
        success: true,
        message: `Balance ${action === 'add' ? 'added to' : 'subtracted from'} admin successfully`,
        newBalance,
      });
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Admin balance update error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 
