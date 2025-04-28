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
          { success: false, message: 'Only owners and admins can remove admins' },
          { status: 403 }
        );
      }
      
      // Get request body
      const { adminId, action } = await request.json();
      
      if (!adminId || !action) {
        return NextResponse.json(
          { success: false, message: 'Admin ID and action are required' },
          { status: 400 }
        );
      }
      
      if (action !== 'ban' && action !== 'delete') {
        return NextResponse.json(
          { success: false, message: 'Action must be either "ban" or "delete"' },
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
      
      if (action === 'ban') {
        // Ban the admin
        await db.collection('users').updateOne(
          { _id: new ObjectId(adminId) },
          { $set: { isBanned: true } }
        );
        
        // Log the ban
        await db.collection('adminActions').insertOne({
          adminId,
          action: 'ban',
          performedBy: decoded.userId,
          performedAt: new Date(),
          reason: 'Banned by owner',
        });
        
        return NextResponse.json({
          success: true,
          message: 'Admin banned successfully',
        });
      } else {
        // Delete the admin
        await db.collection('users').deleteOne({
          _id: new ObjectId(adminId),
        });
        
        // Log the deletion
        await db.collection('adminActions').insertOne({
          adminId,
          action: 'delete',
          performedBy: decoded.userId,
          performedAt: new Date(),
          reason: 'Deleted by owner',
        });
        
        return NextResponse.json({
          success: true,
          message: 'Admin deleted successfully',
        });
      }
    } catch (error) {
      console.error('Token verification error:', error);
      return NextResponse.json(
        { success: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Admin removal error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 
