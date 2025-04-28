// @ts-ignore - Ignore missing type declarations
// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
// @ts-ignore
import { connectToDatabase } from '@/lib/mongodb';
// @ts-ignore
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

// Get dashboard stats
export async function GET() {
  try {
    const { db } = await connectToDatabase();
    
    // Get the logged-in user from the token
    const authToken = cookies().get('authToken')?.value;
    if (!authToken) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
    }
    
    const decoded = jwt.verify(authToken, process.env.JWT_SECRET || 'default_secret');
    if (!decoded || typeof decoded !== 'object') {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }
    
    // Check if the user exists
    const userCollection = db.collection('users');
    let userId;
    
    if (decoded.userId) {
      userId = decoded.userId;
    } else if (decoded._id) {
      userId = decoded._id;
    } else if (decoded.id) {
      userId = decoded.id;
    } else {
      return NextResponse.json({ error: 'Invalid user token' }, { status: 401 });
    }
    
    // Find the user
    const user = await userCollection.findOne({ 
      $or: [
        { userId: userId },
        { _id: new ObjectId(userId) }
      ]
    });
    
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    // Only owner can see full system stats
    if (user.role !== 'owner') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 403 });
    }
    
    // Get stats
    const keysCollection = db.collection('keys');
    const usersCollection = db.collection('users');
    
    // Count total users
    const totalUsers = await usersCollection.countDocuments();
    
    // Count total admins
    const totalAdmins = await usersCollection.countDocuments({ role: 'admin' });
    
    // Count active keys
    const totalActiveKeys = await keysCollection.countDocuments({ isActive: true });
    
    // Count total keys
    const totalKeys = await keysCollection.countDocuments();
    
    // Count usage this month (basic implementation)
    const now = new Date();
    const firstDayOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    
    const monthlyUsage = await keysCollection.countDocuments({
      lastUsed: { $gte: firstDayOfMonth }
    });
    
    return NextResponse.json({
      totalUsers,
      totalAdmins,
      totalActiveKeys,
      totalKeys,
      monthlyUsage
    });
    
  } catch (error) {
    console.error('Error getting dashboard stats:', error);
    return NextResponse.json({ error: 'Failed to get dashboard stats' }, { status: 500 });
  }
}
