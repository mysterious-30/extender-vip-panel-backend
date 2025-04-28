// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/mongodb-connect';
import Key from '@/models/Key';
import User from '@/models/User';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export async function POST(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    console.log(`Reset Key API: POST request received for key ID ${params.id}`);
    
    // Connect to database
    await connectDB();
    console.log('Reset Key API: Connected to MongoDB');
    
    // Direct auth check from cookie
    const cookieStore = req.cookies;
    const token = cookieStore.get('auth_token')?.value;
    
    if (!token) {
      console.log('Reset Key API: No auth token provided');
      return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
    }
    
    // Manually decode and verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as {
        userId: string;
        role: string;
        id?: string;
        _id?: string;
      };
      console.log('Reset Key API: Token decoded:', decoded);
    } catch (error) {
      console.error('Reset Key API: Token verification failed:', error);
      return NextResponse.json({ message: 'Invalid token' }, { status: 401 });
    }
    
    // Find user from token info
    let user;
    if (decoded.userId) {
      user = await User.findOne({ userId: decoded.userId });
      console.log(`Reset Key API: Found user by userId ${decoded.userId}:`, user ? 'Yes' : 'No');
    }
    
    if (!user && (decoded.id || decoded._id)) {
      user = await User.findById(decoded.id || decoded._id);
      console.log(`Reset Key API: Found user by id:`, user ? 'Yes' : 'No');
    }
    
    if (!user) {
      console.log('Reset Key API: No user found from token');
      return NextResponse.json({ message: 'User not found' }, { status: 404 });
    }
    
    console.log(`Reset Key API: Authenticated as ${user.userId} (${user.role})`);
    
    // Get the key ID from route params
    const { id } = params;
    
    // Only owner or admin can reset keys
    if (user.role !== 'owner' && user.role !== 'admin') {
      console.log(`Reset Key API: User ${user.userId} is not authorized to reset keys`);
      return NextResponse.json(
        { message: 'Unauthorized to reset keys' },
        { status: 403 }
      );
    }
    
    // Find the key
    const key = await Key.findById(id);
    
    if (!key) {
      console.log(`Reset Key API: Key with ID ${id} not found`);
      return NextResponse.json(
        { message: 'Key not found' },
        { status: 404 }
      );
    }
    
    // If user is an admin, they can only reset keys they created
    if (user.role === 'admin' && key.createdBy.toString() !== user._id.toString()) {
      console.log(`Reset Key API: Admin ${user.userId} cannot reset key created by someone else`);
      return NextResponse.json(
        { message: 'You can only reset keys you created' },
        { status: 403 }
      );
    }
    
    // Reset the key by clearing device ID and usage count
    key.deviceId = undefined;
    key.usageCount = 0;
    key.lastUsedAt = undefined;
    
    await key.save();
    console.log(`Reset Key API: Successfully reset key ${id}`);
    
    return NextResponse.json({
      message: 'Key reset successfully',
      data: {
        id: key._id,
        key: key.key,
        status: key.isActive ? 'active' : 'inactive'
      }
    });
    
  } catch (error) {
    console.error('Reset Key API: Error:', error);
    return NextResponse.json(
      { message: 'Error resetting key', error: error.message },
      { status: 500 }
    );
  }
} 