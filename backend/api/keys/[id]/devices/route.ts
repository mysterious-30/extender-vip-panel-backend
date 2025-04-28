// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { connectToDatabase } from '@/lib/mongodb';
import { ObjectId } from 'mongodb';

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // Check for Authorization header first (for mobile app)
    const authHeader = request.headers.get('Authorization');
    let decoded;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      try {
        // Verify the token
        decoded = verify(token, process.env.JWT_SECRET || 'default_secret') as {
          userId: string;
          userIdField: string;
          role: string;
          isApiAuthenticated?: boolean;
        };
      } catch (error) {
        return NextResponse.json(
          { success: false, message: 'Invalid token' },
          { status: 401 }
        );
      }
    } else {
      // Fall back to checking cookie (for web app)
      const token = cookies().get('auth_token')?.value;
      
      if (!token) {
        return NextResponse.json(
          { success: false, message: 'Unauthorized' },
          { status: 401 }
        );
      }
      
      try {
        // Verify the token
        decoded = verify(token, process.env.JWT_SECRET || 'default_secret') as {
          userId: string;
          userIdField: string;
          role: string;
        };
      } catch (error) {
        return NextResponse.json(
          { success: false, message: 'Invalid token' },
          { status: 401 }
        );
      }
    }
    
    const keyId = params.id;
    
    if (!keyId) {
      return NextResponse.json(
        { success: false, message: 'Key ID is required' },
        { status: 400 }
      );
    }
    
    // Connect to the database
    const { db } = await connectToDatabase();
    
    // Find the key and verify ownership or admin privileges
    const keysCollection = db.collection('keys');
    const key = await keysCollection.findOne({ 
      _id: new ObjectId(keyId)
    });
    
    if (!key) {
      return NextResponse.json(
        { success: false, message: 'Key not found' },
        { status: 404 }
      );
    }
    
    // Check if user is authorized to view this key's devices
    if (decoded.userIdField !== key.userIdField && decoded.role !== 'admin' && decoded.role !== 'owner') {
      return NextResponse.json(
        { success: false, message: 'Unauthorized to view this key\'s devices' },
        { status: 403 }
      );
    }
    
    // Find all devices for this key
    const devicesCollection = db.collection('devices');
    const devices = await devicesCollection.find({ keyId: keyId }).toArray();
    
    return NextResponse.json({
      success: true,
      devices: devices.map(device => ({
        id: device._id.toString(),
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        lastActive: device.lastActive,
        firstSeen: device.firstSeen,
        status: device.status || 'active'
      }))
    });
    
  } catch (error) {
    console.error('Error fetching devices:', error);
    return NextResponse.json(
      { success: false, message: 'An error occurred while fetching devices' },
      { status: 500 }
    );
  }
} 