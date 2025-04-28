// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { Key } from '@/models/key';

export async function POST(req: NextRequest) {
  try {
    // Parse request body
    const { key, deviceId, deviceName } = await req.json();
    
    // Validate request
    if (!key) {
      return NextResponse.json({ error: 'Key is required' }, { status: 400 });
    }
    
    if (!deviceId) {
      return NextResponse.json({ error: 'Device ID is required' }, { status: 400 });
    }
    
    const { db } = await connectToDatabase();
    
    // Find the key
    const keyDoc = await Key.findOne({ key });
    
    if (!keyDoc) {
      return NextResponse.json({ error: 'Invalid key' }, { status: 400 });
    }
    
    // Check if key is expired
    if (new Date() > new Date(keyDoc.expiresAt)) {
      // Update the key status to expired
      await Key.updateOne(
        { _id: keyDoc._id },
        { $set: { status: 'expired' } }
      );
      
      return NextResponse.json(
        { 
          success: false, 
          message: 'This key has expired and cannot be activated' 
        }, 
        { status: 400 }
      );
    }
    
    // Check if key is blocked
    if (keyDoc.status === 'inactive' || keyDoc.status === 'expired') {
      return NextResponse.json({ error: 'Key has been blocked' }, { status: 400 });
    }
    
    // Check if device is already registered
    const deviceExists = keyDoc.devices && keyDoc.devices.some(device => device.id === deviceId);
    
    if (deviceExists) {
      // Device already registered, update last used time
      await db.collection('keys').updateOne(
        { _id: keyDoc._id, 'devices.id': deviceId },
        { 
          $set: { 
            'devices.$.lastUsed': new Date(),
            'devices.$.name': deviceName || 'Unknown Device'
          }
        }
      );
      
      return NextResponse.json({ 
        success: true, 
        message: 'Key activated successfully',
        expiry: keyDoc.expiry,
        maxDevices: keyDoc.maxDevices,
        usedDevices: keyDoc.usedDevices
      });
    }
    
    // Check if single-device key is already in use
    if (keyDoc.bulkKeyType === 'single_device' && keyDoc.usedDevices > 0) {
      return NextResponse.json({ 
        error: 'This key is restricted to use on one device only and has already been activated on another device.'
      }, { status: 400 });
    }
    
    // Check if max devices limit is reached
    if (keyDoc.usedDevices >= keyDoc.maxDevices) {
      return NextResponse.json({ 
        error: `Maximum device limit reached. This key can be used on ${keyDoc.maxDevices} device(s) only.`
      }, { status: 400 });
    }
    
    // Register new device
    const newDevice = {
      id: deviceId,
      name: deviceName || 'Unknown Device',
      lastUsed: new Date()
    };
    
    await db.collection('keys').updateOne(
      { _id: keyDoc._id },
      { 
        $push: { devices: newDevice },
        $inc: { usedDevices: 1 }
      }
    );
    
    return NextResponse.json({ 
      success: true, 
      message: 'Key activated successfully',
      expiry: keyDoc.expiry,
      maxDevices: keyDoc.maxDevices,
      usedDevices: keyDoc.usedDevices + 1, // Include the newly added device
      isSingleDevice: keyDoc.bulkKeyType === 'single_device'
    });
    
  } catch (error) {
    console.error('Key Activation API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
} 
