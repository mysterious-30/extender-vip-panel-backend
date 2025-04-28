// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/mongodb';
import Key from '@/models/Key';
import { z } from 'zod';

// Define validation schema for request
const verifyKeySchema = z.object({
  key: z.string().min(1, 'Key is required'),
  deviceId: z.string().min(1, 'Device ID is required'),
  appName: z.string().min(1, 'App name is required')
});

export async function POST(req: NextRequest) {
  try {
    // Connect to database
    await connectDB();
    
    // Parse and validate request body
    const body = await req.json();
    const validationResult = verifyKeySchema.safeParse(body);
    
    if (!validationResult.success) {
      return NextResponse.json(
        { 
          success: false, 
          message: 'Invalid request data',
          errors: validationResult.error.errors 
        }, 
        { status: 400 }
      );
    }
    
    const { key, deviceId, appName } = validationResult.data;
    
    // Validate that the appName is valid
    // IMPORTANT: This app name should match what's configured on your website
    if (appName.toUpperCase() !== 'BGMI') {
      return NextResponse.json(
        { 
          success: false, 
          message: 'Invalid application name' 
        }, 
        { status: 400 }
      );
    }
    
    // Find the key in the database
    // Important: We check that it's not only active but actually exists in our database
    const keyDoc = await Key.findOne({ key, isActive: true, status: 'active' });
    
    if (!keyDoc) {
      return NextResponse.json(
        { 
          success: false, 
          message: 'Invalid or inactive key' 
        }, 
        { status: 404 }
      );
    }
    
    // Check if key is expired
    if (new Date() > new Date(keyDoc.expiresAt)) {
      // Update the key status to expired in the database
      await Key.updateOne(
        { _id: keyDoc._id },
        { $set: { status: 'expired' } }
      );
      
      return NextResponse.json(
        { 
          success: false, 
          message: 'Key has expired' 
        }, 
        { status: 400 }
      );
    }
    
    // Verify key can be used on this device
    const canUse = await keyDoc.canUseOnDevice(deviceId);
    
    if (!canUse) {
      return NextResponse.json(
        { 
          success: false, 
          message: 'Key cannot be used on this device' 
        }, 
        { status: 400 }
      );
    }
    
    // Assign key to device if needed
    await keyDoc.assignToDevice(deviceId);
    
    // Return success response with key details
    return NextResponse.json({
      success: true,
      message: 'Key validation successful',
      data: {
        expiresAt: keyDoc.expiresAt,
        remainingDevices: keyDoc.maxDevices - keyDoc.usageCount,
        isFirstUse: keyDoc.usageCount === 1
      }
    });
    
  } catch (error) {
    console.error('Error verifying key:', error);
    return NextResponse.json(
      { 
        success: false, 
        message: 'An error occurred while verifying the key'
      }, 
      { status: 500 }
    );
  }
} 
