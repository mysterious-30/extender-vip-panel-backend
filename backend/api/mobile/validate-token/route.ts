// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/mongodb';
import Key from '@/models/Key';
import { z } from 'zod';

// Define validation schema for the iOS token validation
const validateTokenSchema = z.object({
  token: z.string().min(1, 'API token is required'),
  deviceId: z.string().min(1, 'Device ID is required'),
  bundleId: z.string().min(1, 'Bundle ID is required')
});

export async function POST(req: NextRequest) {
  try {
    // Connect to database
    await connectDB();
    
    // Parse and validate request body
    const body = await req.json();
    const validationResult = validateTokenSchema.safeParse(body);
    
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
    
    const { token, deviceId, bundleId } = validationResult.data;
    
    // Verify the bundle ID matches our expected iOS app bundle ID
    const validBundleId = process.env.IOS_APP_BUNDLE_ID || 'com.extender.bgmi';
    if (bundleId !== validBundleId) {
      return NextResponse.json(
        { 
          success: false, 
          message: 'Invalid bundle ID'
        }, 
        { status: 400 }
      );
    }
    
    // Validate token (token is essentially the key)
    const key = await Key.findOne({ key: token, isActive: true });
    
    if (!key) {
      return NextResponse.json(
        { 
          success: false, 
          message: 'Invalid or inactive token'
        }, 
        { status: 401 }
      );
    }
    
    // Check if token is expired
    if (new Date() > new Date(key.expiresAt)) {
      return NextResponse.json(
        {
          success: false,
          message: 'Token has expired'
        },
        { status: 401 }
      );
    }
    
    // Check if the device is authorized to use this token
    const canUse = await key.canUseOnDevice(deviceId);
    if (!canUse) {
      return NextResponse.json(
        {
          success: false,
          message: 'This device is not authorized to use this token'
        },
        { status: 403 }
      );
    }
    
    // Update last used timestamp and assign to device if necessary
    await key.assignToDevice(deviceId);
    
    // Return success with additional data
    return NextResponse.json({
      success: true,
      message: 'Token validation successful',
      data: {
        expiryDate: key.expiresAt,
        timeRemaining: Math.max(0, new Date(key.expiresAt).getTime() - Date.now()) / 1000, // in seconds
        maxDevices: key.maxDevices,
        usageCount: key.usageCount
      }
    });
    
  } catch (error) {
    console.error('Error validating token:', error);
    return NextResponse.json(
      { 
        success: false, 
        message: 'An error occurred while validating the token'
      }, 
      { status: 500 }
    );
  }
} 
