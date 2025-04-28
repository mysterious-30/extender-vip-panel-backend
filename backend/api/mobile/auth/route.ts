// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { APITokenOperations } from '@/lib/db-utils';
import { sign } from 'jsonwebtoken';

// Set CORS headers for the preflight request
function setCorsHeaders(response: NextResponse) {
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}

// Handle OPTIONS requests for CORS preflight
export async function OPTIONS() {
  return setCorsHeaders(new NextResponse(null, { status: 204 }));
}

// Handle POST requests for mobile authentication
export async function POST(request: NextRequest) {
  console.log('Mobile Auth API: Processing authentication request');
  
  try {
    // Parse request body
    const body = await request.json();
    const { apiToken, deviceInfo, environment = 'production' } = body;

    if (!apiToken) {
      console.log('Mobile Auth API: Missing API token');
      return setCorsHeaders(
        NextResponse.json({ success: false, message: 'API token is required' }, { status: 400 })
      );
    }

    console.log(`Mobile Auth API: Authenticating with token for ${environment} environment`);
    
    // Verify the API token
    const user = await APITokenOperations.verifyToken(apiToken);
    
    if (!user) {
      console.log('Mobile Auth API: Invalid API token');
      return setCorsHeaders(
        NextResponse.json({ success: false, message: 'Invalid API token' }, { status: 401 })
      );
    }

    console.log(`Mobile Auth API: Validated token for user: ${user.userId}`);
    
    // Create a JWT for the mobile app
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('Mobile Auth API: JWT_SECRET environment variable is not set');
      return setCorsHeaders(
        NextResponse.json({ success: false, message: 'Server configuration error' }, { status: 500 })
      );
    }
    
    // Record device usage
    if (deviceInfo) {
      // Connect to the database
      const { db } = await connectToDatabase();
      
      // Store the device info
      await db.collection('mobileDevices').updateOne(
        { 
          userId: user._id.toString(),
          deviceInfo
        },
        { 
          $set: {
            lastSeen: new Date(),
            environment
          },
          $setOnInsert: {
            firstSeen: new Date()
          }
        },
        { upsert: true }
      );
      
      console.log(`Mobile Auth API: Recorded device info for user ${user._id}`);
    }
    
    // Sign JWT token - valid for 7 days
    const token = sign(
      {
        userId: user._id.toString(),
        userIdField: user.userId,
        role: user.role,
        type: 'mobile'
      },
      jwtSecret,
      { expiresIn: '7d' }
    );
    
    console.log('Mobile Auth API: Generated JWT token for mobile app');
    
    // Return success with the JWT token
    return setCorsHeaders(
      NextResponse.json({
        success: true,
        token,
        user: {
          id: user._id.toString(),
          userId: user.userId,
          role: user.role
        }
      })
    );
  } catch (error) {
    console.error('Mobile Auth API Error:', error);
    return setCorsHeaders(
      NextResponse.json(
        { success: false, message: 'Internal server error', error: String(error) },
        { status: 500 }
      )
    );
  }
} 
