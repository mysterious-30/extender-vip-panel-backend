// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import Key from '@/models/Key';
import { connectToDatabase } from '@/lib/db';

export async function POST(req: NextRequest) {
  try {
    // Get user token
    const token = await getToken({ req });
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Only admins and owners can generate keys
    if (token.role !== 'admin' && token.role !== 'owner') {
      return NextResponse.json(
        { success: false, message: 'Permission denied' },
        { status: 403 }
      );
    }

    // Connect to database
    await connectToDatabase();

    // Get request body
    const { duration } = await req.json();

    if (!duration) {
      return NextResponse.json(
        { success: false, message: 'Duration is required' },
        { status: 400 }
      );
    }

    // Parse duration to get expiry date
    let durationDays;
    if (duration.includes('Day')) {
      durationDays = parseInt(duration.split(' ')[0]);
    } else if (duration.includes('Lifetime')) {
      durationDays = 365 * 10; // 10 years for "lifetime"
    } else {
      return NextResponse.json(
        { success: false, message: 'Invalid duration format' },
        { status: 400 }
      );
    }

    // Calculate expiry date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + durationDays);

    // Generate a unique key
    const keyString = await Key.generateUniqueKey();

    // Create the key
    const key = new Key({
      key: keyString,
      isActive: true,
      expiresAt,
      createdBy: token.id,
      maxDevices: 1,
      isBulkKey: false,
      usageCount: 0
    });

    await key.save();

    return NextResponse.json({
      success: true,
      message: 'Key generated successfully',
      data: {
        key: key.key,
        expiresAt: key.expiresAt
      }
    });
  } catch (error) {
    console.error('Error generating key:', error);
    return NextResponse.json(
      { success: false, message: 'Failed to generate key' },
      { status: 500 }
    );
  }
} 
