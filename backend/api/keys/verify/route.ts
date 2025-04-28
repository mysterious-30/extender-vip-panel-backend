// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { createErrorHandler } from '@/lib/error-handler';
import { protectFromDDoS } from '@/lib/ddos-protection';
import { sanitizeInput } from '@/lib/security';
import { withCache } from '@/lib/api-cache';
import { z } from 'zod';

const verifyKeySchema = z.object({
  key: z.string().min(1),
  hwid: z.string().optional(),
  deviceInfo: z.record(z.unknown()).optional()
});

async function handler(request: Request) {
  // DDoS protection
  const ddosCheck = await protectFromDDoS(request as any);
  if (ddosCheck) return ddosCheck;

  const body = await request.json();
  
  // Validate input
  const result = verifyKeySchema.safeParse(body);
  if (!result.success) {
    return NextResponse.json(
      { success: false, message: 'Invalid input' },
      { status: 400 }
    );
  }

  const { key, hwid, deviceInfo } = result.data;
  
  const { db } = await connectToDatabase();
  
  // Find the key in the database - ensure it's not only properly formatted but actually exists
  // and is active in our database
  const keyData = await db.collection('keys').findOne({ 
    key: sanitizeInput(key),
    isActive: true,
    status: 'active'
  });
  
  if (!keyData) {
    return NextResponse.json(
      { success: false, message: 'Invalid key' },
      { status: 404 }
    );
  }
  
  // Check if key is banned
  if (keyData.isBanned) {
    return NextResponse.json(
      { success: false, message: 'This key has been banned' },
      { status: 403 }
    );
  }
  
  // Check if key is expired
  if (new Date() > new Date(keyData.expiresAt)) {
    // Update key status to expired
    await db.collection('keys').updateOne(
      { _id: keyData._id },
      { $set: { status: 'expired' } }
    );
    
    return NextResponse.json(
      { success: false, message: 'This key has expired' },
      { status: 400 }
    );
  }

  // Update key usage data
  await db.collection('keys').updateOne(
    { _id: keyData._id },
    {
      $set: {
        lastUsed: new Date(),
        lastHWID: hwid,
        lastDeviceInfo: deviceInfo
      },
      $inc: { useCount: 1 }
    }
  );

  return NextResponse.json({
    success: true,
    message: 'Key verified successfully',
    data: {
      keyId: keyData._id,
      createdAt: keyData.createdAt,
      expiresAt: keyData.expiresAt
    }
  });
}

export const POST = createErrorHandler(handler); 

