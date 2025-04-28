// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/mongodb-connect';
import Key from '@/models/Key';
import User from '@/models/User';
import mongoose from 'mongoose';

export async function GET(req: NextRequest) {
  try {
    console.log('Seed Keys API: Request received');
    
    // Connect to database
    await connectDB();
    console.log('Seed Keys API: Connected to MongoDB');
    
    // Find the owner user
    const owner = await User.findOne({ role: 'owner' });
    
    if (!owner) {
      console.log('Seed Keys API: Owner user not found');
      return NextResponse.json(
        { message: 'Owner user not found' },
        { status: 404 }
      );
    }
    
    console.log(`Seed Keys API: Found owner with ID ${owner._id}`);
    
    // Create some sample keys
    const sampleKeys = [
      {
        key: 'ABCD-1234-EFGH-5678',
        isActive: true,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        createdBy: owner._id,
        maxDevices: 2,
        usageCount: 1
      },
      {
        key: 'IJKL-9012-MNOP-3456',
        isActive: true,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        createdBy: owner._id,
        maxDevices: 3,
        usageCount: 0
      },
      {
        key: 'QRST-7890-UVWX-1234',
        isActive: false,
        createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000), // 10 days ago
        expiresAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000), // 5 days ago
        createdBy: owner._id,
        maxDevices: 1,
        usageCount: 1
      }
    ];
    
    console.log('Seed Keys API: Creating sample keys');
    
    // Delete any existing keys first
    await Key.deleteMany({});
    console.log('Seed Keys API: Deleted existing keys');
    
    // Insert sample keys
    const result = await Key.insertMany(sampleKeys);
    console.log(`Seed Keys API: Created ${result.length} sample keys`);
    
    return NextResponse.json({
      message: `Successfully created ${result.length} sample keys`,
      keys: result
    });
  } catch (error) {
    console.error('Seed Keys API: Error:', error);
    return NextResponse.json(
      { message: 'Error seeding keys', error: error.message },
      { status: 500 }
    );
  }
} 
