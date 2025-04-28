// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import Key from '@/models/Key';
import { connectToDatabase } from '@/lib/db';
import { withCache } from '@/lib/api-cache';

async function handleKeyList(req: NextRequest) {
  try {
    // Get user token
    const token = await getToken({ req });
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Connect to database
    await connectToDatabase();

    // Get query parameters
    const { searchParams } = new URL(req.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');
    const filter = searchParams.get('filter') || 'all';
    const search = searchParams.get('search') || '';

    // Build query
    const query: any = {};

    // Apply filters
    if (filter === 'active') {
      query.isActive = true;
    } else if (filter === 'inactive') {
      query.isActive = false;
    } else if (filter === 'expired') {
      query.expiresAt = { $lt: new Date() };
    } else if (filter === 'bulk') {
      query.isBulkKey = true;
    } else if (filter === 'single') {
      query.isBulkKey = false;
    }

    // Apply search
    if (search) {
      query.$or = [
        { key: { $regex: search, $options: 'i' } },
        { deviceId: { $regex: search, $options: 'i' } }
      ];
    }

    // Get total count
    const total = await Key.countDocuments(query);

    // Get keys with pagination
    const keys = await Key.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(); // Use lean() for better performance

    // Group bulk keys by bulkGroupId
    const bulkGroups = new Map();
    const singleKeys = [];

    for (const key of keys) {
      if (key.isBulkKey) {
        if (!bulkGroups.has(key.bulkGroupId)) {
          bulkGroups.set(key.bulkGroupId, {
            id: key.bulkGroupId,
            keys: [],
            totalKeys: 0,
            usedKeys: 0,
            createdAt: key.createdAt,
            expiresAt: key.expiresAt
          });
        }
        const group = bulkGroups.get(key.bulkGroupId);
        group.keys.push(key);
        group.totalKeys++;
        if (key.deviceId) group.usedKeys++;
      } else {
        singleKeys.push(key);
      }
    }

    return NextResponse.json({
      success: true,
      data: {
        singleKeys,
        bulkGroups: Array.from(bulkGroups.values()),
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    console.error('Error listing keys:', error);
    return NextResponse.json(
      { success: false, message: 'Failed to list keys' },
      { status: 500 }
    );
  }
}

export async function GET(req: NextRequest) {
  try {
    await connectToDatabase();
    
    // ... authentication and authorization checks ...
    
    // Check and update expired keys
    const now = new Date();
    await Key.updateMany(
      { 
        status: 'active',
        expiresAt: { $lt: now }
      },
      {
        $set: { status: 'expired' }
      }
    );
    
    // Apply caching with 20 second duration
    return withCache(req, handleKeyList, {
      duration: 20 * 1000, // 20 second cache
      cacheKeyBuilder: (req) => {
        const url = new URL(req.url);
        // Cache key includes all query parameters
        return `keys-list-${url.searchParams.toString()}`;
      }
    });
  } catch (error) {
    console.error('Error listing keys:', error);
    return NextResponse.json(
      { success: false, message: 'Failed to list keys' },
      { status: 500 }
    );
  }
} 
