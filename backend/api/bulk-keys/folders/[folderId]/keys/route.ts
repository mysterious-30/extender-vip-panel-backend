// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { verifyAuth } from '@/lib/auth';
import { ObjectId } from 'mongodb';

export async function GET(
  req: NextRequest,
  { params }: { params: { folderId: string } }
) {
  try {
    // Get folder ID from params
    const { folderId } = params;
    
    if (!folderId) {
      return NextResponse.json({ error: 'Folder ID is required' }, { status: 400 });
    }
    
    // Verify authentication
    const authResult = await verifyAuth(req);
    
    if (!authResult.authorized) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const { db } = await connectToDatabase();
    
    // Get user info
    const { userId, role } = authResult;

    console.log(`Folder Keys API: Request for folder ${folderId} from ${userId} with role ${role}`);
    
    // Find the folder first to verify access
    const folder = await db.collection('bulkKeyFolders').findOne({ folderId });
    
    if (!folder) {
      return NextResponse.json({ error: 'Folder not found' }, { status: 404 });
    }

    console.log(`Folder Keys API: Found folder with createdBy: ${folder.createdBy}`);
    
    // Check if user has access to this folder
    if (role === 'admin') {
      let hasAccess = false;
      
      // Compare userId with folder.createdBy (handling ObjectId case)
      if (folder.createdBy instanceof ObjectId) {
        try {
          hasAccess = folder.createdBy.equals(new ObjectId(userId)) || folder.createdBy.toString() === userId;
        } catch (error) {
          console.error('Folder Keys API: Error comparing ObjectIds:', error);
        }
      } else if (typeof folder.createdBy === 'string') {
        hasAccess = folder.createdBy === userId;
      }
      
      if (!hasAccess) {
        console.log(`Folder Keys API: Access denied for admin ${userId} to folder created by ${folder.createdBy}`);
        return NextResponse.json({ error: 'You do not have access to this folder' }, { status: 403 });
      }
    }
    
    // Get keys for this folder
    const keys = await db.collection('keys')
      .find({ folderId })
      .sort({ createdAt: -1 }) // Most recent first
      .toArray();

    console.log(`Folder Keys API: Found ${keys.length} keys for folder ${folderId}`);
    
    // Update expiry status for all keys
    const now = new Date();
    const updatedKeys = keys.map(key => {
      const isExpired = new Date(key.expiry) < now;
      return {
        ...key,
        isExpired: isExpired || key.isExpired
      };
    });
    
    // Return keys
    return NextResponse.json({ success: true, keys: updatedKeys }, { status: 200 });
  } catch (error) {
    console.error('Folder Keys API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
} 