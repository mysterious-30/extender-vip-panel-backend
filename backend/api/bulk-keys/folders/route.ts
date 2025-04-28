// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { verifyAuth } from '@/lib/auth';
import { ObjectId } from 'mongodb';

export async function GET(req: NextRequest) {
  try {
    // Verify authentication
    const authResult = await verifyAuth(req);
    
    if (!authResult.authorized) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const { db } = await connectToDatabase();
    
    // Get user info
    const { userId, role } = authResult;
    
    console.log(`Bulk Keys Folders API: Request from ${userId} with role ${role}`);
    
    // Determine which folders to retrieve based on user role
    let query = {};
    
    if (role === 'admin') {
      // Admins can only see their own folders
      // Need to handle both string IDs and ObjectIds
      try {
        // Create a query that matches both ObjectId and string formats
        query = {
          $or: [
            { createdBy: new ObjectId(userId) },
            { createdBy: userId }
          ]
        };
        console.log(`Bulk Keys Folders API: Using query: ${JSON.stringify(query)}`);
      } catch (error) {
        // If ObjectId conversion fails, just use the string ID
        console.error(`Bulk Keys Folders API: Error creating query:`, error);
        query = { createdBy: userId };
      }
    }
    // Owners can see all folders (empty query)
    
    console.log(`Bulk Keys Folders API: Final query: ${JSON.stringify(query)}`);
    
    // Get folders from database
    const folders = await db.collection('bulkKeyFolders')
      .find(query)
      .sort({ createdAt: -1 }) // Most recent first
      .toArray();
    
    console.log(`Bulk Keys Folders API: Found ${folders.length} folders`);
    
    // Return folders
    return NextResponse.json({ success: true, folders }, { status: 200 });
  } catch (error) {
    console.error('Bulk Keys Folders API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    // Verify authentication
    const authResult = await verifyAuth(req);
    
    if (!authResult.authorized) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const { db } = await connectToDatabase();
    
    // Parse request body to get folder ID
    const { folderId } = await req.json();
    
    if (!folderId) {
      return NextResponse.json({ error: 'Folder ID is required' }, { status: 400 });
    }
    
    // Get user role and ID
    const { userId, role } = authResult;
    
    try {
      // Find the folder first to check ownership
      const folder = await db.collection('bulkKeyFolders').findOne({ folderId });
      
      if (!folder) {
        return NextResponse.json({ error: 'Folder not found' }, { status: 404 });
      }
      
      // Check if user has permission to delete this folder
      if (role !== 'owner' && folder.createdBy !== userId) {
        return NextResponse.json({ 
          error: 'You do not have permission to delete this folder' 
        }, { status: 403 });
      }
      
      // Delete the folder
      const folderResult = await db.collection('bulkKeyFolders').deleteOne({ folderId });
      
      // Delete all keys in the folder
      await db.collection('keys').deleteMany({ folderId });
      
      return NextResponse.json({ 
        success: true, 
        message: 'Folder and all keys deleted successfully' 
      }, { status: 200 });
    } catch (error) {
      console.error('Bulk Keys Folders Delete API error:', error);
      return NextResponse.json({ error: 'Failed to delete folder' }, { status: 500 });
    }
  } catch (error) {
    console.error('Bulk Keys Folders Delete API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
} 
