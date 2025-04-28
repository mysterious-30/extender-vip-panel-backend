// @ts-ignore - Ignore missing type declarations
import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import { verifyAuth } from '@/lib/auth';
import { ObjectId } from 'mongodb';

export async function DELETE(
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
    const { userId, role } = authResult;
    
    console.log(`Bulk Keys Folder Delete: Request for folder ${folderId} from ${userId} with role ${role}`);
    
    try {
      // Find the folder first to check ownership
      const folder = await db.collection('bulkKeyFolders').findOne({ folderId });
      
      if (!folder) {
        return NextResponse.json({ error: 'Folder not found' }, { status: 404 });
      }
      
      console.log(`Bulk Keys Folder Delete: Found folder with createdBy: ${folder.createdBy}`);
      
      // Check if user has permission to delete this folder
      if (role !== 'owner') {
        let hasPermission = false;
        
        // Compare userId with folder.createdBy (handling ObjectId case)
        if (folder.createdBy instanceof ObjectId) {
          try {
            hasPermission = folder.createdBy.equals(new ObjectId(userId)) || folder.createdBy.toString() === userId;
          } catch (error) {
            console.error('Bulk Keys Folder Delete: Error comparing ObjectIds:', error);
          }
        } else if (typeof folder.createdBy === 'string') {
          hasPermission = folder.createdBy === userId;
        }
        
        if (!hasPermission) {
          console.log(`Bulk Keys Folder Delete: Permission denied for ${userId} to delete folder created by ${folder.createdBy}`);
          return NextResponse.json({ 
            error: 'You do not have permission to delete this folder' 
          }, { status: 403 });
        }
      }
      
      // Delete the folder
      const folderResult = await db.collection('bulkKeyFolders').deleteOne({ folderId });
      
      // Delete all keys in the folder
      const keysResult = await db.collection('keys').deleteMany({ folderId });
      
      console.log(`Bulk Keys Folder Delete: Deleted folder ${folderId} and ${keysResult.deletedCount} keys`);
      
      return NextResponse.json({ 
        success: true, 
        message: 'Folder and all keys deleted successfully' 
      }, { status: 200 });
    } catch (error) {
      console.error('Bulk Keys Folder Delete API error:', error);
      return NextResponse.json({ error: 'Failed to delete folder' }, { status: 500 });
    }
  } catch (error) {
    console.error('Bulk Keys Folder Delete API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
} 