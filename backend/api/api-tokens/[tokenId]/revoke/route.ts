// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { APITokenOperations } from '@/lib/db-utils';

// Helper function to verify token and check admin/owner role
async function verifyAndAuthorize(token: string) {
  try {
    const decoded = verify(token, process.env.JWT_SECRET || 'default_secret') as any;
    const userId = decoded.userId;
    const role = decoded.role;

    // Only owners can manage API tokens (changed from admins or owners)
    if (role !== 'owner') {
      return { authorized: false, userId: null, message: 'Unauthorized - Insufficient permissions' };
    }

    return { authorized: true, userId, role };
  } catch (error) {
    console.error('Error verifying token:', error);
    return { authorized: false, userId: null, message: 'Invalid authentication token' };
  }
}

export async function POST(
  request: Request,
  { params }: { params: { tokenId: string } }
) {
  try {
    // Try to get token from cookies first
    const cookieStore = cookies();
    const tokenFromCookie = cookieStore.get('auth_token')?.value;
    
    // Then check Authorization header
    const authHeader = request.headers.get('Authorization');
    let token = tokenFromCookie;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
    
    if (!token) {
      return NextResponse.json({ success: false, message: 'Authentication required' }, { status: 401 });
    }

    // Verify and authorize the user
    const auth = await verifyAndAuthorize(token);
    if (!auth.authorized) {
      return NextResponse.json({ success: false, message: auth.message }, { status: 403 });
    }

    // Get the token ID from the URL parameters
    const { tokenId } = params;

    if (!tokenId) {
      return NextResponse.json({ success: false, message: 'Token ID is required' }, { status: 400 });
    }

    try {
      // Revoke the token
      await APITokenOperations.revokeToken(tokenId, auth.userId);

      return NextResponse.json({ 
        success: true, 
        message: 'API token revoked successfully'
      });
    } catch (revokeError: any) {
      console.error('Error revoking API token:', revokeError);
      
      if (revokeError.message === 'Token not found') {
        return NextResponse.json({ success: false, message: 'Token not found' }, { status: 404 });
      }
      
      if (revokeError.message === 'Unauthorized to revoke this token') {
        return NextResponse.json({ success: false, message: 'You are not authorized to revoke this token' }, { status: 403 });
      }
      
      if (revokeError.message === 'Token is already revoked') {
        return NextResponse.json({ success: false, message: 'Token is already revoked' }, { status: 400 });
      }
      
      return NextResponse.json({ success: false, message: 'Error revoking API token' }, { status: 500 });
    }
  } catch (error) {
    console.error('Error handling POST /api/api-tokens/[tokenId]/revoke:', error);
    return NextResponse.json({ success: false, message: 'Internal server error' }, { status: 500 });
  }
} 