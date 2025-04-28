// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { verify } from 'jsonwebtoken';
import { APITokenOperations } from '@/lib/db-utils';

// Helper function to verify token and check admin/owner role
async function verifyAndAuthorize(token: string) {
  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('JWT_SECRET environment variable is not set');
      return { authorized: false, userId: null, message: 'Server configuration error' };
    }

    const decoded = verify(token, jwtSecret) as any;
    console.log('Token verified successfully:', {
      userId: decoded.userId,
      role: decoded.role,
      userIdField: decoded.userIdField
    });
    
    const userId = decoded.userId;
    const role = decoded.role;

    // Only owners can manage API tokens (changed from admins or owners)
    if (role !== 'owner') {
      console.log('User lacks sufficient permissions:', role);
      return { authorized: false, userId: null, message: 'Unauthorized - Insufficient permissions' };
    }

    return { authorized: true, userId, role };
  } catch (error) {
    console.error('Error verifying token:', error);
    return { authorized: false, userId: null, message: 'Invalid authentication token' };
  }
}

// GET - List all API tokens for the authenticated user
export async function GET(request: Request) {
  console.log('API Tokens GET request received');
  
  try {
    // Try to get token from cookies first
    const cookieStore = cookies();
    const tokenFromCookie = cookieStore.get('auth_token')?.value;
    
    // Then check Authorization header
    const authHeader = request.headers.get('Authorization');
    let token = tokenFromCookie;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
      console.log('Using token from Authorization header');
    } else if (token) {
      console.log('Using token from cookies');
    }
    
    if (!token) {
      console.log('No authentication token found');
      return NextResponse.json({ success: false, message: 'Authentication required' }, { status: 401 });
    }

    // Verify and authorize the user
    const auth = await verifyAndAuthorize(token);
    if (!auth.authorized) {
      return NextResponse.json({ success: false, message: auth.message }, { status: 403 });
    }

    console.log('Fetching tokens for user:', auth.userId);
    // Get all tokens for the user
    const tokens = await APITokenOperations.getUserTokens(auth.userId);
    console.log(`Found ${tokens.length} tokens for user`);

    // Remove sensitive info from tokens before sending
    const sanitizedTokens = tokens.map(token => ({
      id: token._id.toString(),
      name: token.name,
      token: token.token.substring(0, 8) + '...' + token.token.substring(token.token.length - 8),
      createdAt: token.createdAt,
      lastUsed: token.lastUsed,
      expiryDate: token.expiryDate,
      isActive: token.isActive
    }));

    return NextResponse.json({ success: true, tokens: sanitizedTokens });
  } catch (error) {
    console.error('Error handling GET /api/api-tokens:', error);
    return NextResponse.json({ success: false, message: 'Internal server error' }, { status: 500 });
  }
}

// POST - Generate a new API token
export async function POST(request: Request) {
  console.log('API Tokens POST request received');
  
  try {
    // Try to get token from cookies first
    const cookieStore = cookies();
    const tokenFromCookie = cookieStore.get('auth_token')?.value;
    
    // Then check Authorization header
    const authHeader = request.headers.get('Authorization');
    let token = tokenFromCookie;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
      console.log('Using token from Authorization header');
    } else if (token) {
      console.log('Using token from cookies');
    }
    
    if (!token) {
      console.log('No authentication token found');
      return NextResponse.json({ success: false, message: 'Authentication required' }, { status: 401 });
    }

    console.log('Token found, verifying...');
    
    // Verify and authorize the user
    const auth = await verifyAndAuthorize(token);
    if (!auth.authorized) {
      console.log('User not authorized:', auth.message);
      return NextResponse.json({ success: false, message: auth.message }, { status: 403 });
    }

    // Get request body
    const body = await request.json();
    const { name, expiryDays = 30 } = body;

    console.log('Request body:', { name, expiryDays });

    if (!name) {
      return NextResponse.json({ success: false, message: 'Token name is required' }, { status: 400 });
    }

    // Check if user already has active tokens
    const existingTokens = await APITokenOperations.getUserTokens(auth.userId);
    const hasActiveTokens = existingTokens.some(token => token.isActive);
    
    if (hasActiveTokens) {
      console.log('User already has active tokens, denying new token creation');
      return NextResponse.json({ 
        success: false, 
        message: 'You already have an active API token. Please revoke it before generating a new one.' 
      }, { status: 400 });
    }

    // Generate token
    console.log('Generating token for user:', auth.userId);
    try {
      const tokenData = await APITokenOperations.generateToken(auth.userId, expiryDays, name);
      
      console.log('Token generated successfully with ID:', tokenData._id);
      
      return NextResponse.json({ 
        success: true, 
        message: 'API token generated successfully',
        token: {
          id: tokenData._id.toString(),
          token: tokenData.token,
          name: tokenData.name,
          expiryDate: tokenData.expiryDate
        }
      });
    } catch (generateError) {
      console.error('Error in generateToken operation:', generateError);
      return NextResponse.json({ 
        success: false, 
        message: `Error generating token: ${generateError.message}`,
        debugInfo: JSON.stringify(generateError)
      }, { status: 500 });
    }
  } catch (error) {
    console.error('Error handling POST /api/api-tokens:', error);
    return NextResponse.json({ 
      success: false, 
      message: 'Internal server error',
      error: error instanceof Error ? error.message : String(error)
    }, { status: 500 });
  }
} 
