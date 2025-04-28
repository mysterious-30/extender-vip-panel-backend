// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { verify } from 'jsonwebtoken';
import { getSecurityHeaders, sanitizeInput } from '@/lib/security';
import { logSecurityEvent, SecurityEventType, LogLevel } from '@/lib/monitoring';
import { connectToDatabase } from '@/lib/mongodb';
import { ObjectId } from 'mongodb';
import { addCorsHeaders } from '../../_security';

export async function GET(request: Request) {
  console.log('Check session API called');
  
  try {
    // Get the auth_token cookie
    const cookieHeader = request.headers.get('cookie');
    if (!cookieHeader) {
      console.log('No cookies found in request');
      const response = NextResponse.json(
        { success: false, message: 'No cookies found' },
        { 
          status: 401,
          headers: getSecurityHeaders()
        }
      );
      return addCorsHeaders(response);
    }
    
    // Parse cookies manually
    const cookies = Object.fromEntries(
      cookieHeader.split(';').map(cookie => {
        const [name, ...rest] = cookie.trim().split('=');
        return [name, rest.join('=')];
      })
    );
    
    const token = cookies['auth_token'];
    
    if (!token) {
      console.log('No auth_token cookie found');
      const response = NextResponse.json(
        { success: false, message: 'Authentication required' },
        { 
          status: 401,
          headers: getSecurityHeaders()
        }
      );
      return addCorsHeaders(response);
    }
    
    // Verify JWT token
    const jwtSecret = process.env.JWT_SECRET || 'fallback-jwt-secret-for-development-only';
    
    const decoded = verify(token, jwtSecret) as {
      userId: string;
      userIdField?: string;  // Added to support registration token format
      name?: string;
      role: string;
      iat: number;
      exp: number;
    };
    
    console.log('Token decoded successfully:', decoded);
    
    // Connect to the database
    const { db } = await connectToDatabase();
    
    // Find the user in the database
    let user;
    const userId = sanitizeInput(decoded.userId);
    
    try {
      // First try to find by _id
      user = await db.collection('users').findOne({ 
        _id: new ObjectId(userId) 
      });
      
      // If not found and userIdField is available, try by userId field
      if (!user && decoded.userIdField) {
        user = await db.collection('users').findOne({ 
          userId: decoded.userIdField 
        });
      }
    } catch (error) {
      console.error('Error finding user:', error);
    }
    
    if (!user) {
      console.log('User not found in database:', userId);
      logSecurityEvent({
        eventType: SecurityEventType.TOKEN_INVALID,
        userId: userId,
        message: 'User not found in database during session check',
        level: LogLevel.WARN,
        metadata: { tokenUserId: userId }
      });
      
      const response = NextResponse.json(
        { success: false, message: 'Invalid session' },
        { 
          status: 401,
          headers: getSecurityHeaders()
        }
      );
      return addCorsHeaders(response);
    }
    
    console.log('Session valid for user:', user.userId);
    
    // Return user data in a NextAuth-compatible format
    const response = NextResponse.json({
      success: true,
      user: {
        id: user._id.toString(),
        userId: user.userId,
        name: user.name || user.userId,
        role: user.role,
        balance: user.balance || 0,
        expiryDate: user.expiryDate || null,
        email: `${user.userId}@example.com`, // Mock email for compatibility
        image: null
      }
    }, {
      headers: getSecurityHeaders()
    });
    
    return addCorsHeaders(response);
    
  } catch (error) {
    console.error('Session check error:', error);
    
    // Log the security event
    logSecurityEvent({
      eventType: SecurityEventType.ERROR,
      message: `Error during session verification: ${error instanceof Error ? error.message : 'Unknown error'}`,
      level: LogLevel.ERROR,
      path: '/api/auth/check-session'
    });
    
    const response = NextResponse.json(
      { success: false, message: 'Session verification failed' },
      { 
        status: 401,
        headers: getSecurityHeaders()
      }
    );
    return addCorsHeaders(response);
  }
}

// Handle OPTIONS requests for CORS preflight
export function OPTIONS() {
  const response = new NextResponse(null, { status: 204, headers: getSecurityHeaders() });
  return addCorsHeaders(response);
}
