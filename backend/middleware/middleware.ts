import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// List of protected API paths
const protectedPaths = [
  '/api/dashboard',
  '/api/keys',
  '/api/users',
  '/api/referralCodes',
  '/api/api-tokens',
];

// List of public paths that should skip authentication
const publicPaths = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/check-session',
  '/api/test-cookie',
];

// Set runtime to nodejs (instead of edge)
export const runtime = 'nodejs';

// Get the frontend URL from environment variable or use default
const getFrontendUrl = () => {
  return process.env.FRONTEND_URL || 'http://localhost:3000';
};

export function middleware(request: NextRequest) {
  // Handle CORS preflight requests
  if (request.method === 'OPTIONS') {
    const response = NextResponse.next();
    
    // Use exact frontend URL (not wildcard) for credentials to work
    response.headers.set('Access-Control-Allow-Origin', getFrontendUrl());
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.set('Access-Control-Max-Age', '86400'); // 24 hours
    return response;
  }

  // Log the request for debugging
  console.log(`Middleware: Handling request to ${request.nextUrl.pathname}`);
  
  // Skip authentication for public paths
  if (publicPaths.some(path => request.nextUrl.pathname.startsWith(path))) {
    console.log('Middleware: Skipping auth check for public path');
    const response = NextResponse.next();
    
    // Add CORS headers to public paths
    response.headers.set('Access-Control-Allow-Origin', getFrontendUrl());
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    return response;
  }
  
  // Check if the path is protected
  const isProtectedPath = protectedPaths.some(path => 
    request.nextUrl.pathname.startsWith(path)
  );

  if (!isProtectedPath) {
    // Not a protected path, just proceed
    console.log('Middleware: Not a protected path, proceeding');
    const response = NextResponse.next();
    
    // Add CORS headers
    response.headers.set('Access-Control-Allow-Origin', getFrontendUrl());
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    return response;
  }

  // For protected paths, check for Authorization header or auth_token cookie
  const authHeader = request.headers.get('Authorization');
  const authCookie = request.cookies.get('auth_token');

  if (!authHeader && !authCookie) {
    // No authentication provided
    console.log('No authentication provided for protected path:', request.nextUrl.pathname);
    const response = NextResponse.json(
      { success: false, message: 'Authentication required' },
      { status: 401 }
    );
    
    // Add CORS headers to error responses
    response.headers.set('Access-Control-Allow-Origin', getFrontendUrl());
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    return response;
  }

  // Log authentication method for debugging
  if (authHeader) {
    console.log('Authentication provided via Authorization header');
  } else if (authCookie) {
    console.log('Authentication provided via auth_token cookie');
  }

  // Forward the request with the auth information
  // Let the API route handle actual token verification
  const response = NextResponse.next();
  
  // Add CORS headers
  response.headers.set('Access-Control-Allow-Origin', getFrontendUrl());
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  return response;
}

export const config = {
  matcher: '/api/:path*',
}; 