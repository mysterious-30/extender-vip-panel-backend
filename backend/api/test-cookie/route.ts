// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';
import { getSecurityHeaders } from '@/lib/security';
import { addCorsHeaders } from '../../_security';

export async function GET(request: Request) {
  try {
    // Check cookies using next/headers
    const cookieStore = cookies();
    const tokenFromCookieStore = cookieStore.get('auth_token')?.value;
    
    // Check cookies from request headers
    const requestCookies = request.headers.get('cookie');
    
    // In Next.js App Router, we should use the cookies() function from next/headers
    // instead of trying to access cookies directly from the request object
    
    // Debug info
    const response = NextResponse.json({
      success: true,
      cookieInfo: {
        tokenFromCookieStore: tokenFromCookieStore ? 'Present (length: ' + tokenFromCookieStore.length + ')' : 'Not found',
        requestCookies: requestCookies || 'No cookies in request headers',
        allCookiesFromStore: Array.from(cookieStore.getAll()).map(c => ({
          name: c.name,
          value: c.value.substring(0, 10) + '...'
        }))
      }
    }, {
      headers: getSecurityHeaders()
    });
    
    return addCorsHeaders(response);
  } catch (error) {
    console.error('Error in test-cookie route:', error);
    const response = NextResponse.json({
      success: false,
      error: 'An error occurred while testing cookies'
    }, { 
      status: 500,
      headers: getSecurityHeaders()
    });
    
    return addCorsHeaders(response);
  }
}

// Handle OPTIONS requests for CORS preflight
export function OPTIONS() {
  const response = new NextResponse(null, { 
    status: 204,
    headers: getSecurityHeaders()
  });
  
  return addCorsHeaders(response);
}
