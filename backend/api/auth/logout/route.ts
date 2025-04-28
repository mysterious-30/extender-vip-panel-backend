// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
// @ts-ignore - Ignore missing type declarations
import { cookies } from 'next/headers';

export async function POST() {
  console.log('Logout API called');
  
  try {
    // Get the cookie store
    const cookieStore = cookies();
    
    // Check if auth token exists
    const authToken = cookieStore.get('auth_token');
    
    if (authToken) {
      console.log('Clearing auth_token cookie');
      
      // Delete the auth token cookie
      cookies().delete('auth_token');
      
      // Create response
      const response = NextResponse.json({
        success: true,
        message: 'Logged out successfully'
      });
      
      // Ensure cookie is deleted from the response too
      response.cookies.delete('auth_token');
      
      return response;
    }
    
    console.log('No auth_token cookie found to clear');
    
    // Return success even if no token was found (idempotent logout)
    return NextResponse.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Error during logout:', error);
    return NextResponse.json(
      { success: false, message: 'An error occurred during logout' },
      { status: 500 }
    );
  }
} 
