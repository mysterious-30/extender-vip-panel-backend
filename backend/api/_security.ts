import { setupGlobalErrorHandlers } from '@/lib/error-handler';
import { 
  sanitizeInput, 
  generateSecureToken, 
  detectSecurityVulnerabilities, 
  getSecurityHeaders, 
  generateCSRFToken, 
  validateCSRFToken 
} from '../../lib/security';
import { logSecurityEvent } from '@/lib/monitoring';
import { LogLevel, SecurityEventType } from '@/lib/monitoring';

// Initialize security features when this file is imported
// This module will be imported by Next.js when the app starts

// 1. Set up global error handlers to prevent application crashes
setupGlobalErrorHandlers();

// 2. Log application startup
logSecurityEvent({
  level: LogLevel.INFO,
  eventType: SecurityEventType.SYSTEM,
  message: 'Application started with security protections enabled',
  metadata: {
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  }
}).catch((error) => {
  console.error('Failed to log application startup:', error);
});

// 3. Export security utilities for use in other files
export { 
  sanitizeInput, 
  generateSecureToken, 
  detectSecurityVulnerabilities, 
  getSecurityHeaders, 
  generateCSRFToken, 
  validateCSRFToken 
};

// 4. Print security initialization message
console.log(`[SECURITY] Initialized security protections (${process.env.NODE_ENV} mode)`);

// This ensures this file gets executed when the application starts
export const securityEnabled = true;

// Add CORS headers to response
export function addCorsHeaders(response: Response): Response {
  // Get frontend URL from environment variables or use default
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
  
  // Set CORS headers
  response.headers.set('Access-Control-Allow-Origin', frontendUrl);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  
  // Additional recommended security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  
  return response;
}
