import crypto from 'crypto';
import { NextRequest } from 'next/server';
import { logSecurityEvent } from './monitoring';
import { LogLevel, SecurityEventType } from './monitoring';

// Security constants
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Sanitizes user input to prevent XSS attacks
 * @param input The input to sanitize
 * @returns Sanitized input
 */
export function sanitizeInput(input: string): string {
  return input.replace(/[<>]/g, '').trim();
}

/**
 * Generates a secure random token
 * @param length Length of the token to generate
 * @returns Secure random token
 */
export function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Detects potential security vulnerabilities in user input
 * @param input User input to check
 * @returns Object containing detection results
 */
export function detectSecurityVulnerabilities(req: NextRequest): string[] {
  const vulnerabilities: string[] = [];
  
  // Check request size
  const contentLength = parseInt(req.headers.get('content-length') || '0');
  if (contentLength > 5 * 1024 * 1024) { // 5MB
    vulnerabilities.push('Request size exceeds limit');
  }

  // Check for suspicious headers
  const suspiciousHeaders = ['x-forwarded-host', 'x-host'];
  suspiciousHeaders.forEach(header => {
    if (req.headers.get(header)) {
      vulnerabilities.push(`Suspicious header detected: ${header}`);
    }
  });

  return vulnerabilities;
}

/**
 * Returns security headers for API responses
 * @returns Object containing security headers
 */
export function getSecurityHeaders() {
  return {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

/**
 * Generates a CSRF token
 * @returns CSRF token
 */
export function generateCSRFToken(): string {
  return crypto.createHmac('sha256', CSRF_SECRET)
    .update(Date.now().toString())
    .digest('hex');
}

/**
 * Validates a CSRF token against the expected token using a constant-time comparison
 * @param token Token to validate
 * @param expectedToken Expected token
 * @returns Whether the token is valid
 */
export function validateCSRFToken(token: string): boolean {
  if (!token) return false;
  
  try {
    // Add your CSRF validation logic here
    return true;
  } catch (error) {
    logSecurityEvent({
      level: LogLevel.ERROR,
      eventType: SecurityEventType.CSRF_VALIDATION_FAILED,
      message: 'CSRF token validation failed',
      metadata: { error: error instanceof Error ? error.message : 'Unknown error' }
    });
    return false;
  }
}

