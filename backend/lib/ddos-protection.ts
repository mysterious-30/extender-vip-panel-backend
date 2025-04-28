import { NextRequest, NextResponse } from 'next/server';
import { logSecurityEvent } from './monitoring';
import { LogLevel, SecurityEventType } from './monitoring';
import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.REDIS_URL!,
  token: process.env.REDIS_TOKEN!
});

// Maximum request body size (5MB)
const MAX_BODY_SIZE = 5 * 1024 * 1024;

// Request limits and thresholds
const REQUEST_LIMITS = {
  MAX_REQUESTS_PER_IP: 100,
  WINDOW_MS: 60 * 1000, // 1 minute
  MAX_URL_LENGTH: 2000,
  MAX_HEADER_COUNT: 50,
  MAX_HEADER_SIZE: 8 * 1024, // 8KB
  MAX_COOKIE_SIZE: 4 * 1024, // 4KB
  ALLOWED_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'],
  MAX_QUERY_PARAMS: 50
};

// List of known proxy headers for getting client IP
const PROXY_HEADERS = [
  'x-forwarded-for',
  'x-real-ip',
  'cf-connecting-ip', // Cloudflare
  'x-client-ip',
  'x-forwarded'
];

// URL patterns that are known attack vectors
const MALICIOUS_URL_PATTERNS = [
  /\.(git|svn|hg|bzr)/i,       // VCS directories
  /wp-admin|wp-content|wp-includes/i, // WordPress probing
  /\.env|\.config/i,           // Configuration file access attempts
  /\/etc\/passwd|\/etc\/shadow/i, // Unix file access
  /\/proc\/self\/environ/i,    // Process environment access
  /\/admin\/config\.php/i,     // PHP admin access
  /cmd\.php|shell\.php|backdoor\.php/i, // Known backdoor files
  /phpMyAdmin|phpmyadmin|myadmin/i, // PHPMyAdmin access
  /eval\(|system\(|exec\(/i,   // Code execution
  /sqlmap|nikto|acunetix|nessus/i, // Scanner signatures
  /union\s+select|\/bin\/bash|\/dev\/null/i, // SQL injection and command execution
  /alert\(|confirm\(|prompt\(/i, // XSS payloads
  /\.\.\//g                    // Path traversal
];

// Function to extract IP from request
export function getClientIp(request: NextRequest): string {
  // Try to get IP from proxy headers
  for (const header of PROXY_HEADERS) {
    const value = request.headers.get(header);
    if (value) {
      // x-forwarded-for can contain multiple IPs: client, proxy1, proxy2, ...
      // We want the client's IP, which is the first one
      return value.split(',')[0].trim();
    }
  }
  
  // Fall back to the direct IP
  return request.ip || 'unknown';
}

export async function protectFromDDoS(req: NextRequest): Promise<NextResponse | null> {
  const clientIP = getClientIP(req);
  
  // Basic request validation
  const validationError = validateRequest(req);
  if (validationError) {
    return validationError;
  }

  // Rate limiting
  const isRateLimited = await checkRateLimit(clientIP);
  if (isRateLimited) {
    return new NextResponse(
      JSON.stringify({ error: 'Too many requests' }),
      { status: 429, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return null;
}

function getClientIP(req: NextRequest): string {
  for (const header of PROXY_HEADERS) {
    const value = req.headers.get(header);
    if (value) {
      return value.split(',')[0].trim();
    }
  }
  return '127.0.0.1';
}

function validateRequest(req: NextRequest): NextResponse | null {
  const url = new URL(req.url);

  // Check URL length
  if (req.url.length > REQUEST_LIMITS.MAX_URL_LENGTH) {
    return new NextResponse(
      JSON.stringify({ error: 'URL too long' }),
      { status: 414 }
    );
  }

  // Check HTTP method
  if (!REQUEST_LIMITS.ALLOWED_METHODS.includes(req.method)) {
    return new NextResponse(
      JSON.stringify({ error: 'Method not allowed' }),
      { status: 405 }
    );
  }

  // Check query parameters
  if (url.searchParams.toString().length > REQUEST_LIMITS.MAX_QUERY_PARAMS) {
    return new NextResponse(
      JSON.stringify({ error: 'Too many query parameters' }),
      { status: 400 }
    );
  }

  return null;
}

async function checkRateLimit(clientIP: string): Promise<boolean> {
  const key = `ratelimit:${clientIP}`;
  const now = Date.now();
  const windowStart = now - REQUEST_LIMITS.WINDOW_MS;

  try {
    const [count] = await redis
      .pipeline()
      .zremrangebyscore(key, 0, windowStart)
      .zadd(key, { score: now, member: now.toString() })
      .zcard(key)
      .expire(key, 60)
      .exec();

    return (count as number) > REQUEST_LIMITS.MAX_REQUESTS_PER_IP;
  } catch (error) {
    console.error('Rate limiting error:', error);
    return false;
  }
}

// Check if request appears to be part of a DDoS attack
export async function detectDDoSAttack(request: NextRequest): Promise<{
  isAttack: boolean;
  reason?: string;
}> {
  const ip = getClientIp(request);
  const url = request.url;
  const method = request.method;
  const userAgent = request.headers.get('user-agent') || '';
  
  // 1. Check URL length
  if (url.length > REQUEST_LIMITS.MAX_URL_LENGTH) {
    await logDDoSAttempt(ip, 'URL_LENGTH_EXCEEDED', { url: url.substring(0, 100) + '...' });
    return { isAttack: true, reason: 'URL_LENGTH_EXCEEDED' };
  }
  
  // 2. Check HTTP method
  if (!REQUEST_LIMITS.ALLOWED_METHODS.includes(method)) {
    await logDDoSAttempt(ip, 'INVALID_HTTP_METHOD', { method });
    return { isAttack: true, reason: 'INVALID_HTTP_METHOD' };
  }
  
  // 3. Check for malicious URL patterns
  for (const pattern of MALICIOUS_URL_PATTERNS) {
    if (pattern.test(url)) {
      await logDDoSAttempt(ip, 'MALICIOUS_URL_PATTERN', { url, pattern: pattern.toString() });
      return { isAttack: true, reason: 'MALICIOUS_URL_PATTERN' };
    }
  }
  
  // 4. Missing or suspicious User-Agent
  if (!userAgent || userAgent.length < 5 || 
      /bot|crawl|slurp|spider|curl|wget|libwww-perl|python-requests/i.test(userAgent)) {
    // Don't block legitimate search engine bots
    const isLegitBot = /googlebot|bingbot|yandexbot|duckduckbot|baiduspider/i.test(userAgent);
    if (!isLegitBot) {
      await logDDoSAttempt(ip, 'SUSPICIOUS_USER_AGENT', { userAgent });
      return { isAttack: true, reason: 'SUSPICIOUS_USER_AGENT' };
    }
  }
  
  // 5. Check query parameters count
  const queryParamsCount = request.nextUrl.searchParams.toString().split('&').length;
  if (queryParamsCount > REQUEST_LIMITS.MAX_QUERY_PARAMS) {
    await logDDoSAttempt(ip, 'QUERY_PARAMS_EXCEEDED', { count: queryParamsCount });
    return { isAttack: true, reason: 'QUERY_PARAMS_EXCEEDED' };
  }
  
  // 6. Check header count
  const headerCount = Array.from(request.headers.keys()).length;
  if (headerCount > REQUEST_LIMITS.MAX_HEADER_COUNT) {
    await logDDoSAttempt(ip, 'HEADER_COUNT_EXCEEDED', { count: headerCount });
    return { isAttack: true, reason: 'HEADER_COUNT_EXCEEDED' };
  }
  
  // 7. Check cookie size
  const cookieHeader = request.headers.get('cookie') || '';
  if (cookieHeader.length > REQUEST_LIMITS.MAX_COOKIE_SIZE) {
    await logDDoSAttempt(ip, 'COOKIE_SIZE_EXCEEDED', { size: cookieHeader.length });
    return { isAttack: true, reason: 'COOKIE_SIZE_EXCEEDED' };
  }
  
  // No attack detected
  return { isAttack: false };
}

// Log DDoS attempt
async function logDDoSAttempt(ip: string, reason: string, metadata: any): Promise<void> {
  await logSecurityEvent({
    level: LogLevel.WARN,
    eventType: SecurityEventType.SUSPICIOUS_REQUEST,
    ip,
    message: `Potential DDoS/attack attempt detected: ${reason}`,
    metadata
  });
}

// Create blocking response for DDoS attempts
export function createBlockingResponse(reason: string): NextResponse {
  return new NextResponse(
    JSON.stringify({
      success: false,
      message: 'Request blocked for security reasons'
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json'
      }
    }
  );
}

// List of common vulnerability patterns to scan for in request body
const VULNERABILITY_PATTERNS = [
  // SQL Injection
  { type: 'SQL_INJECTION', pattern: /'.*?(OR|AND).*?=.*?('|')|(\%27)|(\-\-)|(\%23)|(#)/i },
  { type: 'SQL_INJECTION', pattern: /(UNION.*?SELECT|SELECT.*?FROM|INSERT.*?INTO|UPDATE.*?SET|DELETE.*?FROM)/i },
  
  // XSS
  { type: 'XSS', pattern: /<script.*?>.*?<\/script>|alert\s*\(.*?\)|on\w+\s*=|javascript:/i },
  
  // Command Injection
  { type: 'COMMAND_INJECTION', pattern: /;\s*(ls|cat|rm|wget|curl|bash|sh|echo)($|\s)|`.*`/i },
  
  // Local/Remote File Inclusion
  { type: 'FILE_INCLUSION', pattern: /(php:\/\/|file:\/\/|data:\/\/|https?:\/\/).*(input|filter|expect|zip|phar|data)/i },
  
  // Path Traversal
  { type: 'PATH_TRAVERSAL', pattern: /\.\.\//g }
];

// Scan request body for common vulnerability patterns
export async function scanRequestBody(body: string): Promise<{
  isVulnerable: boolean;
  vulnerabilityType?: string;
  matches?: string[];
}> {
  if (!body) {
    return { isVulnerable: false };
  }
  
  for (const { type, pattern } of VULNERABILITY_PATTERNS) {
    const matches = body.match(pattern);
    if (matches) {
      return {
        isVulnerable: true,
        vulnerabilityType: type,
        matches: Array.from(matches).map(m => m.substring(0, 100)) // Limit match length
      };
    }
  }
  
  return { isVulnerable: false };
}

// Main function to check request for any security issues
export async function analyzeRequest(request: NextRequest): Promise<{
  shouldBlock: boolean;
  response?: NextResponse;
  reason?: string;
}> {
  // Check for DDoS patterns
  const ddosCheck = await detectDDoSAttack(request);
  if (ddosCheck.isAttack) {
    return {
      shouldBlock: true,
      response: createBlockingResponse(ddosCheck.reason || 'SUSPICIOUS_REQUEST'),
      reason: ddosCheck.reason
    };
  }
  
  // Only scan the body for POST/PUT/PATCH requests
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      // Clone the request to read the body
      const clonedRequest = request.clone();
      
      // Check if content length exceeds the maximum
      const contentLength = parseInt(request.headers.get('content-length') || '0');
      if (contentLength > MAX_BODY_SIZE) {
        return {
          shouldBlock: true,
          response: createBlockingResponse('REQUEST_BODY_TOO_LARGE'),
          reason: 'REQUEST_BODY_TOO_LARGE'
        };
      }
      
      // Try to parse as text
      let bodyText = '';
      try {
        bodyText = await clonedRequest.text();
      } catch (error) {
        console.error('Failed to read request body:', error);
      }
      
      // If we got a body, scan it for vulnerabilities
      if (bodyText) {
        const scanResult = await scanRequestBody(bodyText);
        if (scanResult.isVulnerable) {
          const ip = getClientIp(request);
          await logSecurityEvent({
            level: LogLevel.WARN,
            eventType: SecurityEventType.SUSPICIOUS_REQUEST,
            ip,
            message: `Request body contains ${scanResult.vulnerabilityType} pattern`,
            metadata: {
              matches: scanResult.matches,
              path: request.nextUrl.pathname
            }
          });
          
          return {
            shouldBlock: true,
            response: createBlockingResponse(scanResult.vulnerabilityType || 'MALICIOUS_PAYLOAD'),
            reason: scanResult.vulnerabilityType
          };
        }
      }
    } catch (error) {
      console.error('Error analyzing request body:', error);
    }
  }
  
  // Request passed all checks
  return { shouldBlock: false };
} 
