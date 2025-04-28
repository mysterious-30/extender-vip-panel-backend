import { NextRequest, NextResponse } from 'next/server';

interface CacheEntry {
  response: Response;
  expiry: number;
}

const cache = new Map<string, CacheEntry>();

const CACHE_DURATION = 30 * 1000; // 30 seconds default
const MAX_CACHE_SIZE = 500;
const CACHE_CONTROL_HEADER = 'public, max-age=30, s-maxage=60, stale-while-revalidate=60';

function getCacheKey(request: NextRequest): string {
  const url = new URL(request.url);
  return `${url.pathname}${url.search}`;
}

function cleanupCache() {
  const now = Date.now();
  for (const [key, entry] of cache.entries()) {
    if (entry.expiry < now) {
      cache.delete(key);
    }
  }
  
  // If still over size limit, remove oldest entries
  if (cache.size > MAX_CACHE_SIZE) {
    const entriesToRemove = Array.from(cache.keys())
      .slice(0, cache.size - MAX_CACHE_SIZE);
    entriesToRemove.forEach(key => cache.delete(key));
  }
}

export async function withCache(
  req: NextRequest,
  handler: (req: NextRequest) => Promise<NextResponse>,
  options?: {
    duration?: number;
    ignoreMethods?: string[];
    ignoreSearchParams?: string[];
    cacheKeyBuilder?: (req: NextRequest) => string;
  }
) {
  // Don't cache non-GET requests by default
  if (req.method !== 'GET' && !options?.ignoreMethods?.includes(req.method)) {
    return handler(req);
  }

  const cacheKey = options?.cacheKeyBuilder 
    ? options.cacheKeyBuilder(req) 
    : getCacheKey(req);
  
  const cached = cache.get(cacheKey);
  const now = Date.now();

  if (cached && cached.expiry > now) {
    return new NextResponse(cached.response.body, cached.response);
  }

  const response = await handler(req);
  
  // Only cache successful responses
  if (response.status === 200) {
    const duration = options?.duration || CACHE_DURATION;
    
    cache.set(cacheKey, {
      response: response.clone(),
      expiry: now + duration
    });

    // Add cache control headers
    response.headers.set('Cache-Control', CACHE_CONTROL_HEADER);
  }

  cleanupCache();
  return response;
}

/**
 * Clear cache entry or all cache if no key provided
 */
export function clearCache(key?: string): void {
  if (key) {
    cache.delete(key);
  } else {
    cache.clear();
  }
}

/**
 * Get cache stats
 */
export function getCacheStats() {
  return {
    size: cache.size,
    maxSize: MAX_CACHE_SIZE,
    entries: Array.from(cache.keys())
  };
} 
