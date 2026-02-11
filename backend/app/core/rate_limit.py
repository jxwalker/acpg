"""Rate limiting for ACPG API."""
import time
from collections import defaultdict
from typing import Optional, Tuple
from fastapi import HTTPException, Request
import asyncio


class RateLimiter:
    """
    Token bucket rate limiter.
    
    Allows burst traffic up to bucket size, then enforces rate limit.
    """
    
    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: int = 10
    ):
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.burst_size = burst_size
        self.buckets: dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update)
        self._lock = asyncio.Lock()
    
    def _get_key(self, request: Request) -> str:
        """Get rate limit key from request."""
        # Use API key if present, otherwise IP
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key[:16]}"
        
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"
    
    async def check(self, request: Request) -> bool:
        """
        Check if request is allowed.
        
        Returns True if allowed, raises HTTPException if rate limited.
        """
        async with self._lock:
            key = self._get_key(request)
            now = time.time()
            
            if key in self.buckets:
                tokens, last_update = self.buckets[key]
                # Add tokens based on time passed
                elapsed = now - last_update
                tokens = min(self.burst_size, tokens + elapsed * self.rate)
            else:
                tokens = self.burst_size
            
            if tokens >= 1:
                # Allow request, consume a token
                self.buckets[key] = (tokens - 1, now)
                return True
            else:
                # Calculate retry time
                tokens_needed = 1 - tokens
                retry_after = int(tokens_needed / self.rate) + 1
                
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": retry_after,
                        "limit": f"{int(self.rate * 60)} requests/minute"
                    },
                    headers={"Retry-After": str(retry_after)}
                )
    
    def cleanup_old_buckets(self, max_age: float = 3600):
        """Remove buckets that haven't been used recently."""
        now = time.time()
        expired = [
            key for key, (_, last_update) in self.buckets.items()
            if now - last_update > max_age
        ]
        for key in expired:
            del self.buckets[key]


# Global rate limiter instances
_default_limiter: Optional[RateLimiter] = None
_strict_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the default rate limiter (60 req/min)."""
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = RateLimiter(requests_per_minute=60, burst_size=10)
    return _default_limiter


def get_strict_rate_limiter() -> RateLimiter:
    """Get the strict rate limiter for expensive operations (10 req/min)."""
    global _strict_limiter
    if _strict_limiter is None:
        _strict_limiter = RateLimiter(requests_per_minute=10, burst_size=3)
    return _strict_limiter


async def rate_limit(request: Request):
    """Dependency for default rate limiting."""
    limiter = get_rate_limiter()
    await limiter.check(request)


async def rate_limit_strict(request: Request):
    """Dependency for strict rate limiting (AI endpoints)."""
    limiter = get_strict_rate_limiter()
    await limiter.check(request)


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter for more accurate rate limiting.
    
    Tracks exact request timestamps for precise rate enforcement.
    """
    
    def __init__(self, requests_per_minute: int = 60):
        self.limit = requests_per_minute
        self.window = 60  # seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    def _get_key(self, request: Request) -> str:
        """Get rate limit key from request."""
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key[:16]}"
        
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        
        return f"ip:{request.client.host if request.client else 'unknown'}"
    
    async def check(self, request: Request) -> bool:
        """Check if request is allowed."""
        async with self._lock:
            key = self._get_key(request)
            now = time.time()
            window_start = now - self.window
            
            # Remove old requests outside the window
            self.requests[key] = [
                t for t in self.requests[key] if t > window_start
            ]
            
            if len(self.requests[key]) >= self.limit:
                oldest = min(self.requests[key])
                retry_after = int(oldest + self.window - now) + 1
                
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": retry_after,
                        "limit": f"{self.limit} requests/minute"
                    },
                    headers={"Retry-After": str(retry_after)}
                )
            
            self.requests[key].append(now)
            return True

