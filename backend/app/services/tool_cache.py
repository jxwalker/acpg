"""Tool result caching service."""
import hashlib
import json
import time
from typing import Optional, Dict, Any
from pathlib import Path
import logging

from ..core.config import settings

logger = logging.getLogger(__name__)


class ToolCache:
    """Cache for static analysis tool results."""
    
    def __init__(self, cache_dir: Optional[Path] = None, ttl: int = None):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory for cache files (default: temp directory)
            ttl: Time-to-live in seconds (default: from settings)
        """
        if cache_dir is None:
            from tempfile import gettempdir
            cache_dir = Path(gettempdir()) / "acpg_tool_cache"
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl or settings.STATIC_ANALYSIS_CACHE_TTL
    
    def _get_cache_key(self, tool_name: str, content_hash: str, tool_version: Optional[str] = None) -> str:
        """Generate cache key."""
        key_parts = [tool_name, content_hash]
        if tool_version:
            key_parts.append(tool_version)
        return "_".join(key_parts)
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path."""
        # Use first 2 chars of hash for directory structure
        subdir = cache_key[:2] if len(cache_key) >= 2 else "00"
        subdir_path = self.cache_dir / subdir
        subdir_path.mkdir(parents=True, exist_ok=True)
        return subdir_path / f"{cache_key}.json"
    
    def get(self, tool_name: str, content: str, tool_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get cached result.
        
        Args:
            tool_name: Name of the tool
            content: Code content
            tool_version: Optional tool version
            
        Returns:
            Cached result or None if not found/expired
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        cache_key = self._get_cache_key(tool_name, content_hash, tool_version)
        cache_path = self._get_cache_path(cache_key)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                cached_data = json.load(f)
            
            # Check if expired
            cached_time = cached_data.get('timestamp', 0)
            age = time.time() - cached_time
            
            if age > self.ttl:
                logger.debug(f"Cache expired for {tool_name} (age: {age:.0f}s > {self.ttl}s)")
                cache_path.unlink()  # Delete expired cache
                return None
            
            logger.debug(f"Cache hit for {tool_name} (age: {age:.0f}s)")
            return cached_data.get('result')
            
        except Exception as e:
            logger.warning(f"Error reading cache for {tool_name}: {e}")
            return None
    
    def set(self, tool_name: str, content: str, result: Dict[str, Any], 
            tool_version: Optional[str] = None):
        """
        Cache a result.
        
        Args:
            tool_name: Name of the tool
            content: Code content
            result: Result to cache
            tool_version: Optional tool version
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        cache_key = self._get_cache_key(tool_name, content_hash, tool_version)
        cache_path = self._get_cache_path(cache_key)
        
        try:
            cached_data = {
                'timestamp': time.time(),
                'tool_name': tool_name,
                'content_hash': content_hash,
                'tool_version': tool_version,
                'result': result
            }
            
            with open(cache_path, 'w') as f:
                json.dump(cached_data, f)
            
            logger.debug(f"Cached result for {tool_name}")
            
        except Exception as e:
            logger.warning(f"Error writing cache for {tool_name}: {e}")
    
    def clear(self, tool_name: Optional[str] = None):
        """
        Clear cache entries.
        
        Args:
            tool_name: If provided, clear only this tool's cache. Otherwise clear all.
        """
        if tool_name:
            # Clear specific tool
            pattern = f"{tool_name}_*"
            for cache_file in self.cache_dir.rglob(pattern):
                cache_file.unlink()
            logger.info(f"Cleared cache for {tool_name}")
        else:
            # Clear all
            import shutil
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Cleared all tool cache")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_files = sum(1 for _ in self.cache_dir.rglob("*.json"))
        total_size = sum(f.stat().st_size for f in self.cache_dir.rglob("*.json"))
        
        return {
            "cache_dir": str(self.cache_dir),
            "total_entries": total_files,
            "total_size_bytes": total_size,
            "ttl_seconds": self.ttl
        }


# Global cache instance
_tool_cache: Optional[ToolCache] = None


def get_tool_cache() -> ToolCache:
    """Get the global tool cache instance."""
    global _tool_cache
    if _tool_cache is None:
        _tool_cache = ToolCache()
    return _tool_cache

