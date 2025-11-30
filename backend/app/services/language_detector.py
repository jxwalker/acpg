"""Language detection service for code files."""
import re
from typing import Optional, List
from pathlib import Path


class LanguageDetector:
    """Detects programming language from file content and path."""
    
    # File extension to language mapping
    EXTENSION_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".cpp": "cpp",
        ".c": "c",
        ".cs": "csharp",
        ".rb": "ruby",
        ".php": "php",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
    }
    
    # Shebang patterns
    SHEBANG_PATTERNS = {
        r"^#!/usr/bin/env python": "python",
        r"^#!/usr/bin/python": "python",
        r"^#!/usr/bin/python3": "python",
        r"^#!/usr/bin/env node": "javascript",
        r"^#!/usr/bin/node": "javascript",
    }
    
    def detect(self, file_path: Optional[str] = None, content: Optional[str] = None) -> Optional[str]:
        """
        Detect programming language from file path and/or content.
        
        Args:
            file_path: Path to the file
            content: File content (optional, used for shebang detection)
            
        Returns:
            Detected language or None
        """
        # Try file extension first
        if file_path:
            path = Path(file_path)
            ext = path.suffix.lower()
            if ext in self.EXTENSION_MAP:
                return self.EXTENSION_MAP[ext]
        
        # Try shebang in content
        if content:
            first_line = content.split('\n')[0] if content else ""
            for pattern, language in self.SHEBANG_PATTERNS.items():
                if re.match(pattern, first_line):
                    return language
        
        # Try package.json for JavaScript/TypeScript
        if file_path:
            package_json = Path(file_path).parent / "package.json"
            if package_json.exists():
                try:
                    import json
                    with open(package_json) as f:
                        pkg = json.load(f)
                        # Check for TypeScript
                        if "typescript" in str(pkg.get("dependencies", {})).lower() or \
                           "typescript" in str(pkg.get("devDependencies", {})).lower():
                            return "typescript"
                        # Default to JavaScript
                        return "javascript"
                except Exception:
                    pass
        
        # Try requirements.txt for Python
        if file_path:
            req_file = Path(file_path).parent / "requirements.txt"
            if req_file.exists():
                return "python"
        
        return None
    
    def detect_from_content(self, content: str, filename: Optional[str] = None) -> Optional[str]:
        """
        Detect language from content and optional filename.
        
        Args:
            content: File content
            filename: Optional filename for extension detection
            
        Returns:
            Detected language or None
        """
        return self.detect(file_path=filename, content=content)
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages."""
        return list(set(self.EXTENSION_MAP.values()))


# Global instance
_language_detector: Optional[LanguageDetector] = None


def get_language_detector() -> LanguageDetector:
    """Get the global language detector instance."""
    global _language_detector
    if _language_detector is None:
        _language_detector = LanguageDetector()
    return _language_detector

