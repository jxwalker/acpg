"""Tool execution service for static analysis tools."""
import subprocess
import json
import tempfile
import os
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime
import logging

from ..core.static_analyzers import ToolConfig, get_analyzer_config
from ..core.config import settings

logger = logging.getLogger(__name__)


class ToolExecutionResult:
    """Result of tool execution."""
    
    def __init__(self, tool_name: str, success: bool, output: Optional[str] = None,
                 error: Optional[str] = None, execution_time: float = 0.0,
                 exit_code: Optional[int] = None):
        self.tool_name = tool_name
        self.success = success
        self.output = output
        self.error = error
        self.execution_time = execution_time
        self.exit_code = exit_code
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "execution_time": self.execution_time,
            "exit_code": self.exit_code,
            "timestamp": self.timestamp.isoformat()
        }


class ToolExecutor:
    """Executes static analysis tools safely."""
    
    def __init__(self):
        self.config = get_analyzer_config()
    
    def execute_tool(
        self,
        tool_config: ToolConfig,
        target_path: Optional[str] = None,
        content: Optional[str] = None
    ) -> ToolExecutionResult:
        """
        Execute a static analysis tool.
        
        Args:
            tool_config: Tool configuration
            target_path: Path to file/directory to analyze
            content: File content (if target_path is None, creates temp file)
            
        Returns:
            ToolExecutionResult
        """
        start_time = datetime.utcnow()
        
        try:
            # Prepare command
            if tool_config.requires_file:
                if target_path:
                    file_path = target_path
                elif content:
                    # Create temporary file
                    with tempfile.NamedTemporaryFile(
                        mode='w',
                        suffix=self._get_suffix_for_language(tool_config.languages[0] if tool_config.languages else "python"),
                        delete=False
                    ) as tmp_file:
                        tmp_file.write(content)
                        file_path = tmp_file.name
                    # Clean up temp file after execution
                    try:
                        result = self._execute_with_file(tool_config, file_path)
                    finally:
                        if not target_path:  # Only delete if we created it
                            try:
                                os.unlink(file_path)
                            except Exception:
                                pass
                    return result
                else:
                    return ToolExecutionResult(
                        tool_config.name,
                        False,
                        error="Tool requires file but no path or content provided"
                    )
            else:
                # Tool can read from stdin
                return self._execute_with_stdin(tool_config, content or "")
            
        except subprocess.TimeoutExpired:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            logger.warning(f"Tool {tool_config.name} timed out after {execution_time}s")
            return ToolExecutionResult(
                tool_config.name,
                False,
                error=f"Tool execution timed out after {tool_config.timeout} seconds",
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Error executing tool {tool_config.name}: {e}", exc_info=True)
            return ToolExecutionResult(
                tool_config.name,
                False,
                error=str(e),
                execution_time=execution_time
            )
    
    def _execute_with_file(
        self,
        tool_config: ToolConfig,
        file_path: str
    ) -> ToolExecutionResult:
        """Execute tool with file path."""
        start_time = datetime.utcnow()
        
        # Build command with file path substitution
        command = [part.replace("{target}", file_path) for part in tool_config.command]
        
        # Check for config file requirement
        if tool_config.requires_config:
            config_path = Path(file_path).parent / tool_config.requires_config
            if not config_path.exists():
                logger.warning(f"Config file {tool_config.requires_config} not found for {tool_config.name}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=tool_config.timeout,
                cwd=Path(file_path).parent if Path(file_path).is_file() else Path(file_path),
                check=False  # Don't raise on non-zero exit
            )
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Some tools return non-zero on findings (not errors)
            # Check if we got valid output
            output = result.stdout if result.stdout else result.stderr
            
            # Try to parse as JSON if expected
            if tool_config.output_format == "json" and output:
                try:
                    json.loads(output)  # Validate JSON
                except json.JSONDecodeError:
                    # Not valid JSON, might be error message
                    if result.returncode != 0:
                        return ToolExecutionResult(
                            tool_config.name,
                            False,
                            error=output or result.stderr,
                            execution_time=execution_time,
                            exit_code=result.returncode
                        )
            
            return ToolExecutionResult(
                tool_config.name,
                True,
                output=output,
                error=result.stderr if result.returncode != 0 and not output else None,
                execution_time=execution_time,
                exit_code=result.returncode
            )
            
        except subprocess.TimeoutExpired:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            raise
    
    def _execute_with_stdin(
        self,
        tool_config: ToolConfig,
        content: str
    ) -> ToolExecutionResult:
        """Execute tool with stdin input."""
        start_time = datetime.utcnow()
        
        command = [part.replace("{target}", "-") for part in tool_config.command]
        
        try:
            result = subprocess.run(
                command,
                input=content,
                capture_output=True,
                text=True,
                timeout=tool_config.timeout,
                check=False
            )
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            output = result.stdout if result.stdout else result.stderr
            
            return ToolExecutionResult(
                tool_config.name,
                True,
                output=output,
                error=result.stderr if result.returncode != 0 and not output else None,
                execution_time=execution_time,
                exit_code=result.returncode
            )
            
        except subprocess.TimeoutExpired:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            raise
    
    def _get_suffix_for_language(self, language: str) -> str:
        """Get file suffix for language."""
        suffix_map = {
            "python": ".py",
            "javascript": ".js",
            "typescript": ".ts",
            "java": ".java",
            "go": ".go"
        }
        return suffix_map.get(language, ".txt")
    
    def execute_tools_for_language(
        self,
        language: str,
        target_path: Optional[str] = None,
        content: Optional[str] = None
    ) -> List[ToolExecutionResult]:
        """
        Execute all enabled tools for a language.
        
        Args:
            language: Programming language
            target_path: Path to analyze
            content: File content
            
        Returns:
            List of ToolExecutionResult
        """
        tools = self.config.get_tools_for_language(language)
        results = []
        
        for tool_name, tool_config in tools.items():
            logger.info(f"Executing tool {tool_name} for {language}")
            result = self.execute_tool(tool_config, target_path, content)
            results.append(result)
            
            if not result.success:
                logger.warning(f"Tool {tool_name} failed: {result.error}")
        
        return results


# Global instance
_tool_executor: Optional[ToolExecutor] = None


def get_tool_executor() -> ToolExecutor:
    """Get the global tool executor instance."""
    global _tool_executor
    if _tool_executor is None:
        _tool_executor = ToolExecutor()
    return _tool_executor

