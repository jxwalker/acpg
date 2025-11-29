"""Tool execution service for static analysis tools."""
import subprocess
import json
import tempfile
import os
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime, timezone
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.static_analyzers import ToolConfig, get_analyzer_config
from ..core.config import settings
from .tool_cache import get_tool_cache

logger = logging.getLogger(__name__)


class ToolExecutionResult:
    """Result of tool execution."""
    
    def __init__(self, tool_name: str, success: bool, output: Optional[str] = None,
                 error: Optional[str] = None, execution_time: float = 0.0,
                 exit_code: Optional[int] = None, tool_version: Optional[str] = None):
        self.tool_name = tool_name
        self.success = success
        self.output = output
        self.error = error
        self.execution_time = execution_time
        self.exit_code = exit_code
        self.tool_version = tool_version
        self.timestamp = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "execution_time": self.execution_time,
            "exit_code": self.exit_code,
            "tool_version": self.tool_version,
            "timestamp": self.timestamp.isoformat()
        }


class ToolExecutor:
    """Executes static analysis tools safely."""
    
    def __init__(self):
        self.config = get_analyzer_config()
        self.cache = get_tool_cache()
    
    def execute_tool(
        self,
        tool_config: ToolConfig,
        target_path: Optional[str] = None,
        content: Optional[str] = None,
        use_cache: bool = True
    ) -> ToolExecutionResult:
        """
        Execute a static analysis tool.
        
        Args:
            tool_config: Tool configuration
            target_path: Path to file/directory to analyze
            content: File content (if target_path is None, creates temp file)
            use_cache: Whether to use cached results if available
            
        Returns:
            ToolExecutionResult
        """
        # Check cache if using content
        if use_cache and content and not target_path:
            cached_result = self.cache.get(tool_config.name, content)
            if cached_result:
                logger.debug(f"Using cached result for {tool_config.name}")
                return ToolExecutionResult(
                    tool_config.name,
                    True,
                    output=cached_result.get('output'),
                    execution_time=0.0,  # Cached, no execution time
                    exit_code=cached_result.get('exit_code')
                )
        
        start_time = datetime.now(timezone.utc)
        
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
                        result = self._execute_with_file(tool_config, file_path, use_cache=use_cache, content=content, target_path=target_path)
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
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.warning(f"Tool {tool_config.name} timed out after {execution_time}s")
            return ToolExecutionResult(
                tool_config.name,
                False,
                error=f"Tool execution timed out after {tool_config.timeout} seconds",
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"Error executing tool {tool_config.name}: {e}", exc_info=True)
            return ToolExecutionResult(
                tool_config.name,
                False,
                error=str(e),
                execution_time=execution_time
            )
    
    def _get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get tool version by running --version or similar."""
        try:
            # Try common version flags
            version_commands = [
                [tool_name, "--version"],
                [tool_name, "-v"],
                [tool_name, "version"]
            ]
            
            for cmd in version_commands:
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False
                    )
                    # Some tools return non-zero for --version but still output version
                    if result.stdout or result.stderr:
                        output = (result.stdout or result.stderr).strip()
                        # Extract version number (e.g., "bandit 1.7.5" -> "1.7.5")
                        import re
                        version_match = re.search(r'(\d+\.\d+\.\d+)', output)
                        if version_match:
                            return version_match.group(1)
                        # Fallback: return first line if it looks like a version
                        first_line = output.split('\n')[0].strip()
                        if re.search(r'\d+\.\d+', first_line):
                            return first_line
                except subprocess.TimeoutExpired:
                    logger.debug(f"Tool {tool_name} version check timed out")
                    continue
                except FileNotFoundError:
                    logger.debug(f"Tool {tool_name} not found for version check")
                    continue
                except Exception as e:
                    logger.debug(f"Error checking {tool_name} version: {e}")
                    continue
        except Exception as e:
            logger.warning(f"Failed to get version for {tool_name}: {e}")
        return None
    
    def _execute_with_file(
        self,
        tool_config: ToolConfig,
        file_path: str,
        use_cache: bool = True,
        content: Optional[str] = None,
        target_path: Optional[str] = None
    ) -> ToolExecutionResult:
        """Execute tool with file path."""
        start_time = datetime.now(timezone.utc)
        
        # Get tool version
        tool_version = self._get_tool_version(tool_config.name)
        
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
            
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
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
                        exec_result = ToolExecutionResult(
                            tool_config.name,
                            False,
                            error=output or result.stderr,
                            execution_time=execution_time,
                            exit_code=result.returncode
                        )
                        return exec_result
            
            exec_result = ToolExecutionResult(
                tool_config.name,
                True,
                output=output,
                error=result.stderr if result.returncode != 0 and not output else None,
                execution_time=execution_time,
                exit_code=result.returncode,
                tool_version=tool_version
            )
            
            # Cache successful results
            if use_cache and content and not target_path and exec_result.success:
                try:
                    self.cache.set(
                        tool_config.name,
                        content,
                        {
                            'output': exec_result.output,
                            'exit_code': exec_result.exit_code,
                            'tool_version': exec_result.tool_version
                        },
                        tool_version=exec_result.tool_version  # Include version in cache key
                    )
                except Exception as e:
                    logger.warning(f"Failed to cache result for {tool_config.name}: {e}")
            
            return exec_result
            
        except subprocess.TimeoutExpired:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            raise
    
    def _execute_with_stdin(
        self,
        tool_config: ToolConfig,
        content: str
    ) -> ToolExecutionResult:
        """Execute tool with stdin input."""
        start_time = datetime.now(timezone.utc)
        
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
            
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
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
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
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
        content: Optional[str] = None,
        parallel: bool = True,
        max_workers: Optional[int] = None
    ) -> List[ToolExecutionResult]:
        """
        Execute all enabled tools for a language.
        
        Args:
            language: Programming language
            target_path: Path to analyze
            content: File content
            parallel: Whether to execute tools in parallel
            max_workers: Max parallel workers (default: number of tools)
            
        Returns:
            List of ToolExecutionResult
        """
        tools = self.config.get_tools_for_language(language)
        results = []
        
        if not tools:
            logger.info(f"No enabled tools for {language}")
            return results
        
        logger.info(f"Starting static analysis for {language} with {len(tools)} tool(s)")
        
        if parallel and len(tools) > 1:
            # Execute tools in parallel
            if max_workers is None:
                max_workers = len(tools)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_tool = {
                    executor.submit(
                        self.execute_tool,
                        tool_config,
                        target_path,
                        content,
                        True  # use_cache
                    ): (tool_name, tool_config)
                    for tool_name, tool_config in tools.items()
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_tool):
                    tool_name, tool_config = future_to_tool[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Detailed audit logging
                        if result.success:
                            logger.info(
                                f"Tool {tool_name} completed successfully in {result.execution_time:.2f}s "
                                f"(exit_code={result.exit_code})"
                            )
                        else:
                            logger.warning(
                                f"Tool {tool_name} failed after {result.execution_time:.2f}s: {result.error}"
                            )
                    except Exception as e:
                        logger.error(f"Tool {tool_name} raised exception: {e}", exc_info=True)
                        results.append(ToolExecutionResult(
                            tool_name,
                            False,
                            error=str(e)
                        ))
        else:
            # Execute tools sequentially
            for tool_name, tool_config in tools.items():
                logger.info(f"Executing tool {tool_name} for {language}")
                result = self.execute_tool(tool_config, target_path, content, use_cache=True)
                results.append(result)
                
                # Detailed audit logging
                if result.success:
                    logger.info(
                        f"Tool {tool_name} completed successfully in {result.execution_time:.2f}s "
                        f"(exit_code={result.exit_code})"
                    )
                else:
                    logger.warning(
                        f"Tool {tool_name} failed after {result.execution_time:.2f}s: {result.error}"
                    )
        
        successful = sum(1 for r in results if r.success)
        total_time = sum(r.execution_time for r in results)
        logger.info(
            f"Static analysis completed: {successful}/{len(results)} tools succeeded "
            f"in {total_time:.2f}s total for {language}"
        )
        
        return results


# Global instance
_tool_executor: Optional[ToolExecutor] = None


def get_tool_executor() -> ToolExecutor:
    """Get the global tool executor instance."""
    global _tool_executor
    if _tool_executor is None:
        _tool_executor = ToolExecutor()
    return _tool_executor

