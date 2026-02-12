"""Sandboxed dynamic analyzer for deterministic runtime evidence."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..core.config import settings
from ..models.schemas import (
    DynamicAnalysisResult,
    DynamicExecutionArtifact,
    DynamicReplayArtifact,
    Violation,
)


class DynamicAnalyzer:
    """Run constrained dynamic execution and convert failures into violations."""

    RUNNER = "python_subprocess_isolated"

    def __init__(self):
        self.timeout_seconds = settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS
        self.max_output_bytes = settings.DYNAMIC_SANDBOX_MAX_OUTPUT_BYTES
        self.memory_limit_mb = settings.DYNAMIC_SANDBOX_MEMORY_MB

    def analyze(self, code: str, language: str, artifact_id: str) -> DynamicAnalysisResult:
        """Execute dynamic analysis for supported languages and emit replay artifacts."""
        if not settings.ENABLE_DYNAMIC_TESTING:
            return DynamicAnalysisResult(
                executed=False,
                runner=self.RUNNER,
                timeout_seconds=self.timeout_seconds,
                artifacts=[],
                violations=[],
            )

        normalized_language = (language or "").strip().lower()
        if normalized_language != "python":
            return DynamicAnalysisResult(
                executed=False,
                runner=self.RUNNER,
                timeout_seconds=self.timeout_seconds,
                artifacts=[],
                violations=[],
            )

        run_started = time.perf_counter()
        script_name = "artifact.py"
        command = [sys.executable, "-I", "-B", script_name]
        run_stdout = ""
        run_stderr = ""
        return_code: Optional[int] = None
        timed_out = False

        with tempfile.TemporaryDirectory(prefix="acpg_dyn_") as temp_dir:
            script_path = Path(temp_dir) / script_name
            script_path.write_text(code, encoding="utf-8")

            kwargs = {
                "cwd": temp_dir,
                "capture_output": True,
                "text": True,
                "timeout": self.timeout_seconds,
                "env": self._sandbox_env(),
            }
            preexec = self._resource_limiter()
            if preexec is not None:
                kwargs["preexec_fn"] = preexec

            try:
                completed = subprocess.run(command, check=False, **kwargs)
                return_code = completed.returncode
                run_stdout = completed.stdout or ""
                run_stderr = completed.stderr or ""
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                return_code = None
                run_stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
                run_stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""

        duration_seconds = round(time.perf_counter() - run_started, 6)
        trimmed_stdout = self._truncate_output(run_stdout)
        trimmed_stderr = self._truncate_output(run_stderr)
        replay = DynamicReplayArtifact(
            runner=self.RUNNER,
            command=command,
            timeout_seconds=self.timeout_seconds,
            deterministic_fingerprint=self._fingerprint(command, artifact_id, normalized_language),
            language=normalized_language,
        )
        execution_artifact = DynamicExecutionArtifact(
            artifact_id=f"DYN-{artifact_id}-1",
            duration_seconds=duration_seconds,
            return_code=return_code,
            timed_out=timed_out,
            stdout=trimmed_stdout,
            stderr=trimmed_stderr,
            replay=replay,
        )

        violations = self._to_violations(
            timed_out=timed_out,
            return_code=return_code,
            stderr=trimmed_stderr,
            stdout=trimmed_stdout,
        )

        return DynamicAnalysisResult(
            executed=True,
            runner=self.RUNNER,
            timeout_seconds=self.timeout_seconds,
            artifacts=[execution_artifact],
            violations=violations,
        )

    def _to_violations(
        self,
        timed_out: bool,
        return_code: Optional[int],
        stderr: str,
        stdout: str,
    ) -> list[Violation]:
        if timed_out:
            return [
                Violation(
                    rule_id="DYN-EXEC-TIMEOUT",
                    description=(
                        "Dynamic execution exceeded sandbox timeout; runtime safety could not be established."
                    ),
                    line=None,
                    evidence=f"timeout_seconds={self.timeout_seconds}",
                    detector="dynamic_sandbox",
                    severity="high",
                )
            ]

        if return_code in (0, None):
            return []

        if "Traceback (most recent call last):" in stderr:
            evidence = stderr or stdout or f"return_code={return_code}"
            return [
                Violation(
                    rule_id="DYN-EXEC-EXCEPTION",
                    description=(
                        "Dynamic execution raised an exception in sandboxed runtime analysis."
                    ),
                    line=None,
                    evidence=evidence[:500],
                    detector="dynamic_sandbox",
                    severity="high",
                )
            ]

        evidence = stderr or stdout or f"return_code={return_code}"
        return [
            Violation(
                rule_id="DYN-EXEC-CRASH",
                description="Dynamic execution exited with non-zero status in sandboxed analysis.",
                line=None,
                evidence=evidence[:500],
                detector="dynamic_sandbox",
                severity="medium",
            )
        ]

    def _truncate_output(self, text: str) -> str:
        encoded = (text or "").encode("utf-8", errors="replace")
        if len(encoded) <= self.max_output_bytes:
            return text or ""
        truncated = encoded[: self.max_output_bytes]
        return truncated.decode("utf-8", errors="ignore")

    def _sandbox_env(self) -> dict[str, str]:
        env = {
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PATH": os.environ.get("PATH", ""),
        }
        return env

    def _resource_limiter(self):
        if os.name != "posix":
            return None

        memory_bytes = max(int(self.memory_limit_mb), 64) * 1024 * 1024
        cpu_limit = max(int(self.timeout_seconds), 1)

        def _limit():
            try:
                import resource

                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 1))
            except Exception:
                # Keep best-effort semantics; timeout still applies.
                pass

        return _limit

    def _fingerprint(self, command: list[str], artifact_id: str, language: str) -> str:
        payload = {
            "runner": self.RUNNER,
            "command": command,
            "timeout_seconds": self.timeout_seconds,
            "artifact_id": artifact_id,
            "language": language,
            "memory_limit_mb": self.memory_limit_mb,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


_dynamic_analyzer: Optional[DynamicAnalyzer] = None


def get_dynamic_analyzer() -> DynamicAnalyzer:
    """Get or create dynamic analyzer singleton."""
    global _dynamic_analyzer
    if _dynamic_analyzer is None:
        _dynamic_analyzer = DynamicAnalyzer()
    return _dynamic_analyzer

