"""Sandboxed dynamic analyzer for deterministic runtime evidence."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import ast
from dataclasses import dataclass
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

        suites = self._build_python_suites(code)
        artifacts: list[DynamicExecutionArtifact] = []
        violations: list[Violation] = []

        for index, suite in enumerate(suites, start=1):
            execution_artifact = self._execute_suite(
                code=code,
                suite=suite,
                artifact_id=artifact_id,
                index=index,
                normalized_language=normalized_language,
            )
            artifacts.append(execution_artifact)
            violations.extend(
                self._to_violations(
                    timed_out=execution_artifact.timed_out,
                    return_code=execution_artifact.return_code,
                    stderr=execution_artifact.stderr,
                    stdout=execution_artifact.stdout,
                    suite_id=suite.suite_id,
                    suite_name=suite.suite_name,
                )
            )

        return DynamicAnalysisResult(
            executed=True,
            runner=self.RUNNER,
            timeout_seconds=self.timeout_seconds,
            artifacts=artifacts,
            violations=violations,
        )

    def _execute_suite(
        self,
        *,
        code: str,
        suite: "DynamicSuite",
        artifact_id: str,
        index: int,
        normalized_language: str,
    ) -> DynamicExecutionArtifact:
        run_started = time.perf_counter()
        run_stdout = ""
        run_stderr = ""
        return_code: Optional[int] = None
        timed_out = False

        with tempfile.TemporaryDirectory(prefix="acpg_dyn_") as temp_dir:
            artifact_name = "artifact.py"
            artifact_path = Path(temp_dir) / artifact_name
            artifact_path.write_text(code, encoding="utf-8")

            script_name = suite.script_name
            script_path = Path(temp_dir) / script_name
            script_path.write_text(
                suite.script_content if suite.script_content is not None else code,
                encoding="utf-8",
            )

            command = [sys.executable, "-I", "-B", script_name]
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
            suite_id=suite.suite_id,
            suite_name=suite.suite_name,
            command=[sys.executable, "-I", "-B", suite.script_name],
            timeout_seconds=self.timeout_seconds,
            deterministic_fingerprint=self._fingerprint(
                [sys.executable, "-I", "-B", suite.script_name],
                artifact_id,
                normalized_language,
                suite.suite_id,
            ),
            language=normalized_language,
        )
        return DynamicExecutionArtifact(
            artifact_id=f"DYN-{artifact_id}-{index}",
            suite_id=suite.suite_id,
            suite_name=suite.suite_name,
            duration_seconds=duration_seconds,
            return_code=return_code,
            timed_out=timed_out,
            stdout=trimmed_stdout,
            stderr=trimmed_stderr,
            replay=replay,
        )

    def _to_violations(
        self,
        timed_out: bool,
        return_code: Optional[int],
        stderr: str,
        stdout: str,
        suite_id: str,
        suite_name: str,
    ) -> list[Violation]:
        detector = f"dynamic_sandbox:{suite_id}"
        if timed_out:
            return [
                Violation(
                    rule_id="DYN-EXEC-TIMEOUT",
                    description=(
                        f"Dynamic suite '{suite_name}' exceeded sandbox timeout; runtime safety could not be established."
                    ),
                    line=None,
                    evidence=f"timeout_seconds={self.timeout_seconds}",
                    detector=detector,
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
                        f"Dynamic suite '{suite_name}' raised an exception in sandboxed runtime analysis."
                    ),
                    line=None,
                    evidence=evidence[:500],
                    detector=detector,
                    severity="high",
                )
            ]

        evidence = stderr or stdout or f"return_code={return_code}"
        return [
            Violation(
                rule_id="DYN-EXEC-CRASH",
                description=f"Dynamic suite '{suite_name}' exited with non-zero status in sandboxed analysis.",
                line=None,
                evidence=evidence[:500],
                detector=detector,
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

    def _fingerprint(self, command: list[str], artifact_id: str, language: str, suite_id: str) -> str:
        payload = {
            "runner": self.RUNNER,
            "suite_id": suite_id,
            "command": command,
            "timeout_seconds": self.timeout_seconds,
            "artifact_id": artifact_id,
            "language": language,
            "memory_limit_mb": self.memory_limit_mb,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _build_python_suites(self, code: str) -> list["DynamicSuite"]:
        suites = [
            DynamicSuite(
                suite_id="direct_execution",
                suite_name="Direct Script Execution",
                script_name="artifact.py",
                script_content=None,
            ),
            DynamicSuite(
                suite_id="import_execution",
                suite_name="Module Import Execution",
                script_name="import_harness.py",
                script_content=self._import_harness_script(),
            ),
        ]
        for entrypoint in self._discover_entrypoints(code):
            suites.append(
                DynamicSuite(
                    suite_id=f"entrypoint_{entrypoint}",
                    suite_name=f"Entrypoint Invocation ({entrypoint})",
                    script_name=f"entrypoint_{entrypoint}.py",
                    script_content=self._entrypoint_harness_script(entrypoint),
                )
            )
        return suites

    def _import_harness_script(self) -> str:
        return (
            "import importlib.util\n"
            "spec = importlib.util.spec_from_file_location('artifact_module', 'artifact.py')\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "print('ACPG_IMPORT_OK')\n"
        )

    def _entrypoint_harness_script(self, entrypoint: str) -> str:
        safe_entrypoint = entrypoint.replace("'", "")
        return (
            "import importlib.util\n"
            f"ENTRYPOINT = '{safe_entrypoint}'\n"
            "spec = importlib.util.spec_from_file_location('artifact_module', 'artifact.py')\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "target = getattr(module, ENTRYPOINT)\n"
            "result = target()\n"
            "print(f'ACPG_ENTRYPOINT_OK:{ENTRYPOINT}:{type(result).__name__}')\n"
        )

    def _discover_entrypoints(self, code: str) -> list[str]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        candidates = {"main", "run", "handler"}
        discovered: list[str] = []
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name not in candidates:
                continue
            if not self._has_required_args(node):
                discovered.append(node.name)
        return discovered[:2]

    def _has_required_args(self, node: ast.FunctionDef) -> bool:
        positional_args = node.args.args
        defaults = node.args.defaults
        required_positional = len(positional_args) - len(defaults)
        kwonly_required = sum(1 for default in node.args.kw_defaults if default is None)
        return required_positional > 0 or kwonly_required > 0


@dataclass(frozen=True)
class DynamicSuite:
    suite_id: str
    suite_name: str
    script_name: str
    script_content: Optional[str]


_dynamic_analyzer: Optional[DynamicAnalyzer] = None


def get_dynamic_analyzer() -> DynamicAnalyzer:
    """Get or create dynamic analyzer singleton."""
    global _dynamic_analyzer
    if _dynamic_analyzer is None:
        _dynamic_analyzer = DynamicAnalyzer()
    return _dynamic_analyzer
