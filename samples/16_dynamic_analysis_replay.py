"""
Sample 16: Dynamic analysis replay artifact target
Violations: SEC-003, CRYPTO-001

Purpose:
- Trigger deterministic dynamic execution artifacts (direct/import/entrypoint paths).
- Use with dynamic analysis enabled to inspect replay fingerprints in History and Proof views.
"""

import hashlib
import os


def unsafe_runtime_transform(expr: str) -> str:
    # SEC-003
    return str(eval(expr))


def weak_runtime_hash(value: str) -> str:
    # CRYPTO-001
    return hashlib.md5(value.encode()).hexdigest()


def run_dynamic_path() -> None:
    mode = os.environ.get("ACPG_DYNAMIC_MODE", "demo")
    result = unsafe_runtime_transform("6 * 7")
    digest = weak_runtime_hash("dynamic-artifact")

    if mode == "fail":
        raise RuntimeError("intentional dynamic failure path for replay testing")

    print(f"mode={mode}; result={result}; digest={digest}")


if __name__ == "__main__":
    run_dynamic_path()
