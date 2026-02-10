"""ASP-based argumentation semantics (optional).

This module is used to compute stable/preferred extensions using clingo when available.
It is intentionally optional: the core ACPG decision path remains grounded semantics.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Sequence

from ..models.schemas import ArgumentationGraph


@dataclass
class AspResult:
    """Result from an ASP semantics computation."""

    extensions: List[List[str]]
    raw: Dict


def admissible_semantics_program() -> str:
    """ASP encoding for admissible sets in a Dung AF."""
    return """
% Choose a candidate set
{in(X)} :- arg(X).

% Conflict-free
:- in(X), in(Y), att(X,Y).

% An attacker is defeated if it is attacked by some in-argument
defeated(Y) :- in(Z), att(Z,Y).

% Admissible: each in-argument is defended against every attacker
:- in(X), att(Y,X), not defeated(Y).

#show in/1.
""".lstrip()


def filter_maximal_by_inclusion(sets: List[List[str]]) -> List[List[str]]:
    """Keep only sets that are maximal w.r.t. subset inclusion."""
    normalized = [sorted(set(s)) for s in sets]
    as_sets = [set(s) for s in normalized]
    maximal: List[List[str]] = []
    for i, s in enumerate(as_sets):
        is_subset = False
        for j, t in enumerate(as_sets):
            if i == j:
                continue
            if s.issubset(t) and s != t:
                is_subset = True
                break
        if not is_subset:
            maximal.append(sorted(s))
    # De-dupe
    uniq = []
    seen = set()
    for s in maximal:
        key = tuple(s)
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq


def export_dung_af_to_asp(graph: ArgumentationGraph) -> str:
    """Export a (binary-attack) Dung AF to ASP facts."""
    lines: List[str] = []
    for arg in graph.arguments:
        lines.append(f"arg({json.dumps(arg.id)}).")
    for att in graph.attacks:
        lines.append(f"att({json.dumps(att.attacker)}, {json.dumps(att.target)}).")
    # Joint attacks exist in ACPG, but solver encodings are not implemented yet.
    if getattr(graph, "set_attacks", None):
        lines.append("% NOTE: joint attacks are present but are ignored by this encoding.")
    return "\n".join(lines) + "\n"


def stable_semantics_program() -> str:
    """ASP encoding for stable extensions in Dung AF."""
    return """
% Choose an extension
{in(X)} :- arg(X).

% Conflict-free
:- in(X), in(Y), att(X,Y).

% Attacked arguments are out
out(X) :- in(Y), att(Y,X).

% Stable: every argument is either in or out
:- arg(X), not in(X), not out(X).

#show in/1.
""".lstrip()


def run_clingo(programs: Sequence[str], *, clingo_path: str = "clingo", timeout_s: int = 15) -> Dict:
    """Run clingo with JSON output and return parsed JSON."""
    cmd = [clingo_path, "--outf=2", "-n", "0", "-"]
    proc = subprocess.run(
        cmd,
        input="\n".join(programs),
        text=True,
        capture_output=True,
        timeout=timeout_s,
        check=False,
    )
    if proc.returncode not in (0, 10, 20):  # 10/20 are common for SAT/UNSAT
        raise RuntimeError(f"clingo failed (code={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
    try:
        return json.loads(proc.stdout)
    except Exception as e:
        raise RuntimeError(f"Failed to parse clingo JSON output: {e}. Output: {proc.stdout[:1000]}")


def parse_in_atoms(clingo_json: Dict) -> List[List[str]]:
    """Extract extensions as list of argument IDs from clingo JSON."""
    exts: List[List[str]] = []
    calls = clingo_json.get("Call", [])
    for call in calls:
        witnesses = call.get("Witnesses", []) or []
        for w in witnesses:
            values = w.get("Value", []) or []
            in_args = []
            for atom in values:
                # atom looks like: in("A") or in(A) depending on quoting
                if atom.startswith("in(") and atom.endswith(")"):
                    inner = atom[3:-1]
                    try:
                        # try JSON string first (we emit json.dumps ids)
                        in_args.append(json.loads(inner))
                    except Exception:
                        in_args.append(inner.strip('"'))
            exts.append(sorted(in_args))
    return exts


def compute_stable_extensions(
    graph: ArgumentationGraph,
    *,
    clingo_path: str = "clingo",
    timeout_s: int = 15,
) -> AspResult:
    """Compute stable extensions (if any) for a Dung AF.

    Note: joint attacks are not supported yet for solver semantics.
    """
    if getattr(graph, "set_attacks", None):
        raise ValueError("Stable semantics via ASP is not implemented for joint attacks yet.")

    facts = export_dung_af_to_asp(graph)
    encoding = stable_semantics_program()
    raw = run_clingo([facts, encoding], clingo_path=clingo_path, timeout_s=timeout_s)
    return AspResult(extensions=parse_in_atoms(raw), raw=raw)


def compute_preferred_extensions(
    graph: ArgumentationGraph,
    *,
    clingo_path: str = "clingo",
    timeout_s: int = 15,
) -> AspResult:
    """Compute preferred extensions (maximal admissible sets).

    Implementation strategy:
    1. Enumerate all admissible sets with clingo.
    2. Filter to those maximal w.r.t. subset inclusion (preferred extensions).
    """
    if getattr(graph, "set_attacks", None):
        raise ValueError("Preferred semantics via ASP is not implemented for joint attacks yet.")

    facts = export_dung_af_to_asp(graph)
    encoding = admissible_semantics_program()
    raw = run_clingo([facts, encoding], clingo_path=clingo_path, timeout_s=timeout_s)
    admissible = parse_in_atoms(raw)
    preferred = filter_maximal_by_inclusion(admissible)
    return AspResult(extensions=preferred, raw=raw)
