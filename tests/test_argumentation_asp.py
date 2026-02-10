"""Tests for ASP argumentation export/encodings (no clingo required)."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.models.schemas import Argument, Attack, ArgumentationGraph
from backend.app.services.argumentation_asp import (
  export_dung_af_to_asp,
  stable_semantics_program,
  admissible_semantics_program,
  filter_maximal_by_inclusion,
)


def test_export_dung_af_to_asp():
    graph = ArgumentationGraph(
        arguments=[
            Argument(id="A", rule_id="R1", type="compliance"),
            Argument(id="B", rule_id="R2", type="violation"),
        ],
        attacks=[Attack(attacker="A", target="B")],
    )
    asp = export_dung_af_to_asp(graph)
    assert 'arg("A").' in asp
    assert 'arg("B").' in asp
    assert 'att("A", "B").' in asp


def test_stable_semantics_program_has_show():
  prog = stable_semantics_program()
  assert "#show in/1." in prog


def test_admissible_semantics_program_has_show():
  prog = admissible_semantics_program()
  assert "#show in/1." in prog


def test_filter_maximal_by_inclusion():
  sets = [["a"], ["a", "b"], ["b"], ["c"], ["b", "c"]]
  preferred = filter_maximal_by_inclusion(sets)
  assert sorted(preferred) == sorted([["a", "b"], ["b", "c"]])
