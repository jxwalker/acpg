"""Tests for ASP argumentation export/encodings (no clingo required)."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.models.schemas import Argument, Attack, ArgumentationGraph, SetAttack
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


def test_export_set_attacks_to_asp():
    graph = ArgumentationGraph(
        arguments=[
            Argument(id="A", rule_id="R1", type="compliance"),
            Argument(id="B", rule_id="R2", type="compliance"),
            Argument(id="C", rule_id="R3", type="violation"),
        ],
        attacks=[],
        set_attacks=[SetAttack(attackers=["A", "B"], target="C")],
    )
    asp = export_dung_af_to_asp(graph)
    assert 'set_att("S0", "C").' in asp
    assert 'set_mem("S0", "A").' in asp
    assert 'set_mem("S0", "B").' in asp


def test_stable_semantics_program_has_show():
  prog = stable_semantics_program()
  assert "#show in/1." in prog
  assert "set_att(" in prog


def test_admissible_semantics_program_has_show():
  prog = admissible_semantics_program()
  assert "#show in/1." in prog
  assert "defeated_set" in prog


def test_filter_maximal_by_inclusion():
  sets = [["a"], ["a", "b"], ["b"], ["c"], ["b", "c"]]
  preferred = filter_maximal_by_inclusion(sets)
  assert sorted(preferred) == sorted([["a", "b"], ["b", "c"]])
