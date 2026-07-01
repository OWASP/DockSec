"""Unit tests for docksec.enums helpers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from docksec.enums import Severity


def test_rank_ordering_is_descending_by_severity():
    assert Severity.rank("CRITICAL") > Severity.rank("HIGH")
    assert Severity.rank("HIGH") > Severity.rank("MEDIUM")
    assert Severity.rank("MEDIUM") > Severity.rank("LOW")
    assert Severity.rank("LOW") > Severity.rank("UNKNOWN")


def test_rank_is_case_insensitive_and_safe():
    assert Severity.rank("critical") == Severity.rank("CRITICAL")
    assert Severity.rank(" High ") == Severity.rank("HIGH")
    assert Severity.rank(None) == 0
    assert Severity.rank("not-a-severity") == 0


def test_gate_levels_are_the_four_real_severities_most_severe_first():
    assert Severity.gate_levels() == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert "UNKNOWN" not in Severity.gate_levels()
