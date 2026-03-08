"""Tests for traffic analyzer behavioral heuristics."""
from agentsniff.detectors.traffic_analyzer import HostProfile, detect_ora_loop


def test_ora_loop_detected_in_typical_pattern():
    """LLM call -> pause -> tool calls -> LLM call pattern detected."""
    timestamps = [0.0, 2.0, 2.1, 2.2, 4.0]
    is_llm = [True, False, False, False, True]
    assert detect_ora_loop(timestamps, is_llm) >= 1


def test_ora_loop_not_detected_in_uniform_polling():
    """Uniform polling (cron-like) should not trigger ORA detection."""
    timestamps = [0.0, 5.0, 10.0, 15.0, 20.0]
    is_llm = [False, False, False, False, False]
    assert detect_ora_loop(timestamps, is_llm) == 0


def test_ora_loop_not_detected_in_random_traffic():
    """Random traffic without LLM calls should not trigger."""
    timestamps = [0.0, 0.5, 3.0, 3.2, 7.0]
    is_llm = [False, False, False, False, False]
    assert detect_ora_loop(timestamps, is_llm) == 0


def test_ora_loop_multiple_cycles():
    """Multiple ORA cycles detected in longer session."""
    timestamps = [0.0, 2.0, 2.1, 2.2, 4.0, 6.0, 6.1, 8.0]
    is_llm = [True, False, False, False, True, False, False, True]
    assert detect_ora_loop(timestamps, is_llm) >= 2


def test_ora_loop_too_short_gap():
    """Gap shorter than min_tool_gap should not count."""
    timestamps = [0.0, 0.1, 0.15, 0.2, 0.5]
    is_llm = [True, False, False, False, True]
    assert detect_ora_loop(timestamps, is_llm) == 0


def test_ora_loop_too_long_gap():
    """Gap longer than max_tool_gap should not count."""
    timestamps = [0.0, 15.0, 15.1, 15.2, 20.0]
    is_llm = [True, False, False, False, True]
    assert detect_ora_loop(timestamps, is_llm) == 0


def test_behavior_score_includes_ora_bonus():
    """ORA loop detection should boost behavior score."""
    profile = HostProfile(ip="10.0.0.1")
    profile.llm_api_connections = 2
    profile.ora_loop_count = 2
    assert profile.agent_behavior_score >= 0.55


def test_behavior_score_without_ora():
    """Without ORA loops, score should not include ORA bonus."""
    profile = HostProfile(ip="10.0.0.1")
    profile.llm_api_connections = 1
    profile.ora_loop_count = 0
    assert profile.agent_behavior_score == 0.4


def test_ora_loop_single_tool_call():
    """Single tool call between LLM calls should count."""
    timestamps = [0.0, 2.0, 4.0]
    is_llm = [True, False, True]
    assert detect_ora_loop(timestamps, is_llm) == 1


def test_ora_loop_empty_input():
    """Empty or too-short input returns 0."""
    assert detect_ora_loop([], []) == 0
    assert detect_ora_loop([1.0], [True]) == 0
    assert detect_ora_loop([1.0, 2.0], [True, False]) == 0
