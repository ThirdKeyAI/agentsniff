"""Tests for SSE response pattern detector."""

from agentsniff.config import ScanConfig
from agentsniff.detectors.sse_detector import SSEResponseDetector, detect_sse_timing_pattern
from agentsniff.models import DetectorType


def test_sse_timing_pattern_detected():
    """Token-by-token streaming has characteristic small-gap timing."""
    packet_times = [i * 0.03 for i in range(50)]
    packet_sizes = [50] * 50
    result = detect_sse_timing_pattern(packet_times, packet_sizes)
    assert result["is_sse_streaming"] is True
    assert result["confidence"] >= 0.7


def test_bulk_transfer_not_detected_as_sse():
    """Large bulk transfer should not be detected as SSE streaming."""
    packet_times = [0.0, 0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009]
    packet_sizes = [65535] * 10
    result = detect_sse_timing_pattern(packet_times, packet_sizes)
    assert result["is_sse_streaming"] is False


def test_sparse_traffic_not_detected():
    """Infrequent packets should not be detected as SSE."""
    packet_times = [0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0, 35.0, 40.0, 45.0]
    packet_sizes = [100] * 10
    result = detect_sse_timing_pattern(packet_times, packet_sizes)
    assert result["is_sse_streaming"] is False


def test_too_few_packets():
    """Fewer than min_packets should not trigger."""
    packet_times = [0.0, 0.03, 0.06]
    packet_sizes = [50, 50, 50]
    result = detect_sse_timing_pattern(packet_times, packet_sizes)
    assert result["is_sse_streaming"] is False
    assert result["confidence"] == 0.0


def test_detector_type_exists():
    """SSE_DETECTOR should be in DetectorType enum."""
    assert hasattr(DetectorType, "SSE_DETECTOR")
    assert DetectorType.SSE_DETECTOR.value == "sse_detector"


def test_detector_creation():
    config = ScanConfig()
    det = SSEResponseDetector(config)
    assert det.name == "sse_detector"


def test_high_packet_count_increases_confidence():
    """More packets should increase confidence."""
    times_20 = [i * 0.03 for i in range(20)]
    times_40 = [i * 0.03 for i in range(40)]
    r50 = detect_sse_timing_pattern(times_20, [50] * 20)
    r100 = detect_sse_timing_pattern(times_40, [50] * 40)
    assert r100["confidence"] > r50["confidence"]
