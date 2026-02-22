"""Unit tests for analysis.py — pure function tests with no DB or Flask dependency."""

import pytest
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analysis import (
    parse_rfc3339,
    decode_peer_id,
    build_cumulative_curve,
    build_event_histogram,
    build_piece_count_curve,
    classify_peer,
    extrapolate_finish_time,
    _adaptive_step,
)


# --- parse_rfc3339 ---

class TestParseRfc3339:
    def test_valid_utc_z(self):
        dt = parse_rfc3339('2026-02-09T05:18:37.753Z')
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 2
        assert dt.second == 37
        assert dt.tzinfo is not None

    def test_valid_offset(self):
        dt = parse_rfc3339('2026-02-09T05:18:37+00:00')
        assert dt is not None
        assert dt.year == 2026

    def test_none(self):
        assert parse_rfc3339(None) is None

    def test_empty_string(self):
        assert parse_rfc3339('') is None

    def test_non_string(self):
        assert parse_rfc3339(12345) is None

    def test_garbage(self):
        assert parse_rfc3339('not-a-date') is None


# --- decode_peer_id ---

class TestDecodePeerId:
    def test_none(self):
        assert decode_peer_id(None) == ''

    def test_str_passthrough(self):
        assert decode_peer_id('-qB4530-abc') == '-qB4530-abc'

    def test_all_ascii_bytes(self):
        raw = b'-qB4530-abcdefgh'
        assert decode_peer_id(raw) == '-qB4530-abcdefgh'

    def test_mixed_bytes(self):
        # ASCII prefix followed by non-printable bytes
        raw = b'-qB4530-' + bytes([0x01, 0xFF, 0x00, 0xAB])
        result = decode_peer_id(raw)
        assert result == '-qB4530-01ff00ab'

    def test_all_binary(self):
        raw = bytes([0x00, 0x01, 0x02])
        assert decode_peer_id(raw) == '000102'

    def test_empty_bytes(self):
        assert decode_peer_id(b'') == ''


# --- build_cumulative_curve ---

class TestBuildCumulativeCurve:
    def test_basic(self):
        # 3 pieces arriving at 1.5s, 3.2s, 5.0s; piece_count=10
        times = [1.5, 3.2, 5.0]
        secs, counts = build_cumulative_curve(times, 10)
        assert len(secs) > 0
        assert len(secs) == len(counts)
        # After second 5, should have 3 pieces
        assert counts[-1] == 3

    def test_empty(self):
        secs, counts = build_cumulative_curve([], 100)
        assert secs == []
        assert counts == []

    def test_zero_piece_count(self):
        secs, counts = build_cumulative_curve([1.0], 0)
        assert secs == []
        assert counts == []

    def test_unsorted_input(self):
        # Should sort internally
        times = [5.0, 1.0, 3.0]
        secs, counts = build_cumulative_curve(times, 10)
        assert counts[-1] == 3
        # Counts should be non-decreasing
        for i in range(1, len(counts)):
            assert counts[i] >= counts[i - 1]

    def test_all_at_same_time(self):
        times = [2.0, 2.0, 2.0]
        secs, counts = build_cumulative_curve(times, 3)
        assert counts[-1] == 3

    def test_sub_second_race(self):
        # Fast race completing in ~0.15s — should produce multiple sample points
        times = [0.05 + i * 0.0004 for i in range(246)]  # 246 pieces in 0.15s
        secs, counts = build_cumulative_curve(times, 246)
        assert len(secs) >= 3, f"expected multiple points for sub-second race, got {len(secs)}"
        assert counts[-1] == 246
        # All elapsed values should be in seconds
        assert all(isinstance(s, float) for s in secs)

    def test_long_race_capped(self):
        # 1-hour race — should not produce 3600+ sample points
        times = [float(i) for i in range(3600)]
        secs, counts = build_cumulative_curve(times, 3600)
        assert len(secs) <= 600, f"expected capped points for long race, got {len(secs)}"
        assert counts[-1] == 3600


# --- build_piece_count_curve ---

class TestBuildPieceCountCurve:
    def test_basic(self):
        times = [0.5, 1.2, 3.8]
        curve = build_piece_count_curve(times, 5)
        assert len(curve) == 6  # 0..5
        assert curve[0] == 0
        assert curve[1] == 1   # 0.5 <= 1
        assert curve[2] == 2   # 1.2 <= 2
        assert curve[3] == 2
        assert curve[4] == 3   # 3.8 <= 4
        assert curve[5] == 3

    def test_empty(self):
        curve = build_piece_count_curve([], 3)
        assert curve == [0, 0, 0, 0]

    def test_all_before_start(self):
        times = [-2.0, -1.0]
        curve = build_piece_count_curve(times, 3)
        assert curve[0] == 2  # both <= 0
        assert curve[3] == 2


# --- classify_peer ---

class TestClassifyPeer:
    def _make_curves(self, our_pieces_per_sec, peer_pieces_per_sec, duration):
        """Helper: build linear cumulative curves."""
        our = [min(i * our_pieces_per_sec, 100) for i in range(duration + 1)]
        peer = [min(i * peer_pieces_per_sec, 100) for i in range(duration + 1)]
        return our, peer

    def test_seeder(self):
        # Peer has 90 pre-race pieces out of 100 piece_count
        our = [i for i in range(101)]    # 0..100
        peer = [100] * 101               # all pieces from start
        result = classify_peer(peer, our, 100, 100, 90)
        assert result is not None
        assert result['category'] == 'seeder'

    def test_competitive(self):
        # Peer consistently 10% ahead for the whole race
        our = list(range(0, 101))          # 0..100 pieces over 100 seconds
        peer = [min(i + 10, 100) for i in range(101)]  # 10 pieces ahead
        result = classify_peer(peer, our, 100, 100, 0)
        assert result is not None
        assert result['category'] == 'competitive'
        assert result['ahead_secs'] > 0
        assert result['avg_lead_pct'] >= 2.0

    def test_same_speed_skip(self):
        # Both at the same rate — should not be classified as faster
        curve = list(range(0, 101))
        result = classify_peer(curve, curve, 100, 100, 0)
        assert result is None

    def test_slower_skip(self):
        # Peer is slower than us
        our = list(range(0, 101))
        peer = [i // 2 for i in range(101)]
        result = classify_peer(peer, our, 100, 100, 0)
        assert result is None

    def test_brief_lead_skip(self):
        # Peer leads for only 2 seconds out of 100 — below threshold
        our = list(range(0, 101))
        peer = list(range(0, 101))
        peer[10] = our[10] + 5
        peer[11] = our[11] + 5
        result = classify_peer(peer, our, 100, 100, 0)
        assert result is None


# --- extrapolate_finish_time ---

class TestExtrapolateFinishTime:
    def test_nearly_done(self):
        # 96 of 100 pieces at second 50 — should return 50
        secs = [10, 20, 30, 40, 50]
        counts = [20, 40, 60, 80, 96]
        result = extrapolate_finish_time(secs, counts, 100)
        assert result == 50

    def test_linear_projection(self):
        # Linear 10 pieces/10s, at 50 pieces at second 50 → project 100 at 100s
        secs = [10, 20, 30, 40, 50]
        counts = [10, 20, 30, 40, 50]
        result = extrapolate_finish_time(secs, counts, 100)
        assert result is not None
        assert abs(result - 100.0) < 1.0

    def test_flat_curve(self):
        # Stuck at 30 pieces — can't extrapolate
        secs = [10, 20, 30, 40, 50]
        counts = [30, 30, 30, 30, 30]
        result = extrapolate_finish_time(secs, counts, 100)
        assert result is None

    def test_insufficient_data(self):
        # Only 1 point
        result = extrapolate_finish_time([10], [20], 100)
        assert result is None

    def test_empty(self):
        assert extrapolate_finish_time([], [], 100) is None

    def test_decreasing_curve(self):
        # Regression — shouldn't extrapolate forward
        secs = [10, 20, 30, 40, 50]
        counts = [50, 45, 40, 35, 30]
        result = extrapolate_finish_time(secs, counts, 100)
        assert result is None

    def test_slow_peer(self):
        # 2 pieces/10s, at 20 pieces at 100s → project 100 at 500s
        secs = list(range(10, 110, 10))
        counts = [2 * i for i in range(1, 11)]  # 2, 4, ..., 20
        result = extrapolate_finish_time(secs, counts, 100)
        assert result is not None
        assert abs(result - 500.0) < 5.0


# --- _adaptive_step ---

class TestAdaptiveStep:
    def test_sub_second(self):
        assert _adaptive_step(0.5) == 0.01

    def test_medium(self):
        assert _adaptive_step(15) == 0.1

    def test_long(self):
        assert _adaptive_step(100) == 1.0

    def test_very_long(self):
        step = _adaptive_step(1000)
        assert abs(step - 2.0) < 0.01


# --- build_event_histogram ---

class TestBuildEventHistogram:
    def test_basic(self):
        times = [0.5, 1.2, 1.8, 3.0]
        bins, counts = build_event_histogram(times, 1.0)
        assert bins == [0.0, 1.0, 2.0, 3.0]
        assert counts == [1, 2, 0, 1]

    def test_empty(self):
        assert build_event_histogram([], 1.0) == ([], [])

    def test_sub_second(self):
        times = [0.01, 0.02, 0.05, 0.10]
        bins, counts = build_event_histogram(times, 0.01)
        assert len(bins) >= 10
        assert sum(counts) == 4

    def test_unsorted_input(self):
        times = [3.0, 0.5, 1.8, 1.2]
        bins, counts = build_event_histogram(times, 1.0)
        assert counts == [1, 2, 0, 1]

    def test_all_same_bin(self):
        times = [0.1, 0.2, 0.3]
        bins, counts = build_event_histogram(times, 1.0)
        assert bins == [0.0]
        assert counts == [3]
