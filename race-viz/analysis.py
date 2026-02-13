"""Pure analysis functions for race-monitor visualization.

All functions are stateless — no database or Flask imports. This makes them
independently testable and reusable across different contexts.
"""

from datetime import datetime


def parse_rfc3339(ts):
    """Parse RFC 3339 timestamp string into a datetime. Returns None on failure."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def decode_peer_id(raw):
    """Decode BT peer_id BLOB for display.

    Client prefix (e.g. '-qB4530-') is ASCII; remaining bytes are arbitrary.
    Returns the ASCII-safe prefix plus hex for any non-printable tail bytes.
    """
    if raw is None:
        return ''
    if isinstance(raw, str):
        return raw
    prefix = []
    for b in raw:
        if 0x20 <= b < 0x7F:
            prefix.append(chr(b))
        else:
            break
    tail = raw[len(prefix):]
    return ''.join(prefix) + (tail.hex() if tail else '')


def build_cumulative_curve(piece_times, piece_count):
    """Build (elapsed_secs, completion_pcts) from sorted elapsed-second floats.

    Args:
        piece_times: List of elapsed seconds (floats) when each piece arrived.
                     Need not be sorted — will be sorted internally.
        piece_count: Total pieces in the torrent (for percentage calculation).

    Returns:
        (elapsed_secs, completion_pcts) — parallel lists sampled at 1-second
        boundaries. Only emits a point when the cumulative count changes.
    """
    if not piece_times or piece_count <= 0:
        return [], []

    times = sorted(piece_times)
    elapsed_secs = []
    completion_pcts = []
    piece_idx = 0
    max_sec = int(times[-1]) + 1

    for sec in range(0, max_sec + 1):
        while piece_idx < len(times) and times[piece_idx] <= sec:
            piece_idx += 1
        if piece_idx > 0 and (
            not elapsed_secs
            or piece_idx != int(completion_pcts[-1] * piece_count / 100)
            if completion_pcts
            else True
        ):
            elapsed_secs.append(sec)
            completion_pcts.append(round(100.0 * piece_idx / piece_count, 2))

    return elapsed_secs, completion_pcts


def build_piece_count_curve(sorted_times, duration):
    """Build array where curve[t] = cumulative pieces by second t.

    Args:
        sorted_times: Pre-sorted list of elapsed seconds when pieces arrived.
        duration: Length of array to build (inclusive, so array has duration+1 entries).

    Returns:
        List of ints, length duration+1. curve[t] = total pieces acquired by second t.
    """
    curve = [0] * (duration + 1)
    cum = 0
    ei = 0
    total = len(sorted_times)
    for sec in range(duration + 1):
        while ei < total and sorted_times[ei] <= sec:
            cum += 1
            ei += 1
        curve[sec] = cum
    return curve


def classify_peer(peer_curve, our_curve, piece_count, race_duration, pre_race_count):
    """Compare peer vs our cumulative curve to determine if peer is faster.

    Args:
        peer_curve: List[int] — peer's cumulative piece count per second.
        our_curve: List[int] — our cumulative piece count per second.
        piece_count: Total pieces in the torrent.
        race_duration: Duration in seconds (length of curves - 1).
        pre_race_count: Number of pieces peer had before our first we_have.

    Returns:
        Dict with {category, ahead_secs, avg_lead_pct, max_lead_pct} or None
        if the peer is not meaningfully faster.

    Classification:
        - 'seeder': pre_race_count >= 80% of piece_count
        - 'competitive': ahead >= max(5, 10% duration) AND avg_lead >= 2%
        - None: not meaningfully faster
    """
    is_seeder = pre_race_count >= piece_count * 0.8

    ahead_secs = 0
    total_lead_pct = 0.0
    max_lead_pct = 0.0

    for sec in range(min(len(peer_curve), len(our_curve))):
        our_pct = 100.0 * our_curve[sec] / piece_count
        peer_pct = 100.0 * peer_curve[sec] / piece_count
        lead = peer_pct - our_pct
        if lead > 0:
            ahead_secs += 1
            total_lead_pct += lead
            if lead > max_lead_pct:
                max_lead_pct = lead

    avg_lead_pct = total_lead_pct / ahead_secs if ahead_secs > 0 else 0

    if is_seeder:
        category = 'seeder'
    elif ahead_secs >= max(5, race_duration * 0.10) and avg_lead_pct >= 2.0:
        category = 'competitive'
    else:
        return None

    return {
        'category': category,
        'ahead_secs': ahead_secs,
        'avg_lead_pct': round(avg_lead_pct, 1),
        'max_lead_pct': round(max_lead_pct, 1),
    }


def extrapolate_finish_time(elapsed_secs, completion_pcts, piece_count):
    """Project when a peer reaches 100% completion via linear extrapolation.

    Uses the last N data points (up to 10) to fit a line and project forward.

    Args:
        elapsed_secs: List of elapsed second values (from build_cumulative_curve).
        completion_pcts: Parallel list of completion percentages.
        piece_count: Total pieces (unused directly but kept for interface symmetry).

    Returns:
        Projected elapsed seconds to reach 100%, or None if:
        - Insufficient data (< 2 points)
        - Flat or decreasing curve (slope <= 0)
        - Already >= 95% complete (returns last elapsed_sec as actual finish)
    """
    if not elapsed_secs or not completion_pcts:
        return None

    last_pct = completion_pcts[-1]
    last_sec = elapsed_secs[-1]

    # Nearly done — use actual observed time
    if last_pct >= 95.0:
        return last_sec

    # Need at least 2 points for slope
    n = min(len(elapsed_secs), 10)
    if n < 2:
        return None

    xs = elapsed_secs[-n:]
    ys = completion_pcts[-n:]

    # Simple linear regression
    x_mean = sum(xs) / n
    y_mean = sum(ys) / n
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    den = sum((x - x_mean) ** 2 for x in xs)

    if den == 0 or num <= 0:
        return None  # flat or decreasing

    slope = num / den  # pct per second
    remaining = 100.0 - last_pct
    return round(last_sec + remaining / slope, 1)
