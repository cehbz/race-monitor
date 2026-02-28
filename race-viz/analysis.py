"""Pure analysis functions for race-monitor visualization.

All functions are stateless — no database or Flask imports. This makes them
independently testable and reusable across different contexts.
"""

from datetime import datetime


# Maps ASN → clean infrastructure/hosting provider name.
# Used to build "Brand @ Infrastructure" display strings when the end-user
# brand (from rDNS tier-1) is a reseller on shared hosting.
_ASN_INFRA = {
    60781:  'Leaseweb',
    24940:  'Hetzner',
    16276:  'OVH',
    197540: 'netcup',
    43350:  'NForce',
    49981:  'WorldStream',
    49453:  'Global Layer',
    8473:   'Bahnhof',
    60068:  'DataPacket',
    212238: 'DataPacket',
    11878:  'tzulo',
    12876:  'Scaleway',
    # Providers with their own ASN and IP space — brand == network operator,
    # so no "@" needed (they colocate in third-party DCs but own the BGP layer)
    208959: 'Ultra.cc',
    200052: 'Feral',
    394151: 'Whatbox',
    205689: 'Whatbox',
    139225: 'Whatbox',
    202954: 'Seedboxes.cc',
    211839: 'seedit4.me',
}


def format_provider(brand, asn):
    """Build display string combining end-user brand with infrastructure.

    Returns "Brand @ Infra" when the brand is a reseller on shared hosting,
    or just "Brand" / "Infra" when they are the same entity.
    """
    infra = _ASN_INFRA.get(asn or 0, '')
    if brand and infra and brand.lower() != infra.lower():
        return f'{brand} @ {infra}'
    return brand or infra or ''


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


def _adaptive_step(span):
    """Choose sampling step size based on time span.

        < 2s    → 10ms steps
        < 30s   → 100ms steps
        < 300s  → 1s steps
        >= 300s → span / 500 (caps at ~500 points)
    """
    if span < 2:
        return 0.01
    elif span < 30:
        return 0.1
    elif span < 300:
        return 1.0
    else:
        return span / 500


def build_cumulative_curve(piece_times, piece_count):
    """Build (elapsed_secs, piece_counts) from elapsed-second floats.

    Args:
        piece_times: List of elapsed seconds (floats) when each piece arrived.
                     Need not be sorted — will be sorted internally.
        piece_count: Total pieces in the torrent (used only for validation).

    Returns:
        (elapsed_secs, piece_counts) — parallel lists with adaptive sampling
        resolution. Only emits a point when the cumulative count changes.
        elapsed_secs are always in seconds (floats).
    """
    if not piece_times or piece_count <= 0:
        return [], []

    times = sorted(piece_times)
    span = times[-1]
    step = _adaptive_step(span)

    elapsed_secs = []
    cumulative_pieces = []
    piece_idx = 0
    num_steps = int(span / step) + 2  # +2 for rounding and final point

    for i in range(num_steps):
        t = round(i * step, 3)
        while piece_idx < len(times) and times[piece_idx] <= t:
            piece_idx += 1
        if piece_idx > 0 and (
            not cumulative_pieces
            or piece_idx != cumulative_pieces[-1]
        ):
            elapsed_secs.append(t)
            cumulative_pieces.append(piece_idx)

    return elapsed_secs, cumulative_pieces


def build_event_histogram(times, step):
    """Bucket event times into bins of width `step`.

    Args:
        times: List of elapsed-second floats. Need not be sorted.
        step: Bin width in seconds (from _adaptive_step).

    Returns:
        (bin_starts, counts) — parallel lists. bin_starts[i] is the left edge
        of the bin, counts[i] is the number of events in [bin_start, bin_start+step).
    """
    if not times:
        return [], []
    sorted_t = sorted(times)
    span = sorted_t[-1]
    num_bins = int(span / step) + 1
    counts = [0] * num_bins
    for t in sorted_t:
        idx = min(int(t / step), num_bins - 1)
        counts[idx] += 1
    bin_starts = [round(i * step, 3) for i in range(num_bins)]
    return bin_starts, counts


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


def extrapolate_finish_time(elapsed_secs, piece_counts, piece_count):
    """Project when a peer reaches piece_count via linear extrapolation.

    Uses the last N data points (up to 10) to fit a line and project forward.

    Args:
        elapsed_secs: List of elapsed second values (from build_cumulative_curve).
        piece_counts: Parallel list of cumulative piece counts.
        piece_count: Total pieces in the torrent.

    Returns:
        Projected elapsed seconds to reach piece_count, or None if:
        - Insufficient data (< 2 points)
        - Flat or decreasing curve (slope <= 0)
        - Already >= 95% complete (returns last elapsed_sec as actual finish)
    """
    if not elapsed_secs or not piece_counts:
        return None

    last_pieces = piece_counts[-1]
    last_sec = elapsed_secs[-1]

    # Nearly done — use actual observed time
    if last_pieces >= piece_count * 0.95:
        return last_sec

    # Need at least 2 points for slope
    n = min(len(elapsed_secs), 10)
    if n < 2:
        return None

    xs = elapsed_secs[-n:]
    ys = piece_counts[-n:]

    # Simple linear regression
    x_mean = sum(xs) / n
    y_mean = sum(ys) / n
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    den = sum((x - x_mean) ** 2 for x in xs)

    if den == 0 or num <= 0:
        return None  # flat or decreasing

    slope = num / den  # pieces per second
    remaining = piece_count - last_pieces
    return round(last_sec + remaining / slope, 1)
