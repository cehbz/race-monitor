"""Browser integration tests for the race monitor dashboard UI.

Uses Playwright to test JavaScript behaviour (column rendering, peer
highlighting, sorting) that cannot be tested with pure Python unit tests.

API responses are mocked at the Playwright network layer so tests are
deterministic and do not depend on live database content.

Mock peer topology used throughout:
  Self    (self)             —        —                ← us, finished at 50s
  Seeder  2.3.4.5:7777       —        —                ← pure seeder, finish_sec=0
  Peer A  37.48.95.71:12345  AS60781  37.48.64.0/18   ← beat us, finished at 44s
  Peer B  37.48.95.72:12346  AS60781  37.48.64.0/18   ← same ASN + segment as A
  Peer C  95.211.1.1:12347   AS60781  95.211.0.0/16   ← same ASN, different segment
  Peer D  157.90.0.1:12348   AS24940  88.99.0.0/16    ← different ASN
"""

import pytest

# ---------------------------------------------------------------------------
# Mock API payloads
# ---------------------------------------------------------------------------

_RACE = {
    'id': 1,
    'info_hash': 'a' * 40,
    'name': 'Test.Torrent',
    'size': 1_073_741_824,
    'piece_count': 100,
    'started_at': '2026-02-28T12:00:00Z',
    'completed_at': '2026-02-28T12:01:00Z',
    'start_wallclock': '2026-02-28T12:00:00Z',
    'start_ktime': None,
}

_RACE2 = {
    'id': 2,
    'info_hash': 'b' * 40,
    'name': 'Another.Torrent',
    'size': 536_870_912,
    'piece_count': 50,
    'started_at': '2026-02-27T10:00:00Z',
    'completed_at': '2026-02-27T10:02:00Z',
    'start_wallclock': '2026-02-27T10:00:00Z',
    'start_ktime': None,
}

_RACE_DETAIL = {
    'race': _RACE,
    'timeline': [],
    'peer_count': 5,
}

# Progress with non-empty histogram so bar traces are present in the chart.
_PROGRESS = {
    'piece_count': 100,
    'race_duration_secs': 60.0,
    'self': {'elapsed_secs': [0, 30, 60], 'piece_counts': [0, 50, 100]},
    'peers': [],
    'event_histogram': {
        'self_bins':   [0.0, 10.0, 20.0, 30.0, 40.0, 50.0],
        'self_counts': [5,   12,   18,   20,   25,   20],
        'peer_bins':   [0.0, 10.0, 20.0, 30.0, 40.0, 50.0],
        'peer_counts': [8,   15,   10,   12,   8,    5],
        'step': 10.0,
    },
}


def _peer(ip, port, asn, prefix, finish=45.0):
    return {
        'label': 'qBittorrent',
        'ip': ip,
        'port': port,
        'client': 'qBittorrent',
        'type': 'leecher',
        'pieces': 80,
        'ahead': 20,
        'finish_sec': finish,
        'network': {
            'rdns': 'host.example.com',
            'bgp_prefix': prefix,
            'provider': '',
            'ip_provider': '',
            'isp': f'AS{asn} ISP',
            'city': 'Amsterdam',
            'country': 'NL',
            'asn': asn,
            'asn_org': f'AS{asn} Org',
            'is_datacenter': True,
            'latitude': None,
            'longitude': None,
        },
    }


_SELF = {
    'label': 'Us', 'ip': '(self)', 'port': 0, 'client': '',
    'type': 'self', 'pieces': 100, 'ahead': 50, 'finish_sec': 50.0,
    'network': None,
}

_SEEDER = {
    'label': 'Transmission',
    'ip': '2.3.4.5', 'port': 7777, 'client': 'Transmission',
    'type': 'seeder', 'pieces': 0, 'ahead': 100, 'finish_sec': 0.0,
    'network': None,
}

PEER_A = _peer('37.48.95.71',  12345, 60781, '37.48.64.0/18', finish=44.0)
PEER_B = _peer('37.48.95.72',  12346, 60781, '37.48.64.0/18', finish=45.0)
PEER_C = _peer('95.211.1.1',   12347, 60781, '95.211.0.0/16', finish=46.0)
PEER_D = _peer('157.90.0.1',   12348, 24940, '88.99.0.0/16',  finish=47.0)

# Sorted order from server: seeder first (finish=0), then by finish_sec asc.
# Self is placed at position 2 (our_finish_sec=50, between C and D).
_PEERS = {
    'piece_count': 100,
    'our_finish_sec': 50.0,
    'participants': [_SEEDER, PEER_A, PEER_B, PEER_C, _SELF, PEER_D],
    'errors': [],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_mocks(page):
    """Intercept all /api/* requests and return controlled mock data."""
    def handle(route):
        url = route.request.url
        if '/api/races/counts' in url:
            route.fulfill(json={
                '1': {'peer_count': 5, 'event_count': 400},
                '2': {'peer_count': 2, 'event_count': 100},
            })
        elif '/api/race/1/peer_progress' in url:
            route.fulfill(json=_PROGRESS)
        elif '/api/race/1/peers' in url:
            route.fulfill(json=_PEERS)
        elif '/api/race/1' in url:
            route.fulfill(json=_RACE_DETAIL)
        elif '/api/race/2' in url:
            route.fulfill(json={'race': _RACE2, 'timeline': [], 'peer_count': 2})
        elif '/api/races' in url:
            route.fulfill(json=[_RACE, _RACE2])
        elif '/api/events' in url:
            route.fulfill(body='', content_type='text/event-stream')
        else:
            route.continue_()

    page.route('**/api/**', handle)


def _load_race(page, base_url):
    """Navigate to dashboard and open the single mock race."""
    _setup_mocks(page)
    page.goto(base_url)
    page.locator('.race-item').first.click()
    page.wait_for_selector('.peer-table')


def _click_peer(page, peer_key):
    page.locator(f'tbody tr[data-peer-key="{peer_key}"]').click()


# ---------------------------------------------------------------------------
# Column presence and data rendering
# ---------------------------------------------------------------------------

class TestPeersTableColumns:
    def test_asn_column_present(self, page, base_url):
        _load_race(page, base_url)
        headers = [h.text_content() for h in page.locator('.peer-table th').all()]
        assert 'ASN' in headers

    def test_segment_column_present(self, page, base_url):
        _load_race(page, base_url)
        headers = [h.text_content() for h in page.locator('.peer-table th').all()]
        assert 'Segment' in headers

    def test_asn_values_rendered(self, page, base_url):
        _load_race(page, base_url)
        page.wait_for_selector('.asn-cell')
        cells = page.locator('.asn-cell').all_text_contents()
        assert 'AS60781' in cells
        assert 'AS24940' in cells

    def test_segment_values_rendered(self, page, base_url):
        _load_race(page, base_url)
        page.wait_for_selector('.seg-cell')
        cells = page.locator('.seg-cell').all_text_contents()
        assert '37.48.64.0/18' in cells
        assert '88.99.0.0/16' in cells

    def test_self_row_has_no_asn(self, page, base_url):
        _load_race(page, base_url)
        self_asn = page.locator('tbody tr[data-peer-key="self"] .asn-cell').text_content()
        assert self_asn == '—'

    def test_self_row_has_no_segment(self, page, base_url):
        _load_race(page, base_url)
        self_seg = page.locator('tbody tr[data-peer-key="self"] .seg-cell').text_content()
        assert self_seg == '—'


# ---------------------------------------------------------------------------
# Peer highlighting
# ---------------------------------------------------------------------------

class TestPeerHighlighting:
    _PEER_A_KEY = '37.48.95.71:12345'
    _PEER_B_KEY = '37.48.95.72:12346'  # same ASN + same segment as A
    _PEER_C_KEY = '95.211.1.1:12347'   # same ASN, different segment
    _PEER_D_KEY = '157.90.0.1:12348'   # different ASN

    def test_clicked_row_gets_highlighted(self, page, base_url):
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        classes = page.locator(f'tbody tr[data-peer-key="{self._PEER_A_KEY}"]').get_attribute('class')
        assert 'highlighted' in classes

    def test_clicked_row_cells_not_cell_highlighted(self, page, base_url):
        """The clicked row itself must not receive cell-highlight — it has row highlight."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        asn_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_A_KEY}"] .asn-cell').get_attribute('class')
        seg_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_A_KEY}"] .seg-cell').get_attribute('class')
        assert 'cell-highlight' not in (asn_cls or '')
        assert 'cell-highlight' not in (seg_cls or '')

    def test_same_segment_peer_seg_cell_highlighted(self, page, base_url):
        """Peer B shares segment with A — seg-cell gets cell-highlight."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_B_KEY}"] .seg-cell').get_attribute('class')
        assert 'cell-highlight' in cls

    def test_same_segment_peer_asn_cell_highlighted(self, page, base_url):
        """Peer B shares ASN with A — asn-cell also gets cell-highlight."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_B_KEY}"] .asn-cell').get_attribute('class')
        assert 'cell-highlight' in cls

    def test_same_asn_only_peer_asn_cell_highlighted(self, page, base_url):
        """Peer C shares ASN but not segment — only asn-cell gets cell-highlight."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        asn_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_C_KEY}"] .asn-cell').get_attribute('class')
        seg_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_C_KEY}"] .seg-cell').get_attribute('class')
        assert 'cell-highlight' in asn_cls
        assert 'cell-highlight' not in (seg_cls or '')

    def test_different_asn_no_highlight(self, page, base_url):
        """Peer D has a different ASN — no cells highlighted."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        asn_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_D_KEY}"] .asn-cell').get_attribute('class')
        seg_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_D_KEY}"] .seg-cell').get_attribute('class')
        assert 'cell-highlight' not in (asn_cls or '')
        assert 'cell-highlight' not in (seg_cls or '')

    def test_clicking_again_clears_row_highlight(self, page, base_url):
        """Clicking the same row twice clears the row highlight."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        _click_peer(page, self._PEER_A_KEY)
        classes = page.locator(f'tbody tr[data-peer-key="{self._PEER_A_KEY}"]').get_attribute('class')
        assert 'highlighted' not in (classes or '')

    def test_clicking_again_clears_cell_highlights(self, page, base_url):
        """Clicking the same row twice clears all cell highlights."""
        _load_race(page, base_url)
        _click_peer(page, self._PEER_A_KEY)
        _click_peer(page, self._PEER_A_KEY)
        seg_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_B_KEY}"] .seg-cell').get_attribute('class')
        asn_cls = page.locator(f'tbody tr[data-peer-key="{self._PEER_C_KEY}"] .asn-cell').get_attribute('class')
        assert 'cell-highlight' not in (seg_cls or '')
        assert 'cell-highlight' not in (asn_cls or '')


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

class TestPeersTableSort:
    def test_sort_by_asn_ascending(self, page, base_url):
        """Clicking ASN header sorts peers by ASN numerically ascending."""
        _load_race(page, base_url)
        page.locator('th[data-col="asn"]').click()
        cells = page.locator('.asn-cell').all_text_contents()
        numbers = [int(c.replace('AS', '')) for c in cells if c.startswith('AS')]
        assert numbers == sorted(numbers)

    def test_sort_by_asn_descending(self, page, base_url):
        """Clicking ASN header twice sorts descending."""
        _load_race(page, base_url)
        page.locator('th[data-col="asn"]').click()
        page.locator('th[data-col="asn"]').click()
        cells = page.locator('.asn-cell').all_text_contents()
        numbers = [int(c.replace('AS', '')) for c in cells if c.startswith('AS')]
        assert numbers == sorted(numbers, reverse=True)

    def test_sort_by_segment_ascending(self, page, base_url):
        """Clicking Segment header sorts by BGP prefix lexicographically."""
        _load_race(page, base_url)
        page.locator('th[data-col="segment"]').click()
        cells = page.locator('.seg-cell').all_text_contents()
        prefixes = [c for c in cells if c != '—']
        assert prefixes == sorted(prefixes)

    def test_highlights_preserved_after_sort(self, page, base_url):
        """Cell highlights survive a column re-sort."""
        _load_race(page, base_url)
        _click_peer(page, '37.48.95.71:12345')
        # Sort by ASN — rebuilds the table HTML
        page.locator('th[data-col="asn"]').click()
        # Peer B's seg-cell should still be highlighted
        seg_cls = page.locator('tbody tr[data-peer-key="37.48.95.72:12346"] .seg-cell').get_attribute('class')
        assert 'cell-highlight' in seg_cls

    def test_sort_by_pieces_descending(self, page, base_url):
        """Pieces column sorts descending by default (click once)."""
        _load_race(page, base_url)
        page.locator('th[data-col="pieces"]').click()
        cells = page.locator('tbody td.num').all_text_contents()
        # Pieces column is index 5 (0-based: #, IP, Port, Client, Network, ASN, Seg, Pieces, Ahead, Finish)
        # Collect every 10th td starting from position 7 (Pieces column)
        rows = page.locator('tbody tr').all()
        pieces = []
        for row in rows:
            tds = row.locator('td').all_text_contents()
            if len(tds) >= 8:
                txt = tds[7].strip()
                if txt.isdigit():
                    pieces.append(int(txt))
        assert pieces == sorted(pieces, reverse=True)

    def test_sort_by_finish_ascending(self, page, base_url):
        """Finish column sorts ascending (click once)."""
        _load_race(page, base_url)
        page.locator('th[data-col="finish"]').click()
        rows = page.locator('tbody tr').all()
        finish_secs = []
        for row in rows:
            tds = row.locator('td').all_text_contents()
            if len(tds) >= 10:
                txt = tds[9].strip()  # Finish column
                # Parse e.g. "44s", "1m 5s", "seeder", "—"
                if 's' in txt and txt != '—':
                    parts = txt.replace('h', '').replace('m', '').replace('s', '').split()
                    nums = [int(p) for p in parts if p.isdigit()]
                    if len(nums) == 3:
                        secs = nums[0]*3600 + nums[1]*60 + nums[2]
                    elif len(nums) == 2:
                        secs = nums[0]*60 + nums[1]
                    elif len(nums) == 1:
                        secs = nums[0]
                    else:
                        continue
                    finish_secs.append(secs)
        assert len(finish_secs) >= 2
        assert finish_secs == sorted(finish_secs)


# ---------------------------------------------------------------------------
# Race navigation
# ---------------------------------------------------------------------------

class TestRaceNavigation:
    def test_click_race_shows_visualization(self, page, base_url):
        """Clicking a race item expands the visualization panel."""
        _setup_mocks(page)
        page.goto(base_url)
        page.wait_for_selector('.race-item')
        assert not page.locator('#visualization.active').is_visible()
        page.locator('.race-item').first.click()
        page.wait_for_selector('#visualization.active')
        assert page.locator('#visualization.active').is_visible()

    def test_click_again_hides_visualization(self, page, base_url):
        """Clicking the selected race item again collapses the visualization."""
        _setup_mocks(page)
        page.goto(base_url)
        page.locator('.race-item').first.click()
        page.wait_for_selector('#visualization.active')
        page.locator('.race-item').first.click()
        page.wait_for_function("!document.querySelector('#visualization.active')")
        assert not page.locator('#visualization.active').is_visible()

    def test_click_again_restores_all_race_items(self, page, base_url):
        """After collapsing, both race items in the list are visible again."""
        _setup_mocks(page)
        page.goto(base_url)
        page.wait_for_selector('.race-item')
        assert page.locator('.race-item').count() == 2
        page.locator('.race-item').first.click()
        page.wait_for_selector('#visualization.active')
        # While expanded, only the selected item is visible
        assert page.locator('.race-item:visible').count() == 1
        page.locator('.race-item').first.click()
        page.wait_for_function("document.querySelectorAll('.race-item:not([style*=\"display: none\"])').length === 2")
        assert page.locator('.race-item:visible').count() == 2


# ---------------------------------------------------------------------------
# Peer type display
# ---------------------------------------------------------------------------

class TestPeerTypeDisplay:
    def test_self_row_has_self_row_class(self, page, base_url):
        _load_race(page, base_url)
        assert page.locator('tbody tr.self-row').count() == 1

    def test_seeder_row_has_seeder_row_class(self, page, base_url):
        _load_race(page, base_url)
        assert page.locator('tbody tr.seeder-row').count() == 1

    def test_seeder_finish_cell_shows_seeder(self, page, base_url):
        """Seeder rows show 'seeder' (not a time) in the Finish column."""
        _load_race(page, base_url)
        seeder_row = page.locator('tbody tr[data-peer-key="2.3.4.5:7777"]')
        tds = seeder_row.locator('td').all_text_contents()
        finish = tds[9].strip()  # Finish column
        assert finish == 'seeder'

    def test_leecher_shows_numeric_finish(self, page, base_url):
        """Leecher rows show a formatted time in the Finish column."""
        _load_race(page, base_url)
        peer_a = page.locator('tbody tr[data-peer-key="37.48.95.71:12345"]')
        tds = peer_a.locator('td').all_text_contents()
        finish = tds[9].strip()
        # 44s finish
        assert 's' in finish
        assert 'seeder' not in finish

    def test_peer_that_beat_us_appears_before_self(self, page, base_url):
        """Peers that finished before us (finish_sec < our 50s) rank above self row."""
        _load_race(page, base_url)
        rows = page.locator('tbody tr').all()
        keys = [r.get_attribute('data-peer-key') for r in rows]
        peer_a_idx = keys.index('37.48.95.71:12345')
        self_idx = keys.index('self')
        assert peer_a_idx < self_idx

    def test_self_row_ahead_column_is_dash(self, page, base_url):
        """Self row shows — in the Ahead column (not a number)."""
        _load_race(page, base_url)
        self_row = page.locator('tbody tr.self-row')
        tds = self_row.locator('td').all_text_contents()
        ahead = tds[8].strip()  # Ahead column
        assert ahead == '—'

    def test_leecher_ahead_column_shows_count(self, page, base_url):
        """Leecher rows show a numeric ahead count."""
        _load_race(page, base_url)
        peer_a = page.locator('tbody tr[data-peer-key="37.48.95.71:12345"]')
        tds = peer_a.locator('td').all_text_contents()
        ahead = tds[8].strip()
        assert ahead.isdigit()


# ---------------------------------------------------------------------------
# Race stats panel
# ---------------------------------------------------------------------------

class TestRaceStats:
    def test_race_name_displayed(self, page, base_url):
        _load_race(page, base_url)
        page.wait_for_selector('#race-stats')
        assert 'Test.Torrent' in page.locator('#race-stats').text_content()

    def test_piece_count_displayed(self, page, base_url):
        _load_race(page, base_url)
        page.wait_for_selector('#race-stats')
        assert '100' in page.locator('#race-stats').text_content()

    def test_our_place_displayed(self, page, base_url):
        """Our Place mini-stat shows a rank number in the peers summary bar."""
        _load_race(page, base_url)
        page.wait_for_selector('.analysis-stats')
        assert 'Our Place' in page.locator('.analysis-stats').text_content()

    def test_peer_count_in_summary(self, page, base_url):
        """Participants count mini-stat shows the right number."""
        _load_race(page, base_url)
        page.wait_for_selector('.analysis-stats')
        stats = page.locator('.analysis-stats').text_content()
        # 6 participants: self + seeder + 4 leechers
        assert '6' in stats


# ---------------------------------------------------------------------------
# Chart rendering
# ---------------------------------------------------------------------------

class TestChartRendering:
    def test_progress_chart_svg_rendered(self, page, base_url):
        """Plotly renders an SVG into the peer progress chart container."""
        _load_race(page, base_url)
        page.wait_for_selector('#peer-progress-chart svg', timeout=10_000)
        assert page.locator('#peer-progress-chart svg').count() >= 1

    def test_chart_has_self_progress_trace(self, page, base_url):
        """The 'Us' trace is present in the chart legend data."""
        _load_race(page, base_url)
        page.wait_for_selector('#peer-progress-chart svg', timeout=10_000)
        # Plotly stores trace data on the element; verify via JS
        has_us = page.evaluate("""() => {
            const el = document.getElementById('peer-progress-chart');
            return el && el.data && el.data.some(t => t.name === 'Us');
        }""")
        assert has_us

    def test_chart_has_histogram_bar_traces(self, page, base_url):
        """Event histogram bar traces are present when histogram data is non-empty."""
        _load_race(page, base_url)
        page.wait_for_selector('#peer-progress-chart svg', timeout=10_000)
        has_bars = page.evaluate("""() => {
            const el = document.getElementById('peer-progress-chart');
            return el && el.data && el.data.some(t => t.type === 'bar');
        }""")
        assert has_bars


# ---------------------------------------------------------------------------
# SSE live updates
# ---------------------------------------------------------------------------

class TestSSEUpdates:
    def _patch_sse(self, page):
        """Intercept EventSource construction to expose the instance as window.__sse."""
        page.add_init_script("""
            (() => {
                const _Orig = window.EventSource;
                window.EventSource = class extends _Orig {
                    constructor(url, opts) {
                        super(url, opts);
                        window.__sse = this;
                    }
                };
            })();
        """)

    def _fire_race_added(self, page, race_id=2):
        page.wait_for_function("!!window.__sse && !!window.__sse.onmessage")
        page.evaluate(f"""() => {{
            window.__sse.onmessage(new MessageEvent('message', {{
                data: JSON.stringify({{type: 'race_added', race_id: {race_id}}})
            }}));
        }}""")

    def test_race_added_refreshes_list(self, page, base_url):
        """A race_added SSE event triggers loadRaces() when no race is selected."""
        self._patch_sse(page)

        races_ref = [[_RACE]]

        def handle(route):
            url = route.request.url
            if '/api/races/counts' in url:
                route.fulfill(json={str(r['id']): {'peer_count': 5, 'event_count': 400}
                                    for r in races_ref[0]})
            elif '/api/races' in url:
                route.fulfill(json=races_ref[0])
            elif '/api/events' in url:
                route.continue_()  # real Flask SSE — connection stays open
            else:
                route.continue_()

        page.route('**/api/**', handle)
        page.goto(base_url)
        page.wait_for_selector('.race-item')
        assert page.locator('.race-item').count() == 1

        races_ref[0] = [_RACE, _RACE2]
        self._fire_race_added(page, race_id=2)

        page.wait_for_function("document.querySelectorAll('.race-item').length === 2")
        assert page.locator('.race-item').count() == 2

    def test_race_added_ignored_when_race_selected(self, page, base_url):
        """A race_added SSE event does NOT reload the list when a race is open."""
        self._patch_sse(page)
        races_call = [0]

        def handle(route):
            url = route.request.url
            if '/api/races/counts' in url:
                route.fulfill(json={'1': {'peer_count': 5, 'event_count': 400}})
            elif '/api/race/1/peer_progress' in url:
                route.fulfill(json=_PROGRESS)
            elif '/api/race/1/peers' in url:
                route.fulfill(json=_PEERS)
            elif '/api/race/1' in url:
                route.fulfill(json=_RACE_DETAIL)
            elif '/api/races' in url:
                races_call[0] += 1
                route.fulfill(json=[_RACE])
            elif '/api/events' in url:
                route.continue_()
            else:
                route.continue_()

        page.route('**/api/**', handle)
        page.goto(base_url)
        page.locator('.race-item').first.click()
        page.wait_for_selector('.peer-table')

        calls_before = races_call[0]
        self._fire_race_added(page, race_id=2)
        page.wait_for_timeout(300)

        assert races_call[0] == calls_before, (
            f'loadRaces() was called {races_call[0] - calls_before} extra time(s) '
            'while a race was selected'
        )


# ---------------------------------------------------------------------------
# JS utility functions
# ---------------------------------------------------------------------------

class TestJSUtilities:
    """Test pure utility functions defined in the page's <script> block.

    Functions live in global scope and are accessible via page.evaluate().
    The autouse fixture loads the page once per test so they're available.
    """

    @pytest.fixture(autouse=True)
    def load_page(self, page, base_url):
        _setup_mocks(page)
        page.goto(base_url)
        page.wait_for_load_state('domcontentloaded')

    # --- formatBytes ---

    def test_format_bytes_zero(self, page):
        assert page.evaluate('formatBytes(0)') == '0 B'

    def test_format_bytes_null(self, page):
        assert page.evaluate('formatBytes(null)') == '0 B'

    def test_format_bytes_kilobytes(self, page):
        assert page.evaluate('formatBytes(1024)') == '1 KB'

    def test_format_bytes_megabytes(self, page):
        assert page.evaluate('formatBytes(1048576)') == '1 MB'

    def test_format_bytes_gigabytes(self, page):
        assert page.evaluate('formatBytes(1073741824)') == '1 GB'

    def test_format_bytes_fractional(self, page):
        # 1.5 GB
        result = page.evaluate('formatBytes(1610612736)')
        assert result == '1.5 GB'

    # --- formatDuration ---

    def test_format_duration_zero(self, page):
        assert page.evaluate('formatDuration(0)') == 'Unknown'

    def test_format_duration_negative(self, page):
        assert page.evaluate('formatDuration(-1)') == 'Unknown'

    def test_format_duration_seconds(self, page):
        assert page.evaluate('formatDuration(45)') == '45s'

    def test_format_duration_minutes_seconds(self, page):
        assert page.evaluate('formatDuration(65)') == '1m 5s'

    def test_format_duration_exact_minutes(self, page):
        assert page.evaluate('formatDuration(120)') == '2m 0s'

    def test_format_duration_hours(self, page):
        assert page.evaluate('formatDuration(3661)') == '1h 1m 1s'

    # --- cleanISP ---

    def test_clean_isp_bv(self, page):
        assert page.evaluate("cleanISP('LeaseWeb Netherlands B.V.')") == 'LeaseWeb Netherlands'

    def test_clean_isp_sas(self, page):
        assert page.evaluate("cleanISP('OVH SAS')") == 'OVH'

    def test_clean_isp_gmbh(self, page):
        assert page.evaluate("cleanISP('netcup GmbH')") == 'netcup'

    def test_clean_isp_inc(self, page):
        assert page.evaluate("cleanISP('Cloudflare Inc.')") == 'Cloudflare'

    def test_clean_isp_ltd(self, page):
        assert page.evaluate("cleanISP('DataCamp Limited')") == 'DataCamp Limited'  # no match

    def test_clean_isp_pte_ltd(self, page):
        assert page.evaluate("cleanISP('SlashN Services Pte. Ltd.')") == 'SlashN Services'

    def test_clean_isp_no_suffix(self, page):
        assert page.evaluate("cleanISP('Feral Hosting')") == 'Feral Hosting'

    def test_clean_isp_empty(self, page):
        assert page.evaluate("cleanISP('')") == ''

    def test_clean_isp_null(self, page):
        assert page.evaluate("cleanISP(null)") == ''
