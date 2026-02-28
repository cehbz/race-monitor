"""Pytest configuration for race-viz tests.

Provides a session-scoped Flask server fixture that Playwright tests use
as their base_url. The server runs on a free port in a daemon thread.
API calls are mocked at the Playwright network layer in individual tests,
so the server only needs to serve the HTML.
"""

import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import app as flask_app


@pytest.fixture(scope='session')
def base_url():
    """Start Flask on a free port and return the base URL.

    Overrides pytest-playwright's base_url fixture.
    """
    with socket.socket() as s:
        s.bind(('', 0))
        port = s.getsockname()[1]

    thread = threading.Thread(
        target=lambda: flask_app.app.run(
            host='127.0.0.1', port=port, use_reloader=False, threaded=True
        ),
        daemon=True,
    )
    thread.start()

    # Wait until Flask accepts connections (up to 10 seconds)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError('Flask server did not start in time')

    return f'http://127.0.0.1:{port}'
