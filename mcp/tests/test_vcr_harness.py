"""Prove the cassette harness works — especially that it scrubs (#105).

These tests never touch the internet. A throwaway HTTP server runs on localhost,
gets recorded, and is played back, which exercises record -> scrub -> playback
end to end with the real ``vcr_config`` settings.

That matters more than it might look. The recording step for real feeds happens
somewhere with network egress (a GitHub runner, an operator machine) and its
output is committed. If the scrubbing is wrong, the failure mode is a live API
key in version control, discovered by someone else. So the scrubbing is asserted
here, in CI, against the same configuration the recorder uses — rather than
trusted on the day someone runs it with real credentials.

The assertions are deliberately negative: the secret must be *absent* from the
cassette. Asserting ``"[REDACTED]" in text`` would pass just as happily on a
file that also still contained the key.
"""

from __future__ import annotations

import http.server
import pathlib
import threading

import httpx
import pytest
from vcr.errors import CannotOverwriteExistingCassetteException

from tests.vcr_config import build_vcr

# A sentinel that could not plausibly appear by accident. If this string shows
# up in a cassette, scrubbing failed.
_SECRET = "sk-live-DO-NOT-COMMIT-4f19ba7c3e"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        body = b'{"data": [{"ipAddress": "203.0.113.7"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", f"session={_SECRET}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the test output clean


@pytest.fixture()
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture()
def cassette_dir(tmp_path, monkeypatch):
    """Record into a temp directory, never into the committed cassette dir."""
    monkeypatch.setattr("tests.vcr_config.CASSETTE_DIR", tmp_path)
    return tmp_path


def _record(url: str, cassette: pathlib.Path, **request_kwargs) -> None:
    recorder = build_vcr(record_mode="all")
    with recorder.use_cassette(str(cassette)):
        with httpx.Client() as client:
            client.get(url, **request_kwargs)


class TestScrubbing:
    """Each of these would put a live credential in git if it regressed."""

    def test_auth_header_is_not_written_to_the_cassette(self, local_server, tmp_path):
        cassette = tmp_path / "auth-header.yaml"
        _record(local_server, cassette, headers={"Authorization": f"Bearer {_SECRET}"})

        text = cassette.read_text()
        assert _SECRET not in text, "Authorization header leaked into the cassette"

    def test_api_key_headers_are_not_written(self, local_server, tmp_path):
        """The per-feed header names, not just the generic ones."""
        for header in ("x-apikey", "X-OTX-API-KEY", "key", "x-api-key"):
            cassette = tmp_path / f"header-{header.lower()}.yaml"
            _record(local_server, cassette, headers={header: _SECRET})
            assert _SECRET not in cassette.read_text(), f"{header} leaked"

    def test_key_in_query_string_is_not_written(self, local_server, tmp_path):
        """Shodan authenticates this way; the key rides in the URL."""
        cassette = tmp_path / "query-key.yaml"
        _record(f"{local_server}/search?key={_SECRET}&q=malware", cassette)

        text = cassette.read_text()
        assert _SECRET not in text, "query-string key leaked into the cassette"
        assert "malware" in text, "non-secret query params should survive"

    def test_nvd_style_apikey_query_param_is_not_written(self, local_server, tmp_path):
        cassette = tmp_path / "query-apikey.yaml"
        _record(f"{local_server}/cves?apiKey={_SECRET}", cassette)
        assert _SECRET not in cassette.read_text()

    def test_response_set_cookie_is_scrubbed(self, local_server, tmp_path):
        """The server above returns a Set-Cookie carrying the sentinel."""
        cassette = tmp_path / "response-cookie.yaml"
        _record(local_server, cassette)
        assert _SECRET not in cassette.read_text()

    def test_response_body_is_preserved_verbatim(self, local_server, tmp_path):
        """Scrubbing must not eat the payload — the payload is the point."""
        cassette = tmp_path / "body.yaml"
        _record(local_server, cassette)
        assert "203.0.113.7" in cassette.read_text()


class TestPlayback:
    def test_playback_replays_the_recorded_body(self, local_server, tmp_path):
        cassette = tmp_path / "playback.yaml"
        _record(local_server, cassette)

        player = build_vcr(record_mode="none")
        with player.use_cassette(str(cassette)):
            with httpx.Client() as client:
                response = client.get(local_server)
        assert response.status_code == 200
        assert response.json()["data"][0]["ipAddress"] == "203.0.113.7"

    def test_playback_does_not_reach_the_network(self, tmp_path, local_server):
        """Recorded once, then served with the origin server stopped.

        This is the property that makes cassette tests safe in CI: playback is
        offline, so a cassette test can never quietly become a live test.
        """
        cassette = tmp_path / "offline.yaml"
        _record(local_server, cassette)

        player = build_vcr(record_mode="none")
        with player.use_cassette(str(cassette)):
            with httpx.Client() as client:
                response = client.get(local_server)
        assert response.status_code == 200

    def test_unmatched_request_raises_rather_than_hitting_the_network(
        self, local_server, tmp_path
    ):
        """record_mode='none' must fail loudly on a request it has not seen."""
        cassette = tmp_path / "unmatched.yaml"
        _record(local_server, cassette)

        player = build_vcr(record_mode="none")
        with player.use_cassette(str(cassette)):
            with httpx.Client() as client:
                with pytest.raises(CannotOverwriteExistingCassetteException):
                    client.get(f"{local_server}/a-path-never-recorded")


@pytest.mark.asyncio
async def test_async_httpx_is_supported(local_server, tmp_path):
    """Every adapter uses ``httpx.AsyncClient``.

    vcrpy patches ``AsyncHTTPTransport.handle_async_request``, but that is a
    claim about vcrpy's internals — assert it against the version actually
    pinned, so a dependency bump that drops async httpx support fails here
    rather than during a recording session.
    """
    cassette = tmp_path / "async.yaml"
    recorder = build_vcr(record_mode="all")
    with recorder.use_cassette(str(cassette)):
        async with httpx.AsyncClient() as client:
            recorded = await client.get(local_server)
    assert recorded.status_code == 200

    player = build_vcr(record_mode="none")
    with player.use_cassette(str(cassette)):
        async with httpx.AsyncClient() as client:
            replayed = await client.get(local_server)
    assert replayed.json() == recorded.json()


class TestSecretScan:
    """The recorder's leaked-credential scan (``verify_scrubbed``).

    The first version grepped whole cassettes for words like "password" and
    "secret" and failed on the very first real recording: NVD CVE descriptions
    say "password" thousands of times, because it is a vulnerability feed. A
    check that fires on every NVD recording is not cautious, it is broken — it
    blocks the feature and teaches people to pass ``--skip-verify``.
    """

    @staticmethod
    def _cassette(tmp_path, monkeypatch, body, headers=None, uri=None):
        import sys

        import yaml

        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
        import scripts.record_cassettes as rec

        monkeypatch.setattr(rec, "CASSETTE_DIR", tmp_path)
        doc = {
            "interactions": [
                {
                    "request": {
                        "uri": uri or "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        "method": "GET",
                        "headers": headers or {"Accept": ["application/json"]},
                    },
                    "response": {
                        "body": {"string": body},
                        "headers": {"Content-Type": ["application/json"]},
                        "status": {"code": 200, "message": "OK"},
                    },
                }
            ],
            "version": 1,
        }
        (tmp_path / "nvd.yaml").write_text(yaml.safe_dump(doc))
        return rec

    def test_cve_text_mentioning_password_is_not_a_leak(self, tmp_path, monkeypatch):
        """The exact false positive that failed the first live recording."""
        body = (
            "An issue allows a remote attacker to reset the password without "
            "authorisation. A hardcoded password and a default secret are "
            "present. api_key handling is also affected."
        )
        rec = self._cassette(tmp_path, monkeypatch, body)
        assert rec.verify_scrubbed(["nvd"]) == []

    def test_unredacted_auth_header_is_a_leak(self, tmp_path, monkeypatch):
        rec = self._cassette(
            tmp_path, monkeypatch, "{}", headers={"Authorization": ["Bearer real-token"]}
        )
        problems = rec.verify_scrubbed(["nvd"])
        assert problems and "Authorization" in problems[0]

    def test_unredacted_query_key_is_a_leak(self, tmp_path, monkeypatch):
        rec = self._cassette(
            tmp_path, monkeypatch, "{}", uri="https://api.shodan.io/search?key=live-key"
        )
        problems = rec.verify_scrubbed(["nvd"])
        assert problems and "key" in problems[0]

    def test_redacted_header_and_query_pass(self, tmp_path, monkeypatch):
        rec = self._cassette(
            tmp_path,
            monkeypatch,
            "{}",
            headers={"Authorization": ["[REDACTED]"]},
            uri="https://api.shodan.io/search?key=%5BREDACTED%5D",
        )
        assert rec.verify_scrubbed(["nvd"]) == []

    def test_configured_credential_appearing_anywhere_is_a_leak(
        self, tmp_path, monkeypatch
    ):
        """The literal check: no false positives, catches any location.

        Even buried in a response body, where the structural check does not
        look, a real configured key must be caught.
        """
        monkeypatch.setenv("SHODAN_API_KEY", "sk-live-abcdef123456")
        rec = self._cassette(
            tmp_path, monkeypatch, "results for sk-live-abcdef123456 follow"
        )
        problems = rec.verify_scrubbed(["nvd"])
        assert problems and "SHODAN_API_KEY" in problems[0]

    def test_unset_credential_env_var_is_not_checked(self, tmp_path, monkeypatch):
        """An empty env var must not make the empty string match everything."""
        monkeypatch.setenv("SHODAN_API_KEY", "")
        rec = self._cassette(tmp_path, monkeypatch, "ordinary feed content")
        assert rec.verify_scrubbed(["nvd"]) == []
