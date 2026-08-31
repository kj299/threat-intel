# Cassettes

Recorded HTTP responses from the real feed APIs, replayed by
[`test_cassette_playback.py`](../test_cassette_playback.py). Issue #105.

## Why these exist

Every other adapter test runs against a payload someone wrote. That is how
ThreatFox shipped a parser returning **0 IOCs from a live 1 MB response** while
its tests passed (#100): the fixtures were generated with `csv.writer`, a shape
abuse.ch does not produce, so the suite agreed with a misconception.

A cassette is bytes the service actually sent. It cannot encode a misconception.

Hand-written mocks are still the right tool for edge cases — malformed bodies,
5xx, empty results — which are hard to provoke on demand. Both, not either.

## Recording

Needs network egress to the feed hosts, which the cloud dev sandbox does not
have (`CONNECT tunnel failed, response 403`).

**From a GitHub runner** — Actions → **record-cassettes** → Run workflow. Opens
a draft PR with the result. Runners have open outbound internet.

**Locally**, from a host with egress:

```bash
python mcp/scripts/record_cassettes.py              # keyless feeds
python mcp/scripts/record_cassettes.py --all        # include keyed feeds
python mcp/scripts/record_cassettes.py --only threatfox
```

## Credentials

**Nothing in this directory may contain a credential.** Several feeds
authenticate by header (`x-apikey`, `Authorization`) and two by query string
(Shodan's `key=`, NVD's `apiKey=`), so a naive recording writes live keys into
a file destined for version control. `audit.py` redacts logs; it has never
touched test fixtures.

Three things stand between a recording session and a committed secret:

1. `tests/vcr_config.py` scrubs credential headers and query parameters.
2. `record_cassettes.py` greps its own output for credential-shaped strings and
   exits non-zero if it finds any.
3. The workflow re-greps before it is allowed to commit.

The scrubbing is asserted in CI by
[`test_vcr_harness.py`](../test_vcr_harness.py), against a local server and a
sentinel secret — so it is verified continuously rather than trusted on the day
someone runs a recording with real keys. Those assertions are deliberately
negative: the secret must be *absent*, since asserting `[REDACTED]` is present
would pass on a file that still contained the key too.

**Review the diff anyway.** These are upstream bytes entering version control.

## Reviewing a re-recording

- **A large diff on a feed nobody touched** is the signal these exist for: the
  upstream format moved.
- **A recording with zero records** makes the playback test assert against a
  quiet day forever. The recorder warns; do not commit it.
- **Size.** The ThreatFox CSV is around 1 MB. Prefer a representative slice over
  megabytes per adapter, but keep enough rows to exercise every branch — each
  `ioc_type`, and the tags column whose embedded commas caused #100.

## Playback is offline

`vcr_config.build_vcr()` defaults to `record_mode="none"`: a request with no
matching cassette entry raises rather than reaching the network. A cassette test
cannot quietly become a live test.

Tests **skip** when a cassette is missing. Recording requires egress that CI does
not have, so an absent cassette is a coverage gap, not a broken build.

## Requests are matched with the clock excluded

A request is matched on method, scheme, host, port, path, and query — but
clock-derived query parameters are left out of the comparison
(`_VOLATILE_QUERY_PARAMS` in `tests/vcr_config.py`).

This is not a convenience. NVD's request window is computed from
`datetime.now()`, so the recorded query carries the recording moment and the
replayed one carries the replay moment. Comparing the raw query makes such a
cassette unplayable **by construction**: the first real recording run failed its
own playback gate 110 seconds after recording, on nothing but a clock
difference.

Everything else in the query is still compared, including NVD's `startIndex` —
which is what tells its paginated requests apart. If that were also excluded,
page two would replay page one's body and the adapter would see the same records
several times while looking healthy.

Add a name to that set only when a parameter is genuinely derived from the
clock. A parameter that varies for any other reason is a real difference between
two requests and must keep failing to match.
