# Protocol Adapters (gRPC / MQTT / WebSocket / GraphQL)

Phase 3 of [issue #1](https://github.com/kj299/threat-intel/issues/1) adds secure
credential storage and an adapter abstraction for non-REST intel transports, so
the MCP server is "ready for diverse integrations" without changing how the four
shipped REST feeds work.

## What ships, and what does not

**Ships (real, tested):**

- **Credential bundles** — typed, validated multi-field credentials for each
  protocol, retrieved through the same `CredentialProvider` used everywhere
  (environment variables in dev, HashiCorp Vault in production). No new secret
  store is introduced. See `mcp/src/threat_intel_mcp/vault/protocols.py`.
- **`ProtocolAdapter` base** — an abstract `SourceAdapter` that standardises
  timing, schema validation, deduplication, and `FetchResult` assembly. A
  concrete feed implements only `_collect` (pull raw records over the transport)
  and `_normalize` (map a raw record to an `ioc_network` dict). A
  `ProtocolAdapter` drops straight into the existing concurrent fan-out and gets
  the same circuit-breaker / retry treatment as the REST adapters. See
  `mcp/src/threat_intel_mcp/transports/base.py`.

**Does not ship (by design):**

- **No live protocol feed, no hardcoded endpoint.** A concrete adapter is
  configured entirely from operator-supplied credentials. Building an adapter
  against an invented endpoint or a made-up response schema would violate this
  repo's no-fabrication rule, so the live wiring (and the protocol client
  library it needs) lands with the **first real, named feed** — not before.
- **No protocol client dependencies.** `gql`, `websockets`, `paho-mqtt`, and
  `grpcio` are *not* dependencies of `threat-intel-mcp`. A concrete adapter adds
  the single library it needs.

## Where credentials live

Each protocol feed picks an `adapter` name (e.g. `chronicle_grpc`) and stores its
fields under that name, following the existing `CredentialProvider` convention:

| Mode | Path |
|------|------|
| Env (dev) | `{ADAPTER}_{KEY}` — e.g. `CHRONICLE_GRPC_TARGET` |
| Vault (prod) | `{mount}/data/{adapter}/{key}` — e.g. `secret/data/chronicle_grpc/target` |

Fields per protocol (required in **bold**):

| Protocol | Fields |
|----------|--------|
| `graphql` | **`endpoint`**, `token`, `auth_header` (default `Authorization`), `auth_scheme` (default `Bearer`) |
| `websocket` | **`url`**, `token`, `auth_header`, `auth_scheme`, `subprotocol` |
| `mqtt` | **`host`**, `port` (default `8883`), `topic` (default `#`), `username`, `password`, `tls` (default `true`) |
| `grpc` | **`target`** (`host:port`), `root_cert` (CA PEM), `client_cert` + `client_key` (mTLS pair — both or neither), `use_tls` (default `true`) |

Credential errors name the *missing field*, never a retrieved value.

## Worked example: a GraphQL intel feed

```python
from threat_intel_mcp.transports.base import ProtocolAdapter
from threat_intel_mcp.vault.protocols import GraphQLCredentials
# from gql import Client, gql                      # operator adds this dependency
# from gql.transport.aiohttp import AIOHTTPTransport

class MyGraphQLFeed(ProtocolAdapter):
    name = "Acme Intel (GraphQL)"
    tier = 2
    protocol = "graphql"

    def __init__(self, credentials):
        # Pulls endpoint/token from env or Vault under adapter name "acme_graphql".
        self._creds = GraphQLCredentials.from_provider(credentials, "acme_graphql")

    async def _collect(self, *, time_range, feed_types):
        # Open the operator's real endpoint and run the operator's real query.
        # headers = {self._creds.auth_header: f"{self._creds.auth_scheme} {self._creds.token}"}
        # transport = AIOHTTPTransport(url=self._creds.endpoint, headers=headers)
        # async with Client(transport=transport) as session:
        #     data = await session.execute(gql(MY_QUERY), {"since": time_range})
        # return data["indicators"]
        ...

    def _normalize(self, raw):
        # Map ONE record from this feed's real response shape to ioc_network.
        if raw.get("kind") != "ipv4":
            return None
        return {
            "type": "IPv4",
            "value": raw["value"],
            "confidence": raw.get("confidence", "Medium"),
            "source": self.name,
        }
```

Register it like any other source — wrap it in a `FeedSource` with its own
`CircuitBreaker` and add it to the server's `_FEED_SOURCES` list so `fetch_all_iocs`
picks it up. The base class handles validation, dedup, and `FetchResult`.

## Why credentials, not adapters, are the deliverable here

The original [issue #1](https://github.com/kj299/threat-intel/issues/1)
acceptance criterion is *"securely store and retrieve credentials for REST APIs,
gRPC endpoints, MQTT brokers, WebSockets, GraphQL services."* That is exactly
what the credential bundles deliver and what the test suite covers. The transport
abstraction makes plugging in a real feed a two-method exercise — but the feed
itself only exists once you point it at a real endpoint you have access to.
