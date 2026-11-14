"""Historical integration status, independent of current credential presence.

No feed is removed or disabled because access is unavailable. Discovery does
not probe upstreams or infer health from credentials. Null verification dates
are intentional: historical repository notes are not fresh observations.
"""
import json
from importlib.resources import files


def annotate_discovery(result: dict) -> dict:
    registry = json.loads(files(__package__).joinpath("feed_status.json").read_text())
    for group in ("feeds", "cve_sources", "enrichment_sources"):
        for feed in result[group]:
            status = registry[feed["name"]]
            feed["integration_status"] = {key: value for key, value in status.items()
                                          if key not in ("tool", "kind")}
            feed["integration_status"]["implemented"] = True
            feed["integration_status"]["credential_presence_is_health_check"] = False
    return result
