"""Delivery checks must distinguish green jobs from delivered reports."""
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('check_delivery', Path(__file__).resolve().parents[1] / 'scripts/check_delivery.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)


def test_delivery_requires_artifact():
    run = {'conclusion': 'success', 'created_at': '2026-11-13T00:00:00Z'}
    assert not module.delivered([run], now=NOW)
    run['artifacts'] = [{'name': 'threat-intel-report', 'expired': False, 'size_in_bytes': 100}]
    assert module.delivered([run], now=NOW)
    run['conclusion'] = 'failure'
    assert not module.delivered([run], now=NOW)


def test_expired_and_old_reports_do_not_satisfy_delivery():
    run = {'conclusion': 'success', 'created_at': '2026-11-13T00:00:00Z', 'artifacts': [{'name': 'threat-intel-report', 'expired': True, 'size_in_bytes': 100}]}
    assert not module.delivered([run], now=NOW)
    run['artifacts'][0]['expired'] = False
    run['created_at'] = '2026-10-01T00:00:00Z'
    assert not module.delivered([run], now=NOW)
