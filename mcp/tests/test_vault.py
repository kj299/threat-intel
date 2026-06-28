"""Tests for the vault credential providers and factory.

No live Vault server required — hvac.Client is mocked throughout.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.vault.base import CredentialError
from threat_intel_mcp.vault.env import EnvCredentialProvider
from threat_intel_mcp.vault.factory import credential_provider_from_env
from threat_intel_mcp.vault.hashicorp import VaultCredentialProvider


# ---------------------------------------------------------------------------
# Factory tests
# ---------------------------------------------------------------------------


class TestCredentialProviderFromEnv:
    def test_env_provider_selected_when_no_vault_addr(self, monkeypatch):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        provider = credential_provider_from_env()
        assert isinstance(provider, EnvCredentialProvider)

    def test_vault_provider_selected_when_vault_addr_set(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com:8200")
        monkeypatch.setenv("VAULT_ROLE_ID", "test-role-id")
        monkeypatch.setenv("VAULT_SECRET_ID", "test-secret-id")
        provider = credential_provider_from_env()
        assert isinstance(provider, VaultCredentialProvider)

    def test_vault_provider_missing_role_id_raises(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com:8200")
        monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
        monkeypatch.setenv("VAULT_SECRET_ID", "test-secret-id")
        with pytest.raises(RuntimeError, match="VAULT_ROLE_ID"):
            credential_provider_from_env()

    def test_vault_provider_missing_secret_id_raises(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com:8200")
        monkeypatch.setenv("VAULT_ROLE_ID", "test-role-id")
        monkeypatch.delenv("VAULT_SECRET_ID", raising=False)
        with pytest.raises(RuntimeError, match="VAULT_SECRET_ID"):
            credential_provider_from_env()


# ---------------------------------------------------------------------------
# VaultCredentialProvider unit tests (hvac mocked)
# ---------------------------------------------------------------------------


def _make_kv2_response(key: str, value: str) -> dict:
    """Build a minimal hvac KV v2 read_secret_version response."""
    return {"data": {"data": {key: value}}}


class TestVaultCredentialProvider:
    def test_vault_get_fetches_kv2_secret(self, mocker):
        mock_client_cls = mocker.patch("threat_intel_mcp.vault.hashicorp.hvac.Client")
        mock_client = mock_client_cls.return_value
        mock_client.is_authenticated.return_value = True
        mock_client.auth.approle.login.return_value = {"auth": {"client_token": "tok"}}
        mock_client.secrets.kv.v2.read_secret_version.return_value = (
            _make_kv2_response("api_key", "super-secret-value")
        )

        provider = VaultCredentialProvider(
            vault_addr="https://vault.example.com:8200",
            role_id="role-id",
            secret_id="secret-id",
        )
        result = provider.get("qfeeds", "api_key")

        assert result == "super-secret-value"
        mock_client.auth.approle.login.assert_called_once_with(
            role_id="role-id",
            secret_id="secret-id",
        )
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="qfeeds/api_key",
            mount_point="secret",
        )

    def test_vault_get_reraises_credential_error_on_missing_secret(self, mocker):
        import hvac.exceptions

        mock_client_cls = mocker.patch("threat_intel_mcp.vault.hashicorp.hvac.Client")
        mock_client = mock_client_cls.return_value
        mock_client.is_authenticated.return_value = True
        mock_client.auth.approle.login.return_value = {"auth": {"client_token": "tok"}}
        mock_client.secrets.kv.v2.read_secret_version.side_effect = (
            hvac.exceptions.InvalidPath("not found")
        )

        provider = VaultCredentialProvider(
            vault_addr="https://vault.example.com:8200",
            role_id="role-id",
            secret_id="secret-id",
        )
        with pytest.raises(CredentialError, match="not found"):
            provider.get("qfeeds", "api_key")

    def test_vault_token_renewal_on_forbidden(self, mocker):
        import hvac.exceptions

        mock_client_cls = mocker.patch("threat_intel_mcp.vault.hashicorp.hvac.Client")
        mock_client = mock_client_cls.return_value
        mock_client.is_authenticated.return_value = True
        mock_client.auth.approle.login.return_value = {"auth": {"client_token": "tok"}}

        # First read raises Forbidden; second read (after re-auth) succeeds.
        mock_client.secrets.kv.v2.read_secret_version.side_effect = [
            hvac.exceptions.Forbidden("token expired"),
            _make_kv2_response("api_key", "renewed-value"),
        ]

        provider = VaultCredentialProvider(
            vault_addr="https://vault.example.com:8200",
            role_id="role-id",
            secret_id="secret-id",
        )
        result = provider.get("qfeeds", "api_key")

        assert result == "renewed-value"
        # Should have authenticated twice (initial + renewal).
        assert mock_client.auth.approle.login.call_count == 2

    def test_vault_auth_failure_raises_credential_error(self, mocker):
        mock_client_cls = mocker.patch("threat_intel_mcp.vault.hashicorp.hvac.Client")
        mock_client = mock_client_cls.return_value
        mock_client.auth.approle.login.side_effect = Exception("connection refused")

        provider = VaultCredentialProvider(
            vault_addr="https://vault.example.com:8200",
            role_id="bad-role",
            secret_id="bad-secret",
        )
        with pytest.raises(CredentialError, match="authentication failed"):
            provider.get("qfeeds", "api_key")

    def test_vault_secret_value_not_in_exception_message(self, mocker):
        """Ensure secret values never appear in CredentialError messages."""
        mock_client_cls = mocker.patch("threat_intel_mcp.vault.hashicorp.hvac.Client")
        mock_client = mock_client_cls.return_value
        mock_client.is_authenticated.return_value = True
        mock_client.auth.approle.login.return_value = {"auth": {"client_token": "tok"}}
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {}}  # key missing
        }

        provider = VaultCredentialProvider(
            vault_addr="https://vault.example.com:8200",
            role_id="role-id",
            secret_id="secret-id",
        )
        with pytest.raises(CredentialError) as exc_info:
            provider.get("qfeeds", "api_key")

        # Verify the secret_id does not appear in the error message.
        assert "secret-id" not in str(exc_info.value)
        assert "role-id" not in str(exc_info.value)
