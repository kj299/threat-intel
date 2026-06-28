"""HashiCorp Vault credential provider using AppRole auth and KV v2."""

from __future__ import annotations

import logging

import hvac
import hvac.exceptions

from .base import CredentialError

logger = logging.getLogger(__name__)


class VaultCredentialProvider:
    """Retrieves secrets from HashiCorp Vault using AppRole authentication.

    Authenticates lazily on the first ``get()`` call and caches the token.
    On a ``Forbidden`` error the provider re-authenticates once before raising.

    Secret path convention: ``{mount_point}/data/{adapter_name}/{key}``
    Example: ``secret/data/qfeeds/api_key``

    The secret value is never logged.
    """

    def __init__(
        self,
        vault_addr: str,
        role_id: str,
        secret_id: str,
        mount_point: str = "secret",
    ) -> None:
        self._vault_addr = vault_addr
        self._role_id = role_id
        self._secret_id = secret_id
        self._mount_point = mount_point
        self._client: hvac.Client | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _authenticate(self) -> None:
        """Perform AppRole login and store the authenticated client."""
        client = hvac.Client(url=self._vault_addr)
        try:
            result = client.auth.approle.login(
                role_id=self._role_id,
                secret_id=self._secret_id,
            )
        except Exception as exc:
            # Do not include exc details — they may contain secret_id fragments.
            raise CredentialError(
                "Vault AppRole authentication failed. "
                "Check VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID."
            ) from exc

        if not result or not client.is_authenticated():
            raise CredentialError(
                "Vault AppRole login returned an invalid token. "
                "Verify the role_id and secret_id are correct."
            )

        self._client = client
        logger.debug("Vault AppRole authentication successful.")

    def _read_secret(self, adapter_name: str, key: str) -> str:
        """Read a single secret value from the KV v2 engine."""
        assert self._client is not None  # guaranteed by callers
        path = f"{adapter_name}/{key}"
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._mount_point,
            )
        except hvac.exceptions.Forbidden:
            # Let Forbidden propagate so get() can attempt token renewal.
            raise
        except hvac.exceptions.InvalidPath:
            raise CredentialError(
                f"Secret not found at path '{self._mount_point}/data/{path}'. "
                "Ensure the secret exists in Vault."
            )
        except Exception as exc:
            raise CredentialError(
                f"Failed to read secret '{self._mount_point}/data/{path}' from Vault."
            ) from exc

        try:
            value = response["data"]["data"][key]
        except (KeyError, TypeError):
            raise CredentialError(
                f"Key '{key}' not present in Vault secret at "
                f"'{self._mount_point}/data/{path}'."
            )

        if value is None:
            raise CredentialError(
                f"Key '{key}' exists but has a null value at "
                f"'{self._mount_point}/data/{path}'."
            )

        return str(value)

    # ------------------------------------------------------------------
    # CredentialProvider protocol
    # ------------------------------------------------------------------

    def get(self, adapter_name: str, key: str) -> str:
        """Return the secret value for ``(adapter_name, key)`` from Vault.

        Reads from ``{mount_point}/data/{adapter_name}/{key}``.

        Raises:
            CredentialError: If authentication fails or the secret is absent.
        """
        # Lazy authentication on first call.
        if self._client is None:
            self._authenticate()

        logger.debug(
            "Fetching Vault secret: adapter=%s key=%s mount=%s",
            adapter_name,
            key,
            self._mount_point,
        )

        try:
            return self._read_secret(adapter_name, key)
        except hvac.exceptions.Forbidden:
            # Token may have expired; re-authenticate once.
            logger.debug(
                "Vault token forbidden for adapter=%s key=%s — re-authenticating.",
                adapter_name,
                key,
            )
            self._client = None
            self._authenticate()
            return self._read_secret(adapter_name, key)
