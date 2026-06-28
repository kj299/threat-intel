from __future__ import annotations

from typing import Protocol, runtime_checkable


class CredentialError(Exception):
    """Raised when a credential cannot be retrieved.

    Messages must never contain secret values or tokens.
    """


@runtime_checkable
class CredentialProvider(Protocol):
    """Retrieves secrets for a named adapter and key.

    Implementations must never log, print, or otherwise expose the returned value.
    Phase 2 adds HashicorpVaultProvider; Phase 3 will add AwsSecretsManagerProvider.
    """

    def get(self, adapter_name: str, key: str) -> str:
        """Return the secret value for (adapter_name, key).

        Raises CredentialError if authentication fails or the secret is missing.
        Raises KeyError if not found (legacy; prefer CredentialError in new impls).
        """
        ...
