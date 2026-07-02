from __future__ import annotations

from typing import Protocol, runtime_checkable


class CredentialError(Exception):
    """Raised when a credential cannot be retrieved.

    Messages must never contain secret values or tokens.
    """


class CredentialNotFoundError(CredentialError, KeyError):
    """The credential is definitively absent (unset env var, missing Vault path).

    Distinct from a provider *failure* (Vault outage, auth error), which raises
    plain :class:`CredentialError`: optional-field lookups may default on
    not-found but must propagate a failure — otherwise a transient outage
    silently downgrades a feed to unauthenticated/default settings.

    Subclasses ``KeyError`` too so existing ``except (CredentialError, KeyError)``
    sites keep working unchanged.
    """

    def __str__(self) -> str:  # KeyError.__str__ repr()s the message; undo that.
        return Exception.__str__(self)


@runtime_checkable
class CredentialProvider(Protocol):
    """Retrieves secrets for a named adapter and key.

    Implementations must never log, print, or otherwise expose the returned value.
    """

    def get(self, adapter_name: str, key: str) -> str:
        """Return the secret value for (adapter_name, key).

        Raises CredentialNotFoundError if the secret is definitively absent.
        Raises CredentialError for provider failures (auth, connectivity).
        """
        ...
