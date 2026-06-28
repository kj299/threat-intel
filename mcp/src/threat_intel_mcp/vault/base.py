from typing import Protocol, runtime_checkable


@runtime_checkable
class CredentialProvider(Protocol):
    """Retrieves secrets for a named adapter and key.

    Implementations must never log, print, or otherwise expose the returned value.
    Phase 2 will add HashicorpVaultProvider and AwsSecretsManagerProvider.
    """

    def get(self, adapter_name: str, key: str) -> str:
        """Return the secret value for (adapter_name, key).

        Raises KeyError if not found.
        """
        ...
