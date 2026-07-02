import logging
import os

from .base import CredentialNotFoundError

logger = logging.getLogger(__name__)


class EnvCredentialProvider:
    """Dev-only credential provider that reads from environment variables.

    Maps (adapter_name, key) to an env var named {ADAPTER_NAME}_{KEY} (uppercased).
    Example: ("qfeeds", "api_key") -> QFEEDS_API_KEY.

    Logs a loud warning at startup. Replace with HashicorpVaultProvider for
    any non-local deployment — environment variables are visible in process
    listings and container inspection output.
    """

    def __init__(self) -> None:
        logger.warning(
            "EnvCredentialProvider is active. Credentials are read from environment "
            "variables. This is suitable for local development only. Replace with "
            "HashicorpVaultProvider or AwsSecretsManagerProvider before deploying."
        )

    def get(self, adapter_name: str, key: str) -> str:
        env_var = f"{adapter_name.upper()}_{key.upper()}"
        value = os.environ.get(env_var)
        if value is None:
            raise CredentialNotFoundError(
                f"Credential not found. Expected environment variable {env_var!r} "
                f"to be set. Set it with: export {env_var}=<your-key>"
            )
        return value
