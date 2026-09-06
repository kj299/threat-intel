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
        # Empty counts as absent. An unset GitHub Actions secret interpolates to
        # the EMPTY STRING, not to nothing, so a workflow that wires up all
        # twelve feed credentials hands every unconfigured adapter a `""` to
        # authenticate with. The feed then rejects it and the adapter reports
        # HTTPStatusError -- an upstream, RETRYABLE failure -- when the truth is
        # a missing credential, which is a config failure and not retryable.
        #
        # Measured, not theorised: the first prefetch run (2026-09-06) spent 94
        # seconds retrying nine feeds that simply had no key, and its coverage
        # ledger would have told the reader those feeds had upstream errors.
        # Misreporting *why* a source is unverified is the kind of quiet
        # dishonesty the whole ledger exists to prevent.
        # `.strip()` only to TEST it -- the value returned is never altered, since
        # a real credential may legitimately contain spaces (ANY.RUN's is the
        # full `API-Key <token>` header). A whitespace-only value is a paste
        # error and produces the same misleading HTTPStatusError.
        if not value or not value.strip():
            raise CredentialNotFoundError(
                f"Credential not found. Expected environment variable {env_var!r} "
                f"to be set. Set it with: export {env_var}=<your-key>"
            )
        return value
