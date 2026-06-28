"""Factory for selecting the appropriate CredentialProvider at startup."""

from __future__ import annotations

import logging
import os

from .base import CredentialProvider
from .env import EnvCredentialProvider
from .hashicorp import VaultCredentialProvider

logger = logging.getLogger(__name__)


def credential_provider_from_env() -> CredentialProvider:
    """Return the correct CredentialProvider based on environment variables.

    Selection logic:
    - If ``VAULT_ADDR`` is set: return a ``VaultCredentialProvider`` configured
      from ``VAULT_ADDR``, ``VAULT_ROLE_ID``, and ``VAULT_SECRET_ID``.
    - Otherwise: return ``EnvCredentialProvider`` (dev / local mode).

    Raises:
        RuntimeError: If ``VAULT_ADDR`` is set but ``VAULT_ROLE_ID`` or
            ``VAULT_SECRET_ID`` are missing.
    """
    vault_addr = os.environ.get("VAULT_ADDR")

    if vault_addr:
        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")

        if not role_id:
            raise RuntimeError(
                "VAULT_ADDR is set but VAULT_ROLE_ID is missing. "
                "Set VAULT_ROLE_ID to the AppRole role ID."
            )
        if not secret_id:
            raise RuntimeError(
                "VAULT_ADDR is set but VAULT_SECRET_ID is missing. "
                "Set VAULT_SECRET_ID to the AppRole secret ID."
            )

        logger.info(
            "Credential provider: VaultCredentialProvider (addr=%s)", vault_addr
        )
        return VaultCredentialProvider(
            vault_addr=vault_addr,
            role_id=role_id,
            secret_id=secret_id,
        )

    logger.info("Credential provider: EnvCredentialProvider (dev mode)")
    return EnvCredentialProvider()
