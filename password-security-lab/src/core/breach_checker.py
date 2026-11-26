"""HIBP k-anonymity breach-exposure checker."""

from __future__ import annotations

import hashlib

from src.core.models import BreachCheckResult
from src.services.hibp_client import HIBPClientError, HIBPRangeClient
from src.utils.validation import validate_password_input

BREACH_CAVEAT = (
    "Not appearing in the HIBP Pwned Passwords dataset is not a guarantee that a "
    "password is safe, unique, or uncompromised elsewhere."
)


def compute_sha1_parts(password: str) -> tuple[str, str]:
    """Compute local UTF-8 SHA-1 uppercase digest and split into (prefix5, suffix35).

    SHA-1 is used solely because the HIBP Pwned Passwords range API indexes
    compromised passwords by SHA-1 hash prefix. SHA-1 is not suitable for
    password storage or encryption.
    """
    validate_password_input(password)
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:5], digest[5:]


class BreachChecker:
    """Coordinates local SHA-1 prefix splitting and remote range lookup."""

    def __init__(self, client: HIBPRangeClient | None = None) -> None:
        self._client = client or HIBPRangeClient()

    def check_password(self, password: str) -> BreachCheckResult:
        """Check whether ``password`` appears in the HIBP Pwned Passwords dataset.

        Only the first 5 characters of the SHA-1 digest are sent over HTTPS.
        Full hashes and unrelated returned suffixes are discarded immediately.
        """
        prefix, suffix = compute_sha1_parts(password)
        try:
            count = self._client.lookup_suffix_count(prefix, suffix)
        except HIBPClientError as exc:
            return BreachCheckResult(
                checked=False,
                exposed=None,
                occurrence_count=0,
                hash_prefix=prefix,
                padding_enabled=self._client.add_padding,
                status_message=str(exc),
                caveat=BREACH_CAVEAT,
                error_code=exc.error_code,
            )
        finally:
            # Drop local reference to suffix promptly after comparison.
            del suffix

        if count > 0:
            return BreachCheckResult(
                checked=True,
                exposed=True,
                occurrence_count=count,
                hash_prefix=prefix,
                padding_enabled=self._client.add_padding,
                status_message=(
                    f"Exposed: This password was found {count:,} time(s) in known "
                    "data breaches tracked by Have I Been Pwned."
                ),
                caveat=BREACH_CAVEAT,
            )

        return BreachCheckResult(
            checked=True,
            exposed=False,
            occurrence_count=0,
            hash_prefix=prefix,
            padding_enabled=self._client.add_padding,
            status_message=(
                "Not found in the HIBP Pwned Passwords dataset for the checked "
                f"5-character prefix ({prefix})."
            ),
            caveat=BREACH_CAVEAT,
        )
