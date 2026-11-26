"""HTTPS client for the Have I Been Pwned (HIBP) Pwned Passwords range API.

Strictly transmits only the first 5 uppercase hexadecimal characters of a
SHA-1 digest over HTTPS and never persists or logs returned suffix lists.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import requests

from src.utils.logging_config import get_logger, safe_error_context
from src.utils.validation import validate_hibp_prefix

_LOGGER = get_logger(__name__)

HIBP_RANGE_BASE_URL = "https://api.pwnedpasswords.com/range/"
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = "Password-Security-Lab/1.0 (Educational-Defensive-Security-Tool)"
_LINE_RE = re.compile(r"^([0-9A-F]{35}):([0-9]+)$")


class HIBPClientError(RuntimeError):
    """Base error for HIBP range lookup failures."""

    error_code: str = "hibp_error"


class HIBPTimeoutError(HIBPClientError):
    """Raised when the HIBP API request times out."""

    error_code = "timeout"


class HIBPNetworkError(HIBPClientError):
    """Raised when a network or TLS connectivity error occurs."""

    error_code = "network_error"


class HIBPHttpError(HIBPClientError):
    """Raised when HIBP returns an unexpected HTTP status code."""

    error_code = "http_error"

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class HIBPMalformedResponseError(HIBPClientError):
    """Raised when the HIBP range response cannot be parsed safely."""

    error_code = "malformed_response"


def iter_parsed_range_entries(response_text: str) -> Iterator[tuple[str, int]]:
    """Yield validated ``(suffix, count)`` pairs from an HIBP range body.

    Entries with a zero count (padding entries added by ``Add-Padding: true``)
    are skipped immediately so they are never treated as breaches.
    """
    if not isinstance(response_text, str):
        raise HIBPMalformedResponseError("HIBP API returned a non-text response.")

    for raw_line in response_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _LINE_RE.fullmatch(line.upper())
        if match is None:
            raise HIBPMalformedResponseError(
                "HIBP API returned an unexpected line format in the range response."
            )
        suffix = match.group(1)
        count = int(match.group(2))
        if count == 0:
            # Ignore padded dummy entries returned when Add-Padding is enabled.
            continue
        yield suffix, count


class HIBPRangeClient:
    """Privacy-preserving HTTP client for the HIBP Pwned Passwords range endpoint."""

    def __init__(
        self,
        *,
        base_url: str = HIBP_RANGE_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        add_padding: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        session: requests.Session | None = None,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("HIBP range client requires an HTTPS endpoint.")
        if timeout <= 0:
            raise ValueError("Request timeout must be positive.")

        self._base_url = base_url if base_url.endswith("/") else f"{base_url}/"
        self._timeout = timeout
        self._add_padding = add_padding
        self._user_agent = user_agent
        self._session = session or requests.Session()

    @property
    def add_padding(self) -> bool:
        """Whether the HIBP Add-Padding header is requested."""
        return self._add_padding

    def lookup_suffix_count(self, prefix: str, target_suffix: str) -> int:
        """Fetch matching suffixes for ``prefix`` and return count for ``target_suffix``.

        Unrelated returned suffixes are streamed over and discarded immediately
        without being retained in memory or written to disk.
        """
        validated_prefix = validate_hibp_prefix(prefix)
        url = f"{self._base_url}{validated_prefix}"
        headers = {
            "User-Agent": self._user_agent,
        }
        if self._add_padding:
            headers["Add-Padding"] = "true"

        try:
            response = self._session.get(
                url,
                headers=headers,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            _LOGGER.warning("HIBP request timed out: %s", safe_error_context(exc))
            raise HIBPTimeoutError(
                "The HIBP breach-check request timed out. Please check your connection and try again."
            ) from exc
        except requests.RequestException as exc:
            _LOGGER.warning("HIBP network request failed: %s", safe_error_context(exc))
            raise HIBPNetworkError(
                "Unable to reach the HIBP service. Check your internet connection and try again."
            ) from exc

        if response.status_code != 200:
            _LOGGER.warning("HIBP returned HTTP status %s", response.status_code)
            raise HIBPHttpError(
                response.status_code,
                f"HIBP service returned HTTP {response.status_code}. Please try again later.",
            )

        matched_count = 0
        try:
            for suffix, count in iter_parsed_range_entries(response.text):
                if suffix == target_suffix:
                    matched_count = count
        finally:
            response.close()

        return matched_count
