"""External and platform services for Password Security Lab."""

from src.services.clipboard_service import copy_to_clipboard
from src.services.hibp_client import (
    HIBPClientError,
    HIBPHttpError,
    HIBPMalformedResponseError,
    HIBPNetworkError,
    HIBPRangeClient,
    HIBPTimeoutError,
)

__all__ = [
    "HIBPClientError",
    "HIBPHttpError",
    "HIBPMalformedResponseError",
    "HIBPNetworkError",
    "HIBPRangeClient",
    "HIBPTimeoutError",
    "copy_to_clipboard",
]
