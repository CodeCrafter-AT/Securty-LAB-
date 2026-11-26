"""Unit and mocked integration tests for HIBP k-anonymity breach checking."""

from unittest.mock import MagicMock

import requests

from src.core.breach_checker import BreachChecker, compute_sha1_parts
from src.services.hibp_client import HIBPRangeClient

# Synthetic example documented by HIBP for the literal string "password":
# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
SYNTHETIC_SAMPLE = "password"
SYNTHETIC_PREFIX = "5BAA6"
SYNTHETIC_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def _make_mock_session(
    *,
    status_code: int = 200,
    text: str = "",
    side_effect: Exception | None = None,
) -> MagicMock:
    session = MagicMock(spec=requests.Session)
    if side_effect is not None:
        session.get.side_effect = side_effect
        return session

    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.text = text
    session.get.return_value = response
    return session


def test_sha1_prefix_and_suffix_calculation() -> None:
    prefix, suffix = compute_sha1_parts(SYNTHETIC_SAMPLE)
    assert prefix == SYNTHETIC_PREFIX
    assert suffix == SYNTHETIC_SUFFIX
    assert len(prefix) == 5
    assert len(suffix) == 35


def test_breach_found_with_occurrence_count() -> None:
    body = (
        "003D68EB55068C33ACE09247EE4C639306B:3\r\n"
        f"{SYNTHETIC_SUFFIX}:3861493\r\n"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
    )
    session = _make_mock_session(text=body)
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is True
    assert result.exposed is True
    assert result.occurrence_count == 3861493
    assert result.hash_prefix == SYNTHETIC_PREFIX
    assert result.padding_enabled is True


def test_breach_not_found_distinguishes_from_safe() -> None:
    body = "003D68EB55068C33ACE09247EE4C639306B:3\r\n11111111111111111111111111111111111:12\r\n"
    session = _make_mock_session(text=body)
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is True
    assert result.exposed is False
    assert result.occurrence_count == 0
    assert "not a guarantee" in result.caveat.lower()


def test_padded_zero_count_entries_are_ignored() -> None:
    body = f"{SYNTHETIC_SUFFIX}:0\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n"
    session = _make_mock_session(text=body)
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is True
    assert result.exposed is False
    assert result.occurrence_count == 0


def test_empty_api_response_handled_as_not_found() -> None:
    session = _make_mock_session(text="")
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is True
    assert result.exposed is False
    assert result.occurrence_count == 0


def test_network_timeout_handled_gracefully() -> None:
    session = _make_mock_session(side_effect=requests.Timeout("timed out"))
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is False
    assert result.exposed is None
    assert result.error_code == "timeout"
    assert "timed out" in result.status_message.lower()


def test_network_connection_error_handled_gracefully() -> None:
    session = _make_mock_session(side_effect=requests.ConnectionError("offline"))
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is False
    assert result.exposed is None
    assert result.error_code == "network_error"
    assert "internet" in result.status_message.lower()


def test_http_error_status_handled_gracefully() -> None:
    session = _make_mock_session(status_code=503, text="Service Unavailable")
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is False
    assert result.exposed is None
    assert result.error_code == "http_error"
    assert "503" in result.status_message


def test_malformed_response_handled_gracefully() -> None:
    session = _make_mock_session(text="NOT_A_VALID_HASH_LINE\nGARBAGE")
    client = HIBPRangeClient(session=session)
    result = BreachChecker(client=client).check_password(SYNTHETIC_SAMPLE)

    assert result.checked is False
    assert result.exposed is None
    assert result.error_code == "malformed_response"
