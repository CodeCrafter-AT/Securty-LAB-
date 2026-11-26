"""Privacy, redaction, and HTTP minimization tests."""

import logging
from unittest.mock import MagicMock

import pytest
import requests

from src.core.breach_checker import BreachChecker, compute_sha1_parts
from src.services.hibp_client import HIBPRangeClient
from src.utils.logging_config import SecretRedactingFilter, redact_sensitive_text


def test_http_request_sends_only_five_char_prefix_over_https() -> None:
    synthetic_secret = "SyntheticPrivacyCheck!2026"
    prefix, suffix = compute_sha1_parts(synthetic_secret)
    full_hash = prefix + suffix

    session = MagicMock(spec=requests.Session)
    response = MagicMock(spec=requests.Response)
    response.status_code = 200
    response.text = "00000000000000000000000000000000000:0\r\n"
    session.get.return_value = response

    client = HIBPRangeClient(session=session)
    checker = BreachChecker(client=client)
    result = checker.check_password(synthetic_secret)

    assert result.checked is True
    assert session.get.call_count == 1

    called_url = session.get.call_args.args[0]
    called_kwargs = session.get.call_args.kwargs

    assert called_url == f"https://api.pwnedpasswords.com/range/{prefix}"
    assert synthetic_secret not in called_url
    assert full_hash not in called_url
    assert suffix not in called_url
    assert called_kwargs["headers"]["Add-Padding"] == "true"
    assert called_kwargs["allow_redirects"] is False
    assert "params" not in called_kwargs
    assert "data" not in called_kwargs
    assert "json" not in called_kwargs


def test_hibp_client_rejects_non_https_endpoint() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        HIBPRangeClient(base_url="http://api.pwnedpasswords.com/range/")


def test_redacting_filter_strips_hashes_suffixes_and_labeled_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    full_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    redacted = redact_sensitive_text(f"debug password=MySecret123 full={full_sha1} suf={suffix}")
    assert "MySecret123" not in redacted
    assert full_sha1 not in redacted
    assert suffix not in redacted

    logger = logging.getLogger("password_security_lab.test_privacy")
    logger.setLevel(logging.DEBUG)
    logger.addFilter(SecretRedactingFilter())

    with caplog.at_level(logging.DEBUG, logger="password_security_lab.test_privacy"):
        logger.warning("failure password=SyntheticValue hash=%s", full_sha1)

    assert "SyntheticValue" not in caplog.text
    assert full_sha1 not in caplog.text


def test_breach_checker_logs_no_passwords_or_hashes_on_network_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    synthetic_secret = "SyntheticOfflineSecret#42"
    prefix, suffix = compute_sha1_parts(synthetic_secret)
    full_hash = prefix + suffix

    session = MagicMock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("dns failed")

    client = HIBPRangeClient(session=session)
    with caplog.at_level(logging.DEBUG, logger="password_security_lab"):
        result = BreachChecker(client=client).check_password(synthetic_secret)

    assert result.checked is False
    assert synthetic_secret not in caplog.text
    assert full_hash not in caplog.text
    assert suffix not in caplog.text
