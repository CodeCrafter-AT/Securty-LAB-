"""Validation tests ensuring invalid inputs fail safely without echoing secrets."""

import pytest

from src.utils.validation import (
    MAX_ASSESSMENT_LENGTH,
    ValidationError,
    validate_generator_options,
    validate_hibp_prefix,
    validate_hibp_suffix,
    validate_passphrase_options,
    validate_password_input,
)


def test_validate_password_input_rejects_empty_and_oversized() -> None:
    with pytest.raises(ValidationError):
        validate_password_input("")

    oversized = "X" * (MAX_ASSESSMENT_LENGTH + 1)
    with pytest.raises(ValidationError) as exc_info:
        validate_password_input(oversized)
    assert oversized not in str(exc_info.value)


def test_validate_password_input_rejects_non_string() -> None:
    with pytest.raises(ValidationError):
        validate_password_input(None)  # type: ignore[arg-type]


def test_validate_generator_options_rejects_bool_and_empty_sets() -> None:
    with pytest.raises(ValidationError):
        validate_generator_options(
            length=True,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True,
        )
    with pytest.raises(ValidationError):
        validate_generator_options(
            length=16,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            use_symbols=False,
        )


def test_validate_passphrase_options_bounds() -> None:
    with pytest.raises(ValidationError):
        validate_passphrase_options(word_count=3, separator="-")
    with pytest.raises(ValidationError):
        validate_passphrase_options(word_count=13, separator="-")
    with pytest.raises(ValidationError):
        validate_passphrase_options(word_count=5, separator="\n")


def test_validate_hibp_prefix_and_suffix() -> None:
    assert validate_hibp_prefix("5BAA6") == "5BAA6"
    with pytest.raises(ValidationError):
        validate_hibp_prefix("5baa6")
    with pytest.raises(ValidationError):
        validate_hibp_prefix("5BAA61E4C9")

    valid_suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert validate_hibp_suffix(valid_suffix) == valid_suffix
    with pytest.raises(ValidationError):
        validate_hibp_suffix("SHORT")
