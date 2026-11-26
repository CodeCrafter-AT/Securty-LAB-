"""Input validation helpers that never echo sensitive values in errors."""

import re

MIN_ASSESSMENT_LENGTH = 1
MAX_ASSESSMENT_LENGTH = 1024

MIN_GENERATED_LENGTH = 8
MAX_GENERATED_LENGTH = 128
DEFAULT_GENERATED_LENGTH = 16

MIN_PASSPHRASE_WORDS = 4
MAX_PASSPHRASE_WORDS = 12
DEFAULT_PASSPHRASE_WORDS = 5

_HEX_5_RE = re.compile(r"^[0-9A-F]{5}$")
_HEX_35_RE = re.compile(r"^[0-9A-F]{35}$")


class ValidationError(ValueError):
    """Raised when user or configuration input fails validation."""


def validate_password_input(password: str) -> str:
    """Validate that a password is a non-empty string within safe bounds.

    Never includes the password value in error messages.
    """
    if not isinstance(password, str):
        raise ValidationError("Password must be provided as text.")
    if len(password) < MIN_ASSESSMENT_LENGTH:
        raise ValidationError("Password cannot be empty.")
    if len(password) > MAX_ASSESSMENT_LENGTH:
        raise ValidationError(
            f"Password exceeds the maximum supported assessment length ({MAX_ASSESSMENT_LENGTH} characters)."
        )
    return password


def validate_generator_options(
    *,
    length: int,
    use_uppercase: bool,
    use_lowercase: bool,
    use_digits: bool,
    use_symbols: bool,
) -> None:
    """Validate password generator length and character-set selections."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValidationError("Password length must be an integer.")
    if length < MIN_GENERATED_LENGTH or length > MAX_GENERATED_LENGTH:
        raise ValidationError(
            f"Password length must be between {MIN_GENERATED_LENGTH} and {MAX_GENERATED_LENGTH} characters."
        )
    if not any((use_uppercase, use_lowercase, use_digits, use_symbols)):
        raise ValidationError(
            "Select at least one character set (uppercase, lowercase, numbers, or symbols)."
        )


def validate_passphrase_options(*, word_count: int, separator: str) -> None:
    """Validate passphrase word count and separator string."""
    if isinstance(word_count, bool) or not isinstance(word_count, int):
        raise ValidationError("Word count must be an integer.")
    if word_count < MIN_PASSPHRASE_WORDS or word_count > MAX_PASSPHRASE_WORDS:
        raise ValidationError(
            f"Passphrase word count must be between {MIN_PASSPHRASE_WORDS} and {MAX_PASSPHRASE_WORDS}."
        )
    if not isinstance(separator, str) or len(separator) > 3:
        raise ValidationError("Passphrase separator must be a string of at most 3 characters.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in separator):
        raise ValidationError("Passphrase separator cannot contain control characters.")


def validate_hibp_prefix(prefix: str) -> str:
    """Ensure a hash prefix is strictly 5 uppercase hexadecimal characters."""
    if not isinstance(prefix, str) or not _HEX_5_RE.fullmatch(prefix):
        raise ValidationError(
            "HIBP range prefix must be exactly 5 uppercase hexadecimal characters."
        )
    return prefix


def validate_hibp_suffix(suffix: str) -> str:
    """Ensure a hash suffix is strictly 35 uppercase hexadecimal characters."""
    if not isinstance(suffix, str) or not _HEX_35_RE.fullmatch(suffix):
        raise ValidationError(
            "HIBP hash suffix must be exactly 35 uppercase hexadecimal characters."
        )
    return suffix
