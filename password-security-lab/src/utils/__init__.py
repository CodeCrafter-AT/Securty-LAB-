"""Shared validation and privacy-preserving logging utilities."""

from src.utils.logging_config import SecretRedactingFilter, configure_logging, get_logger
from src.utils.validation import (
    DEFAULT_GENERATED_LENGTH,
    DEFAULT_PASSPHRASE_WORDS,
    MAX_ASSESSMENT_LENGTH,
    MAX_GENERATED_LENGTH,
    MAX_PASSPHRASE_WORDS,
    MIN_GENERATED_LENGTH,
    MIN_PASSPHRASE_WORDS,
    ValidationError,
    validate_generator_options,
    validate_hibp_prefix,
    validate_hibp_suffix,
    validate_passphrase_options,
    validate_password_input,
)

__all__ = [
    "DEFAULT_GENERATED_LENGTH",
    "DEFAULT_PASSPHRASE_WORDS",
    "MAX_ASSESSMENT_LENGTH",
    "MAX_GENERATED_LENGTH",
    "MAX_PASSPHRASE_WORDS",
    "MIN_GENERATED_LENGTH",
    "MIN_PASSPHRASE_WORDS",
    "SecretRedactingFilter",
    "ValidationError",
    "configure_logging",
    "get_logger",
    "validate_generator_options",
    "validate_hibp_prefix",
    "validate_hibp_suffix",
    "validate_passphrase_options",
    "validate_password_input",
]
