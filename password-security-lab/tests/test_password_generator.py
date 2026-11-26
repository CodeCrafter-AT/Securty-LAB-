"""Unit tests for cryptographically secure password and passphrase generation."""

import inspect

import pytest

from src.core import password_generator
from src.core.models import GeneratorConfig
from src.core.password_generator import (
    AMBIGUOUS_CHARS,
    DIGIT_CHARS,
    LOWERCASE_CHARS,
    SYMBOL_CHARS,
    UPPERCASE_CHARS,
    PasswordGenerator,
)
from src.core.wordlist import PASSPHRASE_WORDS
from src.utils.validation import MAX_GENERATED_LENGTH, MIN_GENERATED_LENGTH, ValidationError


@pytest.fixture
def generator() -> PasswordGenerator:
    return PasswordGenerator()


def test_generator_uses_secrets_and_never_random_module() -> None:
    source = inspect.getsource(password_generator)
    assert "import secrets" in source
    assert "import random" not in source


def test_default_password_generation_includes_all_enabled_sets(
    generator: PasswordGenerator,
) -> None:
    result = generator.generate_password(GeneratorConfig(length=16))
    assert result.mode == "password"
    assert len(result.secret) == 16
    assert any(c in UPPERCASE_CHARS for c in result.secret)
    assert any(c in LOWERCASE_CHARS for c in result.secret)
    assert any(c in DIGIT_CHARS for c in result.secret)
    assert any(c in SYMBOL_CHARS for c in result.secret)
    assert "password manager" in result.storage_warning.lower()


def test_single_character_set_options(generator: PasswordGenerator) -> None:
    digits_only = generator.generate_password(
        GeneratorConfig(
            length=12,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=True,
            use_symbols=False,
        )
    )
    assert len(digits_only.secret) == 12
    assert all(ch in DIGIT_CHARS for ch in digits_only.secret)

    symbols_only = generator.generate_password(
        GeneratorConfig(
            length=10,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            use_symbols=True,
        )
    )
    assert len(symbols_only.secret) == 10
    assert all(ch in SYMBOL_CHARS for ch in symbols_only.secret)


def test_exclude_ambiguous_characters(generator: PasswordGenerator) -> None:
    for _ in range(10):
        result = generator.generate_password(GeneratorConfig(length=32, exclude_ambiguous=True))
        assert not any(ch in AMBIGUOUS_CHARS for ch in result.secret)


def test_length_limits(generator: PasswordGenerator) -> None:
    min_res = generator.generate_password(GeneratorConfig(length=MIN_GENERATED_LENGTH))
    max_res = generator.generate_password(GeneratorConfig(length=MAX_GENERATED_LENGTH))
    assert len(min_res.secret) == MIN_GENERATED_LENGTH
    assert len(max_res.secret) == MAX_GENERATED_LENGTH

    with pytest.raises(ValidationError):
        generator.generate_password(GeneratorConfig(length=MIN_GENERATED_LENGTH - 1))
    with pytest.raises(ValidationError):
        generator.generate_password(GeneratorConfig(length=MAX_GENERATED_LENGTH + 1))


def test_passphrase_generation_and_wordlist_integrity(
    generator: PasswordGenerator,
) -> None:
    assert len(PASSPHRASE_WORDS) >= 512
    assert len(set(PASSPHRASE_WORDS)) == len(PASSPHRASE_WORDS)

    phrase = generator.generate_passphrase(
        word_count=6, separator="_", capitalize=True, include_number=True
    )
    assert phrase.mode == "passphrase"
    parts = phrase.secret.split("_")
    assert len(parts) == 6
    assert all(part[0].isupper() for part in parts)
    assert any(any(ch.isdigit() for ch in part) for part in parts)
