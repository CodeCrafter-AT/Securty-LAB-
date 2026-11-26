"""Cryptographically secure password and passphrase generation via ``secrets``."""

from __future__ import annotations

import math
import secrets

from src.core.models import GeneratedSecretResult, GeneratorConfig
from src.core.wordlist import PASSPHRASE_WORDS
from src.utils.validation import (
    ValidationError,
    validate_generator_options,
    validate_passphrase_options,
)

UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz"
DIGIT_CHARS = "0123456789"
SYMBOL_CHARS = "!@#$%^&*()-_=+[]{};:,.?/"

AMBIGUOUS_CHARS = frozenset("IOl01")

STORAGE_WARNING = (
    "Generated passwords are never saved automatically. Store this secret in a "
    "reputable password manager rather than relying on memory or plain files."
)


def _secrets_shuffle(items: list[str]) -> None:
    """In-place Fisher-Yates shuffle using ``secrets.randbelow``."""
    for idx in range(len(items) - 1, 0, -1):
        swap_idx = secrets.randbelow(idx + 1)
        items[idx], items[swap_idx] = items[swap_idx], items[idx]


def _filter_ambiguous(pool: str, exclude_ambiguous: bool) -> str:
    if not exclude_ambiguous:
        return pool
    return "".join(ch for ch in pool if ch not in AMBIGUOUS_CHARS)


class PasswordGenerator:
    """Generates random passwords and passphrases using ``secrets``."""

    def generate_password(self, config: GeneratorConfig | None = None) -> GeneratedSecretResult:
        """Generate a random password satisfying the selected character sets."""
        cfg = config or GeneratorConfig()
        validate_generator_options(
            length=cfg.length,
            use_uppercase=cfg.use_uppercase,
            use_lowercase=cfg.use_lowercase,
            use_digits=cfg.use_digits,
            use_symbols=cfg.use_symbols,
        )

        pools: list[tuple[str, str]] = []
        if cfg.use_uppercase:
            pools.append(("uppercase", _filter_ambiguous(UPPERCASE_CHARS, cfg.exclude_ambiguous)))
        if cfg.use_lowercase:
            pools.append(("lowercase", _filter_ambiguous(LOWERCASE_CHARS, cfg.exclude_ambiguous)))
        if cfg.use_digits:
            pools.append(("digits", _filter_ambiguous(DIGIT_CHARS, cfg.exclude_ambiguous)))
        if cfg.use_symbols:
            pools.append(("symbols", _filter_ambiguous(SYMBOL_CHARS, cfg.exclude_ambiguous)))

        if any(not chars for _, chars in pools):
            raise ValidationError("Selected character set became empty after filtering.")

        if cfg.length < len(pools):
            raise ValidationError(
                f"Length ({cfg.length}) must be at least {len(pools)} to include every selected character set."
            )

        combined_pool = "".join(chars for _, chars in pools)
        chosen: list[str] = [secrets.choice(chars) for _, chars in pools]
        for _ in range(cfg.length - len(chosen)):
            chosen.append(secrets.choice(combined_pool))

        _secrets_shuffle(chosen)
        secret = "".join(chosen)
        entropy_bits = round(cfg.length * math.log2(len(combined_pool)), 1)

        return GeneratedSecretResult(
            secret=secret,
            mode="password",
            length=len(secret),
            character_sets_used=tuple(name for name, _ in pools),
            estimated_entropy_bits=entropy_bits,
            storage_warning=STORAGE_WARNING,
        )

    def generate_passphrase(
        self,
        *,
        word_count: int = 5,
        separator: str = "-",
        capitalize: bool = False,
        include_number: bool = False,
    ) -> GeneratedSecretResult:
        """Generate a multi-word passphrase from the bundled wordlist using ``secrets``."""
        validate_passphrase_options(word_count=word_count, separator=separator)

        words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
        if capitalize:
            words = [w.capitalize() for w in words]

        sets_used = ["wordlist"]
        if capitalize:
            sets_used.append("capitalized")

        extra_bits = 0.0
        if include_number:
            target_idx = secrets.randbelow(len(words))
            digit = str(secrets.randbelow(10))
            words[target_idx] = f"{words[target_idx]}{digit}"
            sets_used.append("digit")
            extra_bits = math.log2(10 * len(words))

        secret = separator.join(words)
        entropy_bits = round(word_count * math.log2(len(PASSPHRASE_WORDS)) + extra_bits, 1)

        return GeneratedSecretResult(
            secret=secret,
            mode="passphrase",
            length=len(secret),
            character_sets_used=tuple(sets_used),
            estimated_entropy_bits=entropy_bits,
            storage_warning=STORAGE_WARNING,
        )
