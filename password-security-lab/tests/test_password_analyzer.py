"""Unit tests for offline password-strength assessment."""

from dataclasses import asdict

import pytest

from src.core.password_analyzer import PasswordAnalyzer
from src.utils.validation import ValidationError


@pytest.fixture
def analyzer() -> PasswordAnalyzer:
    return PasswordAnalyzer()


def test_very_short_password_scores_very_weak(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze("a1")
    assert result.score == 0
    assert result.rating == "Very Weak"
    assert result.length == 2
    assert any(f.category == "Short Length" for f in result.findings)
    assert "estimate" in result.disclaimer.lower()


def test_common_and_predictable_passwords(analyzer: PasswordAnalyzer) -> None:
    for synthetic in ("password", "123456", "p@ssw0rd", "letmein123"):
        result = analyzer.analyze(synthetic)
        assert result.score <= 1
        assert result.rating in ("Very Weak", "Weak")


def test_repeated_character_password_flagged(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze("aaaaaaaaaaaa")
    categories = {f.category for f in result.findings}
    assert "Repeated Pattern" in categories
    assert "Low Character Variety" in categories
    assert result.score <= 1


def test_sequential_and_keyboard_patterns_detected(analyzer: PasswordAnalyzer) -> None:
    seq_result = analyzer.analyze("abcdef123456")
    seq_categories = {f.category for f in seq_result.findings}
    assert "Sequential Characters" in seq_categories

    kbd_result = analyzer.analyze("qwertyuiop12")
    kbd_categories = {f.category for f in kbd_result.findings}
    assert "Keyboard Pattern" in kbd_categories


def test_long_passphrase_rated_strong_without_symbol_penalty(
    analyzer: PasswordAnalyzer,
) -> None:
    phrase = "harbor-lantern-glacier-compass-meadow-quartz"
    result = analyzer.analyze(phrase)
    assert result.score >= 3
    assert result.rating in ("Strong", "Very Strong")
    assert result.length == len(phrase)
    # Should not force missing-symbol warnings onto a strong passphrase
    assert any(f.category == "Passphrase Profile" for f in result.findings)


def test_very_long_passphrase_over_100_chars(analyzer: PasswordAnalyzer) -> None:
    long_phrase = "-".join(["harbor", "glacier", "lantern", "compass", "quartz"] * 4)
    assert len(long_phrase) > 100
    result = analyzer.analyze(long_phrase)
    assert result.length == len(long_phrase)
    assert result.score >= 3
    assert any(f.category == "Estimator Scope" for f in result.findings)


def test_unicode_password_supported(analyzer: PasswordAnalyzer) -> None:
    sample = "café-über-naïve-aurora-42"
    result = analyzer.analyze(sample)
    assert result.character_classes["unicode"] is True
    assert result.length == len(sample)
    assert result.score >= 3


def test_result_never_echoes_evaluated_password(analyzer: PasswordAnalyzer) -> None:
    secret = "UniqueSynthTestToken#9941"
    result = analyzer.analyze(secret)
    serialized = str(asdict(result))
    assert secret not in serialized


def test_empty_password_raises_validation_error(analyzer: PasswordAnalyzer) -> None:
    with pytest.raises(ValidationError):
        analyzer.analyze("")
