"""Domain models for Password Security Lab.

None of these result structures store plaintext passwords or full password hashes.
"""

from dataclasses import dataclass
from typing import Literal

StrengthRating = Literal["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
FindingSeverity = Literal["info", "warning", "high"]
RecommendationPriority = Literal["critical", "high", "medium", "best_practice"]


@dataclass(frozen=True, slots=True)
class PatternFinding:
    """Single structural or heuristic observation about a password."""

    category: str
    description: str
    severity: FindingSeverity


@dataclass(frozen=True, slots=True)
class PasswordAnalysisResult:
    """Offline password-strength evaluation result (never retains the password)."""

    length: int
    score: int
    rating: StrengthRating
    estimated_guesses_log10: float
    crack_time_display: str
    character_classes: dict[str, bool]
    unique_characters: int
    findings: tuple[PatternFinding, ...]
    estimator_warnings: tuple[str, ...]
    estimator_suggestions: tuple[str, ...]
    disclaimer: str


@dataclass(frozen=True, slots=True)
class BreachCheckResult:
    """Result of an HIBP k-anonymity range check (retains only the 5-char prefix)."""

    checked: bool
    exposed: bool | None
    occurrence_count: int
    hash_prefix: str
    padding_enabled: bool
    status_message: str
    caveat: str
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class GeneratorConfig:
    """Configuration options for cryptographically random password generation."""

    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class GeneratedSecretResult:
    """Generated password or passphrase metadata and value."""

    secret: str
    mode: Literal["password", "passphrase"]
    length: int
    character_sets_used: tuple[str, ...]
    estimated_entropy_bits: float
    storage_warning: str


@dataclass(frozen=True, slots=True)
class Recommendation:
    """Actionable defensive security guidance item."""

    title: str
    detail: str
    priority: RecommendationPriority
