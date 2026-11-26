"""Core defensive security modules (UI-independent)."""

from src.core.breach_checker import BreachChecker, compute_sha1_parts
from src.core.models import (
    BreachCheckResult,
    GeneratedSecretResult,
    GeneratorConfig,
    PasswordAnalysisResult,
    PatternFinding,
    Recommendation,
    StrengthRating,
)
from src.core.password_analyzer import PasswordAnalyzer
from src.core.password_generator import PasswordGenerator
from src.core.recommendations import RecommendationEngine

__all__ = [
    "BreachCheckResult",
    "BreachChecker",
    "GeneratedSecretResult",
    "GeneratorConfig",
    "PasswordAnalysisResult",
    "PasswordAnalyzer",
    "PasswordGenerator",
    "PatternFinding",
    "Recommendation",
    "RecommendationEngine",
    "StrengthRating",
    "compute_sha1_parts",
]
