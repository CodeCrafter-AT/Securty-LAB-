"""Offline password-strength assessment powered by zxcvbn and pattern heuristics.

Never echoes the evaluated password or matched secret tokens in results.
"""

from __future__ import annotations

from typing import Any

from zxcvbn import zxcvbn

from src.core.models import PasswordAnalysisResult, PatternFinding, StrengthRating
from src.utils.validation import validate_password_input

SCORE_TO_RATING: dict[int, StrengthRating] = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}

ESTIMATE_DISCLAIMER = (
    "This rating is an estimate based on guessability heuristics and known patterns, "
    "not a guarantee that a password cannot be guessed or compromised."
)

_KEYBOARD_ROWS = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


def _has_repeated_run(password: str, min_run: int = 3) -> bool:
    """Return True if any character repeats consecutively at least ``min_run`` times."""
    run = 1
    for idx in range(1, len(password)):
        if password[idx] == password[idx - 1]:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def _has_sequential_run(password: str, min_run: int = 3) -> bool:
    """Return True if ASCII alphanumeric characters form an ascending/descending run."""
    lowered = password.lower()
    if len(lowered) < min_run:
        return False

    asc_run = 1
    desc_run = 1
    for idx in range(1, len(lowered)):
        prev_ch = lowered[idx - 1]
        curr_ch = lowered[idx]
        both_alpha = (
            prev_ch.isascii() and curr_ch.isascii() and prev_ch.isalpha() and curr_ch.isalpha()
        )
        both_digit = (
            prev_ch.isascii() and curr_ch.isascii() and prev_ch.isdigit() and curr_ch.isdigit()
        )

        if both_alpha or both_digit:
            diff = ord(curr_ch) - ord(prev_ch)
            asc_run = asc_run + 1 if diff == 1 else 1
            desc_run = desc_run + 1 if diff == -1 else 1
            if asc_run >= min_run or desc_run >= min_run:
                return True
        else:
            asc_run = 1
            desc_run = 1
    return False


def _has_keyboard_walk(password: str, min_run: int = 4) -> bool:
    """Return True if the password contains an obvious QWERTY keyboard row run."""
    lowered = password.lower()
    for row in _KEYBOARD_ROWS:
        reversed_row = row[::-1]
        for start in range(0, len(row) - min_run + 1):
            segment = row[start : start + min_run]
            rev_segment = reversed_row[start : start + min_run]
            if segment in lowered or rev_segment in lowered:
                return True
    return False


def _extract_zxcvbn_findings(sequence: list[dict[str, Any]]) -> list[PatternFinding]:
    """Translate zxcvbn match sequence metadata into privacy-safe findings."""
    findings: list[PatternFinding] = []
    seen_categories: set[str] = set()

    for match in sequence:
        pattern = str(match.get("pattern", ""))
        if pattern == "dictionary":
            dict_name = str(match.get("dictionary_name", ""))
            is_l33t = bool(match.get("l33t", False))
            if "passwords" in dict_name and "common_password" not in seen_categories:
                seen_categories.add("common_password")
                findings.append(
                    PatternFinding(
                        category="Common Password",
                        description="Matches or embeds a frequently used password from common-password lists.",
                        severity="high",
                    )
                )
            elif "dictionary" not in seen_categories:
                seen_categories.add("dictionary")
                findings.append(
                    PatternFinding(
                        category="Dictionary Word",
                        description="Contains a recognizable word or name that lowers guessing resistance.",
                        severity="warning",
                    )
                )
            if is_l33t and "substitution" not in seen_categories:
                seen_categories.add("substitution")
                findings.append(
                    PatternFinding(
                        category="Predictable Substitution",
                        description="Uses predictable character substitutions (such as '@' for 'a' or '0' for 'o').",
                        severity="warning",
                    )
                )
        elif pattern == "spatial" and "keyboard" not in seen_categories:
            seen_categories.add("keyboard")
            findings.append(
                PatternFinding(
                    category="Keyboard Pattern",
                    description="Contains adjacent keyboard key patterns (e.g., row or diagonal walks).",
                    severity="warning",
                )
            )
        elif pattern == "repeat" and "repeat" not in seen_categories:
            seen_categories.add("repeat")
            findings.append(
                PatternFinding(
                    category="Repeated Pattern",
                    description="Repeats characters or short substrings, reducing effective entropy.",
                    severity="warning",
                )
            )
        elif pattern == "sequence" and "sequence" not in seen_categories:
            seen_categories.add("sequence")
            findings.append(
                PatternFinding(
                    category="Sequential Characters",
                    description="Contains predictable alphabetic or numeric sequences.",
                    severity="warning",
                )
            )
        elif pattern == "date" and "date" not in seen_categories:
            seen_categories.add("date")
            findings.append(
                PatternFinding(
                    category="Date Pattern",
                    description="Contains a date-like pattern that attackers commonly test early.",
                    severity="warning",
                )
            )

    return findings


class PasswordAnalyzer:
    """Evaluates password strength offline using zxcvbn and structural heuristics."""

    # zxcvbn 4.5+ enforces max_length=72 by default; we evaluate pattern scoring
    # on the 72-character prefix while tracking full-length structural metrics.
    _ZXCVBN_MAX_INPUT = 72

    def analyze(self, password: str) -> PasswordAnalysisResult:
        """Assess password quality without persisting or echoing the password."""
        validate_password_input(password)

        length = len(password)
        char_classes = {
            "lowercase": any(ch.islower() for ch in password),
            "uppercase": any(ch.isupper() for ch in password),
            "digits": any(ch.isdigit() for ch in password),
            "symbols": any(not ch.isalnum() and not ch.isspace() for ch in password),
            "whitespace": any(ch.isspace() for ch in password),
            "unicode": any(ord(ch) > 127 for ch in password),
        }
        unique_chars = len(set(password))

        estimator_input = password[: self._ZXCVBN_MAX_INPUT]
        zx = zxcvbn(estimator_input, max_length=self._ZXCVBN_MAX_INPUT)

        score = int(zx.get("score", 0))
        score = max(0, min(4, score))
        rating = SCORE_TO_RATING[score]
        guesses_log10 = float(zx.get("guesses_log10", 0.0))
        crack_times = zx.get("crack_times_display", {})
        crack_display = str(crack_times.get("offline_slow_hashing_1e4_per_second", "unknown"))

        findings = _extract_zxcvbn_findings(list(zx.get("sequence", [])))
        existing_categories = {f.category for f in findings}

        if length < 12:
            findings.append(
                PatternFinding(
                    category="Short Length",
                    description=f"Length is {length} characters; 14+ characters (or a multi-word passphrase) provides substantially better resistance.",
                    severity="high" if length < 8 else "warning",
                )
            )

        if _has_repeated_run(password) and "Repeated Pattern" not in existing_categories:
            findings.append(
                PatternFinding(
                    category="Repeated Pattern",
                    description="Contains 3 or more identical consecutive characters.",
                    severity="warning",
                )
            )

        if _has_sequential_run(password) and "Sequential Characters" not in existing_categories:
            findings.append(
                PatternFinding(
                    category="Sequential Characters",
                    description="Contains sequential characters or numbers.",
                    severity="warning",
                )
            )

        if _has_keyboard_walk(password) and "Keyboard Pattern" not in existing_categories:
            findings.append(
                PatternFinding(
                    category="Keyboard Pattern",
                    description="Contains adjacent keys from a standard QWERTY keyboard row.",
                    severity="warning",
                )
            )

        if length >= 6 and unique_chars <= max(2, length // 4):
            findings.append(
                PatternFinding(
                    category="Low Character Variety",
                    description="Only a small number of distinct characters are used relative to total length.",
                    severity="warning",
                )
            )

        # Do not penalize strong passphrases for lacking arbitrary symbol rules.
        active_basic_classes = sum(
            1 for key in ("lowercase", "uppercase", "digits", "symbols") if char_classes[key]
        )
        if score >= 3 and active_basic_classes < 3:
            findings.append(
                PatternFinding(
                    category="Passphrase Profile",
                    description="Rated strong primarily due to length and unpredictability despite using fewer character classes.",
                    severity="info",
                )
            )
        elif score < 3 and active_basic_classes <= 1:
            findings.append(
                PatternFinding(
                    category="Limited Character Diversity",
                    description="Uses only a single character class; increasing length or mixing independent words/character types helps.",
                    severity="info",
                )
            )

        if length > self._ZXCVBN_MAX_INPUT:
            findings.append(
                PatternFinding(
                    category="Estimator Scope",
                    description=(
                        f"Password length is {length} characters; zxcvbn evaluates "
                        f"the first {self._ZXCVBN_MAX_INPUT} characters for pattern matching."
                    ),
                    severity="info",
                )
            )

        feedback = zx.get("feedback", {})
        raw_warning = str(feedback.get("warning", "") or "").strip()
        warnings = (raw_warning,) if raw_warning else ()
        raw_suggestions = feedback.get("suggestions", []) or []
        suggestions = tuple(str(item).strip() for item in raw_suggestions if str(item).strip())

        return PasswordAnalysisResult(
            length=length,
            score=score,
            rating=rating,
            estimated_guesses_log10=round(guesses_log10, 2),
            crack_time_display=crack_display,
            character_classes=char_classes,
            unique_characters=unique_chars,
            findings=tuple(findings),
            estimator_warnings=warnings,
            estimator_suggestions=suggestions,
            disclaimer=ESTIMATE_DISCLAIMER,
        )
