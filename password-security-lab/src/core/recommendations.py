"""Defensive security recommendation engine."""

from __future__ import annotations

from src.core.models import BreachCheckResult, PasswordAnalysisResult, Recommendation


class RecommendationEngine:
    """Produces prioritized, actionable password-security guidance."""

    def generate(
        self,
        analysis: PasswordAnalysisResult | None = None,
        breach: BreachCheckResult | None = None,
    ) -> tuple[Recommendation, ...]:
        """Build recommendations from optional assessment and breach results."""
        recs: list[Recommendation] = []

        if breach is not None:
            if breach.checked and breach.exposed:
                recs.append(
                    Recommendation(
                        title="Change this compromised password promptly",
                        detail=(
                            f"This password appeared {breach.occurrence_count:,} time(s) in known "
                            "data breaches. Replace it immediately on any account where it is used."
                        ),
                        priority="critical",
                    )
                )
            elif not breach.checked:
                recs.append(
                    Recommendation(
                        title="Breach status could not be verified",
                        detail=(
                            "The HIBP range lookup did not complete. Retry when online before "
                            "relying on this password."
                        ),
                        priority="high",
                    )
                )

        if analysis is not None:
            if analysis.score <= 1:
                recs.append(
                    Recommendation(
                        title="Replace with a much longer, unpredictable secret",
                        detail=(
                            "This password is easy to guess. Use a password generator for 16+ "
                            "random characters or a 5+ random word passphrase."
                        ),
                        priority="high",
                    )
                )
            elif analysis.score == 2:
                recs.append(
                    Recommendation(
                        title="Increase length and remove predictable patterns",
                        detail=(
                            "Extend the password to at least 14-16 characters or switch to a "
                            "randomly generated passphrase without common words or sequences."
                        ),
                        priority="medium",
                    )
                )

            finding_categories = {f.category for f in analysis.findings}
            if finding_categories & {
                "Common Password",
                "Dictionary Word",
                "Predictable Substitution",
                "Keyboard Pattern",
                "Sequential Characters",
                "Repeated Pattern",
                "Date Pattern",
            }:
                recs.append(
                    Recommendation(
                        title="Avoid predictable words, substitutions, and sequences",
                        detail=(
                            "Password-guessing tools test common words, l33t substitutions, "
                            "dates, and keyboard walks early. Prefer true randomness over "
                            "manual tweaks."
                        ),
                        priority="medium",
                    )
                )

        recs.extend(
            [
                Recommendation(
                    title="Use a unique password for every account",
                    detail=(
                        "Never reuse passwords across services—a breach on one site puts "
                        "every account sharing that password at risk of credential stuffing."
                    ),
                    priority="best_practice",
                ),
                Recommendation(
                    title="Store credentials in a reputable password manager",
                    detail=(
                        "A dedicated password manager makes it practical to use long, unique, "
                        "randomly generated passwords for every site without memorizing them."
                    ),
                    priority="best_practice",
                ),
                Recommendation(
                    title="Enable multi-factor authentication (MFA)",
                    detail=(
                        "Add phishing-resistant or authenticator-app MFA wherever supported so "
                        "a compromised password alone cannot grant account access."
                    ),
                    priority="best_practice",
                ),
                Recommendation(
                    title="Prefer long, unpredictable passwords or passphrases",
                    detail=(
                        "Length and unpredictability matter more than memorizing short complex "
                        "strings. No password tool can guarantee absolute security."
                    ),
                    priority="best_practice",
                ),
            ]
        )

        return tuple(recs)
