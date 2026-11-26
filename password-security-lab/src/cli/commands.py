"""Argparse CLI for Password Security Lab.

Passwords are never accepted as command-line arguments to prevent exposure in
shell history and process listings. Interactive prompts use ``getpass``.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from src.core.breach_checker import BreachChecker
from src.core.models import (
    BreachCheckResult,
    GeneratorConfig,
    PasswordAnalysisResult,
    Recommendation,
)
from src.core.password_analyzer import PasswordAnalyzer
from src.core.password_generator import PasswordGenerator
from src.core.recommendations import RecommendationEngine
from src.services.clipboard_service import copy_to_clipboard
from src.services.hibp_client import HIBPRangeClient
from src.utils.logging_config import configure_logging
from src.utils.validation import (
    DEFAULT_GENERATED_LENGTH,
    DEFAULT_PASSPHRASE_WORDS,
    ValidationError,
)


def _read_secret_from_prompt_or_stdin(prompt: str) -> str:
    """Read a secret via getpass on TTY, or one line from stdin when piped."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    line = sys.stdin.readline()
    return line.rstrip("\r\n")


def _print_analysis(result: PasswordAnalysisResult) -> None:
    classes = [
        label
        for key, label in (
            ("lowercase", "lowercase"),
            ("uppercase", "uppercase"),
            ("digits", "digits"),
            ("symbols", "symbols"),
            ("whitespace", "whitespace"),
            ("unicode", "unicode"),
        )
        if result.character_classes.get(key)
    ]

    print("\n=== Password Strength Assessment ===")
    print(f"Rating:             {result.rating} (Score: {result.score}/4)")
    print(f"Length:             {result.length} characters ({result.unique_characters} unique)")
    print(f"Character classes:  {', '.join(classes) if classes else 'none'}")
    print(f"Estimated guesses:  ~10^{result.estimated_guesses_log10}")
    print(f"Offline slow hash:  {result.crack_time_display}")

    if result.findings:
        print("\nFindings:")
        for finding in result.findings:
            print(f"  - [{finding.severity.upper()}] {finding.category}: {finding.description}")

    if result.estimator_warnings:
        print("\nEstimator Warnings:")
        for warning in result.estimator_warnings:
            print(f"  - {warning}")

    if result.estimator_suggestions:
        print("\nEstimator Suggestions:")
        for suggestion in result.estimator_suggestions:
            print(f"  - {suggestion}")

    print(f"\nNote: {result.disclaimer}")


def _print_breach(result: BreachCheckResult) -> None:
    print("\n=== HIBP Breach Exposure Check (k-Anonymity) ===")
    print(f"Transmitted prefix: {result.hash_prefix} (first 5 SHA-1 hex chars only)")
    print(f"Add-Padding:        {'enabled' if result.padding_enabled else 'disabled'}")
    if not result.checked:
        print(f"Status:             Unavailable ({result.error_code or 'error'})")
        print(f"Details:            {result.status_message}")
    elif result.exposed:
        print(f"Status:             EXPOSED ({result.occurrence_count:,} occurrence(s))")
        print(f"Details:            {result.status_message}")
    else:
        print("Status:             Not found in HIBP dataset")
        print(f"Details:            {result.status_message}")
    print(f"Note: {result.caveat}")


def _print_recommendations(recommendations: tuple[Recommendation, ...]) -> None:
    print("\n=== Security Recommendations ===")
    for rec in recommendations:
        tag = rec.priority.replace("_", " ").upper()
        print(f"  [{tag}] {rec.title}")
        print(f"      {rec.detail}")


def _handle_gui(_args: argparse.Namespace) -> int:
    from src.gui.app import launch_gui

    return launch_gui()


def _handle_assess(args: argparse.Namespace) -> int:
    try:
        password = _read_secret_from_prompt_or_stdin("Enter password to assess (input hidden): ")
        analyzer = PasswordAnalyzer()
        analysis = analyzer.analyze(password)
    except ValidationError as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1

    breach_result: BreachCheckResult | None = None
    if args.check_breach:
        client = HIBPRangeClient(timeout=args.timeout)
        breach_result = BreachChecker(client=client).check_password(password)

    del password

    _print_analysis(analysis)
    if breach_result is not None:
        _print_breach(breach_result)

    recommendations = RecommendationEngine().generate(analysis, breach_result)
    _print_recommendations(recommendations)
    return 0


def _handle_check(args: argparse.Namespace) -> int:
    try:
        password = _read_secret_from_prompt_or_stdin(
            "Enter password to check against HIBP (input hidden): "
        )
        client = HIBPRangeClient(
            timeout=args.timeout,
            add_padding=not args.no_padding,
        )
        breach_result = BreachChecker(client=client).check_password(password)
    except ValidationError as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1
    finally:
        if "password" in locals():
            del password

    _print_breach(breach_result)
    recommendations = RecommendationEngine().generate(breach=breach_result)
    _print_recommendations(recommendations)

    if not breach_result.checked:
        return 1
    if breach_result.exposed:
        return 2
    return 0


def _handle_generate(args: argparse.Namespace) -> int:
    generator = PasswordGenerator()
    try:
        if args.passphrase:
            result = generator.generate_passphrase(
                word_count=args.words,
                separator=args.separator,
                capitalize=args.capitalize,
                include_number=args.include_number,
            )
        else:
            config = GeneratorConfig(
                length=args.length,
                use_uppercase=not args.no_uppercase,
                use_lowercase=not args.no_lowercase,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
            )
            result = generator.generate_password(config)
    except ValidationError as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 1

    print("\n=== Generated Secret ===")
    print(f"Mode:               {result.mode}")
    print(f"Length:             {result.length} characters")
    print(f"Options:            {', '.join(result.character_sets_used)}")
    print(f"Estimated entropy:  ~{result.estimated_entropy_bits} bits")
    print(f"Value:              {result.secret}")

    if args.copy:
        copied, copy_msg = copy_to_clipboard(result.secret)
        status = "Clipboard:" if copied else "Clipboard warning:"
        print(f"{status}          {copy_msg}")

    print(f"\nReminder: {result.storage_warning}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Password Security Lab — Local-first educational password strength "
            "analyzer, HIBP k-anonymity checker, and cryptographic password generator."
        ),
        epilog=(
            "Privacy note: Passwords are requested securely via hidden terminal input "
            "(getpass) and are never accepted as CLI flags, logged, or saved."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    gui_parser = subparsers.add_parser(
        "gui",
        help="Launch the Tkinter desktop application.",
    )
    gui_parser.set_defaults(handler=_handle_gui)

    assess_parser = subparsers.add_parser(
        "assess",
        help="Assess password strength offline (uses hidden getpass prompt).",
    )
    assess_parser.add_argument(
        "--check-breach",
        action="store_true",
        help="Also query HIBP range API using only a 5-character SHA-1 prefix.",
    )
    assess_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTPS request timeout in seconds when --check-breach is set (default: 10).",
    )
    assess_parser.set_defaults(handler=_handle_assess)

    check_parser = subparsers.add_parser(
        "check",
        help=(
            "Check password exposure against HIBP k-anonymity API "
            "(exit code 0=not found, 2=exposed, 1=error)."
        ),
    )
    check_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTPS request timeout in seconds (default: 10).",
    )
    check_parser.add_argument(
        "--no-padding",
        action="store_true",
        help="Disable the HIBP Add-Padding request header.",
    )
    check_parser.set_defaults(handler=_handle_check)

    gen_parser = subparsers.add_parser(
        "generate",
        help="Generate a cryptographically random password or passphrase using secrets.",
    )
    gen_parser.add_argument(
        "--length",
        type=int,
        default=DEFAULT_GENERATED_LENGTH,
        help=f"Password length in characters (default: {DEFAULT_GENERATED_LENGTH}).",
    )
    gen_parser.add_argument(
        "--no-uppercase",
        action="store_true",
        help="Exclude uppercase letters (A-Z).",
    )
    gen_parser.add_argument(
        "--no-lowercase",
        action="store_true",
        help="Exclude lowercase letters (a-z).",
    )
    gen_parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Exclude digits (0-9).",
    )
    gen_parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Exclude special symbols.",
    )
    gen_parser.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Exclude visually ambiguous characters (I, O, l, 0, 1).",
    )
    gen_parser.add_argument(
        "--passphrase",
        action="store_true",
        help="Generate a multi-word passphrase instead of a random character password.",
    )
    gen_parser.add_argument(
        "--words",
        type=int,
        default=DEFAULT_PASSPHRASE_WORDS,
        help=f"Number of words in passphrase mode (default: {DEFAULT_PASSPHRASE_WORDS}).",
    )
    gen_parser.add_argument(
        "--separator",
        type=str,
        default="-",
        help="Word separator in passphrase mode (default: '-').",
    )
    gen_parser.add_argument(
        "--capitalize",
        action="store_true",
        help="Capitalize each word in passphrase mode.",
    )
    gen_parser.add_argument(
        "--include-number",
        action="store_true",
        help="Append a random digit to one word in passphrase mode.",
    )
    gen_parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy the generated secret to the system clipboard.",
    )
    gen_parser.set_defaults(handler=_handle_generate)

    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments and dispatch to the selected command handler."""
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    return int(handler(args))
