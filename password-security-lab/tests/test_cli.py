"""CLI integration tests using mocked stdin and mocked HIBP HTTP client."""

import io
from unittest.mock import patch

import pytest

from src.cli.commands import build_parser, run_cli
from src.core.models import BreachCheckResult


def test_cli_parser_has_no_password_argument() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "--password" not in help_text
    for sub_action in parser._subparsers._group_actions:
        for sub_parser in sub_action.choices.values():
            assert "--password" not in sub_parser.format_help()


def test_cli_generate_command(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_cli(["generate", "--length", "20"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Length:             20 characters" in captured.out
    assert "password manager" in captured.out.lower()


def test_cli_assess_from_stdin_never_echoes_password(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "SyntheticCliInput#2026!"
    fake_stdin = io.StringIO(f"{secret}\n")
    fake_stdin.isatty = lambda: False  # type: ignore[method-assign]
    monkeypatch.setattr("sys.stdin", fake_stdin)

    code = run_cli(["assess"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Password Strength Assessment" in captured.out
    assert secret not in captured.out


def test_cli_check_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_stdin = io.StringIO("SyntheticTestSample\n")
    fake_stdin.isatty = lambda: False  # type: ignore[method-assign]
    monkeypatch.setattr("sys.stdin", fake_stdin)

    not_found = BreachCheckResult(
        checked=True,
        exposed=False,
        occurrence_count=0,
        hash_prefix="AAAAA",
        padding_enabled=True,
        status_message="Not found",
        caveat="Not guaranteed safe.",
    )
    with patch("src.cli.commands.BreachChecker.check_password", return_value=not_found):
        assert run_cli(["check"]) == 0

    fake_stdin2 = io.StringIO("SyntheticTestSample\n")
    fake_stdin2.isatty = lambda: False  # type: ignore[method-assign]
    monkeypatch.setattr("sys.stdin", fake_stdin2)

    exposed = BreachCheckResult(
        checked=True,
        exposed=True,
        occurrence_count=42,
        hash_prefix="AAAAA",
        padding_enabled=True,
        status_message="Exposed",
        caveat="Not guaranteed safe.",
    )
    with patch("src.cli.commands.BreachChecker.check_password", return_value=exposed):
        assert run_cli(["check"]) == 2
