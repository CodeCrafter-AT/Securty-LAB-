"""Application entry point for Password Security Lab."""

import sys

from src.cli.commands import run_cli


def main() -> int:
    """Execute the Password Security Lab CLI."""
    return run_cli()


if __name__ == "__main__":
    sys.exit(main())
