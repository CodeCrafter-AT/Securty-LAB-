"""Cross-platform clipboard support for generated passwords."""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any


def copy_to_clipboard(text: str, tk_widget: Any | None = None) -> tuple[bool, str]:
    """Copy ``text`` to the system clipboard.

    Intended strictly for user-initiated copying of generated passwords/passphrases.
    Never passes secrets as command-line arguments.
    """
    if not text:
        return False, "Nothing to copy."

    if tk_widget is not None:
        try:
            tk_widget.clipboard_clear()
            tk_widget.clipboard_append(text)
            tk_widget.update_idletasks()
            return True, "Copied to clipboard. Store it in a reputable password manager."
        except Exception:
            return False, "Unable to access the desktop clipboard."

    cmd = _resolve_platform_clipboard_command()
    if cmd is None:
        return False, "No system clipboard utility was found on this platform."

    try:
        subprocess.run(  # noqa: S603 - fixed OS clipboard binaries only, shell=False
            cmd,
            input=text,
            text=True,
            check=True,
            shell=False,
            timeout=3,
        )
        return True, "Copied to clipboard. Store it in a reputable password manager."
    except (OSError, subprocess.SubprocessError):
        return False, "Failed to copy to clipboard."


def _resolve_platform_clipboard_command() -> list[str] | None:
    """Locate an OS clipboard binary using explicit executable lookup."""
    if sys.platform == "darwin":
        pbcopy = shutil.which("pbcopy")
        return [pbcopy] if pbcopy else None
    if sys.platform.startswith("win"):
        clip = shutil.which("clip")
        return [clip] if clip else None

    for candidate in ("wl-copy", "xclip", "xsel"):
        resolved = shutil.which(candidate)
        if not resolved:
            continue
        if candidate == "xclip":
            return [resolved, "-selection", "clipboard"]
        if candidate == "xsel":
            return [resolved, "--clipboard", "--input"]
        return [resolved]
    return None
