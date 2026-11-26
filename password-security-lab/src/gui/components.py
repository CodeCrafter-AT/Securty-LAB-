"""Reusable Tkinter UI widgets and theme constants for Password Security Lab."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk
from typing import Any

PALETTE = {
    "bg": "#F1F5F9",
    "surface": "#FFFFFF",
    "surface_alt": "#F8FAFC",
    "border": "#CBD5E1",
    "header_bg": "#0F172A",
    "header_fg": "#F8FAFC",
    "header_sub": "#94A3B8",
    "accent": "#1D4ED8",
    "accent_hover": "#1E40AF",
    "text": "#0F172A",
    "muted": "#475569",
    "badge_bg": "#E2E8F0",
    "danger": "#DC2626",
    "danger_bg": "#FEF2F2",
    "warning": "#D97706",
    "warning_bg": "#FFFBEB",
    "orange": "#EA580C",
    "success": "#15803D",
    "success_bg": "#F0FDF4",
    "emerald": "#047857",
    "info": "#0369A1",
    "info_bg": "#F0F9FF",
}

RATING_COLORS: dict[str, str] = {
    "Very Weak": PALETTE["danger"],
    "Weak": PALETTE["orange"],
    "Fair": PALETTE["warning"],
    "Strong": PALETTE["success"],
    "Very Strong": PALETTE["emerald"],
}


def configure_styles(root: tk.Misc) -> ttk.Style:
    """Configure a consistent, high-contrast ttk theme across platforms."""
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    base_font = ("Segoe UI", 10) if sys.platform.startswith("win") else ("Helvetica Neue", 11)
    bold_font = (base_font[0], base_font[1], "bold")
    title_font = (base_font[0], base_font[1] + 2, "bold")
    small_font = (base_font[0], max(9, base_font[1] - 1))

    style.configure(".", background=PALETTE["bg"], foreground=PALETTE["text"], font=base_font)
    style.configure("App.TFrame", background=PALETTE["bg"])
    style.configure("Card.TFrame", background=PALETTE["surface"])
    style.configure("CardInner.TFrame", background=PALETTE["surface"])
    style.configure("SurfaceAlt.TFrame", background=PALETTE["surface_alt"])

    style.configure(
        "CardTitle.TLabel",
        background=PALETTE["surface"],
        foreground=PALETTE["text"],
        font=title_font,
    )
    style.configure(
        "CardSub.TLabel",
        background=PALETTE["surface"],
        foreground=PALETTE["muted"],
        font=small_font,
    )
    style.configure(
        "CardBody.TLabel",
        background=PALETTE["surface"],
        foreground=PALETTE["text"],
        font=base_font,
    )
    style.configure(
        "CardMuted.TLabel",
        background=PALETTE["surface"],
        foreground=PALETTE["muted"],
        font=small_font,
    )
    style.configure(
        "CardBold.TLabel",
        background=PALETTE["surface"],
        foreground=PALETTE["text"],
        font=bold_font,
    )
    style.configure(
        "Card.TCheckbutton",
        background=PALETTE["surface"],
        foreground=PALETTE["text"],
        font=base_font,
    )
    style.configure(
        "Card.TRadiobutton",
        background=PALETTE["surface"],
        foreground=PALETTE["text"],
        font=base_font,
    )
    style.configure(
        "Primary.TButton",
        background=PALETTE["accent"],
        foreground="#FFFFFF",
        font=bold_font,
        padding=(14, 7),
        borderwidth=0,
    )
    style.map(
        "Primary.TButton",
        background=[("active", PALETTE["accent_hover"]), ("disabled", "#94A3B8")],
        foreground=[("disabled", "#F8FAFC")],
    )
    style.configure(
        "Secondary.TButton",
        background=PALETTE["badge_bg"],
        foreground=PALETTE["text"],
        font=base_font,
        padding=(12, 7),
        borderwidth=0,
    )
    style.map(
        "Secondary.TButton",
        background=[("active", "#CBD5E1"), ("disabled", "#E2E8F0")],
    )
    style.configure(
        "TEntry",
        fieldbackground="#FFFFFF",
        foreground=PALETTE["text"],
        padding=(6, 5),
    )
    style.configure(
        "TSpinbox",
        fieldbackground="#FFFFFF",
        foreground=PALETTE["text"],
        padding=(4, 4),
    )
    return style


class CardFrame(tk.Frame):
    """Clean bordered card container with title and optional subtitle."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        subtitle: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            parent,
            bg=PALETTE["surface"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
            bd=0,
            **kwargs,
        )
        self.columnconfigure(0, weight=1)

        header = ttk.Frame(self, style="CardInner.TFrame", padding=(16, 12, 16, 6))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text=title, style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        if subtitle:
            ttk.Label(
                header,
                text=subtitle,
                style="CardSub.TLabel",
                wraplength=460,
                justify="left",
            ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        sep = tk.Frame(self, bg="#E2E8F0", height=1)
        sep.grid(row=1, column=0, sticky="ew", padx=16)

        self.body = ttk.Frame(self, style="CardInner.TFrame", padding=(16, 12, 16, 14))
        self.body.grid(row=2, column=0, sticky="nsew")
        self.rowconfigure(2, weight=1)


class StrengthMeter(tk.Canvas):
    """Five-segment visual password strength bar."""

    def __init__(self, parent: tk.Misc, height: int = 12) -> None:
        super().__init__(
            parent,
            height=height,
            bg=PALETTE["surface"],
            highlightthickness=0,
            bd=0,
        )
        self._score: int | None = None
        self._rating: str = ""
        self.bind("<Configure>", lambda _e: self._redraw())

    def set_score(self, score: int | None, rating: str = "") -> None:
        """Update displayed score (0..4) or None for unchecked state."""
        self._score = score
        self._rating = rating
        self._redraw()

    def _redraw(self) -> None:
        self.delete("all")
        width = max(120, self.winfo_width())
        height = max(10, self.winfo_height())
        segments = 5
        gap = 6
        seg_w = (width - gap * (segments - 1)) / segments

        active_count = 0 if self._score is None else self._score + 1
        active_color = RATING_COLORS.get(self._rating, PALETTE["accent"])

        for idx in range(segments):
            x0 = idx * (seg_w + gap)
            x1 = x0 + seg_w
            fill = active_color if idx < active_count else "#E2E8F0"
            self.create_rectangle(x0, 1, x1, height - 1, fill=fill, outline="")


class ScrollableContainer(ttk.Frame):
    """Vertically scrollable container that keeps child frame matched to width."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, style="App.TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self._canvas = tk.Canvas(
            self,
            bg=PALETTE["bg"],
            highlightthickness=0,
            bd=0,
        )
        self._scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._canvas.grid(row=0, column=0, sticky="nsew")
        self._scrollbar.grid(row=0, column=1, sticky="ns")

        self.inner = ttk.Frame(self._canvas, style="App.TFrame")
        self._window_id = self._canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self._canvas.bind_all("<Button-4>", lambda _e: self._canvas.yview_scroll(-1, "units"))
        self._canvas.bind_all("<Button-5>", lambda _e: self._canvas.yview_scroll(1, "units"))

    def _on_inner_configure(self, _event: tk.Event[Any]) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event[Any]) -> None:
        self._canvas.itemconfigure(self._window_id, width=event.width)

    def _on_mousewheel(self, event: tk.Event[Any]) -> None:
        if sys.platform == "darwin":
            delta = -1 if event.delta > 0 else 1
        else:
            delta = int(-event.delta / 120) if event.delta else 0
        if delta:
            self._canvas.yview_scroll(delta, "units")
