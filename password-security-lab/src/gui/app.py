"""Polished Tkinter desktop application for Password Security Lab."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk

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
from src.gui.components import (
    PALETTE,
    RATING_COLORS,
    CardFrame,
    ScrollableContainer,
    StrengthMeter,
    configure_styles,
)
from src.services.clipboard_service import copy_to_clipboard
from src.utils.logging_config import configure_logging
from src.utils.validation import (
    DEFAULT_GENERATED_LENGTH,
    DEFAULT_PASSPHRASE_WORDS,
    MAX_GENERATED_LENGTH,
    MAX_PASSPHRASE_WORDS,
    MIN_GENERATED_LENGTH,
    MIN_PASSPHRASE_WORDS,
    ValidationError,
)


class PasswordSecurityLabApp:
    """Main Tkinter desktop GUI controller."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Password Security Lab — Local Defensive Assessment")
        self.root.geometry("1120x800")
        self.root.minsize(880, 640)
        self.root.configure(bg=PALETTE["bg"])

        configure_styles(self.root)

        self._analyzer = PasswordAnalyzer()
        self._breach_checker = BreachChecker()
        self._generator = PasswordGenerator()
        self._recommender = RecommendationEngine()

        self._last_analysis: PasswordAnalysisResult | None = None
        self._last_breach: BreachCheckResult | None = None
        self._breach_in_flight = False

        # Form state variables (bound to UI controls; never logged or persisted)
        self._password_var = tk.StringVar()
        self._show_password_var = tk.BooleanVar(value=False)
        self._input_error_var = tk.StringVar()
        self._status_var = tk.StringVar(
            value="Ready. Password analysis runs offline; breach checks use HIBP k-anonymity."
        )

        # Generator variables
        self._gen_mode_var = tk.StringVar(value="password")
        self._gen_length_var = tk.IntVar(value=DEFAULT_GENERATED_LENGTH)
        self._gen_upper_var = tk.BooleanVar(value=True)
        self._gen_lower_var = tk.BooleanVar(value=True)
        self._gen_digits_var = tk.BooleanVar(value=True)
        self._gen_symbols_var = tk.BooleanVar(value=True)
        self._gen_no_ambig_var = tk.BooleanVar(value=False)

        self._pass_words_var = tk.IntVar(value=DEFAULT_PASSPHRASE_WORDS)
        self._pass_sep_var = tk.StringVar(value="-")
        self._pass_cap_var = tk.BooleanVar(value=False)
        self._pass_num_var = tk.BooleanVar(value=False)

        self._generated_secret_var = tk.StringVar()
        self._gen_meta_var = tk.StringVar(value="Configure options above and click Generate.")
        self._gen_feedback_var = tk.StringVar()

        self._build_layout()
        self._refresh_recommendations()

    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        self._build_header()

        self._scroll = ScrollableContainer(self.root)
        self._scroll.grid(row=1, column=0, sticky="nsew")
        content = ttk.Frame(self._scroll.inner, style="App.TFrame", padding=(20, 16, 20, 20))
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1, uniform="col")
        content.columnconfigure(1, weight=1, uniform="col")

        self._build_input_card(content)
        self._build_assessment_card(content)
        self._build_generator_card(content)
        self._build_breach_card(content)
        self._build_recommendations_card(content)
        self._build_privacy_card(content)

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=PALETTE["header_bg"], padx=22, pady=14)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="Password Security Lab",
            bg=PALETTE["header_bg"],
            fg=PALETTE["header_fg"],
            font=("Helvetica Neue", 18, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        tk.Label(
            header,
            text=(
                "Evaluate password strength locally, check breach exposure via HIBP "
                "k-anonymity, and generate cryptographically random secrets."
            ),
            bg=PALETTE["header_bg"],
            fg=PALETTE["header_sub"],
            font=("Helvetica Neue", 10),
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))

        badge = tk.Label(
            header,
            text="LOCAL-FIRST  •  ZERO STORAGE  •  5-CHAR PREFIX ONLY",
            bg="#1E293B",
            fg="#38BDF8",
            font=("Helvetica Neue", 9, "bold"),
            padx=10,
            pady=5,
        )
        badge.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_input_card(self, parent: ttk.Frame) -> None:
        card = CardFrame(
            parent,
            title="Password Evaluation & Breach Check",
            subtitle=(
                "Entered passwords stay masked by default, are never echoed in results, "
                "and are never written to disk or logs."
            ),
        )
        card.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        body = card.body
        body.columnconfigure(0, weight=1)

        ttk.Label(
            body,
            text="Enter a password or passphrase to evaluate:",
            style="CardBold.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        entry_row = ttk.Frame(body, style="CardInner.TFrame")
        entry_row.grid(row=1, column=0, sticky="ew")
        entry_row.columnconfigure(0, weight=1)

        self._password_entry = ttk.Entry(
            entry_row,
            textvariable=self._password_var,
            show="•",
            font=("Courier", 12),
        )
        self._password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._password_entry.bind("<Return>", lambda _e: self._on_analyze())
        self._password_entry.focus_set()

        self._show_btn = ttk.Checkbutton(
            entry_row,
            text="Show",
            variable=self._show_password_var,
            command=self._toggle_password_visibility,
            style="Card.TCheckbutton",
        )
        self._show_btn.grid(row=0, column=1, padx=(0, 8))

        ttk.Button(
            entry_row,
            text="Clear",
            command=self._on_clear,
            style="Secondary.TButton",
        ).grid(row=0, column=2)

        action_row = ttk.Frame(body, style="CardInner.TFrame")
        action_row.grid(row=2, column=0, sticky="ew", pady=(12, 4))

        ttk.Button(
            action_row,
            text="Analyze Strength (Offline)",
            command=self._on_analyze,
            style="Primary.TButton",
        ).pack(side="left", padx=(0, 10))

        self._breach_btn = ttk.Button(
            action_row,
            text="Check HIBP Breach Exposure",
            command=self._on_check_breach,
            style="Secondary.TButton",
        )
        self._breach_btn.pack(side="left", padx=(0, 14))

        self._loading_bar = ttk.Progressbar(
            action_row,
            mode="indeterminate",
            length=150,
        )

        self._status_label = ttk.Label(
            action_row,
            textvariable=self._status_var,
            style="CardMuted.TLabel",
        )
        self._status_label.pack(side="left", fill="x", expand=True)

        self._input_error_label = tk.Label(
            body,
            textvariable=self._input_error_var,
            bg=PALETTE["surface"],
            fg=PALETTE["danger"],
            font=("Helvetica Neue", 10, "bold"),
            anchor="w",
        )
        self._input_error_label.grid(row=3, column=0, sticky="ew", pady=(4, 0))

    def _build_assessment_card(self, parent: ttk.Frame) -> None:
        card = CardFrame(
            parent,
            title="Strength Assessment",
            subtitle="Offline heuristic and zxcvbn guessability estimation.",
        )
        card.grid(row=1, column=0, sticky="nsew", padx=(0, 8), pady=(0, 14))
        body = card.body
        body.columnconfigure(0, weight=1)

        top_row = ttk.Frame(body, style="CardInner.TFrame")
        top_row.grid(row=0, column=0, sticky="ew")
        top_row.columnconfigure(0, weight=1)

        self._rating_label = tk.Label(
            top_row,
            text="Not analyzed yet",
            bg=PALETTE["badge_bg"],
            fg=PALETTE["text"],
            font=("Helvetica Neue", 11, "bold"),
            padx=10,
            pady=4,
        )
        self._rating_label.grid(row=0, column=0, sticky="w")

        self._score_label = ttk.Label(
            top_row,
            text="Score: — / 4",
            style="CardBold.TLabel",
        )
        self._score_label.grid(row=0, column=1, sticky="e")

        self._meter = StrengthMeter(body, height=12)
        self._meter.grid(row=1, column=0, sticky="ew", pady=(10, 10))

        self._metrics_label = ttk.Label(
            body,
            text="Length: —   •   Unique chars: —   •   Est. offline slow-hash time: —",
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        )
        self._metrics_label.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        self._classes_label = ttk.Label(
            body,
            text="Character classes: —",
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        )
        self._classes_label.grid(row=3, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(
            body,
            text="Pattern Findings & Feedback:",
            style="CardBold.TLabel",
        ).grid(row=4, column=0, sticky="w", pady=(0, 4))

        self._findings_text = tk.Text(
            body,
            height=9,
            wrap="word",
            bg=PALETTE["surface_alt"],
            fg=PALETTE["text"],
            relief="flat",
            highlightbackground="#E2E8F0",
            highlightthickness=1,
            font=("Helvetica Neue", 10),
            padx=10,
            pady=8,
            state="disabled",
        )
        self._findings_text.grid(row=5, column=0, sticky="nsew")
        body.rowconfigure(5, weight=1)

        self._set_text(
            self._findings_text,
            "Enter a password above and click 'Analyze Strength (Offline)' to view "
            "length, diversity, pattern findings, and estimated guessing resistance.",
        )

        ttk.Label(
            body,
            text=(
                "Note: Ratings are heuristic estimates only, not a guarantee that a "
                "password cannot be guessed."
            ),
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        ).grid(row=6, column=0, sticky="w", pady=(8, 0))

    def _build_breach_card(self, parent: ttk.Frame) -> None:
        card = CardFrame(
            parent,
            title="HIBP Breach Exposure (k-Anonymity)",
            subtitle="Only the first 5 SHA-1 hex characters leave your machine.",
        )
        card.grid(row=2, column=0, sticky="nsew", padx=(0, 8), pady=(0, 14))
        body = card.body
        body.columnconfigure(0, weight=1)

        self._breach_banner = tk.Label(
            body,
            text="No breach check run yet.",
            bg=PALETTE["surface_alt"],
            fg=PALETTE["text"],
            font=("Helvetica Neue", 11, "bold"),
            anchor="w",
            justify="left",
            wraplength=450,
            padx=12,
            pady=10,
        )
        self._breach_banner.grid(row=0, column=0, sticky="ew")

        self._breach_count_label = ttk.Label(
            body,
            text="Occurrence count: —",
            style="CardBold.TLabel",
        )
        self._breach_count_label.grid(row=1, column=0, sticky="w", pady=(10, 4))

        self._breach_prefix_label = ttk.Label(
            body,
            text="Transmitted prefix: —",
            style="CardMuted.TLabel",
        )
        self._breach_prefix_label.grid(row=2, column=0, sticky="w", pady=(0, 8))

        ttk.Label(
            body,
            text=(
                "How k-anonymity protects you: Your password is hashed locally with "
                "SHA-1. Only the 5-character prefix is sent via HTTPS (with Add-Padding "
                "enabled). Matching happens locally, and unrelated suffixes are discarded."
            ),
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        ).grid(row=3, column=0, sticky="w", pady=(0, 6))

        ttk.Label(
            body,
            text=(
                "Caveat: 'Not found in HIBP' does not guarantee a password is safe or "
                "unused in private breaches."
            ),
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        ).grid(row=4, column=0, sticky="w")

    def _build_generator_card(self, parent: ttk.Frame) -> None:
        card = CardFrame(
            parent,
            title="Secure Password & Passphrase Generator",
            subtitle="Uses Python's cryptographically secure secrets module.",
        )
        card.grid(row=1, column=1, sticky="nsew", padx=(8, 0), pady=(0, 14))
        body = card.body
        body.columnconfigure(0, weight=1)

        mode_row = ttk.Frame(body, style="CardInner.TFrame")
        mode_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Radiobutton(
            mode_row,
            text="Random Password",
            value="password",
            variable=self._gen_mode_var,
            command=self._on_gen_mode_change,
            style="Card.TRadiobutton",
        ).pack(side="left", padx=(0, 14))
        ttk.Radiobutton(
            mode_row,
            text="Passphrase (Wordlist)",
            value="passphrase",
            variable=self._gen_mode_var,
            command=self._on_gen_mode_change,
            style="Card.TRadiobutton",
        ).pack(side="left")

        # Random password options frame
        self._pwd_opts_frame = ttk.Frame(body, style="CardInner.TFrame")
        self._pwd_opts_frame.grid(row=1, column=0, sticky="ew")
        self._pwd_opts_frame.columnconfigure(1, weight=1)

        ttk.Label(
            self._pwd_opts_frame,
            text=f"Length ({MIN_GENERATED_LENGTH}-{MAX_GENERATED_LENGTH}):",
            style="CardBody.TLabel",
        ).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 6))

        ttk.Spinbox(
            self._pwd_opts_frame,
            from_=MIN_GENERATED_LENGTH,
            to=MAX_GENERATED_LENGTH,
            textvariable=self._gen_length_var,
            width=7,
        ).grid(row=0, column=1, sticky="w", pady=(0, 6))

        checks = ttk.Frame(self._pwd_opts_frame, style="CardInner.TFrame")
        checks.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(2, 6))
        ttk.Checkbutton(
            checks, text="Uppercase (A-Z)", variable=self._gen_upper_var, style="Card.TCheckbutton"
        ).grid(row=0, column=0, sticky="w", padx=(0, 12))
        ttk.Checkbutton(
            checks, text="Lowercase (a-z)", variable=self._gen_lower_var, style="Card.TCheckbutton"
        ).grid(row=0, column=1, sticky="w", padx=(0, 12))
        ttk.Checkbutton(
            checks, text="Numbers (0-9)", variable=self._gen_digits_var, style="Card.TCheckbutton"
        ).grid(row=1, column=0, sticky="w", padx=(0, 12), pady=(4, 0))
        ttk.Checkbutton(
            checks,
            text="Symbols (!@#$...)",
            variable=self._gen_symbols_var,
            style="Card.TCheckbutton",
        ).grid(row=1, column=1, sticky="w", pady=(4, 0))
        ttk.Checkbutton(
            checks,
            text="Exclude ambiguous (I, O, l, 0, 1)",
            variable=self._gen_no_ambig_var,
            style="Card.TCheckbutton",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # Passphrase options frame (hidden initially)
        self._phrase_opts_frame = ttk.Frame(body, style="CardInner.TFrame")
        self._phrase_opts_frame.columnconfigure(1, weight=1)

        ttk.Label(
            self._phrase_opts_frame,
            text=f"Word count ({MIN_PASSPHRASE_WORDS}-{MAX_PASSPHRASE_WORDS}):",
            style="CardBody.TLabel",
        ).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Spinbox(
            self._phrase_opts_frame,
            from_=MIN_PASSPHRASE_WORDS,
            to=MAX_PASSPHRASE_WORDS,
            textvariable=self._pass_words_var,
            width=7,
        ).grid(row=0, column=1, sticky="w", pady=(0, 6))

        ttk.Label(
            self._phrase_opts_frame,
            text="Separator:",
            style="CardBody.TLabel",
        ).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        ttk.Combobox(
            self._phrase_opts_frame,
            textvariable=self._pass_sep_var,
            values=["-", "_", ".", " "],
            width=6,
            state="readonly",
        ).grid(row=1, column=1, sticky="w", pady=(0, 6))

        ttk.Checkbutton(
            self._phrase_opts_frame,
            text="Capitalize words",
            variable=self._pass_cap_var,
            style="Card.TCheckbutton",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 0))
        ttk.Checkbutton(
            self._phrase_opts_frame,
            text="Append random digit",
            variable=self._pass_num_var,
            style="Card.TCheckbutton",
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # Controls and generated output
        btn_row = ttk.Frame(body, style="CardInner.TFrame")
        btn_row.grid(row=2, column=0, sticky="ew", pady=(10, 10))

        ttk.Button(
            btn_row,
            text="Generate",
            command=self._on_generate,
            style="Primary.TButton",
        ).pack(side="left", padx=(0, 10))

        ttk.Button(
            btn_row,
            text="Copy to Clipboard",
            command=self._on_copy_generated,
            style="Secondary.TButton",
        ).pack(side="left")

        self._gen_output_entry = ttk.Entry(
            body,
            textvariable=self._generated_secret_var,
            font=("Courier", 12, "bold"),
            state="readonly",
        )
        self._gen_output_entry.grid(row=3, column=0, sticky="ew")

        ttk.Label(
            body,
            textvariable=self._gen_meta_var,
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        ).grid(row=4, column=0, sticky="w", pady=(6, 2))

        self._gen_feedback_label = tk.Label(
            body,
            textvariable=self._gen_feedback_var,
            bg=PALETTE["surface"],
            fg=PALETTE["info"],
            font=("Helvetica Neue", 9, "bold"),
            anchor="w",
            wraplength=460,
            justify="left",
        )
        self._gen_feedback_label.grid(row=5, column=0, sticky="ew", pady=(2, 0))

        ttk.Label(
            body,
            text=(
                "Warning: Generated secrets are never auto-saved. Store them in a "
                "reputable password manager."
            ),
            style="CardMuted.TLabel",
            wraplength=460,
            justify="left",
        ).grid(row=6, column=0, sticky="w", pady=(6, 0))

    def _build_recommendations_card(self, parent: ttk.Frame) -> None:
        card = CardFrame(
            parent,
            title="Security Recommendations",
            subtitle="Defensive actions tailored to your current assessment.",
        )
        card.grid(row=2, column=1, sticky="nsew", padx=(8, 0), pady=(0, 14))
        body = card.body
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        self._recs_text = tk.Text(
            body,
            height=10,
            wrap="word",
            bg=PALETTE["surface_alt"],
            fg=PALETTE["text"],
            relief="flat",
            highlightbackground="#E2E8F0",
            highlightthickness=1,
            font=("Helvetica Neue", 10),
            padx=10,
            pady=8,
            state="disabled",
        )
        self._recs_text.grid(row=0, column=0, sticky="nsew")

    def _build_privacy_card(self, parent: ttk.Frame) -> None:
        card = CardFrame(
            parent,
            title="Privacy, Architecture & Educational Scope",
        )
        card.grid(row=3, column=0, columnspan=2, sticky="ew")
        body = card.body
        body.columnconfigure(0, weight=1)

        privacy_points = (
            "1. Local Processing: Strength assessment (zxcvbn + structural heuristics) and "
            "SHA-1 hashing run strictly in local memory.\n"
            "2. k-Anonymity Lookup: Breach checks send only the first 5 characters of the "
            "SHA-1 hash to https://api.pwnedpasswords.com/range/ with Add-Padding enabled. "
            "Returned suffixes are compared locally and immediately discarded.\n"
            "3. Zero Persistence: No plaintext passwords, full hashes, history, analytics, or "
            "generated secrets are ever stored or logged.\n"
            "4. Educational Disclaimer: This project is an educational defensive-security "
            "tool. A password not found in HIBP is not guaranteed safe, and strength scores "
            "are estimates rather than security guarantees."
        )
        ttk.Label(
            body,
            text=privacy_points,
            style="CardMuted.TLabel",
            wraplength=1020,
            justify="left",
        ).grid(row=0, column=0, sticky="w")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _toggle_password_visibility(self) -> None:
        show_char = "" if self._show_password_var.get() else "•"
        self._password_entry.configure(show=show_char)

    def _on_clear(self) -> None:
        self._password_var.set("")
        self._input_error_var.set("")
        self._last_analysis = None
        self._last_breach = None
        self._rating_label.configure(
            text="Not analyzed yet", bg=PALETTE["badge_bg"], fg=PALETTE["text"]
        )
        self._score_label.configure(text="Score: — / 4")
        self._meter.set_score(None)
        self._metrics_label.configure(
            text="Length: —   •   Unique chars: —   •   Est. offline slow-hash time: —"
        )
        self._classes_label.configure(text="Character classes: —")
        self._set_text(
            self._findings_text,
            "Enter a password above and click 'Analyze Strength (Offline)' to view "
            "length, diversity, pattern findings, and estimated guessing resistance.",
        )
        self._breach_banner.configure(
            text="No breach check run yet.",
            bg=PALETTE["surface_alt"],
            fg=PALETTE["text"],
        )
        self._breach_count_label.configure(text="Occurrence count: —")
        self._breach_prefix_label.configure(text="Transmitted prefix: —")
        self._status_var.set("Cleared input and results.")
        self._refresh_recommendations()

    def _on_analyze(self) -> None:
        self._input_error_var.set("")
        password = self._password_var.get()
        try:
            result = self._analyzer.analyze(password)
        except ValidationError as exc:
            self._input_error_var.set(str(exc))
            return

        self._last_analysis = result
        self._render_analysis(result)
        self._refresh_recommendations()
        self._status_var.set("Offline strength assessment completed.")

    def _on_check_breach(self) -> None:
        if self._breach_in_flight:
            return
        self._input_error_var.set("")
        password = self._password_var.get()
        try:
            # Validate before spawning background worker.
            from src.utils.validation import validate_password_input

            validate_password_input(password)
        except ValidationError as exc:
            self._input_error_var.set(str(exc))
            return

        self._breach_in_flight = True
        self._breach_btn.configure(state="disabled")
        self._loading_bar.pack(side="left", padx=(0, 10))
        self._loading_bar.start(12)
        self._status_var.set("Checking HIBP range API (5-character prefix only)...")

        worker = threading.Thread(
            target=self._run_breach_worker,
            args=(password,),
            daemon=True,
        )
        worker.start()

    def _run_breach_worker(self, password: str) -> None:
        result = self._breach_checker.check_password(password)
        del password
        self.root.after(0, lambda: self._on_breach_complete(result))

    def _on_breach_complete(self, result: BreachCheckResult) -> None:
        self._breach_in_flight = False
        self._loading_bar.stop()
        self._loading_bar.pack_forget()
        self._breach_btn.configure(state="normal")

        self._last_breach = result
        self._render_breach(result)
        self._refresh_recommendations()

    def _on_gen_mode_change(self) -> None:
        if self._gen_mode_var.get() == "passphrase":
            self._pwd_opts_frame.grid_remove()
            self._phrase_opts_frame.grid(row=1, column=0, sticky="ew")
        else:
            self._phrase_opts_frame.grid_remove()
            self._pwd_opts_frame.grid(row=1, column=0, sticky="ew")

    def _on_generate(self) -> None:
        self._gen_feedback_var.set("")
        try:
            if self._gen_mode_var.get() == "passphrase":
                result = self._generator.generate_passphrase(
                    word_count=int(self._pass_words_var.get()),
                    separator=self._pass_sep_var.get(),
                    capitalize=bool(self._pass_cap_var.get()),
                    include_number=bool(self._pass_num_var.get()),
                )
            else:
                config = GeneratorConfig(
                    length=int(self._gen_length_var.get()),
                    use_uppercase=bool(self._gen_upper_var.get()),
                    use_lowercase=bool(self._gen_lower_var.get()),
                    use_digits=bool(self._gen_digits_var.get()),
                    use_symbols=bool(self._gen_symbols_var.get()),
                    exclude_ambiguous=bool(self._gen_no_ambig_var.get()),
                )
                result = self._generator.generate_password(config)
        except (ValidationError, ValueError, tk.TclError) as exc:
            self._gen_feedback_label.configure(fg=PALETTE["danger"])
            self._gen_feedback_var.set(f"Invalid generator option: {exc}")
            return

        self._generated_secret_var.set(result.secret)
        self._gen_meta_var.set(
            f"Mode: {result.mode.capitalize()}  •  Length: {result.length}  •  "
            f"Estimated entropy: ~{result.estimated_entropy_bits} bits"
        )
        self._gen_feedback_label.configure(fg=PALETTE["info"])
        self._gen_feedback_var.set("Generated using secrets (CSPRNG). Not saved to disk.")

    def _on_copy_generated(self) -> None:
        secret = self._generated_secret_var.get()
        ok, message = copy_to_clipboard(secret, tk_widget=self.root)
        self._gen_feedback_label.configure(fg=PALETTE["success"] if ok else PALETTE["danger"])
        self._gen_feedback_var.set(message)

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _render_analysis(self, result: PasswordAnalysisResult) -> None:
        rating_color = RATING_COLORS.get(result.rating, PALETTE["accent"])
        self._rating_label.configure(
            text=result.rating.upper(),
            bg=rating_color,
            fg="#FFFFFF",
        )
        self._score_label.configure(text=f"Score: {result.score} / 4")
        self._meter.set_score(result.score, result.rating)

        self._metrics_label.configure(
            text=(
                f"Length: {result.length} chars   •   "
                f"Unique: {result.unique_characters}   •   "
                f"Est. guesses: ~10^{result.estimated_guesses_log10}   •   "
                f"Offline slow hash: {result.crack_time_display}"
            )
        )

        active_classes = [
            label
            for key, label in (
                ("lowercase", "Lowercase"),
                ("uppercase", "Uppercase"),
                ("digits", "Numbers"),
                ("symbols", "Symbols"),
                ("whitespace", "Spaces"),
                ("unicode", "Unicode"),
            )
            if result.character_classes.get(key)
        ]
        self._classes_label.configure(
            text=f"Character diversity: {', '.join(active_classes) if active_classes else 'None'}"
        )

        lines: list[str] = []
        if result.findings:
            for finding in result.findings:
                lines.append(
                    f"[{finding.severity.upper()}] {finding.category}: {finding.description}"
                )
        else:
            lines.append("No common predictable patterns were detected by local heuristics.")

        if result.estimator_warnings:
            lines.append("")
            lines.append("Estimator Warning:")
            for warning in result.estimator_warnings:
                lines.append(f"• {warning}")

        if result.estimator_suggestions:
            lines.append("")
            lines.append("Estimator Suggestions:")
            for suggestion in result.estimator_suggestions:
                lines.append(f"• {suggestion}")

        self._set_text(self._findings_text, "\n".join(lines))

    def _render_breach(self, result: BreachCheckResult) -> None:
        pad_state = "enabled" if result.padding_enabled else "disabled"
        self._breach_prefix_label.configure(
            text=f"Transmitted prefix: {result.hash_prefix}  (Add-Padding: {pad_state})"
        )

        if not result.checked:
            self._breach_banner.configure(
                text=f"Check unavailable: {result.status_message}",
                bg=PALETTE["warning_bg"],
                fg=PALETTE["warning"],
            )
            self._breach_count_label.configure(text="Occurrence count: Unavailable")
            self._status_var.set("HIBP check failed or offline.")
            return

        if result.exposed:
            self._breach_banner.configure(
                text=result.status_message,
                bg=PALETTE["danger_bg"],
                fg=PALETTE["danger"],
            )
            self._breach_count_label.configure(
                text=f"Occurrence count: {result.occurrence_count:,} breach record(s)"
            )
            self._status_var.set("HIBP check complete: exposure detected.")
        else:
            self._breach_banner.configure(
                text=result.status_message,
                bg=PALETTE["success_bg"],
                fg=PALETTE["success"],
            )
            self._breach_count_label.configure(text="Occurrence count: 0")
            self._status_var.set("HIBP check complete: not found in dataset.")

    def _refresh_recommendations(self) -> None:
        recs: tuple[Recommendation, ...] = self._recommender.generate(
            self._last_analysis,
            self._last_breach,
        )
        lines: list[str] = []
        for rec in recs:
            tag = rec.priority.replace("_", " ").upper()
            lines.append(f"[{tag}] {rec.title}")
            lines.append(f"  {rec.detail}")
            lines.append("")
        self._set_text(self._recs_text, "\n".join(lines).strip())

    @staticmethod
    def _set_text(widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")


def launch_gui() -> int:
    """Launch the Tkinter desktop application."""
    configure_logging()
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Unable to initialize Tkinter desktop GUI: {exc}")
        return 1

    PasswordSecurityLabApp(root)
    root.mainloop()
    return 0
