#!/usr/bin/env python3
"""Local-only password strength checker with a Rich terminal interface."""

from __future__ import annotations

# Standard-library imports provide the analysis, input handling, and tests.
import argparse
import getpass
import math
import os
import re
import shutil
import string
import subprocess
import sys
import time
import unicodedata
import unittest
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import ttk
except ImportError:  # Tk is optional on some minimal Python installations.
    tk = None  # type: ignore[assignment]
    tkfont = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]

# Rich supplies the visual terminal interface. Install it with:
# python -m pip install -r requirements.txt
try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:  # Give a clear setup message instead of a long traceback.
    print(
        "Missing dependency: rich\n"
        "Install the project requirements with: python -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1)


# These settings make the estimates configurable and keep the demo bounded.
APP_NAME = "ZPC"
APP_VERSION = "2.0.0"
MAX_PASSWORD_LENGTH = 1024
ONLINE_GUESSES_PER_SECOND = 10.0
OFFLINE_FAST_HASH_GUESSES_PER_SECOND = 1_000_000_000.0
UNICODE_CLASS_POOL_ESTIMATE = 100
SECONDS_PER_MINUTE = 60.0
SECONDS_PER_HOUR = 60.0 * SECONDS_PER_MINUTE
SECONDS_PER_DAY = 24.0 * SECONDS_PER_HOUR
SECONDS_PER_YEAR = 365.2425 * SECONDS_PER_DAY

# This compact local blocklist is for a classroom demonstration, not production use.
# A real service should use a large, current blocklist of breached/common passwords.
COMMON_PASSWORDS = frozenset(
    {
        "123456", "1234567", "12345678", "123456789", "1234567890",
        "password", "password1", "password123", "qwerty", "qwerty123",
        "abc123", "111111", "123123", "admin", "admin123", "letmein",
        "welcome", "monkey", "dragon", "iloveyou", "sunshine", "princess",
        "football", "baseball", "master", "login", "passw0rd", "trustno1",
        "changeme", "secret", "shadow", "access", "computer", "michael",
    }
)

# These common words are checked as complete tokens, not arbitrary substrings.
# This reduces false positives for long, unrelated multi-word passphrases.
COMMON_DICTIONARY_WORDS = frozenset(
    {
        "password", "welcome", "letmein", "iloveyou", "sunshine", "princess",
        "football", "baseball", "dragon", "monkey", "master", "secret",
        "summer", "winter", "flower", "freedom", "whatever", "computer",
        "admin", "login", "shadow", "trustno", "changeme", "hello",
        "michael", "jordan", "qwerty", "abcde", "love", "starwars",
    }
)

# This translation catches a few predictable letter-for-number substitutions.
# It is only used for local dictionary matching; it never changes the password.
LEET_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


@dataclass(frozen=True)
class PasswordReport:
    """Store analysis results without retaining the submitted password itself."""

    length: int
    character_classes: Dict[str, bool]
    pool_size: int
    entropy_bits: float
    uses_unicode: bool
    common_match: Optional[str]
    pattern_warnings: Tuple[str, ...]
    score: int
    grade: str
    recommendations: Tuple[str, ...]


# This function normalizes text only for detecting common password patterns.
def normalize_for_dictionary(password: str) -> str:
    """Return a case-insensitive, lightly de-obfuscated comparison value."""
    normalized = unicodedata.normalize("NFKC", password).casefold()
    return normalized.translate(LEET_TRANSLATION)


# This function identifies weak complete passwords and common dictionary tokens.
def find_common_match(password: str) -> Optional[str]:
    """Return a generic match reason, without returning or displaying the secret."""
    original_normalized = unicodedata.normalize("NFKC", password).casefold()
    normalized = normalize_for_dictionary(password)

    # Check the full normalized value against the small demonstration blocklist.
    if normalized in COMMON_PASSWORDS or original_normalized in COMMON_PASSWORDS:
        return "matches a common-password blocklist entry"

    # Check tokens before and after leetspeak normalization. The original token pass
    # catches ordinary suffixes such as 'Password123!', while the second catches
    # substitutions such as 'P@ssw0rd!'.
    tokens = set(re.findall(r"[a-z]+", original_normalized))
    tokens.update(re.findall(r"[a-z]+", normalized))
    if any(token in COMMON_DICTIONARY_WORDS for token in tokens):
        return "contains a common dictionary word"

    return None


# This function measures only which character categories appear in the input.
def detect_character_classes(password: str) -> Dict[str, bool]:
    """Detect lowercase, uppercase, digits, symbols, and whitespace."""
    return {
        "lowercase": any(char.islower() for char in password),
        "uppercase": any(char.isupper() for char in password),
        "digits": any(char.isdigit() for char in password),
        "symbols": any(not char.isalnum() and not char.isspace() for char in password),
        "whitespace": any(char.isspace() for char in password),
    }


# This helper estimates the source alphabet size represented by the input.
def calculate_character_pool(password: str) -> Tuple[int, bool]:
    """Return an approximate alphabet pool size and whether Unicode was used."""
    pool_size = 0
    uses_unicode = any(ord(char) > 127 for char in password)

    # Count the ASCII character pools only when those character types are present.
    if any(char in string.ascii_lowercase for char in password):
        pool_size += 26
    if any(char in string.ascii_uppercase for char in password):
        pool_size += 26
    if any(char in string.digits for char in password):
        pool_size += 10
    if any(char in string.punctuation for char in password):
        pool_size += len(string.punctuation)

    # Non-ASCII variants use a deliberately rough bucket instead of claiming
    # that every Unicode character belongs to a precisely known alphabet.
    if any(char.islower() and char not in string.ascii_lowercase for char in password):
        pool_size += UNICODE_CLASS_POOL_ESTIMATE
    if any(char.isupper() and char not in string.ascii_uppercase for char in password):
        pool_size += UNICODE_CLASS_POOL_ESTIMATE
    if any(char.isdigit() and char not in string.digits for char in password):
        pool_size += UNICODE_CLASS_POOL_ESTIMATE
    if any(
        not char.isalnum() and not char.isspace() and char not in string.punctuation
        for char in password
    ):
        pool_size += UNICODE_CLASS_POOL_ESTIMATE
    if any(
        ord(char) > 127
        and char.isalnum()
        and not char.islower()
        and not char.isupper()
        and not char.isdigit()
        for char in password
    ):
        pool_size += UNICODE_CLASS_POOL_ESTIMATE

    # Whitespace is modeled as one additional character choice when it appears.
    if any(char.isspace() for char in password):
        pool_size += 1

    return pool_size, uses_unicode


# This function identifies a few obvious patterns that often reduce guess resistance.
def detect_obvious_patterns(password: str) -> Tuple[str, ...]:
    """Find repeated runs, keyboard walks, and ascending/descending sequences."""
    warnings_found: List[str] = []

    # Repeated runs of three or more identical characters are easy to guess.
    if re.search(r"(.)\1{2,}", password, flags=re.DOTALL):
        warnings_found.append("contains a run of the same character repeated three or more times")

    # Remove separators for sequence detection, but do not alter the original input.
    normalized = unicodedata.normalize("NFKC", password).casefold()
    compact = re.sub(r"[^a-z0-9]", "", normalized)

    # Common keyboard rows and nearby-key walks are frequent human choices.
    keyboard_patterns = ("qwerty", "asdf", "zxcv", "qwert", "asdfg", "zxcvb")
    if any(pattern in compact for pattern in keyboard_patterns):
        warnings_found.append("contains a familiar keyboard-row pattern")

    # Check for four-character ascending or descending ASCII sequences.
    for index in range(max(0, len(compact) - 3)):
        window = compact[index : index + 4]
        differences = [ord(window[position + 1]) - ord(window[position]) for position in range(3)]
        if all(step == 1 for step in differences) or all(step == -1 for step in differences):
            warnings_found.append("contains an ascending or descending character sequence")
            break

    return tuple(warnings_found)


# This function converts the composition formula into a human-readable duration.
def format_log2_duration(log2_seconds: float) -> str:
    """Format a duration from its base-2 logarithm without overflowing floats."""
    try:
        log2_seconds = float(log2_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise TypeError("log2_seconds must be a finite number") from exc
    if not math.isfinite(log2_seconds):
        raise ValueError("log2_seconds must be finite")
    if log2_seconds < 0:
        return "less than 1 second"

    # Very large values are represented using a power of ten to avoid overflow.
    if log2_seconds > 1023:
        log10_seconds = log2_seconds * math.log10(2)
        return f"approximately 10^{log10_seconds:,.1f} seconds"

    # Convert manageable values to seconds and select the largest useful unit.
    seconds = 2.0 ** log2_seconds
    if seconds < 60:
        return f"about {seconds:,.1f} seconds"
    if seconds < SECONDS_PER_HOUR:
        return f"about {seconds / SECONDS_PER_MINUTE:,.1f} minutes"
    if seconds < SECONDS_PER_DAY:
        return f"about {seconds / SECONDS_PER_HOUR:,.1f} hours"
    if seconds < SECONDS_PER_YEAR:
        return f"about {seconds / SECONDS_PER_DAY:,.1f} days"

    years = seconds / SECONDS_PER_YEAR
    if years >= 1_000_000_000:
        return f"about {years / 1_000_000_000:.2e} billion years"
    if years >= 1_000_000:
        return f"about {years / 1_000_000:.2e} million years"
    if years >= 1_000:
        return f"about {years / 1_000:,.2f} thousand years"
    return f"about {years:,.1f} years"


# This function estimates the average search time for a uniform search space.
def estimate_crack_time(entropy_bits: float, guesses_per_second: float) -> str:
    """Estimate median search time using 2^(entropy-1) guesses at a stated rate."""
    try:
        entropy_bits = float(entropy_bits)
        guesses_per_second = float(guesses_per_second)
    except (TypeError, ValueError, OverflowError) as exc:
        raise TypeError("entropy_bits and guesses_per_second must be numbers") from exc

    if not math.isfinite(entropy_bits) or not math.isfinite(guesses_per_second):
        raise ValueError("entropy_bits and guesses_per_second must be finite")
    if entropy_bits < 0:
        raise ValueError("entropy_bits cannot be negative")
    if guesses_per_second <= 0:
        raise ValueError("guesses_per_second must be greater than zero")

    # Use logarithms so very large search spaces never require huge integers.
    log2_seconds = entropy_bits - 1.0 - math.log2(guesses_per_second)
    return format_log2_duration(log2_seconds)


# This function turns the analysis into a clearly labeled educational score.
def calculate_score(
    length: int,
    character_classes: Dict[str, bool],
    common_match: Optional[str],
    pattern_warnings: Tuple[str, ...],
) -> Tuple[int, str]:
    """Calculate a transparent rule-based score; it is not a formal security rating."""
    # An empty password must never receive points from the absence of warnings.
    if length == 0:
        return 0, "VERY WEAK"

    # Award the largest share of points for length, with a stronger threshold at 15.
    if length < 8:
        length_points = 0
    elif length < 12:
        length_points = 10
    elif length < 15:
        length_points = 25
    elif length < 20:
        length_points = 40
    else:
        length_points = 50

    # Character variety contributes a smaller educational amount, not a requirement.
    variety_points = 5 * sum(
        character_classes[name] for name in ("lowercase", "uppercase", "digits", "symbols")
    )

    # Avoid rewarding a password that appears on the small blocklist or has obvious patterns.
    blocklist_points = 0 if common_match else 20
    pattern_points = 10 if not pattern_warnings else 0
    pattern_penalty = min(15, 5 * len(pattern_warnings))
    score = max(0, min(100, length_points + variety_points + blocklist_points + pattern_points - pattern_penalty))

    # A common-password or dictionary-word match forces a low score.
    if common_match:
        score = min(score, 20)

    # Map the numeric score to a simple label used by the terminal interface.
    if score < 20:
        grade = "VERY WEAK"
    elif score < 40:
        grade = "WEAK"
    elif score < 60:
        grade = "FAIR"
    elif score < 80:
        grade = "STRONG"
    else:
        grade = "VERY STRONG"

    return score, grade


# This is the main analysis function; it never returns or stores the password value.
def analyze_password(password: str) -> PasswordReport:
    """Analyze length, character pools, common words, patterns, and estimates."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password is longer than the {MAX_PASSWORD_LENGTH}-character demo limit")

    # Measure the original input exactly as entered; do not strip or rewrite spaces.
    length = len(password)
    character_classes = detect_character_classes(password)
    pool_size, uses_unicode = calculate_character_pool(password)

    # Compute the raw structural upper bound from the observed alphabet and length.
    entropy_bits = length * math.log2(pool_size) if length and pool_size else 0.0

    # Look for common values and obvious human-selected patterns independently of entropy.
    common_match = find_common_match(password)
    pattern_warnings = detect_obvious_patterns(password)
    score, grade = calculate_score(length, character_classes, common_match, pattern_warnings)

    # Give actionable feedback without telling users to satisfy arbitrary composition rules.
    recommendations: List[str] = []
    if length < 15:
        recommendations.append(
            "Consider a longer password or passphrase; 15+ characters is a useful single-factor target."
        )
    if common_match:
        recommendations.append(
            "Avoid common words, breached-password patterns, and predictable number/symbol substitutions."
        )
    if pattern_warnings:
        recommendations.append(
            "Avoid repeated runs, keyboard walks, and simple ascending or descending sequences."
        )
    recommendations.append(
        "Use a unique password for every account and store it in a reputable password manager."
    )
    recommendations.append(
        "Prefer a randomly generated secret or a long, unrelated passphrase; human choices are not uniformly random."
    )

    # Return only derived metrics, so the report cannot accidentally print the password.
    return PasswordReport(
        length=length,
        character_classes=character_classes,
        pool_size=pool_size,
        entropy_bits=entropy_bits,
        uses_unicode=uses_unicode,
        common_match=common_match,
        pattern_warnings=pattern_warnings,
        score=score,
        grade=grade,
        recommendations=tuple(recommendations),
    )


# This block draws the application title and summarizes its local-only behavior.
def render_banner(console: Console) -> None:
    """Render the application banner."""
    title = Text("ZPC", style="bold bright_cyan", justify="center")
    subtitle = Text("ZYNX PASSWORD CHECKER  •  ENTROPY ESTIMATOR", style="bold white", justify="center")
    note = Text("LOCAL ANALYSIS  |  NO NETWORK  |  HIDDEN INPUT", style="dim", justify="center")
    console.print(
        Panel(
            Align.center(Group(title, subtitle, note)),
            border_style="bright_cyan",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )


# This block renders the result without ever displaying the submitted password.
def render_report(console: Console, report: PasswordReport) -> None:
    """Render score, measurements, crack-time scenarios, and recommendations."""
    grade_colors = {
        "VERY WEAK": "bold red",
        "WEAK": "red",
        "FAIR": "yellow",
        "STRONG": "green",
        "VERY STRONG": "bold bright_green",
    }
    grade_style = grade_colors[report.grade]

    # Present the score and core measurements in a compact summary panel.
    summary = Table.grid(expand=True)
    summary.add_column("Metric", style="bold white")
    summary.add_column("Result", justify="right")
    summary.add_row("Educational strength score", f"[bold bright_cyan]{report.score}/100[/]")
    summary.add_row("Assessment", f"[{grade_style}]{report.grade}[/]")
    summary.add_row("Password length", f"{report.length} characters")
    summary.add_row("Structural entropy (raw upper bound)", f"{report.entropy_bits:,.2f} bits")
    summary.add_row("Estimated character pool", f"{report.pool_size:,} possible characters")
    console.print(Panel(summary, title="[bold]ANALYSIS SUMMARY[/]", border_style="bright_blue"))

    # Show the character categories used by the structural entropy formula.
    classes = Table(title="Character Categories", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    classes.add_column("Category")
    classes.add_column("Detected", justify="right")
    class_labels = (
        ("lowercase letters (a-z)", "lowercase"),
        ("uppercase letters (A-Z)", "uppercase"),
        ("digits (0-9)", "digits"),
        ("symbols", "symbols"),
        ("whitespace", "whitespace"),
    )
    for label, key in class_labels:
        status = "[green]YES[/]" if report.character_classes[key] else "[dim]NO[/]"
        classes.add_row(label, status)
    console.print(classes)

    # Compare the same entropy model against two explicitly stated guessing rates.
    crack_table = Table(title="Illustrative Crack-Time Scenarios", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    crack_table.add_column("Scenario")
    crack_table.add_column("Assumed rate", justify="right")
    crack_table.add_column("Estimated median time", justify="right")
    crack_table.add_row(
        "Online / rate-limited",
        f"{ONLINE_GUESSES_PER_SECOND:,.0f} guesses/sec",
        estimate_crack_time(report.entropy_bits, ONLINE_GUESSES_PER_SECOND),
    )
    crack_table.add_row(
        "Offline / fast unsalted hash",
        f"{OFFLINE_FAST_HASH_GUESSES_PER_SECOND:,.0f} guesses/sec",
        estimate_crack_time(report.entropy_bits, OFFLINE_FAST_HASH_GUESSES_PER_SECOND),
    )
    console.print(crack_table)

    # Display any local blocklist or pattern findings in clear language.
    findings: List[str] = []
    if report.common_match:
        findings.append(f"[red]• {report.common_match}[/]")
    for warning_text in report.pattern_warnings:
        findings.append(f"[yellow]• {warning_text}[/]")
    if not findings:
        findings.append("[green]• No matches found in this tool's small local checks.[/]")
    console.print(Panel("\n".join(findings), title="[bold]FINDINGS[/]", border_style="yellow"))

    # Show recommendations generated from the report's findings and length.
    recommendation_text = "\n".join(
        f"[bright_cyan]{index}.[/] {recommendation}"
        for index, recommendation in enumerate(report.recommendations, start=1)
    )
    console.print(Panel(recommendation_text, title="[bold]RECOMMENDATIONS[/]", border_style="green"))

    # Make assumptions visible next to the result to prevent false confidence.
    caveats = [
        "Entropy assumes independent, uniformly random character selection from the estimated pool.",
        "Real human-chosen passwords are usually more predictable; actual crack time can be much shorter.",
        "The bundled common-password/dictionary list is small and is not a breach database.",
        "Offline rate is a demonstration scenario; hashing algorithm, hardware, salts, and attack setup change it greatly.",
    ]
    if report.uses_unicode:
        caveats.append(
            f"Unicode characters were found; their alphabet contribution uses a rough {UNICODE_CLASS_POOL_ESTIMATE}-character bucket."
        )
    caveat_text = "\n".join(f"[dim]• {item}[/]" for item in caveats)
    console.print(Panel(caveat_text, title="[bold]IMPORTANT LIMITATIONS[/]", border_style="dim"))


# This function requests a password without echoing it to the terminal.
def read_hidden_password() -> str:
    """Read a password with terminal echo disabled; fail closed if hiding is unavailable."""
    with warnings.catch_warnings():
        # Convert getpass's visible-input fallback warning into an exception.
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass("Enter a test password (input hidden): ")


# This function contains the interactive TUI loop and safely discards the local variable.
def run_tui() -> int:
    """Run the interactive password checker."""
    console = Console(highlight=False)
    render_banner(console)
    console.print(
        "[dim]Use a test password, not a real password you currently use. "
        "The submitted value is not printed, saved, or transmitted.[/]\n"
    )

    # Keep the application in a loop so the user can check multiple test values.
    while True:
        choice = console.input("[bold bright_cyan]Press [1] to analyze or [Q] to quit:[/] ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            console.print("[bright_cyan]Session closed. Stay secure.[/]")
            return 0
        if choice not in {"1", ""}:
            console.print("[yellow]Please choose 1 or Q.[/]\n")
            continue

        # Read the password in hidden mode and reject empty or oversized input.
        try:
            password = read_hidden_password()
        except (getpass.GetPassWarning, EOFError):
            console.print(
                "[bold red]Secure hidden input is unavailable in this terminal. "
                "Run the program in a normal terminal; visible input is intentionally disabled.[/]"
            )
            return 1

        if not password:
            console.print("[yellow]Empty input was not analyzed.[/]\n")
            continue
        if len(password) > MAX_PASSWORD_LENGTH:
            console.print(f"[yellow]Input exceeds the {MAX_PASSWORD_LENGTH}-character demo limit.[/]\n")
            del password
            continue

        # Analyze the value, then delete the local reference before rendering results.
        try:
            report = analyze_password(password)
        finally:
            del password

        render_report(console, report)
        console.print()


# ---------------------------------------------------------------------------
# ZPC desktop interface
# ---------------------------------------------------------------------------

# Tkinter is part of Python's standard library. The terminal interface remains
# available when Tk is not installed or when the application is run headlessly.
ZPC_BG = "#08070D"
ZPC_BG_MID = "#100B1B"
ZPC_PANEL = "#100D18"
ZPC_PANEL_ALT = "#171121"
ZPC_PURPLE = "#8E54E9"
ZPC_PURPLE_LIGHT = "#B38AFF"
ZPC_WHITE = "#F7F3FF"
ZPC_MUTED = "#A79BB8"
ZPC_BORDER = "#38264F"


def _mix_color(start: str, end: str, amount: float) -> str:
    """Blend two #RRGGBB colors. Amount is clamped to the 0..1 range."""
    amount = max(0.0, min(1.0, amount))
    start_rgb = tuple(int(start[index : index + 2], 16) for index in (1, 3, 5))
    end_rgb = tuple(int(end[index : index + 2], 16) for index in (1, 3, 5))
    result = tuple(round(a + (b - a) * amount) for a, b in zip(start_rgb, end_rgb))
    return "#{:02X}{:02X}{:02X}".format(*result)


def _draw_gradient(canvas, width: int, height: int, tag: str = "background") -> None:
    """Draw a dark vertical gradient using small rectangles (Tk has no native gradient)."""
    canvas.delete(tag)
    if width <= 0 or height <= 0:
        return
    step = 5
    for y in range(0, height, step):
        progress = y / max(1, height - 1)
        if progress < 0.55:
            color = _mix_color(ZPC_BG, ZPC_BG_MID, progress / 0.55)
        else:
            color = _mix_color(ZPC_BG_MID, "#160B25", (progress - 0.55) / 0.45)
        canvas.create_rectangle(
            0, y, width, min(height, y + step + 1),
            fill=color, outline=color, tags=(tag,),
        )


def _rounded_rectangle_points(x1, y1, x2, y2, radius=18):
    """Return the polygon points used for a smooth rounded rectangle."""
    radius = max(2, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    return [
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1,
    ]


def _rounded_rectangle(canvas, x1, y1, x2, y2, radius=18, **kwargs):
    """Draw a smooth rounded rectangle on a Tk Canvas."""
    return canvas.create_polygon(
        _rounded_rectangle_points(x1, y1, x2, y2, radius),
        smooth=True, splinesteps=20, **kwargs,
    )


def _ui_font_family(root) -> str:
    """Use Boldonse when installed; otherwise fall back to a widely available bold font."""
    try:
        installed = {family.casefold() for family in tkfont.families(root)}
    except Exception:
        installed = set()
    if "boldonse" in installed:
        return "Boldonse"
    for candidate in ("Segoe UI Black", "Arial Black", "DejaVu Sans"):
        if candidate.casefold() in installed:
            return candidate
    return "TkDefaultFont"


def choose_interface_mode() -> str:
    """Ask the user to open the desktop GUI or the original terminal interface."""
    if tk is None:
        print("Tkinter is unavailable; starting the terminal interface instead.")
        return "tui"

    try:
        window = tk.Tk()
    except Exception as exc:
        print(f"The interface chooser could not start ({exc}); using the terminal interface.")
        return "tui"

    window.title("ZPC | Choose Interface")
    window.geometry("620x455")
    window.minsize(560, 420)
    window.configure(bg=ZPC_BG)
    window.resizable(False, False)
    font_family = _ui_font_family(window)
    canvas = tk.Canvas(window, highlightthickness=0, bd=0, bg=ZPC_BG)
    canvas.pack(fill="both", expand=True)
    window.update_idletasks()
    width, height = 620, 455
    _draw_gradient(canvas, width, height)
    canvas.create_oval(-170, 250, 280, 680, fill="#100B1B", outline="", tags=("mode-art",))
    canvas.create_oval(390, -190, 800, 240, fill="#120A20", outline="", tags=("mode-art",))
    canvas.create_text(
        width // 2, 82, text="ZPC", fill=ZPC_WHITE,
        font=(font_family, 48, "bold"), tags=("mode-art",),
    )
    canvas.create_text(
        width // 2, 132, text="Zynx Password Checker", fill=ZPC_MUTED,
        font=("Segoe UI", 13), tags=("mode-art",),
    )
    canvas.create_text(
        width // 2, 198, text="CHOOSE YOUR EXPERIENCE", fill=ZPC_WHITE,
        font=("Segoe UI", 12, "bold"), tags=("mode-art",),
    )
    canvas.create_text(
        width // 2, 226, text="You can switch modes next time you launch ZPC.",
        fill=ZPC_MUTED, font=("Segoe UI", 9), tags=("mode-art",),
    )

    selection = {"value": "exit"}

    def choose(value: str) -> None:
        selection["value"] = value
        window.destroy()

    for y, label, detail, value in (
        (292, "GUI  ·  DESKTOP", "Animated visual interface and detailed report", "gui"),
        (372, "TUI  ·  POWERSHELL", "Keyboard-driven Rich terminal interface", "tui"),
    ):
        _rounded_rectangle(
            canvas, 72, y - 28, 548, y + 27, 15,
            fill="#191126", outline=ZPC_BORDER, width=1, tags=("mode-art",),
        )
        button = tk.Button(
            window,
            text=label,
            command=lambda picked=value: choose(picked),
            font=("Segoe UI", 10, "bold"),
            bg="#241737", fg=ZPC_WHITE,
            activebackground="#55318A", activeforeground=ZPC_WHITE,
            relief="flat", bd=0, highlightthickness=0,
            cursor="hand2", padx=12, pady=7,
        )
        canvas.create_window(188, y, window=button, width=190, height=42, tags=("mode-widget",))
        canvas.create_text(
            395, y, text=detail, fill=ZPC_MUTED,
            font=("Segoe UI", 9), tags=("mode-art",),
        )

    window.protocol("WM_DELETE_WINDOW", lambda: choose("exit"))
    window.mainloop()
    try:
        window.destroy()
    except Exception:
        pass
    return selection["value"]


def launch_tui_mode() -> int:
    """Start Rich TUI in a fresh PowerShell window when selected on Windows."""
    if os.name == "nt":
        powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe") or "powershell.exe"
        python_executable = sys.executable
        if python_executable.lower().endswith("pythonw.exe"):
            python_executable = python_executable[:-len("pythonw.exe")] + "python.exe"
        script_path = os.path.abspath(__file__)

        def ps_quote(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        command = f"& {ps_quote(python_executable)} {ps_quote(script_path)} --tui"
        try:
            creation_flag = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
            subprocess.Popen(
                [powershell, "-NoLogo", "-NoExit", "-Command", command],
                cwd=os.path.dirname(script_path),
                creationflags=creation_flag,
            )
            return 0
        except OSError as exc:
            message = f"Could not open PowerShell ({exc})."
            try:
                if tk is not None:
                    from tkinter import messagebox
                    messagebox.showerror("ZPC - TUI launch failed", message)
                else:
                    print(message, file=sys.stderr)
            except Exception:
                print(message, file=sys.stderr)
            return 1

    # On Linux/macOS, keep the terminal interface in the current terminal.
    return run_tui()


class PasswordCheckerGUI:
    """Single-window desktop GUI with an animated landing screen and report view."""

    LOADING_MESSAGES = (
        "Preparing your local security analysis",
        "Reviewing character variety and length",
        "Checking for common words and patterns",
        "Calculating entropy and time estimates",
        "Organizing your security report",
    )
    LOADING_SECONDS = 4.6

    def __init__(self, root) -> None:
        self.root = root
        self.root.title("ZPC | Zynx Password Checker")
        self.root.geometry("1120x840")
        self.root.minsize(900, 700)
        self.root.configure(bg=ZPC_BG)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.screen = "home"
        self.pending_password: Optional[str] = None
        self.loading_started = 0.0
        self.result_frame = None
        self.result_window = None
        self._last_canvas_size = (0, 0)
        self.display_font_family = _ui_font_family(root)
        self.title_font = tkfont.Font(root=root, family=self.display_font_family, size=70, weight="bold")
        self.subtitle_font = tkfont.Font(root=root, family="Segoe UI", size=14)
        self.body_font = tkfont.Font(root=root, family="Segoe UI", size=11)
        self.small_font = tkfont.Font(root=root, family="Segoe UI", size=9)
        self.heading_font = tkfont.Font(root=root, family="Segoe UI", size=12, weight="bold")

        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "ZPC.Horizontal.TProgressbar",
            troughcolor="#271C35", background=ZPC_PURPLE_LIGHT,
            bordercolor="#271C35", lightcolor=ZPC_PURPLE_LIGHT,
            darkcolor=ZPC_PURPLE, thickness=13,
        )

        self.canvas = tk.Canvas(root, bg=ZPC_BG, highlightthickness=0, bd=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar = tk.Scrollbar(
            root, orient="vertical", command=self.canvas.yview,
            bg="#241633", troughcolor=ZPC_BG, activebackground=ZPC_PURPLE,
            relief="flat", bd=0, width=14,
        )
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.password_entry = tk.Entry(
            root, show="●", relief="flat", bd=0,
            bg="#17121F", fg=ZPC_WHITE, insertbackground=ZPC_PURPLE_LIGHT,
            selectbackground="#6940A0", selectforeground=ZPC_WHITE,
            font=("Segoe UI", 15), justify="center",
            highlightthickness=0,
        )
        self.password_entry.bind("<Return>", lambda _event: self.submit_password())
        self.entry_window = self.canvas.create_window(
            0, 0, window=self.password_entry, width=500, height=54,
            tags=("home-widget",),
        )
        self.enter_button = tk.Button(
            root, text="Enter", command=self.submit_password,
            font=(self.display_font_family, 14, "bold"),
            bg="#7040B5", fg=ZPC_WHITE,
            activebackground="#8D5BD0", activeforeground=ZPC_WHITE,
            relief="flat", bd=0, highlightthickness=0,
            cursor="hand2", padx=20, pady=9,
        )
        self.button_window = self.canvas.create_window(
            0, 0, window=self.enter_button, width=230, height=54,
            tags=("home-widget",),
        )
        self.root.bind("<Return>", self._on_return)
        self._draw_home()
        self._animate_home()

    def close(self) -> None:
        """Close the GUI and release any transient reference to the password."""
        self.pending_password = None
        self.root.destroy()

    def _on_return(self, _event=None):
        if self.screen == "home":
            self.submit_password()
        return "break"

    def _on_canvas_configure(self, event) -> None:
        size = (event.width, event.height)
        if size == self._last_canvas_size:
            return
        self._last_canvas_size = size
        if self.screen == "home":
            self._draw_home()
        elif self.screen == "results" and self.result_window is not None:
            self.canvas.itemconfigure(self.result_window, width=max(600, event.width - 76))
            self._update_result_scrollregion()

    def _draw_home(self) -> None:
        if self.screen != "home":
            return
        width = max(1, self.canvas.winfo_width())
        height = max(1, self.canvas.winfo_height())
        _draw_gradient(self.canvas, width, height, "background")
        self.canvas.delete("home-art")

        # Soft background glows and layered shadows create a glass-like effect.
        self.canvas.create_oval(-220, height * 0.45, width * 0.38, height * 1.14,
                                fill="#0D0916", outline="", tags=("home-art",))
        self.canvas.create_oval(width * 0.66, -height * 0.25, width * 1.18, height * 0.55,
                                fill="#11091B", outline="", tags=("home-art",))
        self.canvas.create_oval(width * 0.38, height * 0.58, width * 0.72, height * 1.12,
                                fill="#110B1A", outline="", tags=("home-art",))

        center_x = width / 2
        title_y = max(105, height * 0.17)
        title_size = int(max(54, min(78, width * 0.071)))
        self.title_font.configure(size=title_size)
        self.title_item = self.canvas.create_text(
            center_x, title_y, text="ZPC", fill=ZPC_WHITE,
            font=self.title_font, tags=("home-art",),
        )
        self.canvas.create_text(
            center_x, title_y + title_size * 0.68,
            text="Zynx Password Checker", fill="#D7CBE8",
            font=self.subtitle_font, tags=("home-art",),
        )
        self.canvas.create_text(
            center_x, title_y + title_size * 1.13,
            text="LOCAL PASSWORD STRENGTH ANALYSIS", fill=ZPC_MUTED,
            font=("Segoe UI", 8, "bold"), tags=("home-art",),
        )

        card_width = min(700, max(570, width - 130))
        card_left = center_x - card_width / 2
        card_right = center_x + card_width / 2
        card_center_y = min(height * 0.64, height - 150)
        card_top = card_center_y - 155
        card_bottom = card_center_y + 150
        for offset, color in ((15, "#0B0811"), (9, "#100B18"), (4, "#171021")):
            _rounded_rectangle(
                self.canvas, card_left, card_top + offset, card_right, card_bottom + offset,
                26, fill=color, outline="", tags=("home-art",),
            )
        _rounded_rectangle(
            self.canvas, card_left, card_top, card_right, card_bottom,
            26, fill="#100D18", outline="#352448", width=1, tags=("home-art",),
        )
        self.canvas.create_text(
            center_x, card_top + 40, text="CHECK A PASSWORD",
            fill=ZPC_WHITE, font=("Segoe UI", 12, "bold"), tags=("home-art",),
        )
        self.canvas.create_text(
            center_x, card_top + 68, text="Use a test password — never enter a password you actively use.",
            fill=ZPC_MUTED, font=("Segoe UI", 9), tags=("home-art",),
        )
        field_left = center_x - min(260, card_width * 0.39)
        field_right = center_x + min(260, card_width * 0.39)
        field_top = card_top + 98
        field_bottom = field_top + 58
        _rounded_rectangle(
            self.canvas, field_left, field_top, field_right, field_bottom,
            13, fill="#17121F", outline="#30223F", width=1, tags=("home-art",),
        )
        self.home_entry_y = (field_top + field_bottom) / 2
        self.entry_base_y = self.home_entry_y
        self.canvas.coords(self.entry_window, center_x, self.home_entry_y)
        self.canvas.itemconfigure(self.entry_window, width=field_right - field_left - 24, height=48)

        self.button_base_y = card_top + 222
        button_width = 230
        self.button_shadow = []
        for offset, color in ((8, "#0B0711"), (4, "#20132F"), (1, "#3A2456")):
            shadow = _rounded_rectangle(
                self.canvas,
                center_x - button_width / 2, self.button_base_y - 28 + offset,
                center_x + button_width / 2, self.button_base_y + 28 + offset,
                16, fill=color, outline="", tags=("home-art",),
            )
            self.button_shadow.append(shadow)
        self.canvas.coords(self.button_window, center_x, self.button_base_y)
        self.canvas.itemconfigure(self.button_window, width=button_width - 8, height=50)

        self.status_item = self.canvas.create_text(
            center_x, card_bottom - 15, text="Your password stays on this device.",
            fill="#81758F", font=("Segoe UI", 8), tags=("home-art",),
        )
        self.canvas.create_text(
            center_x, height - 35,
            text="NO NETWORK  •  NO PASSWORD STORAGE  •  EDUCATIONAL ESTIMATES",
            fill="#72677F", font=("Segoe UI", 8), tags=("home-art",),
        )

    def _animate_home(self) -> None:
        if not self.root.winfo_exists():
            return
        if self.screen == "home" and hasattr(self, "entry_window"):
            phase = time.monotonic() * 1.35
            entry_offset = math.sin(phase) * 2.2
            button_offset = math.sin(phase + 1.2) * 3.0
            width = max(1, self.canvas.winfo_width())
            center_x = width / 2
            self.canvas.coords(self.entry_window, center_x, self.entry_base_y + entry_offset)
            self.canvas.coords(self.button_window, center_x, self.button_base_y + button_offset)
            button_width = 230
            for shadow, extra in zip(self.button_shadow, (8, 4, 1)):
                shadow_points = _rounded_rectangle_points(
                    center_x - button_width / 2,
                    self.button_base_y - 28 + button_offset + extra,
                    center_x + button_width / 2,
                    self.button_base_y + 28 + button_offset + extra,
                    16,
                )
                self.canvas.coords(shadow, *shadow_points)
            if hasattr(self, "title_item"):
                self.canvas.coords(self.title_item, center_x, max(105, self.canvas.winfo_height() * 0.17) + math.sin(phase * 0.55) * 1.5)
        self.root.after(45, self._animate_home)

    def _set_home_status(self, message: str, color: str = "#F0A8BF") -> None:
        if hasattr(self, "status_item"):
            self.canvas.itemconfigure(self.status_item, text=message, fill=color)

    def submit_password(self) -> None:
        """Validate input locally, clear the entry, then show the loading animation."""
        if self.screen != "home":
            return
        password = self.password_entry.get()
        if not password:
            self._set_home_status("Enter a test password to begin.")
            self.password_entry.focus_set()
            return
        if len(password) > MAX_PASSWORD_LENGTH:
            self._set_home_status(f"The demo limit is {MAX_PASSWORD_LENGTH} characters.")
            self.password_entry.delete(0, "end")
            return

        # Clear the visible field immediately. The short-lived value is held only
        # until local analysis completes; it is never logged, printed, or saved.
        self.password_entry.delete(0, "end")
        self.pending_password = password
        del password
        self.screen = "loading"
        self.canvas.itemconfigure("home-widget", state="hidden")
        self.canvas.itemconfigure("home-art", state="hidden")
        self.loading_started = time.monotonic()
        self._draw_loading()
        self._tick_loading()

    def _draw_loading(self) -> None:
        self.canvas.delete("loading-art")
        width = max(1, self.canvas.winfo_width())
        height = max(1, self.canvas.winfo_height())
        center_x = width / 2
        center_y = height / 2
        panel_width = min(610, width - 90)
        left, right = center_x - panel_width / 2, center_x + panel_width / 2
        top, bottom = center_y - 110, center_y + 112
        for offset, color in ((12, "#0A0710"), (6, "#120B1B")):
            _rounded_rectangle(
                self.canvas, left, top + offset, right, bottom + offset,
                23, fill=color, outline="", tags=("loading-art",),
            )
        _rounded_rectangle(
            self.canvas, left, top, right, bottom, 23,
            fill="#100D18", outline=ZPC_BORDER, width=1, tags=("loading-art",),
        )
        self.canvas.create_text(
            center_x, top + 50, text="ANALYZING YOUR PASSWORD",
            fill=ZPC_WHITE, font=("Segoe UI", 12, "bold"), tags=("loading-art",),
        )
        self.canvas.create_text(
            center_x, top + 79, text="Everything is processed locally on this device.",
            fill=ZPC_MUTED, font=("Segoe UI", 9), tags=("loading-art",),
        )
        self.loading_bar_left = center_x - min(220, panel_width * 0.36)
        self.loading_bar_right = center_x + min(220, panel_width * 0.36)
        self.loading_bar_y = center_y + 4
        _rounded_rectangle(
            self.canvas, self.loading_bar_left, self.loading_bar_y - 6,
            self.loading_bar_right, self.loading_bar_y + 6, 6,
            fill="#281C35", outline="", tags=("loading-art",),
        )
        self.loading_fill = _rounded_rectangle(
            self.canvas, self.loading_bar_left, self.loading_bar_y - 6,
            self.loading_bar_left + 1, self.loading_bar_y + 6, 6,
            fill=ZPC_PURPLE_LIGHT, outline="", tags=("loading-art",),
        )
        self.loading_message_shadow = self.canvas.create_text(
            center_x + 1, center_y + 57, text=self.LOADING_MESSAGES[0],
            fill="#3B2B4D", font=("Segoe UI", 9), tags=("loading-art",),
        )
        self.loading_message = self.canvas.create_text(
            center_x, center_y + 56, text=self.LOADING_MESSAGES[0],
            fill=ZPC_WHITE, font=("Segoe UI", 9), tags=("loading-art",),
        )

    def _tick_loading(self) -> None:
        if self.screen != "loading":
            return
        elapsed = max(0.0, time.monotonic() - self.loading_started)
        progress = min(1.0, elapsed / self.LOADING_SECONDS)
        bar_end = self.loading_bar_left + max(2, (self.loading_bar_right - self.loading_bar_left) * progress)
        fill_points = _rounded_rectangle_points(
            self.loading_bar_left, self.loading_bar_y - 6, bar_end, self.loading_bar_y + 6, 6
        )
        self.canvas.coords(self.loading_fill, *fill_points)

        index = min(len(self.LOADING_MESSAGES) - 1, int(elapsed))
        phase = elapsed - int(elapsed)
        fade = min(1.0, phase / 0.18, (1.0 - phase) / 0.18)
        fade = max(0.0, fade)
        message_color = _mix_color("#554567", ZPC_WHITE, fade)
        message_y = self.canvas.winfo_height() / 2 + 56 + math.sin(elapsed * 2.0) * 2.0
        self.canvas.itemconfigure(self.loading_message, text=self.LOADING_MESSAGES[index], fill=message_color)
        self.canvas.itemconfigure(self.loading_message_shadow, text=self.LOADING_MESSAGES[index])
        self.canvas.coords(self.loading_message, self.canvas.winfo_width() / 2, message_y)
        self.canvas.coords(self.loading_message_shadow, self.canvas.winfo_width() / 2 + 1, message_y + 1)

        if elapsed >= self.LOADING_SECONDS:
            self._finish_analysis()
            return
        self.root.after(35, self._tick_loading)

    def _finish_analysis(self) -> None:
        if self.screen != "loading":
            return
        password = self.pending_password
        self.pending_password = None
        try:
            if password is None:
                raise RuntimeError("The pending input was cleared before analysis.")
            report = analyze_password(password)
        except (TypeError, ValueError, RuntimeError) as exc:
            self.screen = "home"
            self.canvas.delete("loading-art")
            self.canvas.itemconfigure("home-widget", state="normal")
            self.canvas.itemconfigure("home-art", state="normal")
            self._set_home_status(f"Analysis could not be completed: {exc}")
            return
        finally:
            # Python cannot guarantee secure zeroization of immutable strings.
            password = None
        self._show_report(report)

    def _make_card(self, parent, title: str, subtitle: Optional[str] = None):
        card = tk.Frame(
            parent, bg=ZPC_PANEL, bd=0, padx=18, pady=15,
            highlightthickness=1, highlightbackground=ZPC_BORDER,
        )
        heading = tk.Label(
            card, text=title.upper(), bg=ZPC_PANEL, fg=ZPC_WHITE,
            font=self.heading_font, anchor="w",
        )
        heading.pack(fill="x", anchor="w")
        if subtitle:
            tk.Label(
                card, text=subtitle, bg=ZPC_PANEL, fg=ZPC_MUTED,
                font=self.small_font, anchor="w", justify="left", wraplength=760,
            ).pack(fill="x", anchor="w", pady=(4, 10))
        return card

    def _show_report(self, report: PasswordReport) -> None:
        self.screen = "results"
        self.canvas.delete("loading-art")
        self.canvas.itemconfigure("home-widget", state="hidden")
        self.canvas.itemconfigure("home-art", state="hidden")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

        self.result_frame = tk.Frame(self.canvas, bg=ZPC_BG, padx=28, pady=24)
        self.result_window = self.canvas.create_window(
            self.canvas.winfo_width() / 2, 25,
            anchor="n", window=self.result_frame,
            width=max(600, self.canvas.winfo_width() - 76),
            tags=("results-window",),
        )
        self._build_report_content(report)
        self.root.update_idletasks()
        self._update_result_scrollregion()
        self.canvas.yview_moveto(0)

    def _update_result_scrollregion(self) -> None:
        if self.screen != "results" or self.result_frame is None:
            return
        self.root.update_idletasks()
        content_height = self.result_frame.winfo_reqheight() + 54
        self.canvas.configure(scrollregion=(0, 0, self.canvas.winfo_width(), content_height))
        if self.result_window is not None:
            self.canvas.coords(self.result_window, self.canvas.winfo_width() / 2, 24)

    def _build_report_content(self, report: PasswordReport) -> None:
        parent = self.result_frame
        parent.grid_columnconfigure(0, weight=1)

        header = tk.Frame(parent, bg=ZPC_BG)
        header.pack(fill="x", pady=(2, 16))
        tk.Label(
            header, text="ZPC", bg=ZPC_BG, fg=ZPC_WHITE,
            font=(self.display_font_family, 25, "bold"),
        ).pack()
        tk.Label(
            header, text="Zynx Password Checker  /  Analysis Report",
            bg=ZPC_BG, fg=ZPC_MUTED, font=self.body_font,
        ).pack(pady=(2, 0))

        grade_colors = {
            "VERY WEAK": "#F06A83", "WEAK": "#E48A72", "FAIR": "#D6B36D",
            "STRONG": "#87C99D", "VERY STRONG": "#B38AFF",
        }
        grade_color = grade_colors.get(report.grade, ZPC_PURPLE_LIGHT)
        score_card = self._make_card(parent, "Overall assessment", "A transparent educational score, not a formal security certification.")
        score_row = tk.Frame(score_card, bg=ZPC_PANEL)
        score_row.pack(fill="x")
        tk.Label(
            score_row, text=f"{report.score:02d}", bg=ZPC_PANEL,
            fg=grade_color, font=(self.display_font_family, 42, "bold"),
        ).pack(side="left", padx=(2, 16))
        score_text = tk.Frame(score_row, bg=ZPC_PANEL)
        score_text.pack(side="left", fill="x", expand=True)
        tk.Label(
            score_text, text=f"{report.grade}", bg=ZPC_PANEL,
            fg=grade_color, font=("Segoe UI", 16, "bold"), anchor="w",
        ).pack(fill="x")
        tk.Label(
            score_text, text="Strength score out of 100", bg=ZPC_PANEL,
            fg=ZPC_MUTED, font=self.small_font, anchor="w",
        ).pack(fill="x", pady=(3, 0))
        ttk.Progressbar(
            score_card, maximum=100, value=report.score,
            style="ZPC.Horizontal.TProgressbar",
        ).pack(fill="x", pady=(12, 0))
        score_card.pack(fill="x", pady=(0, 12))

        metrics = self._make_card(parent, "Quick metrics")
        metric_grid = tk.Frame(metrics, bg=ZPC_PANEL)
        metric_grid.pack(fill="x", pady=(10, 0))
        metric_items = (
            ("PASSWORD LENGTH", f"{report.length} characters"),
            ("STRUCTURAL ENTROPY", f"{report.entropy_bits:,.2f} bits"),
            ("ESTIMATED POOL", f"{report.pool_size:,} characters"),
        )
        for column, (label, value) in enumerate(metric_items):
            metric_grid.grid_columnconfigure(column, weight=1, uniform="metrics")
            tile = tk.Frame(metric_grid, bg=ZPC_PANEL_ALT, padx=12, pady=12)
            tile.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 5, 5 if column < 2 else 0))
            tk.Label(tile, text=label, bg=ZPC_PANEL_ALT, fg=ZPC_MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(tile, text=value, bg=ZPC_PANEL_ALT, fg=ZPC_WHITE, font=("Segoe UI", 13, "bold"), wraplength=220).pack(anchor="w", pady=(7, 0))
        metrics.pack(fill="x", pady=(0, 12))

        classes = self._make_card(parent, "Character categories", "The categories observed in the input; character variety is not a requirement by itself.")
        class_labels = (
            ("Lowercase letters (a-z)", "lowercase"),
            ("Uppercase letters (A-Z)", "uppercase"),
            ("Digits (0-9)", "digits"),
            ("Symbols", "symbols"),
            ("Whitespace", "whitespace"),
        )
        for label, key in class_labels:
            row = tk.Frame(classes, bg=ZPC_PANEL)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=ZPC_PANEL, fg=ZPC_WHITE, font=self.body_font, anchor="w").pack(side="left", fill="x", expand=True)
            detected = report.character_classes[key]
            tk.Label(
                row, text="DETECTED" if detected else "NOT FOUND",
                bg="#1B3027" if detected else "#211A29",
                fg="#9CE0B1" if detected else "#988CA5",
                font=("Segoe UI", 8, "bold"), padx=10, pady=4,
            ).pack(side="right")
        classes.pack(fill="x", pady=(0, 12))

        scenarios = self._make_card(
            parent, "Illustrative crack-time scenarios",
            "Median search-time estimates using the same theoretical entropy value and the stated guessing rates.",
        )
        scenario_grid = tk.Frame(scenarios, bg=ZPC_PANEL)
        scenario_grid.pack(fill="x", pady=(3, 0))
        for column in range(2):
            scenario_grid.grid_columnconfigure(column, weight=1, uniform="scenarios")
        scenario_values = (
            ("ONLINE / RATE-LIMITED", f"{ONLINE_GUESSES_PER_SECOND:,.0f} guesses/sec", estimate_crack_time(report.entropy_bits, ONLINE_GUESSES_PER_SECOND)),
            ("OFFLINE / FAST UNSALTED HASH", f"{OFFLINE_FAST_HASH_GUESSES_PER_SECOND:,.0f} guesses/sec", estimate_crack_time(report.entropy_bits, OFFLINE_FAST_HASH_GUESSES_PER_SECOND)),
        )
        for column, (title, rate, duration) in enumerate(scenario_values):
            tile = tk.Frame(scenario_grid, bg=ZPC_PANEL_ALT, padx=13, pady=12)
            tile.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 5, 5 if column == 0 else 0))
            tk.Label(tile, text=title, bg=ZPC_PANEL_ALT, fg=ZPC_PURPLE_LIGHT, font=("Segoe UI", 8, "bold"), anchor="w", justify="left", wraplength=300).pack(fill="x")
            tk.Label(tile, text=rate, bg=ZPC_PANEL_ALT, fg=ZPC_MUTED, font=self.small_font, anchor="w").pack(fill="x", pady=(7, 2))
            tk.Label(tile, text=duration, bg=ZPC_PANEL_ALT, fg=ZPC_WHITE, font=("Segoe UI", 11, "bold"), anchor="w", justify="left", wraplength=310).pack(fill="x")
        scenarios.pack(fill="x", pady=(0, 12))

        findings = self._make_card(parent, "Findings", "Local blocklist and simple pattern checks only.")
        finding_lines = []
        if report.common_match:
            finding_lines.append(("COMMON-PASSWORD CHECK", report.common_match, "#F0A1B4"))
        for warning_text in report.pattern_warnings:
            finding_lines.append(("PATTERN WARNING", warning_text, "#E3BE7F"))
        if not finding_lines:
            finding_lines.append(("NO LOCAL MATCH", "No matches were found in this tool's small local checks.", "#9CE0B1"))
        for title, detail, color in finding_lines:
            row = tk.Frame(findings, bg=ZPC_PANEL)
            row.pack(fill="x", pady=4)
            tk.Label(row, text="•", bg=ZPC_PANEL, fg=color, font=("Segoe UI", 15, "bold")).pack(side="left", padx=(0, 9))
            body = tk.Frame(row, bg=ZPC_PANEL)
            body.pack(side="left", fill="x", expand=True)
            tk.Label(body, text=title, bg=ZPC_PANEL, fg=color, font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x")
            tk.Label(body, text=detail, bg=ZPC_PANEL, fg=ZPC_WHITE, font=self.body_font, anchor="w", justify="left", wraplength=740).pack(fill="x", pady=(2, 0))
        findings.pack(fill="x", pady=(0, 12))

        recommendations = self._make_card(parent, "Recommendations")
        for index, recommendation in enumerate(report.recommendations, start=1):
            row = tk.Frame(recommendations, bg=ZPC_PANEL)
            row.pack(fill="x", pady=5)
            tk.Label(row, text=f"{index:02d}", bg=ZPC_PANEL_ALT, fg=ZPC_PURPLE_LIGHT, font=("Segoe UI", 9, "bold"), padx=8, pady=5).pack(side="left", padx=(0, 10))
            tk.Label(row, text=recommendation, bg=ZPC_PANEL, fg=ZPC_WHITE, font=self.body_font, anchor="w", justify="left", wraplength=760).pack(side="left", fill="x", expand=True)
        recommendations.pack(fill="x", pady=(0, 12))

        caveats = self._make_card(parent, "Important limitations")
        caveat_lines = [
            "Entropy assumes each character was selected independently and uniformly from the estimated character pool.",
            "Human-created passwords are usually more predictable, so real guessing time may be much shorter.",
            "The built-in common-password list is small and is not a breach database or a live exposure check.",
            "The offline rate is only an example. Hashing algorithm, hardware, salts, and attack setup change it substantially.",
        ]
        if report.uses_unicode:
            caveat_lines.append(
                f"Unicode characters were found; their alphabet contribution uses a rough {UNICODE_CLASS_POOL_ESTIMATE}-character bucket."
            )
        for line in caveat_lines:
            tk.Label(caveats, text=f"•  {line}", bg=ZPC_PANEL, fg=ZPC_MUTED, font=self.small_font, anchor="w", justify="left", wraplength=770).pack(fill="x", pady=3)
        caveats.pack(fill="x", pady=(0, 16))

        footer = tk.Frame(parent, bg=ZPC_BG)
        footer.pack(fill="x", pady=(0, 24))
        tk.Button(
            footer, text="CHECK ANOTHER PASSWORD", command=self.reset_home,
            bg="#7040B5", fg=ZPC_WHITE, activebackground="#8D5BD0",
            activeforeground=ZPC_WHITE, relief="flat", bd=0,
            highlightthickness=0, cursor="hand2", padx=18, pady=11,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        tk.Button(
            footer, text="EXIT", command=self.close,
            bg="#1A1422", fg=ZPC_MUTED, activebackground="#2A2035",
            activeforeground=ZPC_WHITE, relief="flat", bd=0,
            highlightthickness=0, cursor="hand2", padx=18, pady=11,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right")

    def reset_home(self) -> None:
        """Return to the entry screen without retaining the previous report."""
        if self.result_frame is not None:
            self.result_frame.destroy()
            self.result_frame = None
        if self.result_window is not None:
            self.canvas.delete(self.result_window)
            self.result_window = None
        self.scrollbar.pack_forget()
        self.canvas.configure(yscrollcommand="", scrollregion=(0, 0, 0, 0))
        self.canvas.yview_moveto(0)
        self.canvas.delete("loading-art")
        self.canvas.itemconfigure("home-widget", state="normal")
        self.canvas.itemconfigure("home-art", state="normal")
        self.screen = "home"
        self.password_entry.delete(0, "end")
        self._set_home_status("Your password stays on this device.", "#81758F")
        self.password_entry.focus_set()


def run_gui() -> int:
    """Create and run the ZPC desktop application."""
    if tk is None or tkfont is None or ttk is None:
        print(
            "Tkinter is not available in this Python installation. "
            "Install a Python build with Tk support or run with --tui.",
            file=sys.stderr,
        )
        return 1
    try:
        root = tk.Tk()
        PasswordCheckerGUI(root)
        root.mainloop()
        return 0
    except tk.TclError as exc:
        print(f"Could not open the desktop interface: {exc}", file=sys.stderr)
        return 1


# The self-tests verify important logic paths without requiring any real credentials.
class PasswordCheckerTests(unittest.TestCase):
    """Unit tests for deterministic analysis and crack-time edge cases."""

    def test_empty_password_has_zero_entropy(self) -> None:
        report = analyze_password("")
        self.assertEqual(report.entropy_bits, 0.0)
        self.assertEqual(report.score, 0)

    def test_ascii_lowercase_entropy_formula(self) -> None:
        report = analyze_password("abc")
        self.assertEqual(report.pool_size, 26)
        self.assertAlmostEqual(report.entropy_bits, 3 * math.log2(26))

    def test_common_password_is_flagged(self) -> None:
        report = analyze_password("Password123!")
        self.assertIsNotNone(report.common_match)
        self.assertLessEqual(report.score, 20)

    def test_leetspeak_dictionary_word_is_flagged(self) -> None:
        report = analyze_password("P@ssw0rd!")
        self.assertIsNotNone(report.common_match)

    def test_repeated_character_pattern_is_flagged(self) -> None:
        report = analyze_password("Abc!!!xyz")
        self.assertTrue(any("repeated" in item for item in report.pattern_warnings))

    def test_keyboard_pattern_is_flagged(self) -> None:
        report = analyze_password("myQwertyKey")
        self.assertTrue(any("keyboard" in item for item in report.pattern_warnings))

    def test_unicode_password_gets_a_nonzero_pool(self) -> None:
        report = analyze_password("مرحبا123")
        self.assertTrue(report.uses_unicode)
        self.assertGreater(report.pool_size, 0)

    def test_large_entropy_does_not_overflow(self) -> None:
        result = estimate_crack_time(10_000.0, 1_000_000_000.0)
        self.assertIn("10^", result)

    def test_invalid_guess_rate_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            estimate_crack_time(50.0, 0.0)

    def test_non_finite_guess_rate_is_rejected(self) -> None:
        for invalid_rate in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(rate=invalid_rate):
                with self.assertRaises(ValueError):
                    estimate_crack_time(50.0, invalid_rate)

    def test_negative_entropy_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            estimate_crack_time(-0.5, 10.0)

    def test_non_finite_entropy_is_rejected(self) -> None:
        for invalid_entropy in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(entropy=invalid_entropy):
                with self.assertRaises(ValueError):
                    estimate_crack_time(invalid_entropy, 10.0)

    def test_non_finite_log_duration_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            format_log2_duration(float("nan"))

    def test_invalid_password_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            analyze_password(None)  # type: ignore[arg-type]

    def test_password_over_demo_limit_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            analyze_password("a" * (MAX_PASSWORD_LENGTH + 1))


# This entry point supports normal interactive use and a reproducible self-test mode.
def main() -> int:
    """Parse command-line options, choose an interface, and start ZPC."""
    parser = argparse.ArgumentParser(description="ZPC — Zynx Password Checker")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--gui", action="store_true", help="open the desktop GUI directly")
    mode_group.add_argument("--tui", action="store_true", help="open the terminal interface directly")
    parser.add_argument("--self-test", action="store_true", help="run built-in unit tests and exit")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    args = parser.parse_args()

    # Tests never create a GUI window or request password input.
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PasswordCheckerTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    try:
        if args.gui:
            return run_gui()
        if args.tui:
            return run_tui()

        selected_mode = choose_interface_mode()
        if selected_mode == "gui":
            return run_gui()
        if selected_mode == "tui":
            return launch_tui_mode()
        return 0
    except KeyboardInterrupt:
        print("\nSession interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
