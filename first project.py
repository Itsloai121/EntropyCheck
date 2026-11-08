#!/usr/bin/env python3
"""Local-only password strength checker with a Rich terminal interface."""

from __future__ import annotations

# Standard-library imports provide the analysis, input handling, and tests.
import argparse
import getpass
import math
import re
import string
import sys
import unicodedata
import unittest
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

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
APP_NAME = "PASSWORD LAB"
APP_VERSION = "1.0.0"
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
    title = Text("PASSWORD LAB", style="bold bright_cyan", justify="center")
    subtitle = Text("STRENGTH CHECKER  •  ENTROPY ESTIMATOR", style="bold white", justify="center")
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

    def test_password_over_demo_limit_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            analyze_password("a" * (MAX_PASSWORD_LENGTH + 1))


# This entry point supports normal interactive use and a reproducible self-test mode.
def main() -> int:
    """Parse command-line options and start the requested mode."""
    parser = argparse.ArgumentParser(description="Local-only password strength checker")
    parser.add_argument("--self-test", action="store_true", help="run built-in unit tests and exit")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    args = parser.parse_args()

    # Run the built-in test suite when requested, without opening the TUI.
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PasswordCheckerTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    # Start the UI and handle Ctrl+C without displaying a traceback.
    try:
        return run_tui()
    except KeyboardInterrupt:
        print("\nSession interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
