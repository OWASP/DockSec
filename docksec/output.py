"""
Terminal output layer for DockSec.

A single place that owns the look of everything DockSec prints to the terminal:
the banner, section headers, status messages, the severity summary table, the
security score line, the "Quick take" action block, the list of generated
reports, and the suggested next command.

Routing user-facing output through these helpers keeps the CLI visually
consistent and makes global behavior (quiet mode, disabling color) a single
switch instead of scattered ``print`` calls.

Design notes:
- Output goes to stdout via one shared Rich ``Console``. Logs go to stderr
  (see ``utils.get_custom_logger``), so the two streams never fight.
- No emoji or decorative glyphs are used; structure comes from color and
  box-drawing table borders only.
"""

import sys
from typing import Dict, Iterable, List, Optional

from rich.box import SQUARE
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Module-level state configured once by the CLI.
_state = {"quiet": False, "no_color": False, "json_mode": False}
_console: Optional[Console] = None

# Severity display order and colors used across the summary.
_SEVERITY_STYLES = [
    ("CRITICAL", "Critical", "bold red"),
    ("HIGH", "High", "red"),
    ("MEDIUM", "Medium", "yellow"),
    ("LOW", "Low", "cyan"),
]


def configure(quiet: bool = False, no_color: bool = False, json_mode: bool = False) -> None:
    """Configure the output layer. Called once, early, by the CLI.

    json_mode reserves stdout for a single machine-readable JSON payload
    (see --json). All human-readable output (banner, sections, info, warn,
    error, the result summary) is redirected to stderr instead, so scripts
    piping stdout never see anything but the JSON.
    """
    _state["quiet"] = quiet
    _state["no_color"] = no_color
    _state["json_mode"] = json_mode
    global _console
    stream = sys.stderr if json_mode else sys.stdout
    _console = Console(file=stream, no_color=no_color, highlight=False)


def get_console() -> Console:
    """Return the shared console, creating a default one if needed."""
    global _console
    if _console is None:
        stream = sys.stderr if _state["json_mode"] else sys.stdout
        _console = Console(file=stream, no_color=_state["no_color"], highlight=False)
    return _console


def is_json_mode() -> bool:
    return bool(_state["json_mode"])


def _line(renderable) -> None:
    """Print a single line without hard-wrapping (long paths stay intact)."""
    get_console().print(renderable, soft_wrap=True)


def is_quiet() -> bool:
    return bool(_state["quiet"])


# ---------------------------------------------------------------------------
# Basic building blocks
# ---------------------------------------------------------------------------


def banner(version: str, mode: str) -> None:
    """Top-of-run banner with the tool version and the active mode."""
    if is_quiet():
        return
    console = get_console()
    console.print()
    _line(
        Text.assemble(
            (f"DockSec {version}", "bold white"),
            ("  -  ", "dim"),
            ("Docker Security Scanner", "cyan"),
        )
    )
    _line(Text(f"Mode: {mode}", style="dim"))


def section(title: str) -> None:
    """A section header, replacing the old ``=== title ===`` banners."""
    if is_quiet():
        return
    get_console().print()
    _line(Text(title, style="bold cyan"))


def kv(label: str, value: str, label_width: int = 12) -> None:
    """An aligned label/value line used for run metadata."""
    if is_quiet():
        return
    _line(Text.assemble((f"{label:<{label_width}}", "bold"), (str(value), "default")))


def info(message: str) -> None:
    if is_quiet():
        return
    _line(Text.assemble(("info  ", "blue"), (message, "default")))


def detail(message: str) -> None:
    """Secondary/verbose detail (e.g. raw scanner output). Suppressed in quiet mode."""
    if is_quiet():
        return
    _line(Text(message, style="default"))


def success(message: str) -> None:
    if is_quiet():
        return
    _line(Text.assemble(("ok    ", "green"), (message, "default")))


def warn(message: str) -> None:
    # Warnings survive quiet mode; they carry actionable signal.
    _line(Text.assemble(("warn  ", "yellow"), (message, "default")))


def error(message: str) -> None:
    # Errors always print, even in quiet mode.
    _line(Text.assemble(("error ", "bold red"), (message, "default")))


# ---------------------------------------------------------------------------
# Summary components
# ---------------------------------------------------------------------------


def severity_table(counts: Dict[str, int]) -> None:
    """Render the box-drawing severity summary (Critical/High/Medium/Low)."""
    console = get_console()
    table = Table(box=SQUARE, show_edge=True, pad_edge=True, expand=False)
    for _key, header, style in _SEVERITY_STYLES:
        table.add_column(header, justify="center", style=style, header_style=style)
    row = []
    for key, _header, style in _SEVERITY_STYLES:
        value = counts.get(key, 0)
        row.append(Text(str(value), style=f"bold {style}" if value else "dim"))
    table.add_row(*row)
    if not is_quiet():
        console.print()
    console.print(table)


def score(value, rating: Optional[str] = None) -> None:
    """Render the security score with a color-coded rating band."""
    console = get_console()
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        console.print(Text.assemble(("Security Score  ", "bold"), ("N/A", "dim")))
        return

    band, style = _score_band(numeric)
    label = rating or band
    if not is_quiet():
        console.print()
    _line(
        Text.assemble(
            ("Security Score  ", "bold"),
            (f"{numeric:g} / 100", style),
            ("   ", "default"),
            (label, style),
        )
    )


def _score_band(numeric: float):
    if numeric >= 90:
        return "EXCELLENT", "bold green"
    if numeric >= 70:
        return "GOOD", "green"
    if numeric >= 50:
        return "FAIR", "yellow"
    return "POOR", "bold red"


def quick_take(items: Iterable[str]) -> None:
    """Render the 'Quick take' action block."""
    items = [i for i in items if i]
    if is_quiet() or not items:
        return
    console = get_console()
    console.print()
    _line(Text("Quick take", style="bold cyan"))
    for item in items:
        _line(Text.assemble(("  - ", "cyan"), (item, "default")))


def report_results(paths: Dict[str, str], results_dir: str) -> None:
    """List the report formats that were written and where."""
    if is_quiet():
        return
    written = [fmt.upper() for fmt, path in paths.items() if path]
    console = get_console()
    console.print()
    if written:
        _line(
            Text.assemble(
                ("Reports  ", "bold"),
                (", ".join(written), "green"),
                ("  ->  ", "dim"),
                (results_dir, "default"),
            )
        )
    else:
        _line(Text("Reports  none written", style="yellow"))


def next_command(command: str) -> None:
    """Suggest the next command the user might run."""
    if is_quiet() or not command:
        return
    get_console().print()
    _line(Text.assemble(("Next: ", "bold"), (command, "cyan")))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def count_by_severity(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """Count vulnerabilities by severity for the summary table."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in vulnerabilities or []:
        severity = str(vuln.get("Severity", "UNKNOWN")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    return counts
