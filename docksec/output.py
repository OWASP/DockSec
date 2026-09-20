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


def fix_commands(commands: Iterable[str]) -> None:
    """Render a 'Suggested fixes' block of copy-pasteable upgrade hints."""
    commands = [c for c in commands if c]
    if is_quiet() or not commands:
        return
    console = get_console()
    console.print()
    _line(Text("Suggested fixes", style="bold cyan"))
    for cmd in commands:
        _line(Text.assemble(("  ", "default"), (cmd, "green")))


_PRIORITY_STYLES = {
    "fix_now": "bold red",
    "fix_soon": "yellow",
    "monitor": "cyan",
    "low_priority": "dim",
}


def priority_summary(counts: Dict[str, int]) -> None:
    """Render the EPSS priority breakdown, most urgent first.

    Severity says how bad a finding would be; this says what to do first.
    """
    from docksec.epss import PRIORITY_LABELS, PRIORITY_ORDER

    present = [(tier, counts.get(tier, 0)) for tier in PRIORITY_ORDER]
    present = [(tier, count) for tier, count in present if count]
    if is_quiet() or not present:
        return

    console = get_console()
    console.print()
    _line(Text("Priority", style="bold cyan"))
    for tier, count in present:
        _line(
            Text.assemble(
                ("  ", "default"),
                (f"{PRIORITY_LABELS[tier]:<13}", _PRIORITY_STYLES.get(tier, "default")),
                (f" {count}", "bold"),
            )
        )


def fix_plan(plan) -> None:
    """Render the remediation plan: concrete commands, then the honest total."""
    if is_quiet() or plan is None or plan.total_count == 0:
        return

    console = get_console()

    if plan.package_upgrades:
        console.print()
        _line(Text("Fix commands", style="bold cyan"))
        for item in plan.package_upgrades:
            ids = ", ".join(item["ids"])
            more = "" if item["finding_count"] <= len(item["ids"]) else f" +{item['finding_count'] - len(item['ids'])}"
            _line(Text.assemble(("  > ", "dim"), (item["command"], "green")))
            _line(
                Text(
                    f"      {item['severity']} - {item['installed']} -> {item['fixed']}"
                    f"  ({ids}{more})",
                    style="dim",
                )
            )

    if plan.dockerfile_edits:
        console.print()
        _line(Text("Dockerfile changes", style="bold cyan"))
        for edit in plan.dockerfile_edits:
            location = f" (line {edit['line']})" if edit.get("line") else ""
            _line(
                Text.assemble(
                    ("  - ", "cyan"),
                    (f"[{edit['severity']}] ", "dim"),
                    (edit["instruction"], "default"),
                    (location, "dim"),
                )
            )

    if plan.compose_edits:
        console.print()
        _line(Text("Compose changes", style="bold cyan"))
        for edit in plan.compose_edits:
            service = f" ({edit['service']})" if edit.get("service") else ""
            _line(
                Text.assemble(
                    ("  - ", "cyan"),
                    (f"[{edit['severity']}] ", "dim"),
                    (edit["instruction"], "default"),
                    (service, "dim"),
                )
            )

    claim = plan.completion_claim()
    if claim:
        console.print()
        _line(Text(claim, style="bold"))


_CONFIDENCE_STYLES = {"high": "green", "medium": "yellow", "low": "dim"}


def ai_analysis(analysis: Dict) -> None:
    """Render the AI correlation pass.

    Exploit chains come first and are the most prominent thing on screen: they
    are the output no per-artifact scanner can produce, and the reason the
    correlation pass exists.
    """
    if is_quiet() or not analysis:
        return

    console = get_console()
    summary = analysis.get("summary")
    chains = analysis.get("chains") or []
    findings = analysis.get("findings") or []

    if summary:
        console.print()
        _line(Text(summary, style="bold"))

    if chains:
        console.print()
        _line(Text("Exploit chains", style="bold red"))
        for chain in chains:
            severity = str(chain.get("severity", "")).upper()
            _line(
                Text.assemble(
                    ("  ", "default"),
                    (f"[{severity}] ", "red"),
                    (chain.get("title", ""), "bold"),
                )
            )
            services = chain.get("services") or []
            if services:
                _line(Text(f"      services: {', '.join(services)}", style="dim"))
            ids = chain.get("finding_ids") or []
            if ids:
                _line(Text(f"      combines: {', '.join(ids)}", style="dim"))
            if chain.get("narrative"):
                _line(Text(f"      {chain['narrative']}", style="default"))
            if chain.get("fix"):
                _line(Text.assemble(("      break it: ", "dim"), (chain["fix"], "green")))

    if findings:
        console.print()
        _line(Text("AI analysis", style="bold cyan"))
        for finding in findings:
            severity = str(finding.get("severity", "")).upper()
            confidence = str(finding.get("confidence", "")).lower()
            location = f" (line {finding['line']})" if finding.get("line") else ""
            _line(
                Text.assemble(
                    ("  - ", "cyan"),
                    (f"[{severity}] ", "default"),
                    (finding.get("title", ""), "bold"),
                    (location, "dim"),
                    (f"  {confidence} confidence", _CONFIDENCE_STYLES.get(confidence, "dim")),
                )
            )
            if finding.get("why_it_matters"):
                _line(Text(f"      {finding['why_it_matters']}", style="default"))
            if finding.get("fix"):
                _line(Text.assemble(("      fix: ", "dim"), (finding["fix"], "green")))


def fix_diff(diff_text: str, applied, skipped, dry_run: bool = False,
             backup_path: Optional[str] = None,
             before: Optional[int] = None, after: Optional[int] = None) -> None:
    """Render what --fix changed, or would change.

    The diff comes first: a tool editing someone's file should show the edit
    before summarizing it.
    """
    if is_quiet():
        return

    console = get_console()

    if diff_text:
        console.print()
        for line in diff_text.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                style = "bold"
            elif line.startswith("+"):
                style = "green"
            elif line.startswith("-"):
                style = "red"
            elif line.startswith("@@"):
                style = "cyan"
            else:
                style = "dim"
            _line(Text(line, style=style))

    if applied:
        console.print()
        verb = "Would apply" if dry_run else "Applied"
        _line(Text(f"{verb} {len(applied)} change(s)", style="bold cyan"))
        for change in applied:
            _line(
                Text.assemble(
                    ("  - ", "cyan"),
                    (change.get("description", ""), "default"),
                    (f"  [{change.get('rule')}]", "dim"),
                )
            )

    if skipped:
        console.print()
        _line(Text(f"Needs review ({len(skipped)})", style="bold yellow"))
        for change in skipped[:6]:
            _line(
                Text.assemble(
                    ("  - ", "yellow"),
                    (change.get("instruction", ""), "default"),
                )
            )
            if change.get("reason"):
                _line(Text(f"      {change['reason']}", style="dim"))
        if len(skipped) > 6:
            _line(Text(f"  ... and {len(skipped) - 6} more", style="dim"))

    console.print()
    if dry_run:
        _line(Text("Dry run: no files were changed. Re-run without --dry-run to apply.",
                   style="bold"))
        return

    if backup_path:
        _line(Text(f"Original saved to {backup_path}", style="dim"))

    if before is not None and after is not None:
        removed = before - after
        if removed > 0:
            _line(Text(
                f"Dockerfile findings: {before} -> {after} ({removed} resolved)",
                style="bold green",
            ))
        elif removed == 0:
            _line(Text(
                f"Dockerfile findings: {before} -> {after} (no change - the edits "
                f"did not resolve a reported finding)",
                style="yellow",
            ))
        else:
            _line(Text(
                f"Dockerfile findings: {before} -> {after} (went up; review the "
                f"diff above)",
                style="bold red",
            ))
    _line(Text("Review the diff and run your build before committing.", style="dim"))


def coverage(notes: Iterable[str], gaps: Iterable[str] = ()) -> None:
    """Render what the scan could not determine, and what it never examines.

    Gaps come first and are styled as warnings: they mean results may be
    incomplete. Notes are the tool's standing limits, not failures.
    """
    gaps = [g for g in gaps if g]
    notes = [n for n in notes if n]
    if is_quiet() or (not gaps and not notes):
        return

    console = get_console()
    console.print()
    _line(Text("Coverage", style="bold cyan"))
    for gap in gaps:
        _line(Text.assemble(("  ! ", "yellow"), (gap, "yellow")))
    for note in notes:
        _line(Text.assemble(("  . ", "dim"), (note, "dim")))


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
