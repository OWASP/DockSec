"""EPSS exploitation likelihood, and the priority tier derived from it.

A severity label answers "how bad would this be if exploited". It does not
answer "is anyone actually exploiting it", which is what decides what to fix
first. EPSS (the FIRST Exploit Prediction Scoring System) publishes a daily
probability that a given CVE will be exploited in the next 30 days, plus the
percentile that places it against every other scored CVE.

Combining the two gives four tiers that rank a finding list far better than
severity alone:

    CRITICAL/HIGH + top 10% EPSS -> Fix Now
    CRITICAL/HIGH                -> Fix Soon
    MEDIUM/LOW    + top 10% EPSS -> Monitor
    MEDIUM/LOW                   -> Low Priority

Privacy note. This is the only outbound request DockSec makes that is not the
AI pass, so it is deliberately narrow: **only CVE IDs are sent** - no image
names, no file contents, no paths, no identifiers of any kind. Results are
cached, ``--offline`` and ``--no-epss`` disable it, and any failure degrades
silently to severity-only ranking rather than failing the scan.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional

from docksec.enums import Severity
from docksec.utils import get_custom_logger

logger = get_custom_logger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"

# The API's default page size is 100; request the maximum explicitly and batch
# below it so a large finding set never silently truncates.
EPSS_BATCH_SIZE = 100

# A finding at or above this percentile is in the top 10% of all scored CVEs by
# exploitation likelihood.
HIGH_EXPLOITATION_PERCENTILE = 0.90

EPSS_TIMEOUT_SECONDS = 15

# EPSS is republished daily, so a day-old score is still current.
CACHE_TTL_SECONDS = 24 * 60 * 60

FIX_NOW = "fix_now"
FIX_SOON = "fix_soon"
MONITOR = "monitor"
LOW_PRIORITY = "low_priority"

PRIORITY_LABELS = {
    FIX_NOW: "Fix Now",
    FIX_SOON: "Fix Soon",
    MONITOR: "Monitor",
    LOW_PRIORITY: "Low Priority",
}

PRIORITY_DESCRIPTIONS = {
    FIX_NOW: "Critical or high severity, and in the top 10% of CVEs by exploitation likelihood",
    FIX_SOON: "Critical or high severity, but exploitation is less common",
    MONITOR: "Lower severity, but actively exploited - watch it",
    LOW_PRIORITY: "Lower severity and exploitation is uncommon",
}

# Most severe first, for sorting and display.
PRIORITY_ORDER = [FIX_NOW, FIX_SOON, MONITOR, LOW_PRIORITY]


def priority_rank(priority: Optional[str]) -> int:
    """Sort key: higher is more urgent. Unscored findings sort last."""
    if priority not in PRIORITY_ORDER:
        return -1
    return len(PRIORITY_ORDER) - PRIORITY_ORDER.index(priority)


def compute_priority(severity: str, percentile: Optional[float]) -> Optional[str]:
    """Combine a severity label with an EPSS percentile into a tier.

    Returns None when there is no EPSS data for the finding: a missing score is
    not evidence of low risk, so the finding is left untiered rather than
    assigned an optimistic one.
    """
    if percentile is None:
        return None

    level = str(severity or "").strip().upper()
    high_impact = level in (Severity.CRITICAL.value, Severity.HIGH.value)
    high_exploitation = percentile >= HIGH_EXPLOITATION_PERCENTILE

    if high_impact and high_exploitation:
        return FIX_NOW
    if high_impact:
        return FIX_SOON
    if high_exploitation:
        return MONITOR
    return LOW_PRIORITY


def _cache_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, ".docksec_epss_cache.json")


def _load_cache(cache_dir: str) -> Dict[str, Dict]:
    path = _cache_path(cache_dir)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}

    now = time.time()
    return {
        cve: entry
        for cve, entry in data.items()
        if isinstance(entry, dict) and now - entry.get("fetched_at", 0) < CACHE_TTL_SECONDS
    }


def _save_cache(cache_dir: str, cache: Dict[str, Dict]) -> None:
    try:
        os.makedirs(cache_dir, exist_ok=True)
        with open(_cache_path(cache_dir), "w", encoding="utf-8") as handle:
            json.dump(cache, handle)
    except OSError as exc:
        # A cache write failure must never fail a scan.
        logger.debug(f"Could not write EPSS cache: {exc}")


def _fetch_batch(cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
    """Fetch one batch of scores. Returns {} on any failure.

    Only the CVE IDs are transmitted.
    """
    query = urllib.parse.urlencode(
        {"cve": ",".join(cve_ids), "limit": str(EPSS_BATCH_SIZE)}
    )
    url = f"{EPSS_API_URL}?{query}"

    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "DockSec (https://owasp.org/DockSec/)"}
        )
        with urllib.request.urlopen(request, timeout=EPSS_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        logger.debug(f"EPSS lookup failed: {exc}")
        return {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.debug(f"EPSS response was not valid JSON: {exc}")
        return {}

    scores: Dict[str, Dict[str, float]] = {}
    for record in (payload or {}).get("data") or []:
        cve = str(record.get("cve") or "").strip().upper()
        if not cve:
            continue
        try:
            # The API returns these as strings.
            scores[cve] = {
                "epss": float(record["epss"]),
                "percentile": float(record["percentile"]),
            }
        except (KeyError, TypeError, ValueError):
            continue
    return scores


def fetch_scores(
    cve_ids: Iterable[str], cache_dir: Optional[str] = None
) -> Dict[str, Dict[str, float]]:
    """Look up EPSS scores for a set of CVE IDs.

    Cached results are reused; only the remainder is requested, in batches. A
    CVE the API does not know is simply absent from the result - the response
    is not a 1:1 mapping of the request, so callers must not assume one.
    """
    wanted = sorted({
        str(cve).strip().upper()
        for cve in cve_ids
        if str(cve).strip().upper().startswith("CVE-")
    })
    if not wanted:
        return {}

    cache = _load_cache(cache_dir) if cache_dir else {}
    scores = {
        cve: {"epss": cache[cve]["epss"], "percentile": cache[cve]["percentile"]}
        for cve in wanted
        if cve in cache
    }

    missing = [cve for cve in wanted if cve not in scores]
    if not missing:
        return scores

    fetched: Dict[str, Dict[str, float]] = {}
    for start in range(0, len(missing), EPSS_BATCH_SIZE):
        fetched.update(_fetch_batch(missing[start:start + EPSS_BATCH_SIZE]))

    if fetched and cache_dir:
        now = time.time()
        for cve, score in fetched.items():
            cache[cve] = {**score, "fetched_at": now}
        _save_cache(cache_dir, cache)

    scores.update(fetched)
    return scores


def annotate(
    findings: List[Dict], cache_dir: Optional[str] = None, enabled: bool = True
) -> int:
    """Attach EPSS scores and a priority tier to findings, in place.

    Returns how many findings were scored. When disabled, or when the lookup
    fails, findings are left without EPSS fields and the caller falls back to
    severity-only ordering.
    """
    if not enabled or not findings:
        return 0

    cve_ids = [
        finding.get("VulnerabilityID")
        for finding in findings
        if str(finding.get("VulnerabilityID") or "").upper().startswith("CVE-")
    ]
    if not cve_ids:
        return 0

    scores = fetch_scores(cve_ids, cache_dir=cache_dir)
    if not scores:
        return 0

    annotated = 0
    for finding in findings:
        cve = str(finding.get("VulnerabilityID") or "").strip().upper()
        score = scores.get(cve)
        if not score:
            continue
        finding["EPSS"] = score["epss"]
        finding["EPSSPercentile"] = score["percentile"]
        priority = compute_priority(finding.get("Severity"), score["percentile"])
        if priority:
            finding["Priority"] = priority
            annotated += 1

    return annotated


def format_epss(finding: Dict) -> str:
    """Render a finding's EPSS score for display, or '' when unscored."""
    epss = finding.get("EPSS")
    percentile = finding.get("EPSSPercentile")
    if epss is None or percentile is None:
        return ""
    return (
        f"{epss * 100:.1f}% exploitation probability "
        f"(top {max(0.1, (1 - percentile) * 100):.1f}% of all CVEs)"
    )


def counts_by_priority(findings: List[Dict]) -> Dict[str, int]:
    """Count findings per priority tier, most urgent first."""
    counts = {tier: 0 for tier in PRIORITY_ORDER}
    for finding in findings:
        priority = finding.get("Priority")
        if priority in counts:
            counts[priority] += 1
    return counts
