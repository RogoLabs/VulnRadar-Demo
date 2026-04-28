"""CVE parsing and matching logic.

Pure functions for extracting structured data from CVE List V5 JSON,
CVSS scoring, description selection, and watchlist matching.
No I/O or network calls — all inputs are in-memory data structures.
"""

import re
from typing import Any


def norm(s: str) -> str:
    """Normalize a string for case-insensitive comparison.

    Collapses whitespace, strips, and lowercases.

    Args:
        s: Input string (may be None).

    Returns:
        Normalized lowercase string.
    """
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def pick_best_description(containers_cna: dict[str, Any]) -> str:
    """Select the best English description from CNA container.

    Prefers English (``en``, ``en-US``, etc.), falls back to the first
    description with a value.

    Args:
        containers_cna: The ``containers.cna`` dict from a CVE V5 record.

    Returns:
        Description string, or empty string if none found.
    """
    descs = containers_cna.get("descriptions") or []
    if isinstance(descs, list):
        for d in descs:
            if not isinstance(d, dict):
                continue
            if (d.get("lang") or "").lower().startswith("en") and d.get("value"):
                return str(d.get("value"))
        for d in descs:
            if isinstance(d, dict) and d.get("value"):
                return str(d.get("value"))
    return ""


def extract_cvss(containers_cna: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Extract the best available CVSS score from CNA metrics.

    Tries CVSS v3.1 → v3.0 → v4.0 → v2.0 in order.

    Args:
        containers_cna: The ``containers.cna`` dict from a CVE V5 record.

    Returns:
        Tuple of (base_score, base_severity, vector_string).
        All None if no CVSS data found.
    """
    metrics = containers_cna.get("metrics") or []
    if not isinstance(metrics, list):
        return None, None, None

    def _from_metric(metric: dict[str, Any]) -> tuple[float, str | None, str | None] | None:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            cvss = metric.get(key)
            if isinstance(cvss, dict):
                score = cvss.get("baseScore")
                sev = cvss.get("baseSeverity")
                vec = cvss.get("vectorString")
                if score is not None:
                    try:
                        return (
                            float(score),
                            str(sev) if sev is not None else None,
                            str(vec) if vec is not None else None,
                        )
                    except Exception:
                        continue
        return None

    for m in metrics:
        if isinstance(m, dict):
            parsed = _from_metric(m)
            if parsed:
                return parsed
    return None, None, None


def affected_vendor_products(containers_cna: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract affected vendor/product pairs from CNA container.

    Args:
        containers_cna: The ``containers.cna`` dict from a CVE V5 record.

    Returns:
        List of dicts with ``vendor``, ``product``, and ``versions`` keys.
    """
    affected = containers_cna.get("affected") or []
    results: list[dict[str, Any]] = []
    if not isinstance(affected, list):
        return results

    for a in affected:
        if not isinstance(a, dict):
            continue
        vendor = norm(str(a.get("vendor") or ""))
        product = norm(str(a.get("product") or ""))
        versions = a.get("versions")
        results.append(
            {
                "vendor": vendor,
                "product": product,
                "versions": versions if isinstance(versions, list) else None,
            }
        )
    return results


def matches_watchlist(vendor: str, product: str, wl_vendors: set[str], wl_products: set[str]) -> bool:
    """Check whether a vendor/product pair matches the watchlist.

    Uses case-insensitive substring matching in both directions.

    Args:
        vendor: Vendor name from the CVE record.
        product: Product name from the CVE record.
        wl_vendors: Set of normalized watchlist vendor strings.
        wl_products: Set of normalized watchlist product strings.

    Returns:
        True if a match is found.
    """
    v = norm(vendor)
    p = norm(product)

    for wv in wl_vendors:
        if not wv:
            continue
        if v == wv or (wv in v) or (v in wv):
            return True
    for wp in wl_products:
        if not wp:
            continue
        if p == wp or (wp in p) or (p in wp):
            return True
    return False


def parse_cve_json_data(data: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a raw CVE V5 JSON dict into a normalized record.

    Args:
        data: Raw dict loaded from a CVE JSON file.

    Returns:
        Normalized dict with ``cve_id``, ``description``, ``cvss_score``,
        ``cvss_severity``, ``cvss_vector``, and ``affected`` fields.
        Returns None if the record is invalid.
    """
    meta = data.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or data.get("cveId") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None

    containers = data.get("containers") or {}
    cna = (containers.get("cna") or {}) if isinstance(containers, dict) else {}

    description = pick_best_description(cna)
    cvss_score, cvss_severity, cvss_vector = extract_cvss(cna)
    affected = affected_vendor_products(cna)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "affected": affected,
    }


def cve_year_and_num(cve_id: str) -> tuple[int, int] | None:
    """Extract year and sequence number from a CVE ID.

    Args:
        cve_id: A string like ``CVE-2024-12345``.

    Returns:
        Tuple of (year, number) or None if invalid.
    """
    m = re.match(r"^CVE-(\d{4})-(\d+)$", (cve_id or "").strip(), flags=re.IGNORECASE)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def risk_bucket(item: dict[str, Any]) -> str:
    """Classify a radar item into a risk bucket.

    Args:
        item: A radar data item dict.

    Returns:
        One of ``CRITICAL``, ``KEV``, ``High EPSS``,
        ``Critical CVSS``, or ``Other``.
    """
    if bool(item.get("is_critical")):
        return "CRITICAL"
    if bool(item.get("active_threat")):
        return "KEV"
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    try:
        if epss is not None and float(epss) >= 0.7:
            return "High EPSS"
    except Exception:
        pass
    try:
        if cvss is not None and float(cvss) >= 9.0:
            return "Critical CVSS"
    except Exception:
        pass
    return "Other"


def risk_sort_key(item: dict[str, Any]) -> float:
    """Sort key for ordering radar items by risk.

    Higher numbers mean higher priority.
    PatchThis > KEV > EPSS > CVSS.

    Args:
        item: A radar data item dict.

    Returns:
        Numeric sort key.
    """
    critical = 1.0 if bool(item.get("is_critical")) else 0.0
    kev = 1.0 if bool(item.get("active_threat")) else 0.0
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    try:
        epss_v = float(epss) if epss is not None else 0.0
    except Exception:
        epss_v = 0.0
    try:
        cvss_v = float(cvss) if cvss is not None else 0.0
    except Exception:
        cvss_v = 0.0

    return critical * 1000.0 + kev * 900.0 + epss_v * 10.0 + cvss_v


def fuzzy_score(query: str, target: str) -> float:
    """Simple fuzzy matching score (higher = better match).

    Args:
        query: Search term.
        target: Candidate string to score against.

    Returns:
        Score between 0.0 and 1.0.
    """
    query = query.lower()
    target = target.lower()
    if query == target:
        return 1.0
    if query in target:
        return 0.8 + (len(query) / len(target)) * 0.2
    if target in query:
        return 0.6
    common = sum(1 for c in query if c in target)
    return common / max(len(query), len(target)) * 0.5
