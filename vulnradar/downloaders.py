"""HTTP download helpers for all VulnRadar data sources.

Each function fetches a single data source and returns parsed data.
All network I/O is isolated here — the rest of the package works
with in-memory data structures.
"""

import csv
import datetime as dt
import gzip
import io
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

GITHUB_LATEST_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
GITHUB_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=5"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CURRENT_CSV_GZ_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
PATCHTHIS_CSV_URL = "https://raw.githubusercontent.com/RogoLabs/patchthisapp/main/web/data.csv"
NVD_FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

DEFAULT_HTTP_TIMEOUT = (10, 120)  # (connect, read)


def requests_session() -> requests.Session:
    """Create a configured requests session with auth and headers.

    Automatically picks up ``GITHUB_TOKEN`` or ``GH_TOKEN`` from env.

    Returns:
        Configured ``requests.Session``.
    """
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "VulnRadar/0.2 (+https://github.com/)",
            "Accept": "application/json",
        }
    )
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=1, max=30))
def get_json(session: requests.Session, url: str) -> Any:
    """Fetch JSON from a URL with retry logic.

    Args:
        session: Requests session.
        url: URL to fetch.

    Returns:
        Parsed JSON data.
    """
    r = session.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=1, max=30))
def download_bytes(session: requests.Session, url: str) -> bytes:
    """Download raw bytes from a URL with retry logic.

    Args:
        session: Requests session.
        url: URL to fetch.

    Returns:
        Raw bytes of the response body.
    """
    with session.get(url, stream=True, timeout=DEFAULT_HTTP_TIMEOUT) as r:
        r.raise_for_status()
        buf = io.BytesIO()
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                buf.write(chunk)
        return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# CVE List V5
# ─────────────────────────────────────────────────────────────────────────────


def _find_midnight_zip_in_assets(assets: list[dict[str, Any]]) -> str | None:
    """Return the midnight-ZIP download URL from a release asset list, or None."""
    for asset in assets:
        name = asset.get("name") or ""
        if re.search(r"_all_CVEs_at_midnight\.zip(\.zip)?$", name):
            url = asset.get("browser_download_url")
            if url:
                return url
    for asset in assets:
        name = asset.get("name") or ""
        if "all_CVEs_at_midnight" in name:
            url = asset.get("browser_download_url")
            if url:
                return url
    return None


def get_latest_cvelist_zip_url(session: requests.Session) -> str:
    """Resolve the download URL for the latest CVE List V5 bulk export.

    The upstream CVEProject/cvelistV5 repository publishes hourly delta
    releases *and* an ``at_end_of_day`` release that does **not** contain
    the midnight bulk ZIP.  When the GitHub ``/releases/latest`` endpoint
    happens to return one of those releases, this function falls back to
    scanning the most recent releases until it finds an asset whose name
    matches ``*_all_CVEs_at_midnight.zip``.

    Args:
        session: Requests session.

    Returns:
        Browser download URL for the ZIP asset.

    Raises:
        RuntimeError: If no suitable asset is found in the latest releases.
    """
    # Fast path: check the single "latest" release first.
    data = get_json(session, GITHUB_LATEST_RELEASE_API)
    url = _find_midnight_zip_in_assets(data.get("assets") or [])
    if url:
        return url

    # Fallback: scan the most recent releases (covers at_end_of_day and
    # transient asset-upload race conditions).
    releases = get_json(session, GITHUB_RELEASES_API)
    for release in releases:
        url = _find_midnight_zip_in_assets(release.get("assets") or [])
        if url:
            return url

    raise RuntimeError("Could not find *_all_CVEs_at_midnight.zip asset in latest releases")


def download_and_extract_zip(zip_bytes: bytes) -> Path:
    """Extract a CVE List ZIP to a temporary directory.

    Handles nested ``cves.zip`` archives from upstream packaging
    variations.

    Args:
        zip_bytes: Raw bytes of the ZIP file.

    Returns:
        Path to the temporary directory with extracted files.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnradar_cvelist_"))
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(tmp_dir)

        nested = tmp_dir / "cves.zip"
        if nested.exists() and nested.is_file():
            with zipfile.ZipFile(nested) as nested_zf:
                nested_zf.extractall(tmp_dir)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return tmp_dir


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV
# ─────────────────────────────────────────────────────────────────────────────


def download_cisa_kev(session: requests.Session) -> dict[str, dict[str, Any]]:
    """Download the CISA Known Exploited Vulnerabilities catalog.

    Args:
        session: Requests session.

    Returns:
        Dict mapping CVE ID to KEV entry dict.
    """
    data = get_json(session, CISA_KEV_URL)
    vulns = data.get("vulnerabilities") or []
    out: dict[str, dict[str, Any]] = {}
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve = (v.get("cveID") or "").strip().upper()
            if cve.startswith("CVE-"):
                out[cve] = v
    return out


# ─────────────────────────────────────────────────────────────────────────────
# EPSS
# ─────────────────────────────────────────────────────────────────────────────


def download_epss(session: requests.Session) -> dict[str, float]:
    """Download FIRST.org EPSS daily probability scores.

    Args:
        session: Requests session.

    Returns:
        Dict mapping CVE ID to EPSS probability (0.0–1.0).
    """
    raw = download_bytes(session, EPSS_CURRENT_CSV_GZ_URL)
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
        text = gz.read().decode("utf-8", errors="replace")

    lines = []
    for line in text.splitlines():
        if not line:
            continue
        if line.lstrip().startswith("#"):
            continue
        lines.append(line)
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    out: dict[str, float] = {}
    for row in reader:
        cve = (row.get("cve") or "").strip().upper()
        epss = row.get("epss")
        if not cve.startswith("CVE-") or epss is None:
            continue
        try:
            out[cve] = float(epss)
        except Exception:
            continue
    return out


# ─────────────────────────────────────────────────────────────────────────────
# PatchThis
# ─────────────────────────────────────────────────────────────────────────────


def download_patchthis(session: requests.Session) -> set[str]:
    """Download PatchThis intelligence CSV as a set of CVE IDs.

    Args:
        session: Requests session.

    Returns:
        Set of CVE IDs with known exploit PoCs.
    """
    raw = download_bytes(session, PATCHTHIS_CSV_URL)
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return set()

    cve_col: str | None = None
    for col in reader.fieldnames:
        name = str(col).strip().lower()
        if name in {"cveid", "cve_id", "cve"}:
            cve_col = col
            break
    if cve_col is None:
        raise RuntimeError("PatchThis CSV is missing a CVE identifier column (expected cveID)")

    out: set[str] = set()
    for row in reader:
        cve = (row.get(cve_col) or "").strip().upper()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# NVD Feeds
# ─────────────────────────────────────────────────────────────────────────────


def download_nvd_feeds(
    session: requests.Session,
    years: list[int],
    cache_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Download NVD JSON 2.0 data feeds for the specified years.

    If ``cache_dir`` is provided, feeds are cached and reused when
    the cache is less than 24 hours old.

    Args:
        session: Requests session.
        years: List of CVE years to download.
        cache_dir: Optional directory for caching feeds.

    Returns:
        Dict mapping CVE ID to NVD enrichment data (CVSS, CWE, CPE).
    """
    nvd_data: dict[str, dict[str, Any]] = {}
    years_list = sorted(set(years))

    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    for year in years_list:
        url = f"{NVD_FEED_BASE_URL}/nvdcve-2.0-{year}.json.gz"
        cache_file = cache_dir / f"nvdcve-2.0-{year}.json.gz" if cache_dir else None
        raw = None

        # Check cache first
        if cache_file and cache_file.exists():
            cache_age = dt.datetime.now().timestamp() - cache_file.stat().st_mtime
            if cache_age < 86400:
                print(f"  Using cached NVD feed for {year} (age: {cache_age / 3600:.1f}h)")
                raw = cache_file.read_bytes()

        if raw is None:
            print(f"  Downloading NVD feed for {year}...")
            try:
                resp = session.get(url, timeout=(10, 300), headers={"Accept": "*/*"})
                resp.raise_for_status()
                raw = resp.content
                if cache_file:
                    cache_file.write_bytes(raw)
                    print(f"    Cached NVD feed for {year}")
            except Exception as e:
                print(f"    Warning: Failed to download NVD feed for {year}: {e}")
                continue

        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
                feed = json.loads(gz.read().decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"    Warning: Failed to parse NVD feed for {year}: {e}")
            continue

        vulnerabilities = feed.get("vulnerabilities") or []
        count = 0
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = (cve_data.get("id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            if cve_data.get("vulnStatus") == "Rejected":
                continue

            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])

            def get_primary_cvss(metric_list: list) -> dict:
                for m in metric_list:
                    if m.get("type") == "Primary":
                        return m.get("cvssData", {})
                return metric_list[0].get("cvssData", {}) if metric_list else {}

            cvss3_data = get_primary_cvss(cvss_v31) or get_primary_cvss(cvss_v30)
            cvss2_data = get_primary_cvss(cvss_v2)

            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-") and val != "CWE-noinfo":
                        cwe_ids.append(val)

            cpe_count = 0
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    cpe_count += len(node.get("cpeMatch", []))

            ref_count = len(cve_data.get("references", []))

            nvd_data[cve_id] = {
                "cvss_v3_score": cvss3_data.get("baseScore"),
                "cvss_v3_severity": cvss3_data.get("baseSeverity"),
                "cvss_v3_vector": cvss3_data.get("vectorString"),
                "cvss_v2_score": cvss2_data.get("baseScore"),
                "cvss_v2_severity": cvss2_data.get("baseSeverity"),
                "cvss_v2_vector": cvss2_data.get("vectorString"),
                "cwe_ids": list(dict.fromkeys(cwe_ids))[:10] if cwe_ids else None,
                "cpe_count": cpe_count,
                "reference_count": ref_count,
            }
            count += 1

        print(f"    Loaded {count} CVEs from NVD {year} feed")

    return nvd_data
