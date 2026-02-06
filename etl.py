#!/usr/bin/env python3

"""VulnRadar ETL

Downloads and processes CVEs from the CVE List V5 bulk export (CVEProject/cvelistV5),
then enriches them with:

- CISA Known Exploited Vulnerabilities (KEV) catalog (flags `active_threat`)
- FIRST.org EPSS daily probabilities (adds `probability_score`)
- PatchThis intelligence feed (flags `in_patchthis` and sets `priority_label`)

Filtering:
- Loads `watchlist.json` (vendors/products)
- Treats a CVE as relevant if any `containers.cna.affected` vendor/product matches the watchlist
- Always includes CISA KEVs, even if not in the watchlist

Performance defaults:
- Scans the last 5 years of CVEs (inclusive of the current year) to avoid a full historical sweep.
    You can override this via `--min-year` / `--max-year`.
"""

import argparse
import csv
import datetime as dt
import gzip
import io
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import requests
import yaml
from tenacity import retry, stop_after_attempt, wait_exponential

GITHUB_LATEST_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST.org currently links EPSS CSV downloads from epss.empiricalsecurity.com
EPSS_CURRENT_CSV_GZ_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
PATCHTHIS_CSV_URL = "https://raw.githubusercontent.com/RogoLabs/patchthisapp/main/web/data.csv"
# NVD JSON 2.0 Data Feeds (yearly files, no API key required)
NVD_FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

DEFAULT_HTTP_TIMEOUT = (10, 120)  # (connect, read)


def default_min_year() -> int:
    """Inclusive lower bound year for the default scan window.

    "Last 5 years" means the current year and the previous four years.
    Example (current year 2026): 2022..2026.
    """

    return dt.datetime.now().year - 4


@dataclass(frozen=True)
class Watchlist:
    vendors: Set[str]
    products: Set[str]


def _now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def load_watchlist(path: Path) -> Watchlist:
    """Load watchlist from YAML or JSON file.

    Supports both .yaml/.yml and .json files. YAML is preferred for
    better readability and comment support.
    """
    # Auto-detect YAML vs JSON based on extension or try YAML first for .yaml/.yml
    suffix = path.suffix.lower()

    with path.open("r", encoding="utf-8") as f:
        content = f.read()

    if suffix in (".yaml", ".yml"):
        raw = yaml.safe_load(content) or {}
    elif suffix == ".json":
        raw = json.loads(content)
        # Emit deprecation notice for JSON watchlists
        print("Note: JSON watchlists are deprecated. Consider migrating to watchlist.yaml")
        print("      YAML supports comments for documenting your choices.")
    else:
        # Try YAML first, fall back to JSON
        try:
            raw = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            raw = json.loads(content)

    vendors = {_norm(v) for v in (raw.get("vendors") or []) if isinstance(v, str) and v.strip()}
    products = {_norm(p) for p in (raw.get("products") or []) if isinstance(p, str) and p.strip()}
    return Watchlist(vendors=vendors, products=products)


def _requests_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "VulnRadar/0.1 (+https://github.com/)",
            "Accept": "application/json",
        }
    )
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=1, max=30))
def _get_json(session: requests.Session, url: str) -> Any:
    r = session.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=1, max=30))
def _download_bytes(session: requests.Session, url: str) -> bytes:
    with session.get(url, stream=True, timeout=DEFAULT_HTTP_TIMEOUT) as r:
        r.raise_for_status()
        buf = io.BytesIO()
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                buf.write(chunk)
        return buf.getvalue()


def get_latest_cvelist_zip_url(session: requests.Session) -> str:
    data = _get_json(session, GITHUB_LATEST_RELEASE_API)
    assets = data.get("assets") or []
    for asset in assets:
        name = asset.get("name") or ""
        # Upstream naming has varied (e.g., `...zip.zip`). Prefer the full midnight bulk export.
        if re.search(r"_all_CVEs_at_midnight\.zip(\.zip)?$", name):
            url = asset.get("browser_download_url")
            if url:
                return url
    # Fallback: any asset containing the bulk-export marker.
    for asset in assets:
        name = asset.get("name") or ""
        if "all_CVEs_at_midnight" in name:
            url = asset.get("browser_download_url")
            if url:
                return url
    raise RuntimeError("Could not find *_all_CVEs_at_midnight.zip asset in latest release")


def download_and_extract_zip_to_temp(zip_bytes: bytes) -> Path:
    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnradar_cvelist_"))
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(tmp_dir)

        # Upstream packaging can include a nested `cves.zip` (outer release asset -> inner archive).
        nested = tmp_dir / "cves.zip"
        if nested.exists() and nested.is_file():
            with zipfile.ZipFile(nested) as nested_zf:
                nested_zf.extractall(tmp_dir)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return tmp_dir


def _find_cves_root(extracted_dir: Path) -> Path:
    # Expected: .../cvelistV5-main/cves/.... but we handle variations.
    candidates = []
    for p in extracted_dir.rglob("cves"):
        if p.is_dir():
            candidates.append(p)
    if not candidates:
        return extracted_dir
    # Choose the shortest path (closest to root) to reduce chance of nested duplicates.
    return sorted(candidates, key=lambda x: len(str(x)))[0]


def _years_to_process(min_year: int, max_year: Optional[int]) -> List[int]:
    if max_year is None:
        max_year = dt.datetime.now().year
    if max_year < min_year:
        return []
    return list(range(min_year, max_year + 1))


def _iter_cve_json_paths(cves_root: Path, years: Sequence[int]) -> Iterator[Path]:
    # Fast path: traverse by year directories if present.
    for year in years:
        year_dir = cves_root / str(year)
        if year_dir.exists() and year_dir.is_dir():
            yield from year_dir.rglob("CVE-*.json")


def _cve_year_and_num(cve_id: str) -> Optional[Tuple[int, int]]:
    m = re.match(r"^CVE-(\d{4})-(\d+)$", (cve_id or "").strip(), flags=re.IGNORECASE)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _guess_cve_path(cves_root: Path, cve_id: str) -> Optional[Path]:
    parsed = _cve_year_and_num(cve_id)
    if not parsed:
        return None
    year, num = parsed
    group = f"{num // 1000}xxx"
    guess = cves_root / str(year) / group / f"{cve_id.upper()}.json"
    if guess.exists():
        return guess
    # Some trees may use slightly different grouping; do a constrained search under the year.
    year_dir = cves_root / str(year)
    if year_dir.exists():
        match = next(iter(year_dir.rglob(f"{cve_id.upper()}.json")), None)
        if match:
            return match
    return None


def _pick_best_description(containers_cna: Dict[str, Any]) -> str:
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


def _extract_cvss(containers_cna: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    metrics = containers_cna.get("metrics") or []
    if not isinstance(metrics, list):
        return None, None, None

    def _from_metric(metric: Dict[str, Any]) -> Optional[Tuple[float, str, str]]:
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
                            (str(sev) if sev is not None else None),
                            (str(vec) if vec is not None else None),
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


def _affected_vendor_products(containers_cna: Dict[str, Any]) -> List[Dict[str, Any]]:
    affected = containers_cna.get("affected") or []
    results: List[Dict[str, Any]] = []
    if not isinstance(affected, list):
        return results

    for a in affected:
        if not isinstance(a, dict):
            continue
        vendor = _norm(str(a.get("vendor") or ""))
        product = _norm(str(a.get("product") or ""))
        versions = a.get("versions")
        results.append(
            {
                "vendor": vendor,
                "product": product,
                "versions": versions if isinstance(versions, list) else None,
            }
        )
    return results


def _matches_watchlist(vendor: str, product: str, watchlist: Watchlist) -> bool:
    v = _norm(vendor)
    p = _norm(product)

    for wv in watchlist.vendors:
        if not wv:
            continue
        if v == wv or (wv in v) or (v in wv):
            return True
    for wp in watchlist.products:
        if not wp:
            continue
        if p == wp or (wp in p) or (p in wp):
            return True
    return False


def download_cisa_kev(session: requests.Session) -> Dict[str, Dict[str, Any]]:
    data = _get_json(session, CISA_KEV_URL)
    vulns = data.get("vulnerabilities") or []
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve = (v.get("cveID") or "").strip().upper()
            if cve.startswith("CVE-"):
                out[cve] = v
    return out


def download_epss(session: requests.Session) -> Dict[str, float]:
    raw = _download_bytes(session, EPSS_CURRENT_CSV_GZ_URL)
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
        text = gz.read().decode("utf-8", errors="replace")

    # EPSS daily files may include leading comment lines starting with '#'.
    # Remove them so csv.DictReader sees the actual header row.
    lines = []
    for line in text.splitlines():
        if not line:
            continue
        if line.lstrip().startswith("#"):
            continue
        lines.append(line)
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    out: Dict[str, float] = {}
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


def download_patchthis(session: requests.Session) -> Set[str]:
    """Download the PatchThis intelligence CSV as a set of CVE IDs.

    The upstream CSV should contain a CVE identifier column, commonly `cveID`.
    This function returns a normalized set of CVE IDs (uppercased, stripped).
    """

    raw = _download_bytes(session, PATCHTHIS_CSV_URL)
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return set()

    # Identify the CVE column (case-insensitive).
    cve_col: Optional[str] = None
    for col in reader.fieldnames:
        name = str(col).strip().lower()
        if name in {"cveid", "cve_id", "cve"}:
            cve_col = col
            break
    if cve_col is None:
        raise RuntimeError("PatchThis CSV is missing a CVE identifier column (expected cveID)")

    out: Set[str] = set()
    for row in reader:
        cve = (row.get(cve_col) or "").strip().upper()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


def download_nvd_feeds(
    session: requests.Session,
    years: Iterable[int],
    cache_dir: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Download NVD JSON 2.0 data feeds for specified years.

    NVD feeds are split by CVE ID year (not publication year), matching
    how CVE List V5 is organized. E.g., CVE-2025-* entries are in the
    2025 feed even if published in 2026.
    
    If cache_dir is provided, feeds will be cached there and reused if
    the cached file is less than 24 hours old.

    Returns a dict mapping CVE ID to NVD-specific data:
    - cvss_v3_score, cvss_v3_severity, cvss_v3_vector
    - cvss_v2_score, cvss_v2_severity, cvss_v2_vector
    - cwe_ids: list of CWE identifiers
    - cpe_count: number of CPE matches
    - reference_count: number of references

    NVD feeds are gzipped JSON files, ~15-20MB compressed per year.
    This provides richer CVSS data than the CVE List V5 bulk export.
    """

    nvd_data: Dict[str, Dict[str, Any]] = {}
    years_list = sorted(set(years))
    
    # Set up cache directory if provided
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    for year in years_list:
        url = f"{NVD_FEED_BASE_URL}/nvdcve-2.0-{year}.json.gz"
        cache_file = cache_dir / f"nvdcve-2.0-{year}.json.gz" if cache_dir else None
        raw = None
        
        # Check cache first (use if less than 24 hours old)
        if cache_file and cache_file.exists():
            cache_age = dt.datetime.now().timestamp() - cache_file.stat().st_mtime
            if cache_age < 86400:  # 24 hours in seconds
                print(f"  Using cached NVD feed for {year} (age: {cache_age/3600:.1f}h)")
                raw = cache_file.read_bytes()
        
        # Download if not cached or cache expired
        if raw is None:
            print(f"  Downloading NVD feed for {year}...")
            try:
                # NVD feeds need Accept: */* (not application/json)
                resp = session.get(
                    url,
                    timeout=(10, 300),  # Longer read timeout for large files
                    headers={"Accept": "*/*"},
                )
                resp.raise_for_status()
                raw = resp.content
                
                # Save to cache
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

        # NVD 2.0 schema: { vulnerabilities: [ { cve: { id, metrics, weaknesses, ... } } ] }
        vulnerabilities = feed.get("vulnerabilities") or []
        count = 0
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = (cve_data.get("id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            # Skip rejected CVEs
            if cve_data.get("vulnStatus") == "Rejected":
                continue

            # Extract CVSS v3.x data (prefer v3.1 over v3.0)
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])

            # Get primary (NVD) score, fallback to first available
            def get_primary_cvss(metric_list: list) -> dict:
                for m in metric_list:
                    if m.get("type") == "Primary":
                        return m.get("cvssData", {})
                return metric_list[0].get("cvssData", {}) if metric_list else {}

            cvss3_data = get_primary_cvss(cvss_v31) or get_primary_cvss(cvss_v30)
            cvss2_data = get_primary_cvss(cvss_v2)

            # Extract CWE IDs from weaknesses
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-") and val != "CWE-noinfo":
                        cwe_ids.append(val)

            # Count CPE matches from configurations
            cpe_count = 0
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    cpe_count += len(node.get("cpeMatch", []))

            # Count references
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


def parse_cve_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    meta = data.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or data.get("cveId") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None

    containers = data.get("containers") or {}
    cna = (containers.get("cna") or {}) if isinstance(containers, dict) else {}

    description = _pick_best_description(cna)
    cvss_score, cvss_severity, cvss_vector = _extract_cvss(cna)
    affected = _affected_vendor_products(cna)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "affected": affected,
    }


def build_radar_data(
    extracted_dir: Path,
    watchlist: Watchlist,
    kev_by_cve: Dict[str, Dict[str, Any]],
    epss_by_cve: Dict[str, float],
    patchthis_cves: Set[str],
    nvd_by_cve: Dict[str, Dict[str, Any]],
    min_year: int,
    max_year: Optional[int],
    include_kev_outside_window: bool,
) -> List[Dict[str, Any]]:
    cves_root = _find_cves_root(extracted_dir)
    years = _years_to_process(min_year, max_year)

    paths: Set[Path] = set(_iter_cve_json_paths(cves_root, years))

    if include_kev_outside_window:
        # Optionally add KEV CVEs outside the selected year range without scanning everything.
        for cve_id in kev_by_cve.keys():
            parsed = _cve_year_and_num(cve_id)
            if not parsed:
                continue
            year, _ = parsed
            if year in years:
                continue
            p = _guess_cve_path(cves_root, cve_id)
            if p:
                paths.add(p)

    items: List[Dict[str, Any]] = []
    for p in sorted(paths):
        parsed = parse_cve_json(p)
        if not parsed:
            continue

        cve_id = parsed["cve_id"]
        affected = parsed.get("affected") or []
        watch_hit = False
        matched_terms: List[str] = []
        for a in affected:
            if not isinstance(a, dict):
                continue
            vendor = a.get("vendor") or ""
            product = a.get("product") or ""
            if _matches_watchlist(str(vendor), str(product), watchlist):
                watch_hit = True
                if vendor:
                    matched_terms.append(f"vendor:{vendor}")
                if product:
                    matched_terms.append(f"product:{product}")

        kev = kev_by_cve.get(cve_id)
        active_threat = kev is not None

        in_patchthis = cve_id in patchthis_cves
        in_watchlist = watch_hit
        is_critical = bool(in_patchthis and in_watchlist)

        if is_critical:
            priority_label = "CRITICAL (Active Exploit in Stack)"
        else:
            priority_label = ""

        # Include if watchlist hit OR KEV.
        if (not in_watchlist) and (not active_threat):
            continue

        record: Dict[str, Any] = {
            **parsed,
            "watchlist_hit": watch_hit,
            "in_watchlist": in_watchlist,
            "in_patchthis": in_patchthis,
            "is_critical": is_critical,
            "priority_label": priority_label,
            "matched_terms": sorted(set(matched_terms)) if watch_hit else [],
            "active_threat": active_threat,
            "probability_score": epss_by_cve.get(cve_id),
        }

        if kev:
            record["kev"] = {
                "cveID": kev.get("cveID"),
                "vendorProject": kev.get("vendorProject"),
                "product": kev.get("product"),
                "vulnerabilityName": kev.get("vulnerabilityName"),
                "dateAdded": kev.get("dateAdded"),
                "shortDescription": kev.get("shortDescription"),
                "requiredAction": kev.get("requiredAction"),
                "dueDate": kev.get("dueDate"),
                "knownRansomwareCampaignUse": kev.get("knownRansomwareCampaignUse"),
            }

        # Enrich with NVD data (better CVSS coverage, CWE, CPE info)
        nvd = nvd_by_cve.get(cve_id)
        if nvd:
            # Prefer NVD CVSS v3 if we don't have CVSS from CVE List V5
            if record.get("cvss_score") is None and nvd.get("cvss_v3_score"):
                record["cvss_score"] = nvd["cvss_v3_score"]
                record["cvss_severity"] = nvd.get("cvss_v3_severity")
                record["cvss_vector"] = nvd.get("cvss_v3_vector")
            # Add NVD-specific enrichment
            record["nvd"] = {
                "cvss_v3_score": nvd.get("cvss_v3_score"),
                "cvss_v3_severity": nvd.get("cvss_v3_severity"),
                "cvss_v2_score": nvd.get("cvss_v2_score"),
                "cvss_v2_severity": nvd.get("cvss_v2_severity"),
                "cwe_ids": nvd.get("cwe_ids"),
                "cpe_count": nvd.get("cpe_count"),
                "reference_count": nvd.get("reference_count"),
            }

        items.append(record)

    return items


def write_radar_data(path: Path, items: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": _now_utc_iso(),
        "count": len(items),
        "items": items,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    tmp.replace(path)


def risk_bucket(item: Dict[str, Any]) -> str:
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


def risk_sort_key(item: Dict[str, Any]) -> float:
    """Sort key: PatchThis > KEV > EPSS > CVSS.

    Higher numbers mean higher priority.
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


def write_markdown_report(path: Path, items: List[Dict[str, Any]], state_file: Optional[Path] = None) -> None:
    """Write a GitHub-renderable Markdown report.

    This is intended to make the output 100% viewable directly in GitHub,
    without requiring Streamlit.

    Args:
        path: Output path for the markdown report
        items: List of CVE items to report on
        state_file: Optional path to state.json for recent changes section
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    generated_at = _now_utc_iso()

    total = len(items)
    watch_hits = sum(1 for i in items if bool(i.get("watchlist_hit")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    critical_patch_watch = sum(1 for i in items if bool(i.get("in_patchthis")) and bool(i.get("watchlist_hit")))

    top = sorted(items, key=risk_sort_key, reverse=True)[:200]
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_top = sorted(critical_items, key=risk_sort_key, reverse=True)[:25]

    def _cve_link(cve_id: str) -> str:
        cve = (cve_id or "").strip().upper()
        return f"[{cve}](https://www.cve.org/CVERecord?id={cve})" if cve.startswith("CVE-") else cve

    def _short(s: str, n: int = 160) -> str:
        # Replace all whitespace (newlines, tabs, etc.) with single space, escape pipes
        s = " ".join((s or "").split()).replace("|", "\\|")
        return s if len(s) <= n else s[: n - 1] + "…"

    lines: List[str] = []
    lines.append("# VulnRadar Report")
    lines.append("")
    lines.append(f"Generated: `{generated_at}`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        "Critical findings are CVEs that are BOTH in your watchlist AND present in the PatchThis intelligence feed."
    )
    lines.append("")
    if critical_top:
        lines.append("Top critical items:")
        lines.append("")
        lines.append("| CVE | EPSS | CVSS | KEV Due | Description |")
        lines.append("|---|---:|---:|---:|---|")
        for i in critical_top:
            cve_id = str(i.get("cve_id") or "")
            epss = i.get("probability_score")
            cvss = i.get("cvss_score")
            due = ((i.get("kev") or {}) if isinstance(i.get("kev"), dict) else {}).get("dueDate")
            desc = _short(str(i.get("description") or ""), n=120)
            try:
                epss_s = f"{float(epss):.3f}" if epss is not None else ""
            except Exception:
                epss_s = ""
            try:
                cvss_s = f"{float(cvss):.1f}" if cvss is not None else ""
            except Exception:
                cvss_s = ""
            lines.append(f"| {_cve_link(cve_id)} | {epss_s} | {cvss_s} | {due or ''} | {desc} |")
        lines.append("")
    else:
        lines.append("No critical PatchThis+Watchlist findings in this run.")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total items: **{total}**")
    lines.append(f"- Watchlist hits: **{watch_hits}**")
    lines.append(f"- CISA KEVs: **{kev_count}**")
    lines.append(f"- PatchThis hits: **{patch_count}**")
    lines.append(f"- PatchThis + Watchlist (CRITICAL): **{critical_patch_watch}**")
    lines.append("")
    lines.append("## Top Findings (max 200)")
    lines.append("")
    lines.append("| CVE | Priority | Bucket | PatchThis | KEV | KEV Due | EPSS | CVSS | Watchlist | Description |")
    lines.append("|---|---|---|---:|---:|---:|---:|---:|---:|---|")

    for i in top:
        cve_id = str(i.get("cve_id") or "")
        priority = str(i.get("priority_label") or "")
        bucket = risk_bucket(i)
        patch = "✅" if bool(i.get("in_patchthis")) else ""
        kev = "✅" if bool(i.get("active_threat")) else ""
        kev_due = ((i.get("kev") or {}) if isinstance(i.get("kev"), dict) else {}).get("dueDate") or ""
        epss = i.get("probability_score")
        cvss = i.get("cvss_score")
        watch = "✅" if bool(i.get("watchlist_hit")) else ""
        desc = _short(str(i.get("description") or ""))

        try:
            epss_s = f"{float(epss):.3f}" if epss is not None else ""
        except Exception:
            epss_s = ""
        try:
            cvss_s = f"{float(cvss):.1f}" if cvss is not None else ""
        except Exception:
            cvss_s = ""

        lines.append(
            f"| {_cve_link(cve_id)} | {priority} | {bucket} | {patch} | {kev} | {kev_due} | {epss_s} | {cvss_s} | {watch} | {desc} |"
        )

    # Add Recent Changes section if state file exists
    if state_file and state_file.exists():
        try:
            with state_file.open("r", encoding="utf-8") as f:
                state_data = json.load(f)

            # Find CVEs first seen in the last 7 days
            seven_days_ago = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
            recent_changes: List[Tuple[str, str, str]] = []  # (date, cve_id, change_type)

            seen_cves = state_data.get("seen_cves", {})
            for cve_id, entry in seen_cves.items():
                first_seen_str = entry.get("first_seen")
                if not first_seen_str:
                    continue
                try:
                    first_seen = dt.datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
                    if first_seen >= seven_days_ago:
                        snapshot = entry.get("snapshot", {})
                        # Determine change type based on snapshot
                        if snapshot.get("active_threat"):
                            change_type = "🔴 In CISA KEV"
                        elif snapshot.get("in_patchthis"):
                            change_type = "🟠 In PatchThis"
                        elif snapshot.get("is_critical"):
                            change_type = "🔥 Critical"
                        else:
                            change_type = "🆕 New"
                        date_str = first_seen.strftime("%b %d")
                        recent_changes.append((first_seen, date_str, cve_id, change_type))
                except (ValueError, TypeError):
                    continue

            if recent_changes:
                # Sort by date descending
                recent_changes.sort(key=lambda x: x[0], reverse=True)

                lines.append("")
                lines.append("## Recent Changes (Last 7 Days)")
                lines.append("")
                lines.append("| Date | CVE | Status |")
                lines.append("|------|-----|--------|")

                for _, date_str, cve_id, change_type in recent_changes[:50]:
                    lines.append(f"| {date_str} | {_cve_link(cve_id)} | {change_type} |")

                if len(recent_changes) > 50:
                    lines.append(f"| ... | | _and {len(recent_changes) - 50} more_ |")
                lines.append("")
        except (json.JSONDecodeError, KeyError, TypeError):
            # If state file is invalid, skip this section silently
            pass

    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")
    tmp.replace(path)


def _find_watchlist() -> str:
    """Find the watchlist file, preferring YAML over JSON."""
    for name in ("watchlist.yaml", "watchlist.yml", "watchlist.json"):
        if Path(name).exists():
            return name
    return "watchlist.yaml"  # Default to YAML for new users


def _extract_all_vendors_products(extracted_dir: Path, years: List[int]) -> Tuple[Set[str], Set[str]]:
    """Extract all unique vendors and products from CVE data."""
    cves_root = _find_cves_root(extracted_dir)
    vendors: Set[str] = set()
    products: Set[str] = set()

    for p in _iter_cve_json_paths(cves_root, years):
        try:
            with p.open("r", encoding="utf-8") as f:
                raw = json.load(f)
            containers = raw.get("containers", {})
            cna = containers.get("cna", {})
            affected = cna.get("affected") or []
            for a in affected:
                if not isinstance(a, dict):
                    continue
                v = _norm(str(a.get("vendor") or ""))
                prod = _norm(str(a.get("product") or ""))
                if v and v not in ("n/a", "unknown", "unspecified", ""):
                    vendors.add(v)
                if prod and prod not in ("n/a", "unknown", "unspecified", ""):
                    products.add(prod)
        except Exception:
            continue

    return vendors, products


def _handle_discovery_commands(args) -> int:
    """Handle --list-vendors, --list-products, --validate-watchlist commands."""
    session = _requests_session()

    print("Downloading CVE List V5 bulk export for discovery...")
    zip_url = get_latest_cvelist_zip_url(session)
    zip_bytes = _download_bytes(session, zip_url)
    extracted = download_and_extract_zip_to_temp(zip_bytes)

    try:
        # Use last 2 years for faster discovery (good enough for validation)
        current_year = dt.datetime.now().year
        years = [current_year - 1, current_year]

        print("Scanning CVE data (last 2 years)...")
        all_vendors, all_products = _extract_all_vendors_products(extracted, years)
        print(f"  Found {len(all_vendors)} unique vendors, {len(all_products)} unique products")
        print()

        if args.list_vendors is not None:
            filter_str = (args.list_vendors or "").lower()
            matches = sorted(v for v in all_vendors if filter_str in v)
            if filter_str:
                print(f"Vendors containing '{filter_str}' ({len(matches)} matches):")
            else:
                print(f"All vendors ({len(matches)} total):")
            print("-" * 50)
            for v in matches[:200]:  # Limit output
                print(f"  {v}")
            if len(matches) > 200:
                print(f"  ... and {len(matches) - 200} more")
            return 0

        if args.list_products is not None:
            filter_str = (args.list_products or "").lower()
            matches = sorted(p for p in all_products if filter_str in p)
            if filter_str:
                print(f"Products containing '{filter_str}' ({len(matches)} matches):")
            else:
                print(f"All products ({len(matches)} total):")
            print("-" * 50)
            for p in matches[:200]:  # Limit output
                print(f"  {p}")
            if len(matches) > 200:
                print(f"  ... and {len(matches) - 200} more")
            return 0

        if args.validate_watchlist:
            watchlist_path = args.watchlist if args.watchlist else _find_watchlist()
            if not Path(watchlist_path).exists():
                print(f"❌ Watchlist not found: {watchlist_path}")
                return 1

            print(f"Validating watchlist: {watchlist_path}")
            print("=" * 60)
            watchlist = load_watchlist(Path(watchlist_path))

            # Check vendors
            print(f"\n📋 Vendors ({len(watchlist.vendors)} in watchlist):")
            matched_vendors = 0
            unmatched_vendors = []
            for wv in sorted(watchlist.vendors):
                # Check if any real vendor contains this term (substring match)
                matches = [v for v in all_vendors if wv in v or v in wv]
                if matches:
                    matched_vendors += 1
                    print(f"  ✅ {wv} → matches {len(matches)} vendor(s)")
                else:
                    unmatched_vendors.append(wv)
                    print(f"  ⚠️  {wv} → no matches found (may still match future CVEs)")

            # Check products
            print(f"\n📦 Products ({len(watchlist.products)} in watchlist):")
            matched_products = 0
            unmatched_products = []
            for wp in sorted(watchlist.products):
                matches = [p for p in all_products if wp in p or p in wp]
                if matches:
                    matched_products += 1
                    print(f"  ✅ {wp} → matches {len(matches)} product(s)")
                else:
                    unmatched_products.append(wp)
                    print(f"  ⚠️  {wp} → no matches found (may still match future CVEs)")

            # Summary
            print("\n" + "=" * 60)
            print("Summary:")
            print(f"  Vendors:  {matched_vendors}/{len(watchlist.vendors)} matched")
            print(f"  Products: {matched_products}/{len(watchlist.products)} matched")

            if unmatched_vendors or unmatched_products:
                print("\n💡 Suggestions for unmatched terms:")
                for uv in unmatched_vendors[:5]:
                    suggestions = sorted(all_vendors, key=lambda v: _fuzzy_score(uv, v), reverse=True)[:3]
                    print(f"  '{uv}' → try: {', '.join(suggestions)}")
                for up in unmatched_products[:5]:
                    suggestions = sorted(all_products, key=lambda p: _fuzzy_score(up, p), reverse=True)[:3]
                    print(f"  '{up}' → try: {', '.join(suggestions)}")

            return 0

    finally:
        shutil.rmtree(extracted, ignore_errors=True)

    return 0


def _fuzzy_score(query: str, target: str) -> float:
    """Simple fuzzy matching score (higher = better match)."""
    query = query.lower()
    target = target.lower()
    if query == target:
        return 1.0
    if query in target:
        return 0.8 + (len(query) / len(target)) * 0.2
    if target in query:
        return 0.6
    # Count common characters
    common = sum(1 for c in query if c in target)
    return common / max(len(query), len(target)) * 0.5


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Vulnerability Radar ETL")
    parser.add_argument(
        "--watchlist",
        default=None,
        help="Path to watchlist file (YAML or JSON). Auto-detects watchlist.yaml or watchlist.json if not specified.",
    )
    parser.add_argument("--out", default="data/radar_data.json", help="Output JSON path")
    parser.add_argument(
        "--report",
        default="data/radar_report.md",
        help="Output Markdown report path (GitHub-viewable)",
    )
    parser.add_argument(
        "--min-year",
        type=int,
        default=default_min_year(),
        help=(
            "Minimum CVE year to scan in bulk. Defaults to the start of the last 5 years "
            "(inclusive of the current year)."
        ),
    )
    parser.add_argument(
        "--max-year",
        type=int,
        default=None,
        help="Maximum CVE year to scan in bulk (default: current year)",
    )
    parser.add_argument(
        "--include-kev-outside-window",
        action="store_true",
        help=(
            "Also include CISA KEV CVEs outside the scanned year window by resolving their JSON paths. "
            "By default, KEVs are only included if they fall within the scanned year range."
        ),
    )
    parser.add_argument(
        "--skip-nvd",
        action="store_true",
        help="Skip downloading NVD data feeds (faster but less CVSS/CWE enrichment)",
    )
    parser.add_argument(
        "--nvd-cache",
        default=None,
        help="Directory to cache NVD feeds (reused if <24h old). Speeds up repeated runs.",
    )
    parser.add_argument(
        "--state",
        default="data/state.json",
        help="Path to state file for Recent Changes section in report (default: data/state.json)",
    )
    # Discovery commands
    parser.add_argument(
        "--list-vendors",
        nargs="?",
        const="",
        metavar="FILTER",
        help="List all vendors in CVE data (optionally filter by substring)",
    )
    parser.add_argument(
        "--list-products",
        nargs="?",
        const="",
        metavar="FILTER",
        help="List all products in CVE data (optionally filter by substring)",
    )
    parser.add_argument(
        "--validate-watchlist",
        action="store_true",
        help="Validate your watchlist against real CVE data",
    )
    args = parser.parse_args(argv)

    # Handle discovery commands (don't need full ETL)
    if args.list_vendors is not None or args.list_products is not None or args.validate_watchlist:
        return _handle_discovery_commands(args)

    # Auto-detect watchlist file if not specified
    watchlist_path = args.watchlist if args.watchlist else _find_watchlist()
    print(f"Using watchlist: {watchlist_path}")
    watchlist = load_watchlist(Path(watchlist_path))
    session = _requests_session()

    print("Downloading CISA KEV catalog...")
    kev_by_cve = download_cisa_kev(session)
    print(f"  Loaded {len(kev_by_cve)} KEV entries")

    print("Downloading EPSS scores...")
    epss_by_cve = download_epss(session)
    print(f"  Loaded {len(epss_by_cve)} EPSS scores")

    print("Downloading PatchThis intelligence...")
    patchthis_cves = download_patchthis(session)
    print(f"  Loaded {len(patchthis_cves)} PatchThis CVEs")

    # Calculate years for NVD download (same as CVE scan window)
    years = _years_to_process(args.min_year, args.max_year)

    # Download NVD feeds for CVSS/CWE enrichment
    nvd_by_cve: Dict[str, Dict[str, Any]] = {}
    if not args.skip_nvd:
        print("Downloading NVD data feeds...")
        nvd_cache = Path(args.nvd_cache) if args.nvd_cache else None
        nvd_by_cve = download_nvd_feeds(session, years, cache_dir=nvd_cache)
        print(f"  Loaded {len(nvd_by_cve)} CVEs from NVD feeds")
    else:
        print("Skipping NVD data feeds (--skip-nvd)")

    print("Downloading CVE List V5 bulk export...")
    zip_url = get_latest_cvelist_zip_url(session)
    zip_bytes = _download_bytes(session, zip_url)

    extracted = download_and_extract_zip_to_temp(zip_bytes)
    try:
        items = build_radar_data(
            extracted_dir=extracted,
            watchlist=watchlist,
            kev_by_cve=kev_by_cve,
            epss_by_cve=epss_by_cve,
            patchthis_cves=patchthis_cves,
            nvd_by_cve=nvd_by_cve,
            min_year=args.min_year,
            max_year=args.max_year,
            include_kev_outside_window=bool(args.include_kev_outside_window),
        )
    finally:
        shutil.rmtree(extracted, ignore_errors=True)

    items = items or []

    write_radar_data(Path(args.out), items)

    # Pass state file for Recent Changes section
    state_path = Path(args.state) if args.state else None
    write_markdown_report(Path(args.report), items, state_file=state_path)

    print(f"Wrote {len(items)} items to {args.out}")
    print(f"Wrote Markdown report to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
