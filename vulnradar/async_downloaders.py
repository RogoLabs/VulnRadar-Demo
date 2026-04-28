"""Async download orchestrator for parallel data source fetching.

Uses ``aiohttp`` to download all VulnRadar data sources concurrently
instead of sequentially.  This can cut the download phase from ~2-3
minutes to under 30 seconds depending on network conditions.

Usage from synchronous code::

    from vulnradar.async_downloaders import download_all_parallel
    results = download_all_parallel(years=[2022, 2023, 2024])
"""

from __future__ import annotations

import asyncio
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp

from .downloaders import (
    CISA_KEV_URL,
    EPSS_CURRENT_CSV_GZ_URL,
    GITHUB_LATEST_RELEASE_API,
    NVD_FEED_BASE_URL,
    PATCHTHIS_CSV_URL,
)

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=300, connect=15)


@dataclass
class DownloadResults:
    """Container for all parallel download results.

    Attributes:
        kev_by_cve: CVE-ID → KEV record dict.
        epss_by_cve: CVE-ID → EPSS probability float.
        patchthis_cves: Set of CVE IDs with exploit intel.
        nvd_by_cve: CVE-ID → NVD enrichment dict.
        zip_bytes: Raw bytes of the CVE List ZIP archive.
        errors: Human-readable error messages from failed downloads.
    """

    kev_by_cve: dict[str, dict[str, Any]] = field(default_factory=dict)
    epss_by_cve: dict[str, float] = field(default_factory=dict)
    patchthis_cves: set[str] = field(default_factory=set)
    nvd_by_cve: dict[str, dict[str, Any]] = field(default_factory=dict)
    zip_bytes: bytes = b""
    errors: list[str] = field(default_factory=list)


def _auth_headers() -> dict[str, str]:
    """Build HTTP headers including optional GitHub auth."""
    headers = {
        "User-Agent": "VulnRadar/0.2 (+https://github.com/)",
        "Accept": "application/json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# ─── Individual async fetchers ───────────────────────────────────────────────


async def _fetch_json(session: aiohttp.ClientSession, url: str) -> Any:
    """Fetch and parse JSON from a URL."""
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json(content_type=None)


async def _fetch_bytes(session: aiohttp.ClientSession, url: str) -> bytes:
    """Download raw bytes from a URL."""
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.read()


async def _download_kev(session: aiohttp.ClientSession) -> dict[str, dict[str, Any]]:
    """Async version of download_cisa_kev."""
    data = await _fetch_json(session, CISA_KEV_URL)
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


async def _download_epss(session: aiohttp.ClientSession) -> dict[str, float]:
    """Async version of download_epss."""
    raw = await _fetch_bytes(session, EPSS_CURRENT_CSV_GZ_URL)
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
        text = gz.read().decode("utf-8", errors="replace")

    lines = [line for line in text.splitlines() if line and not line.lstrip().startswith("#")]
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


async def _download_patchthis(session: aiohttp.ClientSession) -> set[str]:
    """Async version of download_patchthis."""
    raw = await _fetch_bytes(session, PATCHTHIS_CSV_URL)
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
        raise RuntimeError("PatchThis CSV missing CVE identifier column")

    out: set[str] = set()
    for row in reader:
        cve = (row.get(cve_col) or "").strip().upper()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


async def _download_nvd_feed(
    session: aiohttp.ClientSession,
    year: int,
    cache_dir: Path | None,
) -> dict[str, dict[str, Any]]:
    """Download and parse a single NVD feed year."""
    url = f"{NVD_FEED_BASE_URL}/nvdcve-2.0-{year}.json.gz"
    cache_file = cache_dir / f"nvdcve-2.0-{year}.json.gz" if cache_dir else None
    raw: bytes | None = None

    if cache_file and cache_file.exists():
        cache_age = dt.datetime.now().timestamp() - cache_file.stat().st_mtime
        if cache_age < 86400:
            print(f"  Using cached NVD feed for {year} (age: {cache_age / 3600:.1f}h)")
            raw = cache_file.read_bytes()

    if raw is None:
        print(f"  Downloading NVD feed for {year}...")
        raw = await _fetch_bytes(session, url)
        if cache_file:
            cache_file.write_bytes(raw)

    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
        feed = json.loads(gz.read().decode("utf-8", errors="replace"))

    nvd_data: dict[str, dict[str, Any]] = {}
    for vuln in feed.get("vulnerabilities") or []:
        cve_data = vuln.get("cve", {})
        cve_id = (cve_data.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-") or cve_data.get("vulnStatus") == "Rejected":
            continue

        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_v30 = metrics.get("cvssMetricV30", [])
        cvss_v2 = metrics.get("cvssMetricV2", [])

        def get_primary(metric_list: list) -> dict:
            for m in metric_list:
                if m.get("type") == "Primary":
                    return m.get("cvssData", {})
            return metric_list[0].get("cvssData", {}) if metric_list else {}

        cvss3_data = get_primary(cvss_v31) or get_primary(cvss_v30)
        cvss2_data = get_primary(cvss_v2)

        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-") and val != "CWE-noinfo":
                    cwe_ids.append(val)

        cpe_count = sum(
            len(node.get("cpeMatch", []))
            for config in cve_data.get("configurations", [])
            for node in config.get("nodes", [])
        )

        nvd_data[cve_id] = {
            "cvss_v3_score": cvss3_data.get("baseScore"),
            "cvss_v3_severity": cvss3_data.get("baseSeverity"),
            "cvss_v3_vector": cvss3_data.get("vectorString"),
            "cvss_v2_score": cvss2_data.get("baseScore"),
            "cvss_v2_severity": cvss2_data.get("baseSeverity"),
            "cvss_v2_vector": cvss2_data.get("vectorString"),
            "cwe_ids": list(dict.fromkeys(cwe_ids))[:10] if cwe_ids else None,
            "cpe_count": cpe_count,
            "reference_count": len(cve_data.get("references", [])),
        }

    print(f"    Loaded {len(nvd_data)} CVEs from NVD {year} feed")
    return nvd_data


async def _download_nvd_all(
    session: aiohttp.ClientSession,
    years: list[int],
    cache_dir: Path | None,
) -> dict[str, dict[str, Any]]:
    """Download all NVD feeds in parallel."""
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    tasks = [_download_nvd_feed(session, y, cache_dir) for y in sorted(set(years))]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    merged: dict[str, dict[str, Any]] = {}
    for r in results:
        if isinstance(r, Exception):
            print(f"    Warning: NVD feed failed: {r}")
            continue
        merged.update(r)
    return merged


async def _resolve_cvelist_url(session: aiohttp.ClientSession) -> str:
    """Async version of get_latest_cvelist_zip_url."""
    data = await _fetch_json(session, GITHUB_LATEST_RELEASE_API)
    assets = data.get("assets") or []
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
    raise RuntimeError("Could not find *_all_CVEs_at_midnight.zip asset in latest release")


def download_and_extract_zip(zip_bytes: bytes) -> Path:
    """Extract a CVE List ZIP to a temporary directory.

    Identical to ``downloaders.download_and_extract_zip`` — re-exported
    here for convenience so callers don't need both modules.

    Args:
        zip_bytes: Raw bytes of the ZIP archive.

    Returns:
        Path to the temporary directory containing extracted files.
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


# ─── Orchestrator ────────────────────────────────────────────────────────────


async def _download_all(
    years: list[int],
    skip_nvd: bool = False,
    nvd_cache_dir: Path | None = None,
) -> DownloadResults:
    """Download all data sources concurrently.

    Args:
        years: CVE years to fetch NVD data for.
        skip_nvd: Whether to skip NVD feeds.
        nvd_cache_dir: Optional cache directory for NVD feeds.

    Returns:
        ``DownloadResults`` with all fetched data and any errors.
    """
    results = DownloadResults()
    headers = _auth_headers()

    async with aiohttp.ClientSession(headers=headers, timeout=DEFAULT_TIMEOUT) as session:
        # Phase 1: Launch all independent downloads + CVE list URL resolution
        tasks: dict[str, asyncio.Task] = {}
        tasks["kev"] = asyncio.create_task(_download_kev(session))
        tasks["epss"] = asyncio.create_task(_download_epss(session))
        tasks["patchthis"] = asyncio.create_task(_download_patchthis(session))
        if not skip_nvd:
            tasks["nvd"] = asyncio.create_task(_download_nvd_all(session, years, nvd_cache_dir))
        tasks["cvelist_url"] = asyncio.create_task(_resolve_cvelist_url(session))

        # Collect results with graceful degradation
        for name, task in tasks.items():
            try:
                result = await task
                if name == "kev":
                    results.kev_by_cve = result
                    print(f"  ✅ CISA KEV: {len(result)} entries")
                elif name == "epss":
                    results.epss_by_cve = result
                    print(f"  ✅ EPSS: {len(result)} scores")
                elif name == "patchthis":
                    results.patchthis_cves = result
                    print(f"  ✅ PatchThis: {len(result)} CVEs")
                elif name == "nvd":
                    results.nvd_by_cve = result
                    print(f"  ✅ NVD: {len(result)} CVEs")
                elif name == "cvelist_url":
                    # Phase 2: download the actual ZIP (biggest file, needs resolved URL)
                    print("  ✅ CVE List URL resolved, downloading ZIP...")
                    try:
                        results.zip_bytes = await _fetch_bytes(session, result)
                        print(f"  ✅ CVE List ZIP: {len(results.zip_bytes) / 1024 / 1024:.1f} MB")
                    except Exception as e:
                        msg = f"CVE List ZIP download failed: {e}"
                        print(f"  ❌ {msg}")
                        results.errors.append(msg)
            except Exception as e:
                msg = f"{name} download failed: {e}"
                print(f"  ❌ {msg}")
                results.errors.append(msg)

    return results


def download_all_parallel(
    years: list[int],
    skip_nvd: bool = False,
    nvd_cache_dir: Path | None = None,
) -> DownloadResults:
    """Synchronous wrapper that runs all downloads in parallel via asyncio.

    This is the main entry point for parallel downloads. It creates an
    event loop, runs all downloads concurrently, and returns the results.

    Args:
        years: CVE years to fetch NVD data for.
        skip_nvd: Whether to skip NVD feeds entirely.
        nvd_cache_dir: Optional cache directory for NVD feeds.

    Returns:
        ``DownloadResults`` containing all fetched data and any errors.

    Example::

        results = download_all_parallel(years=[2022, 2023, 2024])
        print(f"KEV: {len(results.kev_by_cve)}")
        if results.errors:
            print(f"Warnings: {results.errors}")
    """
    return asyncio.run(_download_all(years, skip_nvd=skip_nvd, nvd_cache_dir=nvd_cache_dir))
