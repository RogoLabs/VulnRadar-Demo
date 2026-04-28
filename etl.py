#!/usr/bin/env python3
"""VulnRadar ETL — thin shim.

This file re-exports all public symbols from the ``vulnradar`` package
so that existing ``from etl import …`` imports, CI workflows, and
``python etl.py`` invocations continue to work unchanged.

The real implementation lives in ``vulnradar/``.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from vulnradar.cli import main_etl
from vulnradar.config import (
    find_watchlist as _find_watchlist,
)
from vulnradar.config import (
    load_merged_watchlist as _load_merged_watchlist_new,
)
from vulnradar.config import (
    load_watchlist as _load_watchlist_new,
)
from vulnradar.downloaders import (
    download_and_extract_zip as download_and_extract_zip_to_temp,
)
from vulnradar.downloaders import (
    download_bytes as _download_bytes,
)
from vulnradar.downloaders import (
    download_cisa_kev,
    download_epss,
    download_nvd_feeds,
    download_patchthis,
    get_latest_cvelist_zip_url,
)
from vulnradar.downloaders import (
    get_json as _get_json,
)
from vulnradar.downloaders import (
    requests_session as _requests_session,
)
from vulnradar.enrichment import (
    build_radar_data as _build_radar_data_new,
)
from vulnradar.enrichment import (
    extract_all_vendors_products as _extract_all_vendors_products,
)
from vulnradar.enrichment import (
    find_cves_root as _find_cves_root,
)
from vulnradar.enrichment import (
    guess_cve_path as _guess_cve_path,
)
from vulnradar.enrichment import (
    iter_cve_json_paths as _iter_cve_json_paths,
)
from vulnradar.enrichment import (
    now_utc_iso as _now_utc_iso,
)
from vulnradar.enrichment import (
    parse_cve_json,
    write_radar_data,
)
from vulnradar.enrichment import (
    years_to_process as _years_to_process,
)
from vulnradar.parsers import (
    affected_vendor_products as _affected_vendor_products,
)
from vulnradar.parsers import (
    cve_year_and_num as _cve_year_and_num,
)
from vulnradar.parsers import (
    extract_cvss as _extract_cvss,
)
from vulnradar.parsers import (
    fuzzy_score as _fuzzy_score,
)
from vulnradar.parsers import (
    matches_watchlist as _matches_watchlist_inner,
)

# ── Re-exports from vulnradar package ────────────────────────────────────────
from vulnradar.parsers import (
    norm as _norm,
)
from vulnradar.parsers import (
    parse_cve_json_data,
    risk_bucket,
    risk_sort_key,
)
from vulnradar.parsers import (
    pick_best_description as _pick_best_description,
)
from vulnradar.report import write_markdown_report

# ── Backward-compatible Watchlist dataclass ──────────────────────────────────


@dataclass(frozen=True)
class Watchlist:
    vendors: Set[str]
    products: Set[str]


def default_min_year() -> int:
    import datetime as dt

    return dt.datetime.now().year - 4


def load_watchlist(path: Path) -> Watchlist:
    """Load watchlist and return the legacy Watchlist dataclass."""
    cfg = _load_watchlist_new(path)
    return Watchlist(vendors=cfg.vendors, products=cfg.products)


def load_merged_watchlist(main_path: Path, watchlist_dir: Optional[Path] = None) -> Watchlist:
    cfg = _load_merged_watchlist_new(main_path, watchlist_dir)
    return Watchlist(vendors=cfg.vendors, products=cfg.products)


def _matches_watchlist(vendor: str, product: str, watchlist: Watchlist) -> bool:
    return _matches_watchlist_inner(vendor, product, watchlist.vendors, watchlist.products)


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
    return _build_radar_data_new(
        extracted_dir=extracted_dir,
        wl_vendors=watchlist.vendors,
        wl_products=watchlist.products,
        kev_by_cve=kev_by_cve,
        epss_by_cve=epss_by_cve,
        patchthis_cves=patchthis_cves,
        nvd_by_cve=nvd_by_cve,
        min_year=min_year,
        max_year=max_year,
        include_kev_outside_window=include_kev_outside_window,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    return main_etl(argv)


if __name__ == "__main__":
    raise SystemExit(main())
