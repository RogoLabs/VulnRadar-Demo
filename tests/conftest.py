"""Pytest fixtures for VulnRadar tests."""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml


@pytest.fixture
def sample_watchlist_yaml(tmp_path: Path) -> Path:
    """Create a sample YAML watchlist for testing."""
    content = {
        "vendors": ["microsoft", "apache", "linux"],
        "products": ["exchange", "log4j", "kernel", "openssl"],
    }
    path = tmp_path / "watchlist.yaml"
    path.write_text(yaml.dump(content))
    return path


@pytest.fixture
def sample_watchlist_json(tmp_path: Path) -> Path:
    """Create a sample JSON watchlist for testing (deprecated format)."""
    content = {
        "vendors": ["google", "mozilla"],
        "products": ["chrome", "firefox"],
    }
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps(content))
    return path


@pytest.fixture
def empty_watchlist(tmp_path: Path) -> Path:
    """Create an empty watchlist for testing edge cases."""
    content = {"vendors": [], "products": []}
    path = tmp_path / "empty.yaml"
    path.write_text(yaml.dump(content))
    return path


@pytest.fixture
def sample_cve_v5() -> Dict[str, Any]:
    """Sample CVE in V5 format (as found in cvelistV5 repo)."""
    return {
        "cveMetadata": {
            "cveId": "CVE-2024-12345",
            "state": "PUBLISHED",
            "datePublished": "2024-06-15T10:00:00.000Z",
            "dateUpdated": "2024-06-16T12:00:00.000Z",
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Apache Software Foundation",
                        "product": "Log4j",
                        "versions": [{"version": "2.0", "status": "affected"}],
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A critical vulnerability in Apache Log4j allows remote code execution.",
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ],
                "references": [
                    {"url": "https://example.com/advisory"},
                ],
            }
        },
    }


@pytest.fixture
def sample_cve_no_metrics() -> Dict[str, Any]:
    """Sample CVE without CVSS metrics."""
    return {
        "cveMetadata": {
            "cveId": "CVE-2024-99999",
            "state": "PUBLISHED",
            "datePublished": "2024-07-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Example Corp",
                        "product": "Widget",
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ],
                "descriptions": [{"lang": "en", "value": "A vulnerability exists in Widget."}],
            }
        },
    }


@pytest.fixture
def sample_kev_entry() -> Dict[str, Any]:
    """Sample CISA KEV entry."""
    return {
        "cveID": "CVE-2024-12345",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j Remote Code Execution",
        "dateAdded": "2024-06-16",
        "shortDescription": "Apache Log4j contains a vulnerability...",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-07-01",
        "knownRansomwareCampaignUse": "Known",
    }


@pytest.fixture
def sample_radar_item() -> Dict[str, Any]:
    """Sample radar data item (output of ETL)."""
    return {
        "cve_id": "CVE-2024-12345",
        "description": "A critical vulnerability in Apache Log4j allows remote code execution.",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "probability_score": 0.85,
        "active_threat": True,
        "in_patchthis": True,
        "in_watchlist": True,
        "watchlist_hit": True,  # Used by _issue_body for "Watchlist: yes/no"
        "is_critical": True,
        "priority_label": "CRITICAL (Active Exploit in Stack)",
        "matched_terms": ["vendor:apache", "product:log4j"],
        "kev": {
            "cveID": "CVE-2024-12345",
            "vendorProject": "Apache",
            "product": "Log4j",
            "dateAdded": "2024-06-16",
            "dueDate": "2024-07-01",
        },
    }
