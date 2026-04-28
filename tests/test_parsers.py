"""Unit tests for vulnradar.parsers — the pure parsing/matching module."""

import pytest

from vulnradar.parsers import (
    affected_vendor_products,
    cve_year_and_num,
    fuzzy_score,
    norm,
    parse_cve_json_data,
    risk_bucket,
    risk_sort_key,
)

# ── parse_cve_json_data ─────────────────────────────────────────────────────


class TestParseCveJsonData:
    """Tests for parse_cve_json_data()."""

    def test_valid_cve(self, sample_cve_v5):
        result = parse_cve_json_data(sample_cve_v5)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-12345"
        assert "Log4j" in result["description"]
        assert result["cvss_score"] == 9.8
        assert result["cvss_severity"] == "CRITICAL"
        assert len(result["affected"]) == 1
        assert result["affected"][0]["vendor"] == "apache software foundation"

    def test_cve_without_metrics(self, sample_cve_no_metrics):
        result = parse_cve_json_data(sample_cve_no_metrics)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-99999"
        assert result["cvss_score"] is None
        assert result["cvss_severity"] is None

    def test_missing_cve_id(self):
        data = {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        assert parse_cve_json_data(data) is None

    def test_invalid_cve_id(self):
        data = {"cveMetadata": {"cveId": "NOT-A-CVE"}, "containers": {"cna": {}}}
        assert parse_cve_json_data(data) is None

    def test_empty_containers(self):
        data = {"cveMetadata": {"cveId": "CVE-2024-00001"}, "containers": {}}
        result = parse_cve_json_data(data)
        assert result is not None
        assert result["description"] == ""
        assert result["affected"] == []

    def test_containers_not_dict(self):
        data = {"cveMetadata": {"cveId": "CVE-2024-00001"}, "containers": "bad"}
        result = parse_cve_json_data(data)
        assert result is not None
        assert result["description"] == ""

    def test_cve_id_normalised_uppercase(self):
        data = {"cveMetadata": {"cveId": "cve-2024-00001"}, "containers": {"cna": {}}}
        result = parse_cve_json_data(data)
        assert result["cve_id"] == "CVE-2024-00001"


# ── cve_year_and_num ─────────────────────────────────────────────────────────


class TestCveYearAndNum:
    """Tests for cve_year_and_num()."""

    def test_standard_cve(self):
        assert cve_year_and_num("CVE-2024-12345") == (2024, 12345)

    def test_case_insensitive(self):
        assert cve_year_and_num("cve-2023-99") == (2023, 99)

    def test_long_sequence(self):
        assert cve_year_and_num("CVE-2025-1234567") == (2025, 1234567)

    def test_with_whitespace(self):
        assert cve_year_and_num("  CVE-2024-001  ") == (2024, 1)

    def test_invalid_format(self):
        assert cve_year_and_num("NOT-A-CVE") is None

    def test_empty(self):
        assert cve_year_and_num("") is None

    def test_none(self):
        assert cve_year_and_num(None) is None

    def test_partial(self):
        assert cve_year_and_num("CVE-2024") is None

    def test_extra_dash(self):
        assert cve_year_and_num("CVE-2024-123-456") is None


# ── risk_bucket ──────────────────────────────────────────────────────────────


class TestRiskBucket:
    """Tests for risk_bucket()."""

    def test_critical(self):
        assert risk_bucket({"is_critical": True}) == "CRITICAL"

    def test_kev(self):
        assert risk_bucket({"active_threat": True}) == "KEV"

    def test_high_epss(self):
        assert risk_bucket({"probability_score": 0.75}) == "High EPSS"

    def test_critical_cvss(self):
        assert risk_bucket({"cvss_score": 9.5}) == "Critical CVSS"

    def test_other(self):
        assert risk_bucket({"cvss_score": 5.0, "probability_score": 0.1}) == "Other"

    def test_empty_item(self):
        assert risk_bucket({}) == "Other"

    def test_priority_order(self):
        """critical trumps KEV, KEV trumps EPSS, etc."""
        item = {"is_critical": True, "active_threat": True, "probability_score": 0.9}
        assert risk_bucket(item) == "CRITICAL"

        item2 = {"active_threat": True, "probability_score": 0.9}
        assert risk_bucket(item2) == "KEV"

    def test_invalid_epss(self):
        assert risk_bucket({"probability_score": "bad"}) == "Other"

    def test_invalid_cvss(self):
        assert risk_bucket({"cvss_score": "bad"}) == "Other"

    def test_epss_boundary(self):
        assert risk_bucket({"probability_score": 0.7}) == "High EPSS"
        assert risk_bucket({"probability_score": 0.69}) == "Other"

    def test_cvss_boundary(self):
        assert risk_bucket({"cvss_score": 9.0}) == "Critical CVSS"
        assert risk_bucket({"cvss_score": 8.9}) == "Other"


# ── risk_sort_key ────────────────────────────────────────────────────────────


class TestRiskSortKey:
    """Tests for risk_sort_key()."""

    def test_critical_highest(self):
        critical = risk_sort_key({"is_critical": True})
        kev = risk_sort_key({"active_threat": True})
        assert critical > kev

    def test_kev_higher_than_epss(self):
        kev = risk_sort_key({"active_threat": True})
        epss = risk_sort_key({"probability_score": 0.99})
        assert kev > epss

    def test_epss_contributes_to_score(self):
        """EPSS is weighted ×10 in the sort key, so epss=0.9 adds 9.0."""
        with_epss = risk_sort_key({"probability_score": 0.9, "cvss_score": 5.0})
        without_epss = risk_sort_key({"probability_score": 0.0, "cvss_score": 5.0})
        assert with_epss > without_epss

    def test_empty_returns_zero(self):
        assert risk_sort_key({}) == 0.0

    def test_invalid_values_handled(self):
        assert risk_sort_key({"probability_score": "bad", "cvss_score": "bad"}) == 0.0

    def test_sorting_order(self):
        items = [
            {"cvss_score": 5.0},
            {"is_critical": True},
            {"active_threat": True},
            {"probability_score": 0.8},
        ]
        sorted_items = sorted(items, key=risk_sort_key, reverse=True)
        assert sorted_items[0]["is_critical"]
        assert sorted_items[1]["active_threat"]
        assert sorted_items[2].get("probability_score") == 0.8
        assert sorted_items[3].get("cvss_score") == 5.0


# ── fuzzy_score ──────────────────────────────────────────────────────────────


class TestFuzzyScore:
    """Tests for fuzzy_score()."""

    def test_exact_match(self):
        assert fuzzy_score("apache", "apache") == 1.0

    def test_case_insensitive(self):
        assert fuzzy_score("Apache", "APACHE") == 1.0

    def test_query_in_target(self):
        score = fuzzy_score("apache", "apache software foundation")
        assert 0.8 < score < 1.0

    def test_target_in_query(self):
        score = fuzzy_score("apache software foundation", "apache")
        assert score == 0.6

    def test_partial_overlap(self):
        score = fuzzy_score("xyz", "abc")
        assert 0.0 <= score < 0.5

    def test_no_overlap(self):
        score = fuzzy_score("zzz", "aaa")
        assert score == 0.0


# ── affected_vendor_products ─────────────────────────────────────────────────


class TestAffectedVendorProducts:
    """Tests for affected_vendor_products()."""

    def test_single_affected(self, sample_cve_v5):
        cna = sample_cve_v5["containers"]["cna"]
        result = affected_vendor_products(cna)
        assert len(result) == 1
        assert result[0]["vendor"] == "apache software foundation"
        assert result[0]["product"] == "log4j"
        assert isinstance(result[0]["versions"], list)

    def test_empty_affected(self):
        assert affected_vendor_products({}) == []
        assert affected_vendor_products({"affected": []}) == []
        assert affected_vendor_products({"affected": None}) == []

    def test_affected_not_list(self):
        assert affected_vendor_products({"affected": "bad"}) == []

    def test_non_dict_entry_skipped(self):
        result = affected_vendor_products({"affected": ["string", None, 123]})
        assert result == []

    def test_multiple_affected(self):
        cna = {
            "affected": [
                {"vendor": "Microsoft", "product": "Exchange"},
                {"vendor": "Apache", "product": "Tomcat"},
            ]
        }
        result = affected_vendor_products(cna)
        assert len(result) == 2
        assert result[0]["vendor"] == "microsoft"
        assert result[1]["product"] == "tomcat"

    def test_versions_not_list(self):
        cna = {"affected": [{"vendor": "X", "product": "Y", "versions": "bad"}]}
        result = affected_vendor_products(cna)
        assert result[0]["versions"] is None
