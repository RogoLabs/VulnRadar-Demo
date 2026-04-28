"""Configuration models using Pydantic.

Replaces the old ``Watchlist`` dataclass and ``load_watchlist()`` /
``load_merged_watchlist()`` functions with validated Pydantic models.
"""

import json
import shutil
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class ThresholdsConfig(BaseModel):
    """Optional severity thresholds for filtering and criticality.

    Attributes:
        min_cvss: Minimum CVSS score to include (0.0–10.0).
        min_epss: Minimum EPSS probability to include (0.0–1.0).
        severity_threshold: CVSS floor for flagging watchlist CVEs as
            critical.  ``None`` disables this check.
        epss_threshold: EPSS floor for flagging watchlist CVEs as
            critical.  ``None`` disables this check.
    """

    min_cvss: float = Field(default=0.0, ge=0.0, le=10.0)
    min_epss: float = Field(default=0.0, ge=0.0, le=1.0)
    severity_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS score at or above which a CVE is flagged critical (e.g. 9.0)",
    )
    epss_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="EPSS probability at or above which a CVE is flagged critical (e.g. 0.5)",
    )


class OptionsConfig(BaseModel):
    """Optional behaviour flags.

    Attributes:
        always_include_kev: Include KEV entries even without a watchlist match.
        always_include_patchthis: Include PatchThis entries even without a
            watchlist match.
        match_mode: Matching strategy — ``substring``, ``exact``, or ``regex``.
    """

    always_include_kev: bool = True
    always_include_patchthis: bool = True
    match_mode: str = "substring"  # substring | exact | regex


class NotificationRoute(BaseModel):
    """A single notification destination with optional severity filter.

    Example YAML::

        notifications:
          discord:
            - url: $DISCORD_CRITICAL_WEBHOOK
              filter: critical
            - url: $DISCORD_ALL_WEBHOOK
              filter: all
    """

    url: str
    filter: str = "all"  # all | critical | kev | watchlist
    max_alerts: int = Field(default=10, ge=0, le=100)


class NotificationsConfig(BaseModel):
    """Optional per-provider notification routing.

    Attributes:
        discord: List of Discord webhook routes.
        slack: List of Slack webhook routes.
        teams: List of Microsoft Teams webhook routes.
    """

    discord: list[NotificationRoute] = Field(default_factory=list)
    slack: list[NotificationRoute] = Field(default_factory=list)
    teams: list[NotificationRoute] = Field(default_factory=list)


class WatchlistConfig(BaseModel):
    """Validated watchlist configuration.

    All vendor/product strings are normalized on load (lowered, stripped,
    whitespace collapsed).  Exclusions are also normalized.

    Example YAML::

        vendors:
          - microsoft
          - apache
        products:
          - log4j
          - chrome
        exclude_vendors:
          - n/a
        exclude_products:
          - n/a
        thresholds:
          min_cvss: 0.0
          min_epss: 0.0
        options:
          always_include_kev: true
    """

    vendors: set[str] = Field(default_factory=set)
    products: set[str] = Field(default_factory=set)
    exclude_vendors: set[str] = Field(default_factory=set)
    exclude_products: set[str] = Field(default_factory=set)
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    options: OptionsConfig = Field(default_factory=OptionsConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)

    @field_validator("vendors", "products", "exclude_vendors", "exclude_products", mode="before")
    @classmethod
    def _normalize_set(cls, v: Any) -> set[str]:
        """Normalize each entry: lowercase, strip, collapse whitespace."""
        import re

        if v is None:
            return set()
        if isinstance(v, set):
            items = v
        elif isinstance(v, (list, tuple)):
            items = v
        else:
            return set()

        out: set[str] = set()
        for item in items:
            if not isinstance(item, str):
                continue
            normalized = re.sub(r"\s+", " ", item.strip().lower())
            if normalized:
                out.add(normalized)
        return out


def load_watchlist(path: Path) -> WatchlistConfig:
    """Load a watchlist from a YAML or JSON file.

    Args:
        path: Path to the watchlist file.

    Returns:
        Validated ``WatchlistConfig`` instance.

    Raises:
        FileNotFoundError: if the file doesn't exist.
        pydantic.ValidationError: if content fails validation.
    """
    suffix = path.suffix.lower()
    content = path.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        raw = yaml.safe_load(content) or {}
    elif suffix == ".json":
        raw = json.loads(content)
        print("Note: JSON watchlists are deprecated. Consider migrating to watchlist.yaml")
    else:
        try:
            raw = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            raw = json.loads(content)

    return WatchlistConfig.model_validate(raw)


def load_merged_watchlist(
    main_path: Path,
    watchlist_dir: Path | None = None,
) -> WatchlistConfig:
    """Load and merge watchlists from a main file and an optional directory.

    Supports team collaboration where different teams own different
    watchlist files that are merged at runtime.

    Args:
        main_path: Path to the main watchlist file (e.g. ``watchlist.yaml``).
        watchlist_dir: Optional directory with additional ``.yaml`` files.
                       Defaults to ``watchlist.d/`` if it exists.

    Returns:
        Merged ``WatchlistConfig`` with all vendors/products combined.
    """
    main = load_watchlist(main_path)
    vendors = set(main.vendors)
    products = set(main.products)
    exclude_vendors = set(main.exclude_vendors)
    exclude_products = set(main.exclude_products)

    if watchlist_dir is None:
        default_dir = Path("watchlist.d")
        if default_dir.exists() and default_dir.is_dir():
            watchlist_dir = default_dir

    if watchlist_dir and watchlist_dir.exists():
        yaml_files = sorted(watchlist_dir.glob("*.yaml")) + sorted(watchlist_dir.glob("*.yml"))
        if yaml_files:
            print(f"Merging {len(yaml_files)} additional watchlist(s) from {watchlist_dir}/")
            for yaml_file in yaml_files:
                try:
                    extra = load_watchlist(yaml_file)
                    vendors.update(extra.vendors)
                    products.update(extra.products)
                    exclude_vendors.update(extra.exclude_vendors)
                    exclude_products.update(extra.exclude_products)
                    print(f"  + {yaml_file.name}: {len(extra.vendors)} vendors, {len(extra.products)} products")
                except Exception as e:
                    print(f"  ⚠️ Failed to load {yaml_file.name}: {e}")

    return WatchlistConfig(
        vendors=vendors,
        products=products,
        exclude_vendors=exclude_vendors,
        exclude_products=exclude_products,
        thresholds=main.thresholds,
        options=main.options,
    )


def find_watchlist() -> str:
    """Find the watchlist file, auto-creating from example if needed.

    Searches for ``watchlist.yaml``, ``watchlist.yml``, or
    ``watchlist.json`` in the current directory.  If none exist but
    ``watchlist.example.yaml`` is present, it is copied to
    ``watchlist.yaml`` and the user is informed.

    Returns:
        Filename of the first existing watchlist file, or the
        newly created ``watchlist.yaml``.

    Raises:
        FileNotFoundError: if no watchlist can be found or created.
    """
    for name in ("watchlist.yaml", "watchlist.yml", "watchlist.json"):
        if Path(name).exists():
            return name

    # Auto-copy from example on first run
    example = Path("watchlist.example.yaml")
    target = Path("watchlist.yaml")
    if example.exists():
        shutil.copy(example, target)
        print(
            f"⚡ Created {target} from {example}\n"
            f"   Edit it to match your environment, then re-run.\n"
            f"   Docs: docs/configuration.md"
        )
        return str(target)

    raise FileNotFoundError(
        "No watchlist.yaml found and no watchlist.example.yaml to copy from.\n"
        "Create one — see docs/configuration.md for the full reference."
    )
