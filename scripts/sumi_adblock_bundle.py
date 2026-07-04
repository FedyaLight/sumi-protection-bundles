#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SAFETY_POLICY_VERSION = "sumi-native-css-safety/0.4"
ADAPTER_VERSION = "adblock-rust-adapter/0.1.0 adblock-rust/0.12.5"
# WebKit's WKContentRuleListStore compiles a single content rule list up to
# ~150,000 rules; 175,000 is rejected immediately with WKErrorDomain 6
# (measured on macOS 15+ WebKit). Every extra shard is another per-request
# matcher pass in the network process, so we consolidate to as few lists as
# possible while keeping a comfortable ~50k-rule margin below the hard ceiling.
# At 100k rules/shard the ~182k-rule adblock network group fits in 2 lists
# instead of 8, cutting the per-request content-rule-list count from 9 to 3.
# The byte cap is raised in step so the rule cap is the binding constraint
# (a 100k-rule network shard is ~11 MB of compact WebKit CbRule JSON).
DEFAULT_MAX_RULES_PER_SHARD = 100_000
DEFAULT_MAX_BYTES_PER_SHARD = 14_000_000
TRACKING_NETWORK_GROUP_ID = "trackingNetwork"
ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID = "adblockAdsPrivacyNetwork"
PROTECTION_LEVEL_GROUPS: dict[str, list[str]] = {
    "off": [],
    "protection": [TRACKING_NETWORK_GROUP_ID],
    "adblock": [TRACKING_NETWORK_GROUP_ID, ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID],
}
DDG_TDS_SOURCE_NAME = "DuckDuckGo Tracker Radar / TDS"
DDG_TDS_SOURCE_URL = "https://staticcdn.duckduckgo.com/trackerblocking/v6/current/macos-tds.json"
DDG_TDS_SOURCE_LICENSE = "CC BY-NC-SA 4.0"
DDG_TDS_SOURCE_LICENSE_URL = "https://creativecommons.org/licenses/by-nc-sa/4.0/"
DDG_TDS_ATTRIBUTION = (
    "Derived from DuckDuckGo Tracker Radar / Tracker Data Set. "
    "Use and redistribution of generated tracking data are limited to non-commercial "
    "Sumi protection bundles and remain subject to CC BY-NC-SA 4.0 share-alike terms."
)
TRACKING_GENERATOR_VERSION = "sumi-ddg-tds-webkit/0.1 tracker-radar-kit-compatible"
TRACKER_RADAR_SUBDOMAIN_PREFIX = "^[^:]+://+([^:/]+\\.)?"
TRACKER_RADAR_DOMAIN_MATCH_SUFFIX = "[:/]"
TRACKER_RADAR_RESOURCE_MAPPING = {
    "script": "script",
    "xmlhttprequest": "raw",
    "subdocument": "document",
    "image": "image",
    "stylesheet": "style-sheet",
}


DEFAULT_LISTS: dict[str, dict[str, Any]] = {
    "adguard-base": {
        "displayName": "AdGuard Base",
        "category": "baseAds",
        "url": "https://filters.adtidy.org/extension/chromium/filters/2.txt",
    },
    "adguard-mobile-ads": {
        "displayName": "AdGuard Mobile Ads",
        "category": "baseAds",
        "url": "https://filters.adtidy.org/extension/chromium/filters/11.txt",
    },
    "adguard-tracking-protection": {
        "displayName": "AdGuard Tracking Protection",
        "category": "privacyOverlap",
        "url": "https://filters.adtidy.org/extension/chromium/filters/3.txt",
    },
    "adguard-url-tracking": {
        "displayName": "AdGuard URL Tracking",
        "category": "privacyOverlap",
        "url": "https://filters.adtidy.org/windows/filters/17.txt",
    },
    "adguard-dns": {
        "displayName": "AdGuard DNS filter",
        "category": "baseAds",
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    },
    "ublock-filters": {
        "displayName": "uBlock filters - Ads",
        "category": "baseAds",
        "url": "https://ublockorigin.github.io/uAssets/filters/filters.txt",
    },
    "ublock-badware": {
        "displayName": "uBlock filters - Badware risks",
        "category": None,
        "url": "https://ublockorigin.github.io/uAssets/filters/badware.txt",
    },
    "ublock-privacy": {
        "displayName": "uBlock filters - Privacy",
        "category": "privacyOverlap",
        "url": "https://ublockorigin.github.io/uAssets/filters/privacy.txt",
    },
    "ublock-unbreak": {
        "displayName": "uBlock filters - Unbreak",
        "category": None,
        "url": "https://ublockorigin.github.io/uAssets/filters/unbreak.txt",
    },
    "ublock-quick-fixes": {
        "displayName": "uBlock filters - Quick fixes",
        "category": None,
        "url": "https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt",
    },
}


DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "adguardAdsPrivacy": {
        "displayName": "Lean AdGuard browser network",
        "listIds": [
            "adguard-dns",
            "adguard-base",
            "ublock-filters",
            "ublock-badware",
            "ublock-privacy",
            "ublock-unbreak",
            "ublock-quick-fixes",
        ],
        "classification": "Sumi prepared Adblock",
    },
}


@dataclass
class RawDedupeResult:
    rules: list[str]
    input_rule_count: int
    duplicate_removed: int
    skipped_count: int
    skipped_reasons: Counter[str]
    duplicate_attribution: dict[str, list[str]]
    raw_rule_count_by_list: dict[str, int]
    deduped_rule_count_by_list: dict[str, int]


@dataclass
class NativeDedupeResult:
    rules: list[dict[str, Any]]
    duplicate_removed: int
    skipped_count: int
    skipped_reasons: Counter[str]


@dataclass
class PreparedGroup:
    group_id: str
    display_name: str
    status: str
    rules: list[dict[str, Any]]
    shards: list[dict[str, Any]]
    rule_count: int
    shard_count: int
    source: dict[str, Any]
    deduplication: dict[str, Any]
    notes: list[str]

    @property
    def asset_relative_paths(self) -> list[str]:
        return sorted(shard["relativePath"] for shard in self.shards)


@dataclass
class TrackingRulesResult:
    rules: list[dict[str, Any]]
    input_rule_count: int
    source: dict[str, Any]
    deduplication: dict[str, Any]
    diagnostics: dict[str, Any]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_metadata(name: str, fallback: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    path = repo_root() / "metadata" / name
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


LISTS = load_metadata("source-lists.json", DEFAULT_LISTS)
PROFILES = load_metadata("profiles.json", DEFAULT_PROFILES)
SUPPORTED_SUMI_LIST_CATEGORIES = {
    "baseAds",
    "nativeCosmeticCompatibleAds",
    "annoyances",
    "regional",
    "privacyOverlap",
}


def validate_list_categories(lists: dict[str, dict[str, Any]]) -> None:
    for list_id, descriptor in lists.items():
        category = descriptor.get("category")
        if category is not None and category not in SUPPORTED_SUMI_LIST_CATEGORIES:
            raise ValueError(
                f"List {list_id} category {category!r} is not supported by Sumi bundle manifests"
            )


validate_list_categories(LISTS)


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def encoded_rule_list(rules: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        rules,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
        separators=(",", ": "),
    ).encode("utf-8")


def resolve_profile(profile: str) -> str:
    if profile in PROFILES:
        return profile
    for profile_id, descriptor in PROFILES.items():
        if profile in descriptor.get("aliases", []):
            return profile_id
    raise SystemExit(f"Unknown bundle profile: {profile}")


def parse_list_file_overrides(values: list[str]) -> dict[str, Path]:
    overrides: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit("--list-file expects LIST_ID=/path/to/list.txt")
        list_id, path = value.split("=", 1)
        overrides[list_id] = Path(path).expanduser().resolve()
    return overrides


def fetch_or_reuse_list(
    list_id: str,
    cache_dir: Path,
    refresh: bool,
    offline: bool,
    overrides: dict[str, Path],
) -> bytes:
    if list_id in overrides:
        return overrides[list_id].read_bytes()

    descriptor = LISTS[list_id]
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{list_id}.txt"
    if cache_path.exists() and not refresh:
        return cache_path.read_bytes()
    if offline:
        raise SystemExit(f"Missing cached list for offline build: {list_id}")

    data = fetch_url_bytes(descriptor["url"])
    if len(data) < 16:
        raise SystemExit(f"Downloaded list is suspiciously small: {list_id}")
    preview = data[:4096].decode("utf-8", errors="ignore").strip().lower()
    if preview.startswith("<!doctype html") or preview.startswith("<html"):
        raise SystemExit(f"Downloaded list appears to be HTML: {list_id}")
    cache_path.write_bytes(data)
    return data


def fetch_or_reuse_tracking_tds(
    cache_dir: Path,
    refresh: bool,
    offline: bool,
    tracking_tds_url: str,
    tracking_tds_file: Path | None,
) -> bytes:
    if tracking_tds_file is not None:
        return tracking_tds_file.read_bytes()

    tracking_cache_dir = cache_dir / "trackingNetwork"
    tracking_cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = tracking_cache_dir / "macos-tds.json"
    if cache_path.exists() and not refresh:
        return cache_path.read_bytes()
    if offline:
        raise SystemExit("Missing cached DDG TDS for offline trackingNetwork build.")

    data = fetch_url_bytes(tracking_tds_url)
    if len(data) < 1024:
        raise SystemExit("Downloaded DDG TDS is suspiciously small.")
    preview = data[:4096].decode("utf-8", errors="ignore").strip().lower()
    if preview.startswith("<!doctype html") or preview.startswith("<html"):
        raise SystemExit("Downloaded DDG TDS appears to be HTML.")
    cache_path.write_bytes(data)
    return data


def fetch_url_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SumiAdblockBundleBuilder/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.read()
    except urllib.error.URLError as error:
        curl = shutil.which("curl")
        if curl is None:
            raise SystemExit(f"Failed to fetch {url}: {error}") from error
        completed = subprocess.run(
            [
                curl,
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "20",
                "--max-time",
                "90",
                "--user-agent",
                "SumiAdblockBundleBuilder/1.0",
                url,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise SystemExit(f"Failed to fetch {url}: {detail or error}") from error
        return completed.stdout


def current_resident_memory_bytes() -> int | None:
    ps = shutil.which("ps")
    if ps is None:
        return None
    completed = subprocess.run(
        [ps, "-o", "rss=", "-p", str(os.getpid())],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    if not value:
        return None
    try:
        return int(value.splitlines()[-1].strip()) * 1024
    except ValueError:
        return None


def normalized_raw_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("!") or line.startswith("["):
            continue
        lines.append(line)
    return lines


def raw_dedupe_skip_reason(line: str) -> str | None:
    lower = line.lower()
    if line.startswith("@@") or "#@#" in line:
        return "exception rule"
    if "$badfilter" in lower or ",badfilter" in lower:
        return "badfilter rule"
    if "$important" in lower or ",important" in lower:
        return "important rule"
    if "$redirect" in lower or ",redirect" in lower or "$rewrite" in lower or "$replace" in lower:
        return "redirect/resource rule"
    if "#%#" in line or "#?#" in line or "##+js(" in lower:
        return "scriptlet/procedural rule"
    if any(marker in lower for marker in [":has(", ":has-text(", ":matches-css(", ":xpath(", ":-abp-"]):
        return "scriptlet/procedural rule"
    if "$domain=" in lower or ",domain=" in lower:
        return "domain-conditional rule"
    return None


def dedupe_raw_lists(list_texts: dict[str, str]) -> RawDedupeResult:
    seen_safe: set[str] = set()
    seen_all: defaultdict[str, list[str]] = defaultdict(list)
    output: list[str] = []
    duplicate_attribution: defaultdict[str, list[str]] = defaultdict(list)
    skipped_reasons: Counter[str] = Counter()
    raw_rule_count_by_list: dict[str, int] = {}
    deduped_rule_count_by_list: Counter[str] = Counter()
    input_rule_count = 0
    duplicate_removed = 0
    skipped_count = 0

    for list_id in sorted(list_texts):
        lines = normalized_raw_lines(list_texts[list_id])
        raw_rule_count_by_list[list_id] = len(lines)
        for line in lines:
            input_rule_count += 1
            reason = raw_dedupe_skip_reason(line)
            if reason:
                if seen_all[line]:
                    skipped_count += 1
                    skipped_reasons[reason] += 1
                output.append(line)
                deduped_rule_count_by_list[list_id] += 1
                seen_all[line].append(list_id)
                continue

            if line in seen_safe:
                duplicate_removed += 1
                duplicate_attribution[line].append(list_id)
                seen_all[line].append(list_id)
                continue

            seen_safe.add(line)
            output.append(line)
            deduped_rule_count_by_list[list_id] += 1
            seen_all[line].append(list_id)

    for line, sources in seen_all.items():
        if len(sources) > 1 and line in duplicate_attribution:
            duplicate_attribution[line] = sorted(set(sources))

    return RawDedupeResult(
        rules=output,
        input_rule_count=input_rule_count,
        duplicate_removed=duplicate_removed,
        skipped_count=skipped_count,
        skipped_reasons=skipped_reasons,
        duplicate_attribution=dict(sorted(duplicate_attribution.items())),
        raw_rule_count_by_list=raw_rule_count_by_list,
        deduped_rule_count_by_list=dict(deduped_rule_count_by_list),
    )


def build_adapter(root: Path) -> Path:
    manifest = root / "Vendor/Brave/AdblockRustAdapter/Cargo.toml"
    subprocess.run(
        ["cargo", "build", "--locked", "--manifest-path", str(manifest)],
        check=True,
        cwd=root,
    )
    helper = root / "Vendor/Brave/AdblockRustAdapter/target/debug/sumi-adblock-rust-adapter"
    if not helper.exists():
        raise SystemExit(f"adblock-rust adapter did not build: {helper}")
    return helper


def run_adapter(
    helper: Path,
    rules: list[str],
    *,
    include_native_css: bool,
) -> dict[str, Any]:
    command = [str(helper)]
    if not include_native_css:
        command.append("--skip-cosmetic")
    completed = subprocess.run(
        command,
        input=("\n".join(rules) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "adblock-rust adapter failed\n"
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return json.loads(completed.stdout.decode("utf-8"))


def split_selector_list(selector: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    index = 0
    while index < len(selector):
        char = selector[index]
        if quote:
            if char == quote:
                quote = None
            elif char == "\\":
                index += 1
        else:
            if char in {"\"", "'"}:
                quote = char
            elif char in {"[", "("}:
                depth += 1
            elif char in {"]",
                ")",
            }:
                depth = max(0, depth - 1)
            elif char == "," and depth == 0:
                part = selector[start:index].strip()
                if part:
                    parts.append(part)
                start = index + 1
        index += 1
    final = selector[start:].strip()
    if final:
        parts.append(final)
    return parts


def rightmost_selector_compound(selector: str) -> str:
    depth = 0
    quote: str | None = None
    last_boundary = 0
    index = 0
    while index < len(selector):
        char = selector[index]
        if quote:
            if char == quote:
                quote = None
            elif char == "\\":
                index += 1
        else:
            if char in {"\"", "'"}:
                quote = char
            elif char in {"[", "("}:
                depth += 1
            elif char in {"]", ")"}:
                depth = max(0, depth - 1)
            elif char in {">", "+", "~"} and depth == 0:
                last_boundary = index + 1
            elif char.isspace() and depth == 0:
                last_boundary = index + 1
        index += 1
    return selector[last_boundary:].strip()


def is_unsafe_root_selector_subject(subject: str, root: str) -> bool:
    if not subject.startswith(root):
        return False
    suffix = subject[len(root):]
    if not suffix:
        return True
    if suffix.startswith("::"):
        return False
    return suffix.startswith(".") or suffix.startswith("[") or suffix.startswith(":")


def targets_document_root_or_app_container(selector: str) -> bool:
    subject = rightmost_selector_compound(selector.strip())
    if not subject:
        return False
    lower_subject = subject.lower()
    if (
        is_unsafe_root_selector_subject(lower_subject, "html")
        or is_unsafe_root_selector_subject(lower_subject, "body")
        or is_unsafe_root_selector_subject(lower_subject, ":root")
    ):
        return True
    for app_root in ["#app", "#root", "#__next", "#__nuxt"]:
        if (
            subject == app_root
            or subject.startswith(app_root + ".")
            or subject.startswith(app_root + "[")
            or (subject.startswith(app_root + ":") and not subject.startswith(app_root + "::"))
        ):
            return True
    return False


def normalized_root_child_selector(selector: str) -> str:
    normalized = selector.strip().lower().replace("[class*=' ']", "[class*=\" \"]")
    normalized = re.sub(r"\s*>\s*", " > ", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def normalized_root_child_subject_selector(selector: str) -> str:
    index = selector.find(":has(")
    return selector if index < 0 else selector[:index]


def targets_root_child_page_shell_container(selector: str) -> bool:
    subject = normalized_root_child_subject_selector(normalized_root_child_selector(selector))
    return subject in {
        "body > div[id][class*=\" \"]",
        "body > div[id][class*=\" \"]:first-child",
        "html > body > div[id][class*=\" \"]",
        "html > body > div[id][class*=\" \"]:first-child",
    }


def unsafe_native_css_selector_reason(selector: str) -> str | None:
    if targets_document_root_or_app_container(selector):
        return "unsafe native CSS root-container selector"
    if targets_root_child_page_shell_container(selector):
        return "unsafe native CSS root-child page shell selector"
    return None


def sanitize_native_css_rules(rules: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    sanitized: list[dict[str, Any]] = []
    filtered: list[dict[str, str]] = []
    for rule in rules:
        action = rule.get("action")
        if not isinstance(action, dict) or action.get("type") != "css-display-none":
            sanitized.append(rule)
            continue
        selector = action.get("selector")
        if not isinstance(selector, str):
            sanitized.append(rule)
            continue
        retained: list[str] = []
        for component in split_selector_list(selector):
            reason = unsafe_native_css_selector_reason(component)
            if reason:
                filtered.append({"rule": component, "reason": reason})
            else:
                retained.append(component)
        if not retained:
            continue
        if len(retained) == len(split_selector_list(selector)):
            sanitized.append(rule)
        else:
            updated = json.loads(json.dumps(rule))
            updated["action"]["selector"] = ", ".join(retained)
            sanitized.append(updated)
    return sanitized, filtered


def native_dedupe_skip_reason(rule: dict[str, Any]) -> str | None:
    action = rule.get("action")
    if not isinstance(action, dict):
        return "invalid native rule"
    action_type = action.get("type")
    if action_type == "ignore-previous-rules":
        return "exception/order-sensitive native rule"
    if isinstance(action_type, str) and ("redirect" in action_type or "resource" in action_type):
        return "redirect/resource native rule"
    return None


def dedupe_native_rules(rules: list[dict[str, Any]]) -> NativeDedupeResult:
    seen: set[str] = set()
    seen_skipped: set[str] = set()
    output: list[dict[str, Any]] = []
    duplicate_removed = 0
    skipped_count = 0
    skipped_reasons: Counter[str] = Counter()
    for rule in rules:
        key = canonical_json(rule)
        reason = native_dedupe_skip_reason(rule)
        if reason:
            if key in seen_skipped:
                skipped_count += 1
                skipped_reasons[reason] += 1
            seen_skipped.add(key)
            output.append(rule)
            continue
        if key in seen:
            duplicate_removed += 1
            continue
        seen.add(key)
        output.append(rule)
    return NativeDedupeResult(output, duplicate_removed, skipped_count, skipped_reasons)


def chunk_rules(
    rules: list[dict[str, Any]],
    max_rules: int,
    max_bytes: int,
) -> list[list[dict[str, Any]]]:
    if not rules:
        return []
    chunks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_estimated_bytes = 2
    for rule in rules:
        rule_bytes = len(canonical_json(rule).encode("utf-8"))
        separator_bytes = 0 if not current else 1
        if current and (
            len(current) >= max_rules
            or current_estimated_bytes + separator_bytes + rule_bytes > max_bytes
        ):
            chunks.append(current)
            current = []
            current_estimated_bytes = 2
        current.append(rule)
        current_estimated_bytes += (0 if len(current) == 1 else 1) + rule_bytes
    if current:
        chunks.append(current)
    return chunks


def overlap_diagnostics(list_lines: dict[str, list[str]], selected_list_ids: list[str]) -> dict[str, Any]:
    safe_sets = {
        list_id: {line for line in lines if raw_dedupe_skip_reason(line) is None}
        for list_id, lines in list_lines.items()
    }
    pairs: list[dict[str, Any]] = []
    for index, left in enumerate(selected_list_ids):
        for right in selected_list_ids[index + 1:]:
            overlap = safe_sets.get(left, set()) & safe_sets.get(right, set())
            if overlap:
                pairs.append(
                    {
                        "left": left,
                        "right": right,
                        "overlapRuleCount": len(overlap),
                    }
                )
    categories = [LISTS[list_id]["category"] for list_id in selected_list_ids]
    warnings: list[str] = []
    if categories.count("baseAds") > 1:
        warnings.append("Multiple base advertising list families selected; classify as Custom/Maximum.")
    if "privacyOverlap" in categories and "baseAds" in categories:
        warnings.append("Privacy-overlap lists are selected with base lists; keep separate from Balanced.")
    if "annoyances" in categories:
        warnings.append("Annoyance list selected; classify as Custom/Maximum.")
    return {
        "pairs": pairs,
        "warnings": warnings,
    }


def regex_escape_tracker_domain(value: str) -> str:
    return value.replace("\\", "\\\\").replace(".", "\\.").replace("/", "\\/")


def wildcard_domains(domains: list[str] | None) -> list[str] | None:
    if domains is None:
        return None
    return ["*" + domain for domain in domains]


def map_resource_types(types: list[str] | None) -> list[str] | None:
    if types is None:
        return None
    return [
        TRACKER_RADAR_RESOURCE_MAPPING[value]
        for value in types
        if value in TRACKER_RADAR_RESOURCE_MAPPING
    ]


def tracking_trigger(
    url_filter: str,
    *,
    unless_domain: list[str] | None = None,
    if_domain: list[str] | None = None,
    resource_type: list[str] | None = None,
    load_type: list[str] | None = None,
    load_context: list[str] | None = None,
) -> dict[str, Any]:
    trigger: dict[str, Any] = {"url-filter": url_filter}
    if unless_domain is not None:
        trigger["unless-domain"] = unless_domain
    if if_domain is not None:
        trigger["if-domain"] = if_domain
    if resource_type is not None:
        trigger["resource-type"] = resource_type
    if load_type is not None:
        trigger["load-type"] = load_type
    if load_context is not None:
        trigger["load-context"] = load_context
    return trigger


def tracking_rule(trigger: dict[str, Any], action_type: str) -> dict[str, Any]:
    return {
        "trigger": trigger,
        "action": {"type": action_type},
    }


def tracker_owner_related_domains(tds: dict[str, Any], owner: dict[str, Any] | None) -> list[str] | None:
    owner_name = owner.get("name") if isinstance(owner, dict) else None
    if not isinstance(owner_name, str):
        return None
    entity = tds.get("entities", {}).get(owner_name)
    if not isinstance(entity, dict):
        return None
    domains = entity.get("domains")
    if not isinstance(domains, list):
        return None
    return [domain for domain in domains if isinstance(domain, str)]


def normalized_tracker_rule_filter(rule: dict[str, Any]) -> str | None:
    value = rule.get("rule")
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("http"):
        return value
    return TRACKER_RADAR_SUBDOMAIN_PREFIX + value


def tracker_matching_if_domains(matching: dict[str, Any] | None) -> list[str] | None:
    if not isinstance(matching, dict):
        return None
    domains = matching.get("domains")
    if not isinstance(domains, list):
        return None
    return ["*" + domain for domain in domains if isinstance(domain, str)]


def tracker_matching_resource_types(matching: dict[str, Any] | None) -> list[str] | None:
    if not isinstance(matching, dict):
        return None
    types = matching.get("types")
    if not isinstance(types, list):
        return None
    return map_resource_types([value for value in types if isinstance(value, str)])


def tracker_default_is_block(tracker: dict[str, Any]) -> bool:
    return tracker.get("default") in {"block", "block-ctl-fb"}


def block_tracking_rule(
    rule: dict[str, Any],
    *,
    tds: dict[str, Any],
    owner: dict[str, Any] | None,
    matching: dict[str, Any] | None = None,
    load_types: list[str],
) -> dict[str, Any] | None:
    url_filter = normalized_tracker_rule_filter(rule)
    if url_filter is None:
        return None
    if matching is not None:
        return tracking_rule(
            tracking_trigger(
                url_filter,
                if_domain=tracker_matching_if_domains(matching),
                resource_type=tracker_matching_resource_types(matching),
                load_type=["third-party"],
            ),
            "block",
        )
    return tracking_rule(
        tracking_trigger(
            url_filter,
            unless_domain=wildcard_domains(tracker_owner_related_domains(tds, owner)),
            load_type=load_types,
        ),
        "block",
    )


def ignore_previous_tracking_rule(
    rule: dict[str, Any],
    *,
    matching: dict[str, Any] | None = None,
    resource_types: list[str] | None = None,
    load_types: list[str],
    load_context: list[str] | None = None,
) -> dict[str, Any] | None:
    url_filter = normalized_tracker_rule_filter(rule)
    if url_filter is None:
        return None
    return tracking_rule(
        tracking_trigger(
            url_filter,
            if_domain=tracker_matching_if_domains(matching),
            resource_type=resource_types if resource_types is not None else tracker_matching_resource_types(matching),
            load_type=load_types,
            load_context=load_context,
        ),
        "ignore-previous-rules",
    )


def build_rules_for_ignored_tracker_rule(
    rule: dict[str, Any],
    *,
    tracker: dict[str, Any],
    tds: dict[str, Any],
    load_types: list[str],
) -> list[dict[str, Any]]:
    options = rule.get("options") if isinstance(rule.get("options"), dict) else None
    exceptions = rule.get("exceptions") if isinstance(rule.get("exceptions"), dict) else None
    owner = tracker.get("owner") if isinstance(tracker.get("owner"), dict) else None

    if rule.get("action") == "ignore":
        candidates = [
            block_tracking_rule(rule, tds=tds, owner=owner, load_types=load_types),
            ignore_previous_tracking_rule(rule, matching=options, load_types=load_types),
        ]
    elif options is None and exceptions is None:
        candidates = [
            block_tracking_rule(rule, tds=tds, owner=owner, load_types=load_types),
            ignore_previous_tracking_rule(
                rule,
                resource_types=["popup"],
                load_types=load_types,
                load_context=["top-frame"],
            ),
        ]
    elif exceptions is not None and options is not None:
        candidates = [
            block_tracking_rule(rule, tds=tds, owner=owner, matching=options, load_types=load_types),
            ignore_previous_tracking_rule(rule, matching=exceptions, load_types=load_types),
        ]
    elif options is not None:
        candidates = [
            block_tracking_rule(rule, tds=tds, owner=owner, matching=options, load_types=load_types),
        ]
    elif exceptions is not None:
        candidates = [
            block_tracking_rule(rule, tds=tds, owner=owner, load_types=load_types),
            ignore_previous_tracking_rule(rule, matching=exceptions, load_types=load_types),
        ]
    else:
        candidates = []
    return [candidate for candidate in candidates if candidate is not None]


def build_rules_for_blocked_tracker_rule(
    rule: dict[str, Any],
    *,
    tracker: dict[str, Any],
    tds: dict[str, Any],
    load_types: list[str],
) -> list[dict[str, Any]]:
    options = rule.get("options") if isinstance(rule.get("options"), dict) else None
    exceptions = rule.get("exceptions") if isinstance(rule.get("exceptions"), dict) else None
    owner = tracker.get("owner") if isinstance(tracker.get("owner"), dict) else None

    if options is not None and exceptions is not None:
        candidates = [
            ignore_previous_tracking_rule(rule, load_types=load_types),
            block_tracking_rule(rule, tds=tds, owner=owner, matching=options, load_types=load_types),
            ignore_previous_tracking_rule(rule, matching=exceptions, load_types=load_types),
        ]
    elif rule.get("action") == "ignore":
        candidates = [
            ignore_previous_tracking_rule(rule, matching=options, load_types=load_types),
        ]
    elif options is not None:
        candidates = [
            ignore_previous_tracking_rule(rule, load_types=load_types),
            block_tracking_rule(rule, tds=tds, owner=owner, matching=options, load_types=load_types),
        ]
    elif exceptions is not None:
        candidates = [
            ignore_previous_tracking_rule(rule, matching=exceptions, load_types=load_types),
        ]
    else:
        candidates = [
            block_tracking_rule(rule, tds=tds, owner=owner, load_types=load_types),
        ]
    return [candidate for candidate in candidates if candidate is not None]


def build_rules_from_tracker(
    tracker: dict[str, Any],
    *,
    tds: dict[str, Any],
    load_types: list[str],
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    if tracker_default_is_block(tracker):
        domain = tracker.get("domain")
        if isinstance(domain, str) and domain:
            url_filter = (
                TRACKER_RADAR_SUBDOMAIN_PREFIX
                + regex_escape_tracker_domain(domain)
                + TRACKER_RADAR_DOMAIN_MATCH_SUFFIX
            )
            owner = tracker.get("owner") if isinstance(tracker.get("owner"), dict) else None
            rules.append(
                tracking_rule(
                    tracking_trigger(
                        url_filter,
                        unless_domain=wildcard_domains(tracker_owner_related_domains(tds, owner)),
                        load_type=load_types,
                    ),
                    "block",
                )
            )
            rules.append(
                tracking_rule(
                    tracking_trigger(
                        url_filter,
                        resource_type=["popup"],
                        load_type=load_types,
                        load_context=["top-frame"],
                    ),
                    "ignore-previous-rules",
                )
            )

    special_rule_groups: list[list[dict[str, Any]]] = []
    tracker_rules = tracker.get("rules")
    if isinstance(tracker_rules, list):
        for rule in tracker_rules:
            if not isinstance(rule, dict):
                continue
            if tracker_default_is_block(tracker):
                built = build_rules_for_blocked_tracker_rule(rule, tracker=tracker, tds=tds, load_types=load_types)
            else:
                built = build_rules_for_ignored_tracker_rule(rule, tracker=tracker, tds=tds, load_types=load_types)
            if built:
                special_rule_groups.append(built)

    seen_special: set[str] = set()
    for group in sorted(special_rule_groups, key=len, reverse=True):
        for rule in group:
            key = canonical_json(rule)
            if key in seen_special:
                continue
            seen_special.add(key)
            rules.append(rule)
    return rules


def find_tracker_by_cname(tds: dict[str, Any], cname: str) -> dict[str, Any] | None:
    trackers = tds.get("trackers")
    if not isinstance(trackers, dict):
        return None
    current = cname
    while "." in current:
        tracker = trackers.get(current)
        if isinstance(tracker, dict):
            return tracker
        current = ".".join(current.split(".")[1:])
    return None


def validate_tds_shape(tds: Any) -> dict[str, Any]:
    if not isinstance(tds, dict):
        raise SystemExit("DDG TDS must be a JSON object.")
    for key in ["trackers", "entities", "domains"]:
        if not isinstance(tds.get(key), dict):
            raise SystemExit(f"DDG TDS is missing object field: {key}")
    if "cnames" in tds and not isinstance(tds["cnames"], dict):
        raise SystemExit("DDG TDS cnames field must be an object when present.")
    return tds


def tracking_tds_diagnostics(tds: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    trackers = tds["trackers"]
    entities = tds["entities"]
    domains = tds["domains"]
    cnames = tds.get("cnames") or {}
    defaults = Counter(
        tracker.get("default", "missing")
        for tracker in trackers.values()
        if isinstance(tracker, dict)
    )
    tracker_rule_count = 0
    trackers_with_rules = 0
    skipped_missing_rule_patterns = 0
    for tracker in trackers.values():
        if not isinstance(tracker, dict):
            continue
        tracker_rules = tracker.get("rules")
        if not isinstance(tracker_rules, list):
            continue
        trackers_with_rules += 1
        tracker_rule_count += len(tracker_rules)
        skipped_missing_rule_patterns += sum(
            1
            for rule in tracker_rules
            if not isinstance(rule, dict) or not isinstance(rule.get("rule"), str)
        )
    return {
        "sourceName": DDG_TDS_SOURCE_NAME,
        "trackerCount": len(trackers),
        "entityCount": len(entities),
        "domainCount": len(domains),
        "cnameCount": len(cnames),
        "trackerRuleCount": tracker_rule_count,
        "trackersWithSpecialRules": trackers_with_rules,
        "generatedWebKitRuleCount": len(rules),
        "defaultActionCounts": dict(sorted(defaults.items())),
        "skippedMissingRulePatternCount": skipped_missing_rule_patterns,
    }


def generate_tracking_webkit_rules_from_tds(tds: dict[str, Any]) -> list[dict[str, Any]]:
    trackers = tds["trackers"]
    rules: list[dict[str, Any]] = []
    for domain in sorted(trackers):
        tracker = trackers[domain]
        if isinstance(tracker, dict):
            rules.extend(build_rules_from_tracker(tracker, tds=tds, load_types=["third-party"]))

    cnames = tds.get("cnames") or {}
    if isinstance(cnames, dict):
        for cname_domain in sorted(cnames):
            cname = cnames[cname_domain]
            if not isinstance(cname, str):
                continue
            tracker = find_tracker_by_cname(tds, cname)
            if tracker is None:
                continue
            cname_tracker = dict(tracker)
            cname_tracker["domain"] = cname_domain
            rules.extend(
                build_rules_from_tracker(
                    cname_tracker,
                    tds=tds,
                    load_types=["first-party", "third-party"],
                )
            )
    return rules


def load_prepared_webkit_rules(path: Path) -> list[dict[str, Any]]:
    try:
        data = path.read_bytes()
        parsed = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"Prepared WebKit JSON is invalid: {path}: {error}") from error
    if not isinstance(parsed, list):
        raise SystemExit(f"Prepared WebKit JSON must be an array: {path}")
    if not parsed:
        raise SystemExit(f"Prepared WebKit JSON is empty: {path}")
    for index, rule in enumerate(parsed):
        if not isinstance(rule, dict):
            raise SystemExit(f"Prepared WebKit rule at index {index} is not an object: {path}")
        trigger = rule.get("trigger")
        action = rule.get("action")
        if not isinstance(trigger, dict) or not isinstance(action, dict):
            raise SystemExit(f"Prepared WebKit rule at index {index} is missing trigger/action objects: {path}")
        if not isinstance(trigger.get("url-filter"), str):
            raise SystemExit(f"Prepared WebKit rule at index {index} is missing trigger.url-filter: {path}")
        if not isinstance(action.get("type"), str):
            raise SystemExit(f"Prepared WebKit rule at index {index} is missing action.type: {path}")
    return parsed


def tracking_source_metadata(
    *,
    source_type: str,
    source_name: str,
    source_url: str | None,
    source_license: str,
    source_license_url: str | None,
    attribution: str | None,
    source_sha256: str,
    source_byte_size: int,
    input_path: str | None,
    generator: str,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "type": source_type,
        "name": source_name,
        "sourceName": source_name,
        "url": source_url,
        "sourceURL": source_url,
        "license": source_license,
        "sourceLicense": source_license,
        "sourceLicenseURL": source_license_url,
        "attribution": attribution,
        "sourceSha256": source_sha256,
        "sourceByteSize": source_byte_size,
        "generator": generator,
    }
    if input_path is not None:
        metadata["inputPath"] = input_path
    if source_license == DDG_TDS_SOURCE_LICENSE:
        metadata["nonCommercialOnly"] = True
        metadata["shareAlike"] = True
    return metadata


def load_tracking_rules(
    *,
    cache_dir: Path,
    refresh: bool,
    offline: bool,
    tracking_tds_url: str,
    tracking_tds_file: Path | None,
    tracking_webkit_json: Path | None,
    tracking_source_name: str | None,
    tracking_source_url: str | None,
    tracking_source_license: str | None,
) -> TrackingRulesResult:
    if tracking_webkit_json is not None:
        raw_data = tracking_webkit_json.read_bytes()
        rules = load_prepared_webkit_rules(tracking_webkit_json)
        dedupe = dedupe_native_rules(rules)
        source_name = tracking_source_name or tracking_webkit_json.name
        source_url = tracking_source_url
        source_license = tracking_source_license or "caller-attested"
        return TrackingRulesResult(
            rules=dedupe.rules,
            input_rule_count=len(rules),
            source=tracking_source_metadata(
                source_type="preparedWebKitJSON",
                source_name=source_name,
                source_url=source_url,
                source_license=source_license,
                source_license_url=None,
                attribution=None,
                source_sha256=sha256_hex(raw_data),
                source_byte_size=len(raw_data),
                input_path=str(tracking_webkit_json),
                generator="precompiled-webkit-json",
            ),
            deduplication={
                "inputRuleCount": len(rules),
                "nativeJSONDuplicateCountRemoved": dedupe.duplicate_removed,
                "skippedDedupeCount": dedupe.skipped_count,
                "skippedDedupeReasons": dict(sorted(dedupe.skipped_reasons.items())),
            },
            diagnostics={
                "sourceName": source_name,
                "generatedWebKitRuleCount": len(dedupe.rules),
                "inputPreparedWebKitRuleCount": len(rules),
            },
        )

    raw_data = fetch_or_reuse_tracking_tds(
        cache_dir=cache_dir,
        refresh=refresh,
        offline=offline,
        tracking_tds_url=tracking_tds_url,
        tracking_tds_file=tracking_tds_file,
    )
    try:
        tds = validate_tds_shape(json.loads(raw_data.decode("utf-8")))
    except json.JSONDecodeError as error:
        raise SystemExit(f"DDG TDS JSON is invalid: {error}") from error
    rules = generate_tracking_webkit_rules_from_tds(tds)
    if not rules:
        raise SystemExit("DDG TDS generated no trackingNetwork WebKit rules.")
    dedupe = dedupe_native_rules(rules)
    source_url = tracking_source_url or tracking_tds_url
    return TrackingRulesResult(
        rules=dedupe.rules,
        input_rule_count=len(rules),
        source=tracking_source_metadata(
            source_type="ddgTDS",
            source_name=tracking_source_name or DDG_TDS_SOURCE_NAME,
            source_url=source_url,
            source_license=tracking_source_license or DDG_TDS_SOURCE_LICENSE,
            source_license_url=DDG_TDS_SOURCE_LICENSE_URL,
            attribution=DDG_TDS_ATTRIBUTION,
            source_sha256=sha256_hex(raw_data),
            source_byte_size=len(raw_data),
            input_path=str(tracking_tds_file) if tracking_tds_file is not None else None,
            generator=TRACKING_GENERATOR_VERSION,
        ),
        deduplication={
            "inputRuleCount": len(rules),
            "nativeJSONDuplicateCountRemoved": dedupe.duplicate_removed,
            "skippedDedupeCount": dedupe.skipped_count,
            "skippedDedupeReasons": dict(sorted(dedupe.skipped_reasons.items())),
        },
        diagnostics=tracking_tds_diagnostics(tds, dedupe.rules),
    )


def build_tracking_group(
    *,
    bundle_dir: Path,
    generation_id: str,
    generated_at: datetime,
    tracking_rules: TrackingRulesResult,
    max_rules: int,
    max_bytes: int,
) -> PreparedGroup:
    shards = write_shards(
        bundle_dir,
        generation_id,
        "trackingNetwork",
        "network",
        TRACKING_NETWORK_GROUP_ID,
        "sumi.tracking.network",
        tracking_rules.rules,
        max_rules,
        max_bytes,
    )
    source = dict(tracking_rules.source)
    source.update(
        {
            "generatedAt": generated_at.isoformat().replace("+00:00", "Z"),
            "ruleCount": len(tracking_rules.rules),
            "shardCount": len(shards),
        }
    )
    return PreparedGroup(
        group_id=TRACKING_NETWORK_GROUP_ID,
        display_name="Tracking network",
        status="generated",
        rules=tracking_rules.rules,
        shards=shards,
        rule_count=len(tracking_rules.rules),
        shard_count=len(shards),
        source=source,
        deduplication=tracking_rules.deduplication,
        notes=[],
    )


def group_manifest_entry(group: PreparedGroup, active_levels: list[str]) -> dict[str, Any]:
    return {
        "id": group.group_id,
        "displayName": group.display_name,
        "status": group.status,
        "activeLevels": active_levels,
        "ruleCount": group.rule_count,
        "shardCount": group.shard_count,
        "assetRelativePaths": group.asset_relative_paths,
        "source": group.source,
        "deduplication": group.deduplication,
        "notes": group.notes,
    }


def cross_group_overlap_diagnostics(
    tracking_rules: list[dict[str, Any]],
    adblock_rules: list[dict[str, Any]],
) -> dict[str, Any]:
    tracking_canonical = {canonical_json(rule) for rule in tracking_rules}
    adblock_canonical = {canonical_json(rule) for rule in adblock_rules}
    exact_duplicates = tracking_canonical & adblock_canonical
    notes: list[str] = []
    if tracking_rules and adblock_rules:
        notes.append(
            "Exact duplicate WebKit JSON rules are reported across groups only; cross-group rules are not removed because Protection and Adblock activate different group sets."
        )
    else:
        notes.append("Cross-group overlap requires both trackingNetwork and adblockAdsPrivacyNetwork WebKit JSON rules.")
    return {
        "trackingNetworkRuleCount": len(tracking_rules),
        "adblockAdsPrivacyNetworkRuleCount": len(adblock_rules),
        "exactDuplicateRuleCount": len(exact_duplicates),
        "dedupeApplied": False,
        "notes": notes,
    }


def write_shards(
    bundle_dir: Path,
    generation_id: str,
    directory_name: str,
    kind: str,
    group_id: str,
    webkit_identifier_prefix: str,
    rules: list[dict[str, Any]],
    max_rules: int,
    max_bytes: int,
) -> list[dict[str, Any]]:
    group_dir = bundle_dir / directory_name
    group_dir.mkdir(parents=True, exist_ok=True)
    shards: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunk_rules(rules, max_rules, max_bytes), start=1):
        relative_path = f"{directory_name}/{directory_name}-{index:04d}.json"
        data = encoded_rule_list(chunk)
        digest = sha256_hex(data)
        (bundle_dir / relative_path).write_bytes(data)
        shards.append(
            {
                "kind": kind,
                "group": group_id,
                "logicalGroup": group_id,
                "relativePath": relative_path,
                "hash": digest,
                "byteSize": len(data),
                "ruleCount": len(chunk),
                "webKitIdentifier": f"{webkit_identifier_prefix}.{generation_id}.{index:04d}.{digest[:12]}",
            }
        )
    return shards


def build_bundle(args: argparse.Namespace) -> None:
    root = repo_root()
    profiles = [resolve_profile(args.profile)]
    if args.all_profiles:
        profiles = list(PROFILES.keys())
    overrides = parse_list_file_overrides(args.list_file)
    helper = Path(args.adapter).expanduser().resolve() if args.adapter else build_adapter(root)
    output_root = Path(args.output).expanduser().resolve()

    for profile_id in profiles:
        bundle_dir = output_root / profile_id / "SumiAdblockBundle" if args.all_profiles else output_root / "SumiAdblockBundle"
        if bundle_dir.exists():
            shutil.rmtree(bundle_dir)
        bundle_dir.mkdir(parents=True)
        build_one_bundle(
            profile_id=profile_id,
            bundle_dir=bundle_dir,
            cache_dir=Path(args.cache_dir).expanduser().resolve(),
            helper=helper,
            refresh=args.refresh,
            offline=args.offline,
            overrides=overrides,
            tracking_tds_url=args.tracking_tds_url,
            tracking_tds_file=Path(args.tracking_tds_file).expanduser().resolve()
            if args.tracking_tds_file
            else None,
            tracking_webkit_json=Path(args.tracking_webkit_json).expanduser().resolve()
            if args.tracking_webkit_json
            else None,
            tracking_source_name=args.tracking_source_name,
            tracking_source_url=args.tracking_source_url,
            tracking_source_license=args.tracking_source_license,
            max_rules=args.max_rules_per_shard,
            max_bytes=args.max_bytes_per_shard,
            include_native_css=args.include_native_css,
        )


def build_one_bundle(
    profile_id: str,
    bundle_dir: Path,
    cache_dir: Path,
    helper: Path,
    refresh: bool,
    offline: bool,
    overrides: dict[str, Path],
    tracking_tds_url: str,
    tracking_tds_file: Path | None,
    tracking_webkit_json: Path | None,
    tracking_source_name: str | None,
    tracking_source_url: str | None,
    tracking_source_license: str | None,
    max_rules: int,
    max_bytes: int,
    include_native_css: bool,
) -> None:
    profile = PROFILES[profile_id]
    selected_list_ids = profile["listIds"]
    raw_data_by_list: dict[str, bytes] = {}
    list_texts: dict[str, str] = {}
    list_lines: dict[str, list[str]] = {}
    for list_id in selected_list_ids:
        data = fetch_or_reuse_list(list_id, cache_dir, refresh, offline, overrides)
        raw_data_by_list[list_id] = data
        text = data.decode("utf-8", errors="replace")
        list_texts[list_id] = text
        list_lines[list_id] = normalized_raw_lines(text)

    memory = {
        "beforeRawDedupeResidentBytes": current_resident_memory_bytes(),
    }
    raw_dedupe = dedupe_raw_lists(list_texts)
    memory["afterRawDedupeResidentBytes"] = current_resident_memory_bytes()
    adapter_output = run_adapter(
        helper,
        raw_dedupe.rules,
        include_native_css=include_native_css,
    )
    network_input = adapter_output.get("network", [])
    css_input, filtered_css = sanitize_native_css_rules(adapter_output.get("native_cosmetic_css", []))
    memory["beforeNativeJSONDedupeResidentBytes"] = current_resident_memory_bytes()
    network_dedupe = dedupe_native_rules(network_input)
    css_dedupe = dedupe_native_rules(css_input)
    memory["afterNativeJSONDedupeResidentBytes"] = current_resident_memory_bytes()

    generated_at = datetime.now(timezone.utc)
    tracking_rules = load_tracking_rules(
        cache_dir=cache_dir,
        refresh=refresh,
        offline=offline,
        tracking_tds_url=tracking_tds_url,
        tracking_tds_file=tracking_tds_file,
        tracking_webkit_json=tracking_webkit_json,
        tracking_source_name=tracking_source_name,
        tracking_source_url=tracking_source_url,
        tracking_source_license=tracking_source_license,
    )
    seed = canonical_json(
        {
            "profile": profile_id,
            "lists": {
                list_id: sha256_hex(raw_data_by_list[list_id])
                for list_id in selected_list_ids
            },
            "network": len(network_dedupe.rules),
            "nativeCSS": len(css_dedupe.rules),
            "trackingNetwork": len(tracking_rules.rules),
            "trackingSourceSha256": tracking_rules.source.get("sourceSha256"),
            "rawDuplicates": raw_dedupe.duplicate_removed,
            "nativeDuplicates": (
                network_dedupe.duplicate_removed
                + css_dedupe.duplicate_removed
                + tracking_rules.deduplication.get("nativeJSONDuplicateCountRemoved", 0)
            ),
        }
    )
    generation_hash = sha256_hex(seed.encode("utf-8"))[:12]
    generation_id = generated_at.strftime("%Y%m%dT%H%M%SZ") + "-" + generation_hash
    bundle_id = f"sumi.adblock.bundle.{profile_id}.{generation_hash}"

    tracking_group = build_tracking_group(
        bundle_dir=bundle_dir,
        generation_id=generation_id,
        generated_at=generated_at,
        tracking_rules=tracking_rules,
        max_rules=max_rules,
        max_bytes=max_bytes,
    )
    network_shards = write_shards(
        bundle_dir,
        generation_id,
        "network",
        "network",
        ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
        "sumi.adblock.network",
        network_dedupe.rules,
        max_rules,
        max_bytes,
    )
    css_shards = write_shards(
        bundle_dir,
        generation_id,
        "nativeCSS",
        "nativeCSS",
        ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
        "sumi.adblock.nativeCSS",
        css_dedupe.rules,
        max_rules,
        max_bytes,
    )
    adblock_group = PreparedGroup(
        group_id=ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
        display_name="Adblock ads and privacy network",
        status="generated",
        rules=network_dedupe.rules,
        shards=network_shards,
        rule_count=len(network_dedupe.rules),
        shard_count=len(network_shards),
        source={
            "type": "adblockRust",
            "name": profile["displayName"],
            "url": None,
            "license": "see source lists",
            "generator": ADAPTER_VERSION,
        },
        deduplication={
            "inputRuleCount": raw_dedupe.input_rule_count,
            "rawDuplicateCountRemoved": raw_dedupe.duplicate_removed,
            "nativeJSONDuplicateCountRemoved": network_dedupe.duplicate_removed,
            "skippedDedupeCount": raw_dedupe.skipped_count + network_dedupe.skipped_count,
            "skippedDedupeReasons": dict(sorted((raw_dedupe.skipped_reasons + network_dedupe.skipped_reasons).items())),
        },
        notes=[],
    )
    groups = [tracking_group, adblock_group]
    shards = tracking_group.shards + network_shards + css_shards
    overlap = overlap_diagnostics(list_lines, selected_list_ids)
    cross_group_overlap = cross_group_overlap_diagnostics(
        tracking_group.rules,
        adblock_group.rules,
    )

    list_entries = []
    for list_id in selected_list_ids:
        descriptor = LISTS[list_id]
        list_entries.append(
            {
                "id": list_id,
                "displayName": descriptor["displayName"],
                "url": descriptor["url"],
                "hash": sha256_hex(raw_data_by_list[list_id]),
                "byteSize": len(raw_data_by_list[list_id]),
                "ruleCount": raw_dedupe.raw_rule_count_by_list[list_id],
                "dedupedRuleCount": raw_dedupe.deduped_rule_count_by_list.get(list_id, 0),
                "category": descriptor["category"],
            }
        )

    tracking_native_duplicates = tracking_group.deduplication.get("nativeJSONDuplicateCountRemoved", 0)
    tracking_skipped_count = tracking_group.deduplication.get("skippedDedupeCount", 0)
    native_duplicates = network_dedupe.duplicate_removed + css_dedupe.duplicate_removed + tracking_native_duplicates
    tracking_skipped_reasons = Counter(tracking_group.deduplication.get("skippedDedupeReasons", {}))
    skipped_reasons = raw_dedupe.skipped_reasons + network_dedupe.skipped_reasons + css_dedupe.skipped_reasons + tracking_skipped_reasons
    skipped_count = raw_dedupe.skipped_count + network_dedupe.skipped_count + css_dedupe.skipped_count + tracking_skipped_count
    final_rule_count = tracking_group.rule_count + len(network_dedupe.rules) + len(css_dedupe.rules)
    warnings = overlap["warnings"]

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "bundleId": bundle_id,
        "generationId": generation_id,
        "profileId": profile_id,
        "profileDisplayName": profile["displayName"],
        "profileClassification": profile["classification"],
        "compiler": {
            "name": "adblock-rust",
            "version": f"{ADAPTER_VERSION} {SAFETY_POLICY_VERSION}",
        },
        "nativeCSSSafetyPolicyVersion": SAFETY_POLICY_VERSION,
        "generatedDate": generated_at.isoformat().replace("+00:00", "Z"),
        "lists": list_entries,
        "profileLevelMapping": PROTECTION_LEVEL_GROUPS,
        "groups": [
            group_manifest_entry(tracking_group, ["protection", "adblock"]),
            group_manifest_entry(adblock_group, ["adblock"]),
        ],
        "shards": shards,
        "diagnosticsSummary": {
            "inputRuleCount": raw_dedupe.input_rule_count,
            "finalRuleCount": final_rule_count,
            "finalShardCount": len(shards),
            "ruleCountsByGroup": {
                group.group_id: group.rule_count
                for group in groups
            },
            "shardCountsByGroup": {
                group.group_id: group.shard_count
                for group in groups
            },
            "networkRuleCount": len(network_dedupe.rules),
            "nativeCSSRuleCount": len(css_dedupe.rules),
            "unsafeCSSFilteredCount": len(filtered_css),
            "warnings": warnings,
        },
        "unsafeCSSFilteredCount": len(filtered_css),
        "deduplication": {
            "inputRawRuleCount": raw_dedupe.input_rule_count,
            "rawDuplicateCountRemoved": raw_dedupe.duplicate_removed,
            "nativeJSONDuplicateCountRemoved": native_duplicates,
            "skippedDedupeCount": skipped_count,
            "skippedDedupeReasons": dict(sorted(skipped_reasons.items())),
            "finalRuleCount": final_rule_count,
            "finalShardCount": len(shards),
        },
    }
    diagnostics = {
        "manifest": {
            "bundleId": bundle_id,
            "profileId": profile_id,
            "generationId": generation_id,
        },
        "lists": list_entries,
        "groups": [
            group_manifest_entry(tracking_group, ["protection", "adblock"]),
            group_manifest_entry(adblock_group, ["adblock"]),
        ],
        "rawDeduplication": {
            "inputRuleCount": raw_dedupe.input_rule_count,
            "duplicatesRemoved": raw_dedupe.duplicate_removed,
            "skippedDedupeCount": raw_dedupe.skipped_count,
            "skippedDedupeReasons": dict(sorted(raw_dedupe.skipped_reasons.items())),
            "duplicateAttribution": raw_dedupe.duplicate_attribution,
        },
        "nativeJSONDeduplication": {
            "trackingNetworkDuplicatesRemoved": tracking_group.deduplication.get("nativeJSONDuplicateCountRemoved", 0),
            "trackingNetworkSkippedDedupeCount": tracking_group.deduplication.get("skippedDedupeCount", 0),
            "networkDuplicatesRemoved": network_dedupe.duplicate_removed,
            "nativeCSSDuplicatesRemoved": css_dedupe.duplicate_removed,
            "networkSkippedDedupeCount": network_dedupe.skipped_count,
            "nativeCSSSkippedDedupeCount": css_dedupe.skipped_count,
            "skippedDedupeReasons": dict(sorted((network_dedupe.skipped_reasons + css_dedupe.skipped_reasons + tracking_skipped_reasons).items())),
        },
        "trackingNetworkSource": tracking_rules.diagnostics,
        "nativeCSSSafety": {
            "policyVersion": SAFETY_POLICY_VERSION,
            "filteredCount": len(filtered_css),
            "filteredSelectors": filtered_css[:1000],
        },
        "overlap": overlap,
        "crossGroupOverlap": cross_group_overlap,
        "memory": memory,
        "adapter": {
            "unsupportedOrIgnoredCount": len(adapter_output.get("unsupported_or_ignored", [])),
            "enhancedResourceCandidateCount": len(adapter_output.get("enhanced_resource_candidates", [])),
        },
    }

    write_json(bundle_dir / "manifest.json", manifest)
    write_json(bundle_dir / "diagnostics.json", diagnostics)
    verified = verify_bundle_dir(bundle_dir, allow_empty_shards=False, quiet=True)
    print(
        f"{profile_id}: rules={final_rule_count} shards={len(shards)} "
        f"bytes={verified['totalBytes']} rawDupes={raw_dedupe.duplicate_removed} "
        f"nativeDupes={native_duplicates} unsafeCSSFiltered={len(filtered_css)}"
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def verify_bundle_dir(
    bundle_dir: Path,
    allow_empty_shards: bool,
    quiet: bool = False,
) -> dict[str, Any]:
    manifest_path = bundle_dir / "manifest.json"
    diagnostics_path = bundle_dir / "diagnostics.json"
    if not manifest_path.exists():
        raise SystemExit(f"Missing manifest: {manifest_path}")
    if not diagnostics_path.exists():
        raise SystemExit(f"Missing diagnostics: {diagnostics_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise SystemExit(f"Unsupported schemaVersion: {manifest.get('schemaVersion')}")
    required = [
        "bundleId",
        "generationId",
        "profileId",
        "compiler",
        "nativeCSSSafetyPolicyVersion",
        "generatedDate",
        "lists",
        "profileLevelMapping",
        "groups",
        "shards",
        "diagnosticsSummary",
        "deduplication",
    ]
    missing = [key for key in required if key not in manifest]
    if missing:
        raise SystemExit(f"Manifest missing required keys: {', '.join(missing)}")
    if not manifest["shards"]:
        raise SystemExit("Bundle has no shards")
    group_ids = {group.get("id") for group in manifest.get("groups", []) if isinstance(group, dict)}
    for required_group in [TRACKING_NETWORK_GROUP_ID, ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID]:
        if required_group not in group_ids:
            raise SystemExit(f"Bundle manifest missing logical group: {required_group}")

    total_rules = 0
    total_bytes = 0
    for shard in manifest["shards"]:
        relative = shard.get("relativePath")
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise SystemExit(f"Invalid shard relativePath: {relative}")
        shard_path = bundle_dir / relative
        if not shard_path.exists():
            raise SystemExit(f"Missing shard: {relative}")
        data = shard_path.read_bytes()
        if not data and not allow_empty_shards:
            raise SystemExit(f"Empty shard rejected: {relative}")
        if len(data) != shard.get("byteSize"):
            raise SystemExit(f"Shard size mismatch: {relative}")
        digest = sha256_hex(data)
        if digest != shard.get("hash"):
            raise SystemExit(f"Shard hash mismatch: {relative}")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise SystemExit(f"Shard JSON parse failed: {relative}: {error}") from error
        if not isinstance(parsed, list):
            raise SystemExit(f"Shard JSON is not an array: {relative}")
        if not parsed and not allow_empty_shards:
            raise SystemExit(f"Empty shard JSON rejected: {relative}")
        if len(parsed) != shard.get("ruleCount"):
            raise SystemExit(f"Shard rule count mismatch: {relative}")
        total_rules += len(parsed)
        total_bytes += len(data)

    dedupe = manifest["deduplication"]
    summary = manifest["diagnosticsSummary"]
    if total_rules != dedupe.get("finalRuleCount") or total_rules != summary.get("finalRuleCount"):
        raise SystemExit("Final rule count does not match shard contents")
    if len(manifest["shards"]) != dedupe.get("finalShardCount"):
        raise SystemExit("Final shard count does not match manifest shards")

    result = {
        "bundleId": manifest["bundleId"],
        "profileId": manifest["profileId"],
        "ruleCount": total_rules,
        "shardCount": len(manifest["shards"]),
        "totalBytes": total_bytes,
        "unsafeCSSFilteredCount": manifest.get("unsafeCSSFilteredCount", 0),
        "deduplication": dedupe,
    }
    if not quiet:
        print(
            f"verified {manifest['profileId']}: rules={total_rules} shards={len(manifest['shards'])} "
            f"bytes={total_bytes} unsafeCSSFiltered={result['unsafeCSSFilteredCount']} "
            f"rawDupes={dedupe.get('rawDuplicateCountRemoved')} "
            f"nativeDupes={dedupe.get('nativeJSONDuplicateCountRemoved')} "
            f"dedupeSkipped={dedupe.get('skippedDedupeCount')}"
        )
    return result


def verify_command(args: argparse.Namespace) -> None:
    verify_bundle_dir(
        Path(args.bundle).expanduser().resolve(),
        allow_empty_shards=args.allow_empty_shards,
    )


def self_test() -> None:
    raw = dedupe_raw_lists(
        {
            "a": "\n! comment\n||ads.example^\n||ads.example^\n@@||ads.example^\n@@||ads.example^\n",
            "b": "||ads.example^\n||tracker.example^$domain=example.com\n||tracker.example^$domain=example.com\n",
        }
    )
    assert raw.input_rule_count == 7
    assert raw.duplicate_removed == 2
    assert raw.skipped_count == 2
    assert raw.skipped_reasons["exception rule"] == 1
    assert raw.skipped_reasons["domain-conditional rule"] == 1

    rules = [
        {"action": {"type": "css-display-none", "selector": "body, .ad, #app"}, "trigger": {"url-filter": ".*"}},
        {"action": {"type": "css-display-none", "selector": "body > div[id][class*=\" \"]:has(div.adblock_subtitle)"}, "trigger": {"url-filter": ".*"}},
    ]
    sanitized, filtered = sanitize_native_css_rules(rules)
    assert len(sanitized) == 1
    assert sanitized[0]["action"]["selector"] == ".ad"
    assert len(filtered) == 3

    native = dedupe_native_rules(
        [
            {"action": {"type": "block"}, "trigger": {"url-filter": "ads"}},
            {"trigger": {"url-filter": "ads"}, "action": {"type": "block"}},
            {"action": {"type": "ignore-previous-rules"}, "trigger": {"url-filter": "ads"}},
            {"action": {"type": "ignore-previous-rules"}, "trigger": {"url-filter": "ads"}},
        ]
    )
    assert native.duplicate_removed == 1
    assert native.skipped_count == 1
    overlap = cross_group_overlap_diagnostics(
        [{"action": {"type": "block"}, "trigger": {"url-filter": "tracker"}}],
        [{"trigger": {"url-filter": "tracker"}, "action": {"type": "block"}}],
    )
    assert overlap["exactDuplicateRuleCount"] == 1
    assert overlap["dedupeApplied"] is False

    tds_fixture = {
        "trackers": {
            "ignored.example": {
                "domain": "ignored.example",
                "owner": {"name": "Ignored Co", "displayName": "Ignored Co"},
                "default": "ignore",
                "rules": [
                    {"rule": "ignored\\.example\\/pixel"},
                ],
            },
            "tracker.example": {
                "domain": "tracker.example",
                "owner": {"name": "Tracker Co", "displayName": "Tracker Co"},
                "default": "block",
                "rules": [
                    {
                        "rule": "tracker\\.example\\/special",
                        "options": {"domains": ["example.com"], "types": ["script"]},
                        "exceptions": {"domains": ["allowed.example"]},
                    }
                ],
            },
        },
        "entities": {
            "Ignored Co": {"domains": ["ignored.example"], "displayName": "Ignored Co"},
            "Tracker Co": {"domains": ["tracker.example", "firstparty.example"], "displayName": "Tracker Co"},
        },
        "domains": {
            "ignored.example": "Ignored Co",
            "tracker.example": "Tracker Co",
        },
        "cnames": {
            "alias.example": "tracker.example",
        },
    }
    tracking_rules = generate_tracking_webkit_rules_from_tds(validate_tds_shape(tds_fixture))
    assert any(
        rule["trigger"]["url-filter"] == "^[^:]+://+([^:/]+\\.)?tracker\\.example[:/]"
        and rule["action"]["type"] == "block"
        and rule["trigger"]["unless-domain"] == ["*tracker.example", "*firstparty.example"]
        for rule in tracking_rules
    )
    assert any(
        rule["trigger"]["url-filter"] == "^[^:]+://+([^:/]+\\.)?alias\\.example[:/]"
        and rule["trigger"]["load-type"] == ["first-party", "third-party"]
        for rule in tracking_rules
    )
    assert any(
        rule["trigger"]["url-filter"] == "^[^:]+://+([^:/]+\\.)?tracker\\.example\\/special"
        and rule["trigger"].get("if-domain") == ["*example.com"]
        and rule["trigger"].get("resource-type") == ["script"]
        and rule["action"]["type"] == "block"
        for rule in tracking_rules
    )

    with tempfile.TemporaryDirectory() as tmp:
        tds_path = Path(tmp) / "macos-tds.json"
        tds_data = json.dumps(tds_fixture, sort_keys=True).encode("utf-8")
        tds_path.write_bytes(tds_data)
        loaded_tracking = load_tracking_rules(
            cache_dir=Path(tmp),
            refresh=False,
            offline=True,
            tracking_tds_url=DDG_TDS_SOURCE_URL,
            tracking_tds_file=tds_path,
            tracking_webkit_json=None,
            tracking_source_name=None,
            tracking_source_url=None,
            tracking_source_license=None,
        )
        assert loaded_tracking.source["sourceName"] == DDG_TDS_SOURCE_NAME
        assert loaded_tracking.source["sourceLicense"] == DDG_TDS_SOURCE_LICENSE
        assert loaded_tracking.source["sourceLicenseURL"] == DDG_TDS_SOURCE_LICENSE_URL
        assert loaded_tracking.source["sourceSha256"] == sha256_hex(tds_data)
        assert loaded_tracking.diagnostics["trackerCount"] == 2
        assert loaded_tracking.diagnostics["cnameCount"] == 1

    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "SumiAdblockBundle"
        (bundle / "network").mkdir(parents=True)
        shard = [{"action": {"type": "block"}, "trigger": {"url-filter": "ads"}}]
        data = encoded_rule_list(shard)
        shard_path = bundle / "network/network-0001.json"
        shard_path.write_bytes(data)
        manifest = {
            "schemaVersion": SCHEMA_VERSION,
            "bundleId": "sumi.adblock.bundle.test",
            "generationId": "test",
            "profileId": "currentDefault",
            "compiler": {"name": "adblock-rust", "version": ADAPTER_VERSION},
            "nativeCSSSafetyPolicyVersion": SAFETY_POLICY_VERSION,
            "generatedDate": "2026-05-17T00:00:00Z",
            "lists": [],
            "profileLevelMapping": PROTECTION_LEVEL_GROUPS,
            "groups": [
                {
                    "id": TRACKING_NETWORK_GROUP_ID,
                    "displayName": "Tracking network",
                    "status": "placeholder",
                    "activeLevels": ["protection", "adblock"],
                    "ruleCount": 0,
                    "shardCount": 0,
                    "assetRelativePaths": [],
                    "source": {"type": "placeholder"},
                    "deduplication": {},
                    "notes": [],
                },
                {
                    "id": ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
                    "displayName": "Adblock ads and privacy network",
                    "status": "generated",
                    "activeLevels": ["adblock"],
                    "ruleCount": 1,
                    "shardCount": 1,
                    "assetRelativePaths": ["network/network-0001.json"],
                    "source": {"type": "test"},
                    "deduplication": {},
                    "notes": [],
                },
            ],
            "shards": [
                {
                    "kind": "network",
                    "group": ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
                    "logicalGroup": ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
                    "relativePath": "network/network-0001.json",
                    "hash": sha256_hex(data),
                    "byteSize": len(data),
                    "ruleCount": 1,
                    "webKitIdentifier": "sumi.adblock.network.test.0001.hash",
                }
            ],
            "diagnosticsSummary": {
                "inputRuleCount": 1,
                "finalRuleCount": 1,
                "finalShardCount": 1,
                "ruleCountsByGroup": {
                    TRACKING_NETWORK_GROUP_ID: 0,
                    ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID: 1,
                },
                "shardCountsByGroup": {
                    TRACKING_NETWORK_GROUP_ID: 0,
                    ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID: 1,
                },
                "networkRuleCount": 1,
                "nativeCSSRuleCount": 0,
                "unsafeCSSFilteredCount": 0,
                "warnings": [],
            },
            "unsafeCSSFilteredCount": 0,
            "deduplication": {
                "inputRawRuleCount": 1,
                "rawDuplicateCountRemoved": 0,
                "nativeJSONDuplicateCountRemoved": 0,
                "skippedDedupeCount": 0,
                "skippedDedupeReasons": {},
                "finalRuleCount": 1,
                "finalShardCount": 1,
            },
        }
        write_json(bundle / "manifest.json", manifest)
        write_json(bundle / "diagnostics.json", {"ok": True})
        verify_bundle_dir(bundle, allow_empty_shards=False, quiet=True)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify Sumi native Adblock bundles.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--profile", default="adguardAdsPrivacy")
    build.add_argument("--all-profiles", action="store_true")
    build.add_argument("--output", default=".build/sumi-adblock-bundles")
    build.add_argument("--cache-dir", default=".build/sumi-adblock-bundle/raw")
    build.add_argument("--adapter")
    build.add_argument("--refresh", action="store_true")
    build.add_argument("--offline", action="store_true")
    build.add_argument("--list-file", action="append", default=[])
    build.add_argument(
        "--tracking-tds-url",
        default=DDG_TDS_SOURCE_URL,
        help="DuckDuckGo TDS JSON URL used to generate trackingNetwork.",
    )
    build.add_argument(
        "--tracking-tds-file",
        help="Local DDG TDS JSON fixture/input used instead of fetching --tracking-tds-url.",
    )
    build.add_argument(
        "--tracking-webkit-json",
        help="Prepared WebKit JSON array override for trackingNetwork. Prefer DDG TDS generation for release builds.",
    )
    build.add_argument("--tracking-source-name")
    build.add_argument("--tracking-source-url")
    build.add_argument("--tracking-source-license")
    build.add_argument("--max-rules-per-shard", type=int, default=DEFAULT_MAX_RULES_PER_SHARD)
    build.add_argument("--max-bytes-per-shard", type=int, default=DEFAULT_MAX_BYTES_PER_SHARD)
    build.add_argument(
        "--include-native-css",
        action="store_true",
        help="Emit developer-only native CSS shards. Release/browser bundles omit them by default.",
    )
    build.set_defaults(func=build_bundle)

    verify = subparsers.add_parser("verify")
    verify.add_argument("bundle")
    verify.add_argument("--allow-empty-shards", action="store_true")
    verify.set_defaults(func=verify_command)

    tests = subparsers.add_parser("self-test")
    tests.set_defaults(func=lambda _args: self_test())
    return parser


def main() -> None:
    parser = make_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
