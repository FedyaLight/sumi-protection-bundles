#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from sumi_adblock_bundle import (
    ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
    DDG_TDS_SOURCE_URL,
    PROTECTION_LEVEL_GROUPS,
    SAFETY_POLICY_VERSION,
    SCHEMA_VERSION,
    TRACKING_NETWORK_GROUP_ID,
    build_tracking_group,
    fetch_or_reuse_list,
    group_manifest_entry,
    load_tracking_rules,
    normalized_raw_lines,
    parse_list_file_overrides,
    repo_root,
    sha256_hex,
    verify_bundle_dir,
    write_json,
)


SAFARI_CONVERTER_REVISION = "7a2e93f0afa70479cc59985f332025236c3f0c39"
SAFARI_CONVERTER_VERSION = "4.3.0"
DEFAULT_SAFARI_VERSION = "18"
SLOT_TYPES: tuple[tuple[str, ...], ...] = (
    ("general",),
    ("privacy",),
    ("social", "security"),
    ("other",),
    ("custom",),
)
REMOVE_PARAM_RECOGNIZED_OPTIONS = {
    "removeparam", "domain", "to", "third-party", "~third-party",
    "match-case", "important", "badfilter", "document", "main_frame",
    "subdocument", "sub_frame", "stylesheet", "script", "image", "font",
    "object", "xmlhttprequest", "xhr", "ping", "media", "websocket", "other",
}
REMOVE_PARAM_SKIPPED_OPTIONS = {
    "app", "cname", "content", "cookie", "csp", "denyallow", "header",
    "hls", "jsonprune", "permissions", "redirect", "referrerpolicy",
    "removeheader", "replace", "strict1p", "strict3p", "urlblock", "webrtc",
}
REMOVE_PARAM_RESOURCE_TYPES = {
    "document": ["main_frame", "sub_frame"],
    "main_frame": ["main_frame"],
    "subdocument": ["sub_frame"],
    "sub_frame": ["sub_frame"],
    "stylesheet": ["stylesheet"],
    "script": ["script"],
    "image": ["image"],
    "font": ["font"],
    "object": ["object"],
    "xmlhttprequest": ["xmlhttprequest"],
    "xhr": ["xmlhttprequest"],
    "ping": ["ping"],
    "media": ["media"],
    "websocket": ["websocket"],
    "other": ["other"],
}


@dataclass(frozen=True)
class SourceList:
    identifier: str
    display_name: str
    url: str
    category: str | None
    data: bytes
    lines: list[str]

    @property
    def rule_count(self) -> int:
        return len(self.lines)


@dataclass(frozen=True)
class Conversion:
    safari_json: bytes
    safari_rule_count: int
    advanced_rules: str
    advanced_rule_count: int
    source_rule_count: int
    error_count: int


def load_catalog(
    profile_id: str = "wblockDefault",
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    profiles = json.loads(
        (repo_root() / "metadata/profiles.json").read_text(encoding="utf-8")
    )
    lists = json.loads(
        (repo_root() / "metadata/source-lists.json").read_text(encoding="utf-8")
    )
    profile = profiles.get(profile_id)
    if not isinstance(profile, dict):
        raise SystemExit(f"Unknown parity profile: {profile_id}")
    descriptors = []
    for identifier in profile["listIds"]:
        descriptor = lists.get(identifier)
        if not isinstance(descriptor, dict):
            raise SystemExit(f"Profile references unknown list: {identifier}")
        descriptors.append({"id": identifier, **descriptor})
    return profile_id, profile, descriptors


def build_converter_tool(root: Path) -> Path:
    checkout = root / ".build" / f"SafariConverterLib-{SAFARI_CONVERTER_REVISION[:12]}"
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "https://github.com/AdguardTeam/SafariConverterLib.git",
                str(checkout),
            ],
            check=True,
        )
    subprocess.run(
        ["git", "checkout", "--detach", SAFARI_CONVERTER_REVISION],
        cwd=checkout,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != SAFARI_CONVERTER_REVISION:
        raise SystemExit(f"SafariConverterLib revision mismatch: {head}")
    subprocess.run(
        [
            "swift",
            "build",
            "--package-path",
            str(checkout),
            "--configuration",
            "release",
            "--product",
            "ConverterTool",
        ],
        check=True,
    )
    bin_path = subprocess.run(
        [
            "swift",
            "build",
            "--package-path",
            str(checkout),
            "--configuration",
            "release",
            "--show-bin-path",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tool = Path(bin_path) / "ConverterTool"
    if not tool.is_file():
        raise SystemExit(f"SafariConverterLib ConverterTool was not built: {tool}")
    return tool


def distribute(sources: list[SourceList]) -> list[list[SourceList]]:
    slots: list[list[SourceList]] = [[] for _ in SLOT_TYPES]
    totals = [0 for _ in SLOT_TYPES]
    for source in sorted(sources, key=lambda item: (-item.rule_count, item.identifier)):
        slot = min(range(len(slots)), key=lambda index: (totals[index], index))
        slots[slot].append(source)
        totals[slot] += source.rule_count
    return slots


def affinity_rules(
    lines: list[str],
    *,
    include_base_rules: bool,
    target_types: tuple[str, ...],
) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    affinity: set[str] | None = None
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue
        if index == 0 and "adblock plus" in line.lower():
            continue
        if line.startswith("!#safari_cb_affinity(") and line.endswith(")"):
            values = line[len("!#safari_cb_affinity(") : -1]
            affinity = {value.strip() for value in values.split(",") if value.strip()}
            continue
        if line == "!#safari_cb_affinity":
            affinity = None
            continue
        if line.startswith("!"):
            continue
        selected = include_base_rules and affinity is None
        if affinity is not None:
            selected = "all" in affinity or bool(affinity.intersection(target_types))
        if selected and line not in seen:
            seen.add(line)
            output.append(line)
    return output


def slot_rules(
    sources: list[SourceList],
    assigned: list[SourceList],
    target_types: tuple[str, ...],
) -> list[str]:
    assigned_ids = {source.identifier for source in assigned}
    output: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for rule in affinity_rules(
            source.data.decode("utf-8", errors="replace").splitlines(),
            include_base_rules=source.identifier in assigned_ids,
            target_types=target_types,
        ):
            if rule not in seen:
                seen.add(rule)
                output.append(rule)
    return output


def convert(
    tool: Path,
    rules: list[str],
    input_path: Path,
    safari_version: str,
) -> Conversion:
    input_path.parent.mkdir(parents=True, exist_ok=True)
    input_path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    completed = subprocess.run(
        [
            str(tool),
            "convert",
            "--input-path",
            str(input_path),
            "--safari-version",
            safari_version,
            "--advanced-blocking",
            "true",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    discarded = int(result["discardedSafariRules"])
    if discarded != 0:
        raise SystemExit(
            f"SafariConverterLib discarded {discarded} rules; add a content-blocker slot"
        )
    safari_json = (result["safariRulesJSON"] + "\n").encode("utf-8")
    parsed = json.loads(safari_json)
    if len(parsed) != int(result["safariRulesCount"]):
        raise SystemExit("SafariConverterLib rule count does not match its JSON")
    return Conversion(
        safari_json=safari_json,
        safari_rule_count=int(result["safariRulesCount"]),
        advanced_rules=result.get("advancedRulesText") or "",
        advanced_rule_count=int(result["advancedRulesCount"]),
        source_rule_count=int(result["sourceRulesCount"]),
        error_count=int(result["errorsCount"]),
    )


def native_shard(
    bundle_dir: Path,
    generation_id: str,
    index: int,
    conversion: Conversion,
) -> dict[str, Any]:
    relative_path = f"network/network-{index:04d}.json"
    path = bundle_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(conversion.safari_json)
    digest = sha256_hex(conversion.safari_json)
    return {
        "kind": "network",
        "group": ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
        "logicalGroup": ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
        "relativePath": relative_path,
        "hash": digest,
        "byteSize": len(conversion.safari_json),
        "ruleCount": conversion.safari_rule_count,
        "webKitIdentifier": (
            f"sumi.adblock.wblock.{generation_id}.{index:04d}.{digest[:12]}"
        ),
    }


def option_pair(option: str) -> tuple[str, str | None]:
    name, separator, value = option.partition("=")
    return name.strip().lower(), value if separator else None


def parse_domains(value: str | None) -> tuple[list[str], list[str]] | None:
    if value is None or not value:
        return None
    included: list[str] = []
    excluded: list[str] = []
    for raw_domain in value.split("|"):
        domain = raw_domain.strip().lower()
        if not domain:
            return None
        is_excluded = domain.startswith("~")
        if is_excluded:
            domain = domain[1:]
        if (
            not domain
            or any(character in domain for character in "*/:")
            or not all(character.isalnum() or character in ".-" for character in domain)
        ):
            return None
        (excluded if is_excluded else included).append(domain)
    return sorted(included), sorted(excluded)


def decode_removeparam_value(value: str) -> str | None:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return None
    try:
        return unquote(value, errors="strict")
    except UnicodeDecodeError:
        return None


def removeparam_condition(
    pattern: str,
    value: str,
    options: list[tuple[str, str | None]],
) -> dict[str, Any] | None:
    names = [name for name, _ in options]
    for name in names:
        if name.startswith("~") and name[1:] in REMOVE_PARAM_RESOURCE_TYPES:
            return None
        if name in REMOVE_PARAM_SKIPPED_OPTIONS or name == "method":
            return None
        if name not in REMOVE_PARAM_RECOGNIZED_OPTIONS:
            return None
    if value.startswith("~") or value.startswith("/") or "|" in value:
        return None
    decoded = decode_removeparam_value(value)
    if decoded is None:
        return None
    if value and (not decoded or decoded.strip() != decoded or any(c.isspace() for c in decoded)):
        return None
    normalized_pattern = pattern.strip()
    if (
        len(normalized_pattern) > 1
        and normalized_pattern.startswith("/")
        and normalized_pattern.endswith("/")
    ):
        return None
    if normalized_pattern.startswith("||*"):
        normalized_pattern = normalized_pattern[2:]
    url_filter = normalized_pattern or None
    if decoded:
        if any(character in decoded for character in "|*^"):
            return None
        token = f"^{decoded}="
        url_filter = f"{url_filter}*{token}" if url_filter else token

    condition: dict[str, Any] = {}
    if url_filter:
        condition["urlFilter"] = url_filter
    resource_types: list[str] = []
    for name in names:
        for resource_type in REMOVE_PARAM_RESOURCE_TYPES.get(name, []):
            if resource_type not in resource_types:
                resource_types.append(resource_type)
    condition["resourceTypes"] = resource_types or ["main_frame", "sub_frame"]

    for option_name, included_key, excluded_key in [
        ("domain", "initiatorDomains", "excludedInitiatorDomains"),
        ("to", "requestDomains", "excludedRequestDomains"),
    ]:
        matches = [option_value for name, option_value in options if name == option_name]
        if not matches:
            continue
        parsed = parse_domains(matches[0])
        if parsed is None or any(parse_domains(item) is None for item in matches[1:]):
            return None
        included, excluded = parsed
        if included:
            condition[included_key] = included
        if excluded:
            condition[excluded_key] = excluded
    if "third-party" in names:
        condition["domainType"] = "thirdParty"
    elif "~third-party" in names:
        condition["domainType"] = "firstParty"
    if "match-case" in names:
        condition["isUrlFilterCaseSensitive"] = True
    return condition


def make_removeparam_rule(raw_line: str, rule_id: int) -> dict[str, Any] | None:
    line = raw_line.strip()
    if not line or line.startswith(("!", "#", "[")):
        return None
    is_exception = line.startswith("@@")
    if is_exception:
        line = line[2:]
    pattern, separator, options_text = line.rpartition("$")
    if not separator:
        return None
    raw_options = [item.strip() for item in options_text.split(",") if item.strip()]
    options = [option_pair(item) for item in raw_options]
    remove_values = [value or "" for name, value in options if name == "removeparam"]
    if not remove_values:
        return None
    names = [name for name, _ in options]
    if "badfilter" in names or any(name == "~removeparam" for name in names):
        return None
    value = remove_values[0]
    condition = removeparam_condition(pattern, value, options)
    if condition is None:
        return None
    if is_exception:
        action: dict[str, Any] = {"type": "allow"}
        priority = 10_000
    elif value:
        decoded = decode_removeparam_value(value)
        if decoded is None:
            return None
        action = {
            "type": "redirect",
            "redirect": {
                "transform": {
                    "queryTransform": {"removeParams": [decoded]},
                }
            },
        }
        priority = 1_000 if "important" in names else 1
    else:
        action = {
            "type": "redirect",
            "redirect": {"transform": {"query": ""}},
        }
        priority = 1_000 if "important" in names else 1
    return {
        "id": rule_id,
        "priority": priority,
        "action": action,
        "condition": condition,
    }


def write_removeparam_rules(
    sources: list[SourceList],
    bundle_dir: Path,
) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    source_count = 0
    for source in sources:
        for raw_line in source.data.decode("utf-8", errors="replace").splitlines():
            if "removeparam" not in raw_line.lower():
                continue
            source_count += 1
            rule = make_removeparam_rule(raw_line, 1_500_000 + len(rules))
            if rule is not None and len(rules) < 5_000:
                rules.append(rule)
    relative_path = ".webext/removeparam.json"
    data = (
        json.dumps(rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    path = bundle_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "role": "urlCleaningRules",
        "relativePath": relative_path,
        "hash": sha256_hex(data),
        "byteSize": len(data),
        "ruleCount": len(rules),
        "sourceRuleCount": source_count,
    }


def build_engine(
    tool: Path,
    bundle_dir: Path,
    advanced_rules: list[str],
    removeparam_artifact: dict[str, Any],
    safari_version: str,
) -> dict[str, Any]:
    combined = "\n".join(rule for rule in advanced_rules if rule).strip()
    if not combined:
        raise SystemExit("wBlock parity build produced no advanced rules")
    input_path = bundle_dir / ".webext-input.txt"
    input_path.write_text(combined + "\n", encoding="utf-8")
    subprocess.run(
        [
            str(tool),
            "buildengine",
            "--input-path",
            str(input_path),
            "--safari-version",
            safari_version,
            "--output-dir",
            str(bundle_dir),
        ],
        check=True,
    )
    input_path.unlink()
    roles = [
        ("ruleStorage", ".webext/rules.bin"),
        ("engineIndex", ".webext/engine.bin"),
        ("engineMetadata", ".webext/meta.bin"),
        ("sourceRules", ".webext/rules.txt"),
    ]
    artifacts = []
    for role, relative_path in roles:
        data = (bundle_dir / relative_path).read_bytes()
        artifacts.append(
            {
                "role": role,
                "relativePath": relative_path,
                "hash": sha256_hex(data),
                "byteSize": len(data),
            }
        )
    artifacts.append(
        {
            key: value
            for key, value in removeparam_artifact.items()
            if key in {"role", "relativePath", "hash", "byteSize"}
        }
    )
    return {
        "format": "safari-converter-filter-engine",
        "schemaVersion": 1,
        "runtimeVersion": SAFARI_CONVERTER_VERSION,
        "ruleCount": len(combined.splitlines()),
        "artifacts": artifacts,
    }


def build(args: argparse.Namespace) -> None:
    root = repo_root()
    if args.all_profiles:
        profiles = json.loads(
            (root / "metadata/profiles.json").read_text(encoding="utf-8")
        )
        for profile_id in sorted(profiles):
            child_args = argparse.Namespace(**vars(args))
            child_args.all_profiles = False
            child_args.profile = profile_id
            build(child_args)
        return

    profile_id, profile, descriptors = load_catalog(args.profile)
    safari_version = str(profile.get("safariVersion", DEFAULT_SAFARI_VERSION))
    output_root = Path(args.output).expanduser().resolve()
    bundle_dir = output_root / profile_id / "SumiAdblockBundle"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)
    overrides = parse_list_file_overrides(args.list_file)
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    tool = (
        Path(args.converter_tool).expanduser().resolve()
        if args.converter_tool
        else build_converter_tool(root)
    )

    sources: list[SourceList] = []
    for descriptor in descriptors:
        data = fetch_or_reuse_list(
            descriptor["id"], cache_dir, args.refresh, args.offline, overrides
        )
        sources.append(
            SourceList(
                identifier=descriptor["id"],
                display_name=descriptor["displayName"],
                url=descriptor["url"],
                category=descriptor.get("category"),
                data=data,
                lines=normalized_raw_lines(data.decode("utf-8", errors="replace")),
            )
        )

    slots = distribute(sources)
    conversions: list[Conversion] = []
    native_shards: list[dict[str, Any]] = []
    build_inputs = output_root / ".inputs" / profile_id
    for index, (assigned, target_types) in enumerate(zip(slots, SLOT_TYPES), start=1):
        rules = slot_rules(sources, assigned, target_types)
        conversion = convert(
            tool,
            rules,
            build_inputs / f"slot-{index}.txt",
            safari_version,
        )
        conversions.append(conversion)
        native_shards.append(
            native_shard(bundle_dir, "pending", index, conversion)
        )

    removeparam = write_removeparam_rules(sources, bundle_dir)
    advanced = build_engine(
        tool,
        bundle_dir,
        [conversion.advanced_rules for conversion in conversions],
        removeparam,
        safari_version,
    )
    tracking = load_tracking_rules(
        cache_dir=cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        tracking_tds_url=args.tracking_tds_url,
        tracking_tds_file=(
            Path(args.tracking_tds_file).expanduser().resolve()
            if args.tracking_tds_file
            else None
        ),
        tracking_webkit_json=None,
        tracking_source_name=None,
        tracking_source_url=None,
        tracking_source_license=None,
    )

    generated_at = datetime.now(timezone.utc)
    seed = json.dumps(
        {
            "profile": profile_id,
            "sources": {source.identifier: sha256_hex(source.data) for source in sources},
            "native": [shard["hash"] for shard in native_shards],
            "advanced": [artifact["hash"] for artifact in advanced["artifacts"]],
            "tracking": tracking.source["sourceSha256"],
            "compiler": SAFARI_CONVERTER_REVISION,
            "safariVersion": safari_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    generation_hash = sha256_hex(seed.encode("utf-8"))[:12]
    generation_id = generated_at.strftime("%Y%m%dT%H%M%SZ") + "-" + generation_hash
    bundle_id = f"sumi.adblock.bundle.{profile_id}.{generation_hash}"
    for index, shard in enumerate(native_shards, start=1):
        shard["webKitIdentifier"] = (
            f"sumi.adblock.wblock.{generation_id}.{index:04d}.{shard['hash'][:12]}"
        )

    tracking_group = build_tracking_group(
        bundle_dir=bundle_dir,
        generation_id=generation_id,
        generated_at=generated_at,
        tracking_rules=tracking,
        max_rules=args.max_rules_per_shard,
        max_bytes=args.max_bytes_per_shard,
    )
    native_rule_count = sum(item.safari_rule_count for item in conversions)
    adblock_group = {
        "id": ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID,
        "displayName": "wBlock default protection",
        "status": "generated",
        "activeLevels": ["adblock"],
        "ruleCount": native_rule_count,
        "shardCount": len(native_shards),
        "assetRelativePaths": sorted(item["relativePath"] for item in native_shards),
        "source": {
            "type": "wBlockParity",
            "name": profile["displayName"],
            "url": "https://github.com/0xCUB3/wBlock",
            "license": "GPL-3.0",
            "generator": f"SafariConverterLib/{SAFARI_CONVERTER_VERSION}",
            "wBlockRevision": profile["wBlockRevision"],
        },
        "deduplication": {
            "strategy": "wBlock affinity-aware five-slot distribution",
            "nativeJSONDuplicateCountRemoved": 0,
        },
        "notes": [
            "Native WebKit JSON and advanced FilterEngine are generated from the same slot inputs.",
            f"SafariConverterLib target matches wBlock's Safari {safari_version} conversion path.",
            "No converted Safari rule was discarded by the platform rule cap.",
        ],
    }
    shards = tracking_group.shards + native_shards
    list_entries = [
        {
            "id": source.identifier,
            "displayName": source.display_name,
            "url": source.url,
            "hash": sha256_hex(source.data),
            "byteSize": len(source.data),
            "ruleCount": source.rule_count,
            "dedupedRuleCount": source.rule_count,
            "category": source.category,
        }
        for source in sources
    ]
    final_rule_count = sum(shard["ruleCount"] for shard in shards)
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "bundleId": bundle_id,
        "generationId": generation_id,
        "profileId": profile_id,
        "profileDisplayName": profile["displayName"],
        "profileClassification": profile["classification"],
        "compiler": {
            "name": "SafariConverterLib",
            "version": SAFARI_CONVERTER_VERSION,
        },
        "targetSafariVersion": safari_version,
        "nativeCSSSafetyPolicyVersion": SAFETY_POLICY_VERSION,
        "generatedDate": generated_at.isoformat().replace("+00:00", "Z"),
        "lists": list_entries,
        "profileLevelMapping": PROTECTION_LEVEL_GROUPS,
        "groups": [
            group_manifest_entry(tracking_group, ["protection"]),
            adblock_group,
        ],
        "shards": shards,
        "advancedBlocking": advanced,
        "diagnosticsSummary": {
            "inputRuleCount": sum(source.rule_count for source in sources),
            "finalRuleCount": final_rule_count,
            "finalShardCount": len(shards),
            "ruleCountsByGroup": {
                TRACKING_NETWORK_GROUP_ID: tracking_group.rule_count,
                ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID: native_rule_count,
            },
            "shardCountsByGroup": {
                TRACKING_NETWORK_GROUP_ID: tracking_group.shard_count,
                ADBLOCK_ADS_PRIVACY_NETWORK_GROUP_ID: len(native_shards),
            },
            "networkRuleCount": native_rule_count,
            "nativeCSSRuleCount": 0,
            "advancedRuleCount": advanced["ruleCount"],
            "urlCleaningRuleCount": removeparam["ruleCount"],
            "unsafeCSSFilteredCount": 0,
            "warnings": [],
        },
        "unsafeCSSFilteredCount": 0,
        "deduplication": {
            "inputRawRuleCount": sum(source.rule_count for source in sources),
            "rawDuplicateCountRemoved": 0,
            "nativeJSONDuplicateCountRemoved": 0,
            "skippedDedupeCount": 0,
            "skippedDedupeReasons": {},
            "finalRuleCount": final_rule_count,
            "finalShardCount": len(shards),
        },
    }
    diagnostics = {
        "manifest": {
            "bundleId": bundle_id,
            "profileId": profile_id,
            "generationId": generation_id,
            "targetSafariVersion": safari_version,
        },
        "lists": list_entries,
        "slotAssignments": [
            {
                "slot": index,
                "types": list(SLOT_TYPES[index - 1]),
                "listIds": [source.identifier for source in assigned],
                "sourceRuleCount": sum(source.rule_count for source in assigned),
                "convertedSourceRuleCount": conversions[index - 1].source_rule_count,
                "safariRuleCount": conversions[index - 1].safari_rule_count,
                "advancedRuleCount": conversions[index - 1].advanced_rule_count,
                "conversionErrorCount": conversions[index - 1].error_count,
            }
            for index, assigned in enumerate(slots, start=1)
        ],
        "advancedBlocking": advanced,
        "urlCleaning": {
            "sourceRuleCount": removeparam["sourceRuleCount"],
            "generatedRuleCount": removeparam["ruleCount"],
            "skippedRuleCount": (
                removeparam["sourceRuleCount"] - removeparam["ruleCount"]
            ),
        },
        "trackingNetworkSource": tracking.diagnostics,
    }
    write_json(bundle_dir / "manifest.json", manifest)
    write_json(bundle_dir / "diagnostics.json", diagnostics)
    shutil.copyfile(
        root / "metadata/wblock-filter-catalog.json",
        bundle_dir / "filter-catalog.json",
    )
    verified = verify_bundle_dir(bundle_dir, allow_empty_shards=False, quiet=True)
    print(
        f"{profile_id}: native={native_rule_count} advanced={advanced['ruleCount']} "
        f"shards={len(native_shards)} bytes={verified['totalBytes']}"
    )


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build Sumi's wBlock-parity prepared blocker generation."
    )
    parser.add_argument("--profile", default="wblockDefault")
    parser.add_argument("--all-profiles", action="store_true")
    parser.add_argument("--output", default=".build/sumi-adblock-bundles")
    parser.add_argument("--cache-dir", default=".build/sumi-adblock-bundle/raw")
    parser.add_argument("--converter-tool")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--list-file", action="append", default=[])
    parser.add_argument("--tracking-tds-url", default=DDG_TDS_SOURCE_URL)
    parser.add_argument("--tracking-tds-file")
    parser.add_argument("--max-rules-per-shard", type=int, default=100_000)
    parser.add_argument("--max-bytes-per-shard", type=int, default=14_000_000)
    return parser


if __name__ == "__main__":
    build(make_parser().parse_args())
