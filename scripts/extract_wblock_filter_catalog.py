#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


RECOMMENDED_MACOS = {
    "AdGuard Base Filter",
    "AdGuard Tracking Protection Filter",
    "AdGuard URL Tracking Protection Filter",
    "Actually Legitimate URL Shortener Tool",
    "EasyPrivacy",
    "Online Security Filter",
    "Peter Lowe's Blocklist",
    "Anti-Adblock List",
}

LEGACY_IDS = {
    "AdGuard Base Filter": "adguard-base-safari",
    "AdGuard Tracking Protection Filter": "adguard-tracking-safari",
    "AdGuard URL Tracking Protection Filter": "adguard-url-tracking",
    "Actually Legitimate URL Shortener Tool": "actually-legitimate-url-shortener",
    "EasyPrivacy": "easyprivacy-safari",
    "Online Security Filter": "online-malicious-url-safari",
    "Peter Lowe's Blocklist": "peter-lowe-safari",
    "Anti-Adblock List": "adblock-warning-removal-safari",
}


def balanced_calls(source: str, needle: str) -> list[str]:
    calls: list[str] = []
    cursor = 0
    while True:
        start = source.find(needle, cursor)
        if start < 0:
            return calls
        index = start + len(needle)
        depth = 1
        in_string = False
        escaped = False
        while index < len(source) and depth:
            char = source[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            index += 1
        if depth:
            raise ValueError(f"Unterminated {needle} call at byte {start}")
        calls.append(source[start:index])
        cursor = index


def joined_strings(value: str) -> str:
    return "".join(
        bytes(part, "utf-8").decode("unicode_escape")
        for part in re.findall(r'"((?:[^"\\]|\\.)*)"', value)
    )


def argument_region(call: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}\s*:\s*", call)
    if not match:
        return None
    start = match.end()
    index = start
    depth = 0
    in_string = False
    escaped = False
    while index < len(call):
        char = call[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "([":
            depth += 1
        elif char in ")]":
            if depth == 0:
                break
            depth -= 1
        elif char == "," and depth == 0:
            break
        index += 1
    return call[start:index].strip()


def identifier(name: str) -> str:
    if name in LEGACY_IDS:
        return LEGACY_IDS[name]
    value = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return value


def decode_call(call: str) -> dict[str, Any]:
    name_region = argument_region(call, "name")
    url_region = argument_region(call, "url")
    category_region = argument_region(call, "category")
    if not name_region or not url_region or not category_region:
        raise ValueError(f"Incomplete FilterList call: {call[:100]}")
    name = joined_strings(name_region)
    url = joined_strings(url_region)
    category_match = re.search(r"(?:FilterListCategory\.)?\.?([A-Za-z]+)", category_region)
    if not name or not url or not category_match:
        raise ValueError(f"Invalid FilterList call for {name or 'unknown'}")
    description = joined_strings(argument_region(call, "description") or "")
    languages = re.findall(r'"([A-Za-z_-]+)"', argument_region(call, "languages") or "")
    trust_level = joined_strings(argument_region(call, "trustLevel") or "") or None
    result: dict[str, Any] = {
        "id": identifier(name),
        "displayName": name,
        "url": url,
        "category": category_match.group(1),
        "defaultEnabled": name in RECOMMENDED_MACOS,
        "description": description,
    }
    if languages:
        result["languages"] = languages
    if trust_level:
        result["trustLevel"] = trust_level
    return result


def extract(source_path: Path) -> list[dict[str, Any]]:
    source = source_path.read_text(encoding="utf-8")
    start = source.index("private func createDefaultFilterLists()")
    end = source.index("return filterLists", start)
    body = source[start:end]
    body = re.sub(
        r"#if os\(iOS\).*?#endif",
        "",
        body,
        flags=re.DOTALL,
    )
    body = re.sub(r"#if os\(macOS\)|#endif", "", body)
    catalog = [decode_call(call) for call in balanced_calls(body, "FilterList(")]
    ids = [item["id"] for item in catalog]
    if len(catalog) != 79 or len(ids) != len(set(ids)):
        raise ValueError(
            f"Expected 79 unique macOS lists from pinned wBlock, got {len(catalog)}"
        )
    return catalog


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = {
        "schemaVersion": 1,
        "wBlockRevision": "15f65096ccb5a36fdea6883b526037884cb9a60a",
        "lists": extract(args.source),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
