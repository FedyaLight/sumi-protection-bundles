#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from extract_wblock_filter_catalog import RECOMMENDED_MACOS, extract


ROOT = Path(__file__).resolve().parents[1]
WBLOCK_SOURCE = (
    ROOT.parent
    / "references"
    / "wBlock"
    / "wBlock"
    / "FilterListLoader.swift"
)


class WBlockFilterCatalogParityTests(unittest.TestCase):
    def test_checked_catalog_matches_pinned_wblock_source(self) -> None:
        expected = extract(WBLOCK_SOURCE)
        checked = json.loads(
            (ROOT / "metadata" / "wblock-filter-catalog.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(checked["lists"], expected)
        self.assertEqual(len(checked["lists"]), 79)
        self.assertEqual(
            {item["displayName"] for item in checked["lists"] if item["defaultEnabled"]},
            RECOMMENDED_MACOS,
        )


if __name__ == "__main__":
    unittest.main()
