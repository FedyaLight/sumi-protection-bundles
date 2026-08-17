#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().with_name("wblock_parity_bundle.py")
SPEC = importlib.util.spec_from_file_location("wblock_parity_bundle", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["wblock_parity_bundle"] = MODULE
SPEC.loader.exec_module(MODULE)


class WBlockDefaultCatalogParityTests(unittest.TestCase):
    def test_catalog_is_the_exact_pinned_macos_default(self) -> None:
        profile_id, profile, descriptors = MODULE.load_catalog()

        self.assertEqual(profile_id, "wblockDefault")
        self.assertEqual(profile["safariVersion"], "18")
        self.assertEqual(
            profile["wBlockRevision"],
            "15f65096ccb5a36fdea6883b526037884cb9a60a",
        )
        self.assertEqual(MODULE.SAFARI_CONVERTER_VERSION, "4.3.0")
        self.assertEqual(
            MODULE.SAFARI_CONVERTER_REVISION,
            "7a2e93f0afa70479cc59985f332025236c3f0c39",
        )
        self.assertEqual(
            [(item["displayName"], item["url"]) for item in descriptors],
            [
                (
                    "AdGuard Base Filter",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/2_optimized.txt",
                ),
                (
                    "AdGuard Tracking Protection Filter",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/3_optimized.txt",
                ),
                (
                    "AdGuard URL Tracking Protection Filter",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
                ),
                (
                    "Actually Legitimate URL Shortener Tool",
                    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
                ),
                (
                    "EasyPrivacy",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/118_optimized.txt",
                ),
                (
                    "Online Security Filter",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/208_optimized.txt",
                ),
                (
                    "Peter Lowe's Blocklist",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/204_optimized.txt",
                ),
                (
                    "Anti-Adblock List",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/207_optimized.txt",
                ),
            ],
        )
        self.assertEqual(
            MODULE.SLOT_TYPES,
            (
                ("general",),
                ("privacy",),
                ("social", "security"),
                ("other",),
                ("custom",),
            ),
        )

        modern_id, modern_profile, modern_descriptors = MODULE.load_catalog(
            "wblockDefaultSafari26"
        )
        self.assertEqual(modern_id, "wblockDefaultSafari26")
        self.assertEqual(modern_profile["safariVersion"], "26")
        self.assertEqual(
            [(item["displayName"], item["url"]) for item in modern_descriptors],
            [(item["displayName"], item["url"]) for item in descriptors],
        )


class RemoveParamParityTests(unittest.TestCase):
    def make(self, line: str, rule_id: int = 1_500_000):
        return MODULE.make_removeparam_rule(line, rule_id)

    def test_matches_wblock_supported_rule_shapes(self) -> None:
        generic = self.make("$removeparam=utm_source")
        self.assertEqual(generic["condition"]["urlFilter"], "^utm_source=")
        self.assertEqual(
            generic["condition"]["resourceTypes"], ["main_frame", "sub_frame"]
        )
        self.assertEqual(
            generic["action"]["redirect"]["transform"]["queryTransform"]
            ["removeParams"],
            ["utm_source"],
        )

        scoped = self.make("||example.com^$removeparam=fbclid")
        self.assertEqual(
            scoped["condition"]["urlFilter"], "||example.com^*^fbclid="
        )

        exception = self.make("@@||example.com^$removeparam=fbclid")
        self.assertEqual(exception["action"]["type"], "allow")
        self.assertEqual(exception["priority"], 10_000)

        strip_all = self.make("||example.org^$removeparam")
        self.assertEqual(
            strip_all["action"]["redirect"]["transform"]["query"], ""
        )

        encoded = self.make(
            "||encoded.example^$removeparam=%24param,script,"
            "domain=foo.example|~bar.example"
        )
        self.assertEqual(
            encoded["action"]["redirect"]["transform"]["queryTransform"]
            ["removeParams"],
            ["$param"],
        )
        self.assertEqual(encoded["condition"]["resourceTypes"], ["script"])
        self.assertEqual(encoded["condition"]["initiatorDomains"], ["foo.example"])
        self.assertEqual(
            encoded["condition"]["excludedInitiatorDomains"], ["bar.example"]
        )

    def test_rejects_every_scope_wblock_rejects(self) -> None:
        invalid = [
            "||bad.example^$removeparam=/^utm_/",
            "||bad.example^$removeparam=~keep",
            "$removeparam=v,hinta.fi|carrefoursa.com",
            "||wildcard.example^$removeparam=utm,domain=*.example",
            "||slash.example^$removeparam=utm,domain=example.com/path",
            "||port.example^$removeparam=utm,to=example.com:443",
            "||empty.example^$removeparam=utm,domain=",
            "||segment.example^$removeparam=utm,domain=good.example||other.example",
            "||percent.example^$removeparam=%ZZ",
        ]
        for line in invalid:
            with self.subTest(line=line):
                self.assertIsNone(self.make(line))

    def test_preserves_valid_domain_and_resource_scopes(self) -> None:
        rule = self.make(
            "||valid.example^$xmlhttprequest,removeparam=id,third-party,"
            "domain=good.example|~excluded.example,"
            "to=target.example|~not-target.example"
        )
        self.assertEqual(rule["condition"]["resourceTypes"], ["xmlhttprequest"])
        self.assertEqual(rule["condition"]["domainType"], "thirdParty")
        self.assertEqual(rule["condition"]["initiatorDomains"], ["good.example"])
        self.assertEqual(
            rule["condition"]["excludedInitiatorDomains"], ["excluded.example"]
        )
        self.assertEqual(rule["condition"]["requestDomains"], ["target.example"])
        self.assertEqual(
            rule["condition"]["excludedRequestDomains"], ["not-target.example"]
        )


if __name__ == "__main__":
    unittest.main()
