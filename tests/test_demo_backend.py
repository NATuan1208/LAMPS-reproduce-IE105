from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from demo.backend import app as demo_app
from demo.backend import scanner


class _FakeTokenizer:
    def encode(self, text: str, add_special_tokens: bool = False, truncation: bool = False) -> list[int]:
        return list(range(max(1, len(text) // 8)))


def _fake_infer(text: str, strategy: str) -> float:
    if "dfdfdfdfhhh" in text or "CustomInstallCommand" in text:
        return 0.886257 if strategy == "head_tail" else 0.997431
    if "aio3" in text or "20.126.118.208" in text:
        return 0.997705
    return 0.030762


class DemoBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.patches = [
            patch.object(scanner, "_tokenizer", _FakeTokenizer()),
            patch.object(scanner, "_infer", side_effect=_fake_infer),
        ]
        for active_patch in self.patches:
            active_patch.start()

    def tearDown(self) -> None:
        for active_patch in reversed(self.patches):
            active_patch.stop()

    def test_packages_lists_three_demo_packages(self) -> None:
        packages = asyncio.run(demo_app.list_packages())

        self.assertEqual(len(packages), 3)
        self.assertEqual({pkg["id"] for pkg in packages}, {"aio3", "dfdfdfdfhhh", "click"})

    def test_scan_response_keeps_old_fields_and_adds_static_sandbox_contract(self) -> None:
        response = asyncio.run(demo_app.scan(demo_app.ScanRequest(package_id="aio3", strategy="head")))

        self.assertEqual(response["package_id"], "aio3")
        self.assertIn("files", response)
        self.assertIn("verdict", response)
        self.assertEqual(response["sandbox"]["analysis_mode"], "static")
        self.assertFalse(response["sandbox"]["executed"])
        self.assertTrue(response["sandbox"]["network_blocked"])
        self.assertEqual(response["provenance"]["version"], "0.2.8")
        self.assertTrue(response["payload_evidence"])
        self.assertTrue(any(item["kind"] == "decoded_base64" for item in response["payload_evidence"]))
        self.assertIn("sha256", response["files"][0])

    def test_strategy_comparison_matches_dfdfdfdfhhh_known_behavior(self) -> None:
        response = asyncio.run(demo_app.scan(demo_app.ScanRequest(package_id="dfdfdfdfhhh", strategy="head_tail")))

        comparison = response["strategy_comparison"]
        self.assertEqual(comparison["threshold"], 0.9)
        self.assertEqual(comparison["head"], 0.9974)
        self.assertEqual(comparison["head_tail"], 0.8863)
        self.assertEqual(comparison["head_label"], "malicious")
        self.assertEqual(comparison["head_tail_label"], "benign")
        self.assertEqual(response["verdict"], "benign")

    def test_click_baseline_has_no_payload_evidence(self) -> None:
        response = asyncio.run(demo_app.scan(demo_app.ScanRequest(package_id="click", strategy="head")))

        self.assertEqual(response["verdict"], "benign")
        self.assertEqual(response["payload_evidence"], [])
        self.assertTrue(all(file["payload_evidence_count"] == 0 for file in response["files"]))


if __name__ == "__main__":
    unittest.main()
