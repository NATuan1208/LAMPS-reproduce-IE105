from __future__ import annotations

import unittest

from tools.archive_extractor import ArchiveExtractorTool


class ArchiveExtractorPolicyTests(unittest.TestCase):
    def test_d1_mode_keeps_only_setup(self) -> None:
        reason_setup = ArchiveExtractorTool._exclusion_reason("pkg/setup.py", "D1")
        reason_other = ArchiveExtractorTool._exclusion_reason("pkg/module.py", "D1")
        self.assertIsNone(reason_setup)
        self.assertEqual(reason_other, "mode_filter_non_setup")

    def test_d2_mode_excludes_tests(self) -> None:
        reason = ArchiveExtractorTool._exclusion_reason("pkg/tests/test_x.py", "D2")
        self.assertEqual(reason, "excluded_directory")


if __name__ == "__main__":
    unittest.main()
