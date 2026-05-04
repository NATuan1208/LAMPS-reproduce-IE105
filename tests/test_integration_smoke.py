from __future__ import annotations

import unittest

from schemas.output_schemas import BinaryVerdict, FileClassificationResult, compute_conservative_verdict


class IntegrationSmokeTests(unittest.TestCase):
    def test_mixed_package_flips_to_malicious(self) -> None:
        file_results = [
            FileClassificationResult(file_path="pkg/setup.py", prediction=BinaryVerdict.BENIGN, probability=0.1),
            FileClassificationResult(file_path="pkg/helper.py", prediction=BinaryVerdict.MALICIOUS, probability=0.99),
        ]
        verdict = compute_conservative_verdict(file_results, empty_policy=BinaryVerdict.MALICIOUS)
        self.assertEqual(verdict, BinaryVerdict.MALICIOUS)


if __name__ == "__main__":
    unittest.main()
