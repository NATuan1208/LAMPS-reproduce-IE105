from __future__ import annotations

import unittest

from schemas.output_schemas import (
    BinaryVerdict,
    FileClassificationResult,
    compute_conservative_verdict,
    validate_classification_coverage,
)


class OutputSchemaTests(unittest.TestCase):
    def test_conservative_verdict_any_malicious(self) -> None:
        file_results = [
            FileClassificationResult(file_path="a.py", prediction=BinaryVerdict.BENIGN, probability=0.1),
            FileClassificationResult(file_path="b.py", prediction=BinaryVerdict.MALICIOUS, probability=0.9),
        ]
        verdict = compute_conservative_verdict(file_results)
        self.assertEqual(verdict, BinaryVerdict.MALICIOUS)

    def test_conservative_verdict_empty_policy(self) -> None:
        verdict = compute_conservative_verdict([], empty_policy=BinaryVerdict.MALICIOUS)
        self.assertEqual(verdict, BinaryVerdict.MALICIOUS)

    def test_coverage_detection(self) -> None:
        selected = ["a.py", "b.py", "c.py"]
        results = [
            FileClassificationResult(file_path="a.py", prediction=BinaryVerdict.BENIGN, probability=0.2),
            FileClassificationResult(file_path="a.py", prediction=BinaryVerdict.BENIGN, probability=0.2),
            FileClassificationResult(file_path="x.py", prediction=BinaryVerdict.MALICIOUS, probability=0.8),
        ]
        missing, duplicates, unexpected = validate_classification_coverage(selected, results)

        self.assertEqual(missing, ["b.py", "c.py"])
        self.assertEqual(duplicates, ["a.py"])
        self.assertEqual(unexpected, ["x.py"])


if __name__ == "__main__":
    unittest.main()
