from __future__ import annotations

import os
import unittest

from runtime.settings import LampsSettings, ReasoningProvider


class RuntimeSettingsTests(unittest.TestCase):
    def test_auto_detect_openrouter_from_base_url(self) -> None:
        backup = dict(os.environ)
        try:
            os.environ["CODEBERT_MODEL_ID"] = "demo/model"
            os.environ["LAMPS_REASONING_BASE_URL"] = "https://openrouter.ai/api/v1"
            os.environ["OPENROUTER_API_KEY"] = "key"
            os.environ.pop("OPENAI_API_KEY", None)
            os.environ.pop("LAMPS_REASONING_API_KEY", None)

            settings = LampsSettings.from_env()
            self.assertEqual(settings.reasoning_provider, ReasoningProvider.OPENROUTER)
            self.assertEqual(settings.reasoning_base_url, "https://openrouter.ai/api/v1")
        finally:
            os.environ.clear()
            os.environ.update(backup)

    def test_openai_profile_rejects_openrouter_url(self) -> None:
        backup = dict(os.environ)
        try:
            os.environ["CODEBERT_MODEL_ID"] = "demo/model"
            os.environ["LAMPS_REASONING_PROVIDER_PROFILE"] = "openai"
            os.environ["OPENAI_API_KEY"] = "key"
            os.environ["LAMPS_REASONING_BASE_URL"] = "https://openrouter.ai/api/v1"

            with self.assertRaises(ValueError):
                LampsSettings.from_env()
        finally:
            os.environ.clear()
            os.environ.update(backup)


if __name__ == "__main__":
    unittest.main()
