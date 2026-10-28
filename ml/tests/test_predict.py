"""Unit and smoke tests for ScamShield-AI predict interface."""

from __future__ import annotations

import unittest
from pathlib import Path
from ml.src.predict import predict, load_model, DEFAULT_MODEL_PATH


class TestPredictInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure model exists before running unit tests
        if not DEFAULT_MODEL_PATH.exists():
            raise unittest.SkipTest(
                f"Model file not found at {DEFAULT_MODEL_PATH}. Run training first."
            )
        # Pre-warm model cache
        load_model()

    def test_predict_structure(self):
        text = "Meeting today at 3pm."
        res = predict(text)

        self.assertIsInstance(res, dict)
        required_keys = [
            "text",
            "label",
            "is_scam",
            "scam_probability",
            "probabilities",
            "confidence",
            "model_version",
            "calibrated",
        ]
        for key in required_keys:
            self.assertIn(key, res)

        self.assertIn(res["label"], ["scam", "legitimate"])
        self.assertIsInstance(res["is_scam"], bool)
        self.assertIsInstance(res["scam_probability"], float)
        self.assertIsInstance(res["probabilities"], dict)
        self.assertIn("legitimate", res["probabilities"])
        self.assertIn("scam", res["probabilities"])
        self.assertFalse(res["calibrated"], "calibrated flag must accurately reflect uncalibrated baseline")

    def test_probabilities_sum_to_one(self):
        text = "Claim your lottery prize now!"
        res = predict(text)
        prob_sum = res["probabilities"]["legitimate"] + res["probabilities"]["scam"]
        self.assertAlmostEqual(prob_sum, 1.0, places=3)

    def test_empty_string(self):
        res = predict("")
        self.assertEqual(res["label"], "legitimate")
        self.assertFalse(res["is_scam"])
        self.assertEqual(res["scam_probability"], 0.0)

    def test_whitespace_string(self):
        res = predict("   \t  \n ")
        self.assertEqual(res["label"], "legitimate")
        self.assertFalse(res["is_scam"])
        self.assertEqual(res["scam_probability"], 0.0)

    def test_obvious_scam_message(self):
        scam_text = (
            "URGENT! You have won a 1000 cash prize or 2000 bonus gift card! "
            "Call 09061743806 immediately to claim. Stop replies 87070."
        )
        res = predict(scam_text)
        self.assertTrue(res["is_scam"])
        self.assertEqual(res["label"], "scam")
        self.assertGreater(res["scam_probability"], 0.50)

    def test_obvious_legitimate_message(self):
        legit_text = (
            "Hey, are you going to class today? Let me know if you want to grab lunch after."
        )
        res = predict(legit_text)
        self.assertFalse(res["is_scam"])
        self.assertEqual(res["label"], "legitimate")
        self.assertLess(res["scam_probability"], 0.50)


if __name__ == "__main__":
    unittest.main()
