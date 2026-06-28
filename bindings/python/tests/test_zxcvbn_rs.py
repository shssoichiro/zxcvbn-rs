import json
import math
import unittest

from zxcvbn_rs import zxcvbn


class TestZxcvbnRs(unittest.TestCase):
    def test_returns_expected_top_level_keys(self) -> None:
        result = zxcvbn("correcthorsebatterystaple")
        self.assertEqual(
            set(result.keys()),
            {
                "guesses",
                "password",
                "guesses_log10",
                "score",
                "feedback",
                "sequence",
                "calc_time",
                "crack_times_seconds",
                "crack_times_display",
            },
        )

    def test_empty_password_shape(self) -> None:
        result = zxcvbn("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["guesses"], 0)
        self.assertEqual(result["guesses_log10"], 0.0)
        self.assertIsInstance(result["feedback"], dict)
        self.assertIn("warning", result["feedback"])
        self.assertIn("suggestions", result["feedback"])

    def test_user_inputs_are_accepted(self) -> None:
        without_inputs = zxcvbn("codexuniqueterm")
        with_inputs = zxcvbn("codexuniqueterm", ["codexuniqueterm"])
        self.assertLess(with_inputs["guesses"], without_inputs["guesses"])
        self.assertEqual(with_inputs["sequence"][0]["dictionary_name"], "user_inputs")

    def test_feedback_types(self) -> None:
        weak = zxcvbn("password")
        strong = zxcvbn("correcthorsebatterystaple")

        self.assertIsInstance(weak["feedback"]["warning"], str)
        self.assertIsInstance(weak["feedback"]["suggestions"], list)
        self.assertEqual(strong["feedback"]["warning"], "")
        self.assertEqual(strong["feedback"]["suggestions"], [])

    def test_result_is_strict_json_serializable(self) -> None:
        for password in ("", "password", "correcthorsebatterystaple"):
            result = zxcvbn(password)
            json.dumps(result, allow_nan=False)
            self.assertTrue(math.isfinite(result["guesses_log10"]))

    def test_compatibility_fields(self) -> None:
        result = zxcvbn("password")
        self.assertEqual(result["password"], "password")
        match = result["sequence"][0]
        self.assertEqual(match["dictionary_name"], "passwords")
        self.assertNotIn("sub", match)
        self.assertNotIn("sub_display", match)

    def test_max_length_is_optional(self) -> None:
        self.assertEqual(zxcvbn("1234", max_length=4)["password"], "1234")
        with self.assertRaisesRegex(ValueError, "exceeds max length of 3 characters"):
            zxcvbn("1234", max_length=3)

    def test_guesses_fit_unsigned_64_bit(self) -> None:
        result = zxcvbn("a" * 100)
        self.assertLessEqual(result["guesses"], 2**64 - 1)


if __name__ == "__main__":
    unittest.main()
