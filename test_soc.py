"""Unit tests for the offline TinaLab SOC Alert Simulator."""
import subprocess
import sys
import unittest
from datetime import datetime
from pathlib import Path

from soc import analyze

# BASE already points to the scenarios directory. Do not add another
# / "scenarios" segment when building a scenario path.
BASE = Path(__file__).parent / "scenarios"


class DetectorTests(unittest.TestCase):
    def scenario(self, name, window=60, threshold=5):
        path = BASE / name
        return analyze(
            path.read_text(encoding="utf-8").splitlines(),
            threshold=threshold,
            window_seconds=window,
        )

    def test_default_scenario_file_exists(self):
        self.assertTrue((BASE / "01_alert.txt").is_file())

    def test_five_failures_within_window_trigger_alert(self):
        result = self.scenario("01_alert.txt")
        self.assertTrue(result["alert"])
        self.assertEqual(result["ip"], "192.168.1.20")
        self.assertEqual(result["count"], 5)
        self.assertEqual(result["end"], datetime(2026, 10, 28, 10, 0, 25))

    def test_ip_addresses_with_surrounding_spaces_are_normalized(self):
        lines = [
            '2026-01-01 10:00:00 | 192.168.1.20 | LOGIN FAILED',
            '2026-01-01 10:00:10 |  192.168.1.20  | LOGIN FAILED',
            '2026-01-01 10:00:20 | 192.168.1.20 | LOGIN FAILED',
        ]
        result = analyze(lines, threshold=3, window_seconds=60)
        self.assertTrue(result['alert'])
        self.assertEqual(result['ip'], '192.168.1.20')
        self.assertEqual(result['count'], 3)

    def test_spread_out_failures_do_not_trigger_alert(self):
        self.assertFalse(self.scenario("02_spread_out.txt")["alert"])

    def test_failures_from_different_ips_are_not_combined(self):
        self.assertFalse(self.scenario("03_mixed_ips.txt")["alert"])

    def test_window_boundary_is_inclusive(self):
        lines = [
            f"2026-10-28 10:00:{second:02d} | 192.168.1.20 | LOGIN FAILED"
            for second in (0, 5, 10, 15, 30)
        ]
        result = analyze(lines, window_seconds=30)
        self.assertTrue(result["alert"])
        self.assertEqual(result["count"], 5)

    def test_failure_just_outside_window_is_removed(self):
        lines = [
            f"2026-10-28 10:00:{second:02d} | 192.168.1.20 | LOGIN FAILED"
            for second in (0, 5, 10, 15, 30)
        ]
        self.assertFalse(analyze(lines, window_seconds=29)["alert"])

    def test_success_event_does_not_reset_failure_count(self):
        lines = [
            "2026-10-28 10:00:00 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:05 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:10 | 192.168.1.20 | LOGIN SUCCESS",
            "2026-10-28 10:00:15 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:20 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:25 | 192.168.1.20 | LOGIN FAILED",
        ]
        result = analyze(lines, window_seconds=30)
        self.assertTrue(result["alert"])
        self.assertEqual(result["count"], 5)

    def test_records_are_sorted_before_analysis(self):
        lines = [
            f"2026-10-28 10:00:{second:02d} | 192.168.1.20 | LOGIN FAILED"
            for second in (20, 0, 15, 5, 10)
        ]
        result = analyze(lines, window_seconds=30)
        self.assertTrue(result["alert"])
        self.assertEqual(result["end"], datetime(2026, 10, 28, 10, 0, 20))

    def test_custom_threshold_is_respected(self):
        lines = [
            f"2026-10-28 10:00:{second:02d} | 192.168.1.20 | LOGIN FAILED"
            for second in (0, 5, 10)
        ]
        self.assertTrue(analyze(lines, threshold=3, window_seconds=15)["alert"])

    def test_blank_lines_and_comments_are_ignored(self):
        lines = [
            "# Example log",
            "",
            "2026-10-28 10:00:00 | 192.168.1.20 | LOGIN FAILED",
            "   ",
            "2026-10-28 10:00:05 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:10 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:15 | 192.168.1.20 | LOGIN FAILED",
            "2026-10-28 10:00:20 | 192.168.1.20 | LOGIN FAILED",
        ]
        self.assertTrue(analyze(lines)["alert"])

    def test_empty_input_does_not_trigger_alert(self):
        self.assertEqual(analyze([]), {"alert": False})

    def test_invalid_row_shape_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "expected TIMESTAMP"):
            analyze(["this is not a valid log row"])

    def test_invalid_timestamp_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "invalid timestamp"):
            analyze(["not-a-date | 192.168.1.20 | LOGIN FAILED"])

    def test_unknown_event_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "invalid event"):
            analyze(["2026-10-28 10:00:00 | 192.168.1.20 | PASSWORD RESET"])

    def test_empty_ip_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "invalid IP address"):
            analyze(["2026-10-28 10:00:00 |  | LOGIN FAILED"])

    def test_invalid_ip_address_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "invalid IP address"):
            analyze(["2026-10-28 10:00:00 | 999.999.999.999 | LOGIN FAILED"])

    def test_zero_threshold_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "must be positive"):
            analyze([], threshold=0)

    def test_zero_window_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "must be positive"):
            analyze([], window_seconds=0)

    def test_cli_missing_log_file_exits_with_error(self):
        completed = subprocess.run(
            [sys.executable, "soc.py", "file_that_does_not_exist.txt"],
            cwd=Path(__file__).parent,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("ERROR:", completed.stderr)

    def test_cli_zero_threshold_exits_with_error(self):
        completed = subprocess.run(
            [sys.executable, "soc.py", "--threshold", "0"],
            cwd=Path(__file__).parent,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must be positive", completed.stderr)

    def test_cli_zero_window_exits_with_error(self):
        completed = subprocess.run(
            [sys.executable, "soc.py", "--window", "0"],
            cwd=Path(__file__).parent,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must be positive", completed.stderr)

    def test_cli_uses_default_scenario(self):
        completed = subprocess.run(
            [sys.executable, "soc.py"],
            cwd=Path(__file__).parent,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ALERT: Suspicious login activity detected!", completed.stdout)
        self.assertIn("192.168.1.20", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
