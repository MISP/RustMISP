#!/usr/bin/env python3
"""
Unit tests for scripts/check_pymisp_parity.py's PyMISP-fetch pinning.

Run with: python3 -m unittest scripts.test_check_pymisp_parity -v
(from the repo root) or python3 scripts/test_check_pymisp_parity.py directly.

These tests guard against A02: PYMISP_BRANCH = "main" meant the parity
badge could shift from upstream PyMISP churn alone, with no RustMISP
change and no record of what was actually compared against.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_pymisp_parity as parity  # noqa: E402


class TestPinnedRef(unittest.TestCase):
    def test_default_ref_is_a_pinned_commit_not_a_branch(self):
        """The default comparison ref must be a resolved commit SHA, not a
        floating branch name like 'main'."""
        self.assertTrue(
            re.fullmatch(r"[0-9a-f]{40}", parity.PYMISP_REF),
            f"PYMISP_REF should be a 40-char commit SHA, got {parity.PYMISP_REF!r}",
        )
        self.assertNotEqual(parity.PYMISP_REF, "main")


class TestFetchPymisp(unittest.TestCase):
    @patch("check_pymisp_parity.subprocess.run")
    def test_fetch_uses_requested_ref_and_returns_resolved_commit(self, mock_run):
        """fetch_pymisp must fetch the exact ref it was given (not a
        hardcoded branch) and must report the resolved commit SHA back to
        the caller so it can be recorded in job output."""
        expected_sha = "e7debb4f0427dbc33800dc565d771ef1535f3c2f"

        def fake_run(cmd, **kwargs):
            result = MagicMock()
            result.stdout = ""
            if cmd[:2] == ["git", "-C"] and "rev-parse" in cmd:
                result.stdout = expected_sha + "\n"
            return result

        mock_run.side_effect = fake_run

        target_dir = Path("/tmp/does-not-need-to-exist-for-this-mocked-test")
        repo_dir, resolved = parity.fetch_pymisp(target_dir, ref=expected_sha)

        self.assertEqual(resolved, expected_sha)
        self.assertEqual(repo_dir, target_dir / "PyMISP")

        # The fetch step must reference the exact ref passed in, not a
        # hardcoded "main".
        fetch_calls = [
            call.args[0] for call in mock_run.call_args_list
            if "fetch" in call.args[0]
        ]
        self.assertEqual(len(fetch_calls), 1)
        self.assertIn(expected_sha, fetch_calls[0])
        self.assertNotIn("main", fetch_calls[0])

    @patch("check_pymisp_parity.subprocess.run")
    def test_fetch_defaults_to_pinned_ref_when_unspecified(self, mock_run):
        mock_run.return_value.stdout = parity.PYMISP_REF + "\n"

        parity.fetch_pymisp(Path("/tmp/irrelevant"))

        fetch_calls = [
            call.args[0] for call in mock_run.call_args_list
            if "fetch" in call.args[0]
        ]
        self.assertEqual(len(fetch_calls), 1)
        self.assertIn(parity.PYMISP_REF, fetch_calls[0])


if __name__ == "__main__":
    unittest.main()
