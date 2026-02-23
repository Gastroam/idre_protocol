import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.dirname(root_dir))

from hive.cli import configure_node_from_args, get_node_argparser


class TestCliPepperRequirement(unittest.TestCase):
    def _base_args(self):
        ap = get_node_argparser()
        vocab_path = str(Path(__file__).resolve().parents[1] / "vocab.jsonl")
        return ap.parse_args(
            [
                "--node-id",
                "A",
                "--seed",
                "7245",
                "--anchor-seeds",
                "7245",
                "--freeze-field",
                "--backend",
                "frozen",
                "--vocab-file",
                vocab_path,
            ]
        )

    def test_missing_pepper_is_fatal(self):
        args = self._base_args()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                configure_node_from_args(args)
        self.assertIn("missing pepper", str(ctx.exception).lower())

    def test_env_pepper_is_accepted(self):
        args = self._base_args()
        with patch.dict(os.environ, {"IDRE_PEPPER": "env_test_pepper"}, clear=True):
            node = configure_node_from_args(args)
        self.assertEqual(node.pepper, "env_test_pepper")


if __name__ == "__main__":
    unittest.main()
