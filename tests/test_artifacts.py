import json
from pathlib import Path
import tempfile
import unittest

from tron_security_review.artifacts import aggregate_run


class ArtifactTests(unittest.TestCase):
    def test_groups_native_ids_across_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            for profile in ("triage", "verifier"):
                results = run_dir / profile / "results"
                results.mkdir(parents=True)
                (results / "findings.json").write_text(
                    json.dumps(
                        {
                            "findings": [
                                {
                                    "id": "finding-1",
                                    "title": "Example",
                                    "severity": "high",
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
            aggregate = aggregate_run(run_dir)
            self.assertEqual(aggregate["finding_group_count"], 1)
            group = aggregate["finding_groups"][0]
            self.assertTrue(group["corroborated_by_multiple_profiles"])
            self.assertEqual(group["profiles"], ["triage", "verifier"])


if __name__ == "__main__":
    unittest.main()
