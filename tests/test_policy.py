from pathlib import Path
import unittest

from tron_security_review.config import available_knowledge_bases, load_config


ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def test_formal_findings_require_current_production_reachability(self) -> None:
        scan_prompt = (ROOT / "prompts/scan.md").read_text(encoding="utf-8")
        verifier_prompt = (ROOT / "prompts/skeptic.md").read_text(encoding="utf-8")
        validation_prompt = (ROOT / "prompts/validation.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Formal findings must be", scan_prompt)
        self.assertIn("production-reachable", scan_prompt)
        self.assertIn("Reachability unverified", verifier_prompt)
        self.assertIn("`reportable`: only when", validation_prompt)
        self.assertIn("production-reachable", validation_prompt)
        self.assertIn("Do not edit scan-manifest.json", validation_prompt)
        self.assertIn("keep its repository worktree read-only", scan_prompt)
        self.assertIn("scan output directory is authorized and", scan_prompt)
        self.assertIn("legacy-candidate purge", scan_prompt)
        self.assertIn("candidate-shaped deferred item", scan_prompt)
        self.assertIn("fixed before activation", verifier_prompt)
        self.assertIn("Historical-only, pre-activation", validation_prompt)
        self.assertIn("A `complete: false` draft is an intermediate checkpoint only", scan_prompt)
        self.assertIn("top-level `complete: true`", scan_prompt)
        self.assertIn("An empty result is valid", scan_prompt)
        self.assertIn("Return validation status `complete`", validation_prompt)
        self.assertIn("must not leave the scan draft unfinished", validation_prompt)
        self.assertIn("Static deployment closure gate", scan_prompt)
        self.assertIn("Do not make coverage partial merely to request", scan_prompt)
        self.assertIn("operator overrides are outside this static scan", scan_prompt)
        self.assertIn("deployment-only uncertainty", validation_prompt)
        self.assertIn("dynamic execution is the only way", validation_prompt)

    def test_tvm_playbook_requires_final_draft_even_with_zero_findings(self) -> None:
        playbook = (ROOT / "knowledge/tvm-review-playbook.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("finish the semantic scan draft", playbook)
        self.assertIn("final submission must use", playbook)
        self.assertIn("zero findings", playbook)
        self.assertIn("Close deployment-only uncertainty", playbook)
        self.assertIn("must not make coverage partial", playbook)

    def test_tvm_playbook_is_a_required_knowledge_base(self) -> None:
        config = load_config(ROOT)
        knowledge_names = {path.name for path in available_knowledge_bases(config)}
        self.assertIn("threat-model.md", knowledge_names)
        self.assertIn("tvm-review-playbook.md", knowledge_names)


if __name__ == "__main__":
    unittest.main()
