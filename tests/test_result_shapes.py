import json
import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))


class ResultShapeTests(unittest.TestCase):
    def test_latest_sample_analysis_shape(self) -> None:
        path = WORKSPACE_ROOT / "attck_knowledge" / "data" / "index" / "metadata" / "latest_sample_analysis.json"
        payload = json.loads(path.read_text(encoding="utf-8"))

        required_top_keys = {
            "sample_name",
            "sample_hash",
            "function_count",
            "summary",
            "conclusion",
            "aggregated_attack_ids",
            "aggregated_behavior_tags",
            "capability_chains",
        }
        self.assertTrue(required_top_keys.issubset(payload.keys()))
        self.assertIsInstance(payload["aggregated_attack_ids"], list)
        self.assertIsInstance(payload["aggregated_behavior_tags"], list)
        self.assertIsInstance(payload["capability_chains"], list)

    def test_rag_vs_no_rag_shape(self) -> None:
        path = (
            WORKSPACE_ROOT
            / "attck_knowledge"
            / "data"
            / "index"
            / "metadata"
            / "experiments"
            / "rag_vs_no_rag.json"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["experiment"], "rag_vs_no_rag")
        self.assertIn("settings", payload)
        self.assertIn("results", payload)
        self.assertIsInstance(payload["results"], list)
        self.assertGreaterEqual(len(payload["results"]), 2)

        first = payload["results"][0]
        required_result_keys = {
            "label",
            "function_count",
            "suspicious_count",
            "runtime_like_count",
            "candidate_attack_total",
            "attack_doc_hit_count",
            "api_chain_hit_count",
            "similar_func_hit_count",
            "avg_candidate_attack_count",
            "avg_evidence_lines",
        }
        self.assertTrue(required_result_keys.issubset(first.keys()))


if __name__ == "__main__":
    unittest.main()
