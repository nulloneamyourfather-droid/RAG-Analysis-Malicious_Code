import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from attck_knowledge.experiment_runner import select_functions


class ExperimentRunnerTests(unittest.TestCase):
    def test_select_functions_prefers_high_value_records(self) -> None:
        sample = {
            "functions": [
                {
                    "function_name": "runtime_stub",
                    "function_addr": "0x1000",
                    "selection_score": -2,
                    "behavior_tags": [],
                    "api_calls": [],
                },
                {
                    "function_name": "injector",
                    "function_addr": "0x2000",
                    "selection_score": 8.5,
                    "behavior_tags": ["Process Injection"],
                    "api_calls": ["OpenProcess", "WriteProcessMemory", "CreateRemoteThread"],
                },
                {
                    "function_name": "network_logic",
                    "function_addr": "0x3000",
                    "selection_score": 4.0,
                    "behavior_tags": ["C2 Communication"],
                    "api_calls": ["socket", "connect"],
                },
            ]
        }

        selected = select_functions(sample, 2)

        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0]["function_name"], "injector")
        self.assertEqual(selected[1]["function_name"], "network_logic")

    def test_select_functions_never_returns_empty_for_positive_limit(self) -> None:
        sample = {"functions": [{"function_name": "only_one", "function_addr": "0x1", "selection_score": 1.0}]}

        selected = select_functions(sample, 1)

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["function_name"], "only_one")


if __name__ == "__main__":
    unittest.main()
