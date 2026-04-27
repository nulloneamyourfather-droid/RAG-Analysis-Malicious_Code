import sys
import subprocess
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))


class EntryPointImportTests(unittest.TestCase):
    def test_run_sample_pipeline_importable(self) -> None:
        import attck_knowledge.run_sample_pipeline as module

        self.assertTrue(callable(module.main))

    def test_run_sample_pipeline_impl_importable(self) -> None:
        import attck_knowledge.run_sample_pipeline_impl as module

        self.assertTrue(callable(module.main))

    def test_experiment_runner_importable(self) -> None:
        import attck_knowledge.experiment_runner as module

        self.assertTrue(callable(module.main))

    def test_run_sample_pipeline_help(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(WORKSPACE_ROOT / "attck_knowledge" / "run_sample_pipeline.py"), "--help"],
            capture_output=True,
            text=True,
            check=True,
        )

        self.assertIn("One-command pipeline", completed.stdout)
        self.assertIn("--analyze-current-sample", completed.stdout)

    def test_experiment_runner_help(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(WORKSPACE_ROOT / "attck_knowledge" / "experiment_runner.py"), "--help"],
            capture_output=True,
            text=True,
            check=True,
        )

        self.assertIn("Run experiment scripts for thesis evaluation.", completed.stdout)
        self.assertIn("--experiments", completed.stdout)


if __name__ == "__main__":
    unittest.main()
