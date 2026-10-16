import shutil, unittest, tempfile, json
from pathlib import Path
from auditor import audit_snapshot

class TestSyntheticMutation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.snapshot_dir = Path(self.temp_dir)
        source_dir = Path(__file__).parent / 'inputs' / 'snapshot-two'
        shutil.copytree(source_dir, self.snapshot_dir, dirs_exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_synthetic_mutation_fully_hardened(self):
        # 1. Clean up docs/rotation.txt to remove plaintext DEMO_ACTIVE_ROTATED_9D4
        rotation_file = self.snapshot_dir / 'docs' / 'rotation.txt'
        rotation_file.write_text('Rotation complete: all active tokens moved to secure secret manager.\n', encoding='utf-8')

        # 2. Fix pr-build artifact_paths wildcard to avoid matching app/env.txt
        ci_file = self.snapshot_dir / 'ci.json'
        with open(ci_file, 'r', encoding='utf-8') as f:
            ci = json.load(f)
        for wf in ci['workflows']:
            if wf['workflow_id'] == 'pr-build':
                wf['artifact_paths'] = ['build/report.txt']
        with open(ci_file, 'w', encoding='utf-8') as f:
            json.dump(ci, f, indent=2)

        # Audit synthetic snapshot
        res = audit_snapshot(self.snapshot_dir)
        self.assertEqual(res['total_findings'], 0, 'Mutated snapshot should have zero findings after remediation')
        self.assertTrue(res['total_benign_decisions'] >= 10)

if __name__ == '__main__':
    unittest.main()
