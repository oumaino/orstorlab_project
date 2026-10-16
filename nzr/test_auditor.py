import unittest
from pathlib import Path
from auditor import audit_snapshot

class TestPineBuildAuditor(unittest.TestCase):
    def setUp(self):
        self.base_dir = Path(__file__).parent / 'inputs'
        self.snapshot_one = self.base_dir / 'snapshot-one'
        self.snapshot_two = self.base_dir / 'snapshot-two'

    def test_check1_active_text_detection(self):
        res1 = audit_snapshot(self.snapshot_one)
        s1_findings1 = [f for f in res1['findings'] if f['rule_id'] == 'S1']
        self.assertTrue(len(s1_findings1) >= 1)
        self.assertEqual(s1_findings1[0]['file_path'], 'app/env.txt')
        self.assertEqual(s1_findings1[0]['token_id'], 'release-active')

        res2 = audit_snapshot(self.snapshot_two)
        s1_findings2 = [f for f in res2['findings'] if f['rule_id'] == 'S1']
        self.assertTrue(len(s1_findings2) >= 1)
        self.assertEqual(s1_findings2[0]['file_path'], 'docs/rotation.txt')
        self.assertEqual(s1_findings2[0]['token_id'], 'release-rotated')

    def test_check2_test_revoked_suppression(self):
        res1 = audit_snapshot(self.snapshot_one)
        benign_s1_1 = [b for b in res1['benign_decisions'] if b['rule_id'] == 'S1']
        states1 = {b['state'] for b in benign_s1_1}
        self.assertIn('test_only', states1)
        self.assertIn('revoked_in_fixture', states1)
        for b in benign_s1_1:
            self.assertEqual(b['status'], 'BENIGN')

        res2 = audit_snapshot(self.snapshot_two)
        benign_s1_2 = [b for b in res2['benign_decisions'] if b['rule_id'] == 'S1']
        states2 = {b['state'] for b in benign_s1_2}
        self.assertIn('revoked_in_fixture', states2)
        app_env_benign = [b for b in benign_s1_2 if b['file_path'] == 'app/env.txt']
        self.assertTrue(len(app_env_benign) == 1)
        self.assertEqual(app_env_benign[0]['status'], 'BENIGN')

    def test_check3_exact_permission_trigger_policy(self):
        res1 = audit_snapshot(self.snapshot_one)
        s3_findings1 = [f for f in res1['findings'] if f['rule_id'] == 'S3']
        self.assertEqual(len(s3_findings1), 1)
        self.assertEqual(s3_findings1[0]['workflow_id'], 'pr-build')
        self.assertEqual(s3_findings1[0]['permissions'], 'write-all')

        release_s3 = [b for b in res1['benign_decisions'] if b['rule_id'] == 'S3' and b['workflow_id'] == 'release']
        self.assertEqual(len(release_s3), 1)
        self.assertEqual(release_s3[0]['status'], 'BENIGN')

        res2 = audit_snapshot(self.snapshot_two)
        pr_s3_2 = [b for b in res2['benign_decisions'] if b['rule_id'] == 'S3' and b['workflow_id'] == 'pr-build']
        self.assertEqual(len(pr_s3_2), 1)
        self.assertEqual(pr_s3_2[0]['status'], 'BENIGN')

    def test_check4_artifact_wildcard_and_secret_intersection(self):
        res1 = audit_snapshot(self.snapshot_one)
        s2_findings1 = [f for f in res1['findings'] if f['rule_id'] == 'S2']
        self.assertEqual(len(s2_findings1), 1)
        self.assertEqual(s2_findings1[0]['workflow_id'], 'pr-build')

        res2 = audit_snapshot(self.snapshot_two)
        s5_findings2 = [f for f in res2['findings'] if f['rule_id'] == 'S5']
        self.assertEqual(len(s5_findings2), 1)
        self.assertEqual(s5_findings2[0]['workflow_id'], 'pr-build')
        self.assertEqual(s5_findings2[0]['pattern'], 'app/*')
        self.assertEqual(s5_findings2[0]['matched_file'], 'app/env.txt')

if __name__ == '__main__':
    unittest.main()
