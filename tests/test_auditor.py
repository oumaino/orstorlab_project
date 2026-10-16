import json  # Lit et écrit les données JSON.
import subprocess  # Lance ton auditeur comme depuis le terminal.
import sys  # Retrouve le Python actuellement utilisé.
import tempfile  # Crée un dossier temporaire pour chaque test.
import unittest  # Fournit les outils de test.
from pathlib import Path  # Manipule les chemins.


# Retrouve auditor.py dans le dossier parent du dossier tests.
AUDITOR = Path(__file__).resolve().parents[1] / "auditor.py"


class AuditorTests(unittest.TestCase):
    """Vérifie les décisions de l’auditeur avec des données fictives."""

    def setUp(self):
        # Cette préparation s’exécute avant CHAQUE test.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)  # Supprime les fichiers après le test.
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "sample"

        # Crée les quatre dossiers autorisés.
        for folder in ("app", "tests", "docs", "build"):
            (self.snapshot / folder).mkdir(parents=True)

        # Définit trois marqueurs fictifs avec des états différents.
        self.tokens = [
            {
                "token_id": "active-key",
                "value": "DEMO_ACTIVE_TEST_ABC123",
                "state": "active_in_fixture",
            },
            {
                "token_id": "revoked-key",
                "value": "DEMO_REVOKED_TEST_DEF456",
                "state": "revoked_in_fixture",
            },
            {
                "token_id": "test-key",
                "value": "DEMO_TEST_ONLY_GHI789",
                "state": "test_only",
            },
        ]

        # Définit un workflow sans violation au départ.
        self.workflow = {
            "workflow_id": "test-workflow",
            "trigger": "pull_request",
            "runs_untrusted_code": False,
            "secret_refs": [],
            "permissions": "read-only",
            "log_environment": False,
            "artifact_paths": [],
        }

    def write_content(self, path, text):
        # Écrit un fichier de contenu dans le snapshot temporaire.
        (self.snapshot / path).write_text(text, encoding="utf-8")

    def run_audit(self):
        # Enregistre l’inventaire utilisé par le test.
        inventory = {"schema_version": 1, "tokens": self.tokens}
        (self.snapshot / "inventory.json").write_text(
            json.dumps(inventory), encoding="utf-8"
        )

        # Enregistre le workflow, éventuellement modifié par le test.
        (self.snapshot / "ci.json").write_text(
            json.dumps({"workflows": [self.workflow]}),
            encoding="utf-8",
        )

        # Exécute l’auditeur dans le dossier temporaire.
        # -X utf8 garantit un affichage UTF-8, notamment sous Windows.
        result = subprocess.run(
            [
                sys.executable, "-X", "utf8",
                str(AUDITOR), str(self.snapshot),
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
        )

        # Le test échoue si le script termine avec une erreur.
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        # Charge le rapport réellement produit par l’auditeur.
        report_path = self.root / "outputs" / "sample" / "findings.json"
        raw_report = report_path.read_text(encoding="utf-8")
        return json.loads(raw_report), result.stdout, raw_report

    def test_active_token_in_documentation(self):
        # Un token actif reste sensible, même dans la documentation.
        self.write_content(
            "docs/rotation.txt",
            "Rotation note\nKEY=" + self.tokens[0]["value"] + "\n",
        )

        report, _, _ = self.run_audit()
        findings = report["findings"]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "S1")
        self.assertEqual(findings[0]["path"], "docs/rotation.txt")
        self.assertEqual(findings[0]["line"], 2)
        self.assertEqual(findings[0]["token_id"], "active-key")

    def test_revoked_and_test_tokens_are_suppressed(self):
        # Ces deux valeurs ne doivent pas être signalées comme secrets actifs.
        self.write_content(
            "tests/mock.txt",
            self.tokens[1]["value"] + "\n" + self.tokens[2]["value"],
        )

        report, _, _ = self.run_audit()

        self.assertEqual(report["findings"], [])
        self.assertEqual(report["benign_decision_count"], 2)
        self.assertEqual(
            {item["token_id"] for item in report["benign_decisions"]},
            {"revoked-key", "test-key"},
        )

    def test_permission_policy(self):
        # Vérifie les 12 combinaisons de déclenchement, confiance et permissions.
        for trigger in ("pull_request", "tag"):
            for untrusted in (False, True):
                for permission in ("read-only", "release-write", "write-all"):
                    with self.subTest(
                        trigger=trigger,
                        untrusted=untrusted,
                        permission=permission,
                    ):
                        self.workflow.update({
                            "trigger": trigger,
                            "runs_untrusted_code": untrusted,
                            "permissions": permission,
                        })

                        report, _, _ = self.run_audit()
                        rules = [item["rule_id"] for item in report["findings"]]

                        # Liste explicite des situations autorisées.
                        allowed = {
                            ("pull_request", False, "read-only"),
                            ("pull_request", True, "read-only"),
                            ("tag", False, "read-only"),
                            ("tag", True, "read-only"),
                            ("tag", False, "release-write"),
                        }

                        case = (trigger, untrusted, permission)
                        expected = [] if case in allowed else ["S3"]
                        self.assertEqual(rules, expected)

    def test_artifact_wildcard_without_active_token(self):
        # Le fichier est sensible même quand il ne contient aucun token.
        self.write_content("app/env.txt", "TENANT=demo\n")
        self.workflow["artifact_paths"] = ["app/*"]

        report, _, _ = self.run_audit()
        findings = report["findings"]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "S5")
        self.assertEqual(
            findings[0]["evidence"]["sensitive_path"], "app/env.txt"
        )
        self.assertEqual(
            findings[0]["evidence"]["matching_patterns"], ["app/*"]
        )

    def test_secret_availability_and_logging(self):
        # S2 et S4 exigent une référence à un token actif.
        self.workflow["runs_untrusted_code"] = True
        self.workflow["log_environment"] = True

        cases = [
            ([], []),
            (["revoked-key"], []),
            (["test-key"], []),
            (["active-key"], ["S2", "S4"]),
        ]

        for refs, expected_rules in cases:
            with self.subTest(refs=refs):
                self.workflow["secret_refs"] = refs
                report, _, _ = self.run_audit()

                self.assertEqual(
                    [item["rule_id"] for item in report["findings"]],
                    expected_rules,
                )

    def test_output_redaction(self):
        # Place les trois valeurs sur une même ligne pour vérifier le masquage.
        self.write_content(
            "app/env.txt",
            " ".join(token["value"] for token in self.tokens),
        )

        report, stdout, raw_report = self.run_audit()

        # Vérifie qu’une vraie détection a eu lieu.
        self.assertEqual(report["finding_count"], 1)
        self.assertIn("[REDACTED:active-key]", raw_report)

        # Aucune valeur complète ne doit apparaître dans les sorties.
        for token in self.tokens:
            self.assertNotIn(token["value"], stdout)
            self.assertNotIn(token["value"], raw_report)


# Lance les tests seulement lorsque ce fichier est exécuté directement.
if __name__ == "__main__":
    unittest.main()