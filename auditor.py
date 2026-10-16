import argparse
import json
from pathlib import Path

# Le chemin du snapshot sera donné dans le terminal.
parser = argparse.ArgumentParser()
parser.add_argument("snapshot", help="Chemin du snapshot à analyser")
args = parser.parse_args()

# Trouver et lire son inventaire.
snapshot = Path(args.snapshot)
inventory_path = snapshot / "inventory.json"

with inventory_path.open(encoding="utf-8") as file:
    inventory = json.load(file)

# Afficher uniquement les identifiants et les états.
for token in inventory["tokens"]:
    token_id = token["token_id"]
    state = token["state"]

    if state == "active_in_fixture":
        print(f"{token_id} : ACTIF — à protéger")
    elif state == "revoked_in_fixture":
        print(f"{token_id} : RÉVOQUÉ")
    elif state == "test_only":
        print(f"{token_id} : TEST")
    else:
        raise ValueError(f"État inconnu pour {token_id}")


print("\n--- Recherche des secrets actifs : S1 ---")

finding_count = 0

# Scanner uniquement les quatre dossiers autorisés.
for folder_name in ("app", "tests", "docs", "build"):
    folder = snapshot / folder_name

    for file_path in sorted(folder.rglob("*")):
        if not file_path.is_file():
            continue

        relative_path = file_path.relative_to(snapshot).as_posix()
        lines = file_path.read_text(encoding="utf-8").splitlines()

        for line_number, line in enumerate(lines, start=1):
            for token in inventory["tokens"]:
                # Les tokens révoqués ou de test ne déclenchent pas S1.
                if token["state"] != "active_in_fixture":
                    continue

                if token["value"] and token["value"] in line:
                    finding_count += 1

                    # Masquer toutes les valeurs connues dans la preuve.
                    evidence = line
                    for known_token in sorted(
                        inventory["tokens"],
                        key=lambda item: len(item["value"]),
                        reverse=True,
                    ):
                        if known_token["value"]:
                            evidence = evidence.replace(
                                known_token["value"],
                                f"[REDACTED:{known_token['token_id']}]",
                            )

                    print(f"\n[S1] {relative_path}, ligne {line_number}")
                    print(f"Token : {token['token_id']}")
                    print(f"Preuve : {evidence}")
                    print("Raison : un token actif apparaît en clair.")
                    print(
                        "Action : retirer la copie et prévoir le remplacement "
                        "du token exposé dans le scénario."
                    )

print(f"\nTotal S1 : {finding_count}")