import argparse  # Permet de récupérer les arguments écrits dans le terminal.
import json  # Permet de convertir le contenu JSON en objets Python.
from pathlib import Path  # Permet de manipuler les chemins des fichiers et dossiers.
import fnmatch  # Permet de comparer un chemin à un motif comme "app/*".

# --- 1. Récupérer le chemin du snapshot ---

parser = argparse.ArgumentParser()  # Crée un lecteur d’arguments de ligne de commande.

# Déclare un argument obligatoire appelé "snapshot".
# Exemple : python auditor.py candidate/inputs/snapshot-one
# Le texte "help" apparaît lorsque l’utilisateur lance python auditor.py --help.
parser.add_argument("snapshot", help="Chemin du snapshot à analyser")

args = parser.parse_args()  # Lit les arguments du terminal et les stocke dans args.


# --- 2. Charger l’inventaire ---

snapshot = Path(args.snapshot)  # Transforme le chemin reçu en objet Path.

# Avec Path, "/" assemble les éléments d’un chemin : ce n’est pas une division.
inventory_path = snapshot / "inventory.json"

# Ouvre l’inventaire en lecture avec l’encodage UTF-8.
# "with" ferme automatiquement le fichier à la fin du bloc.
# "file" est le nom donné au fichier ouvert.
with inventory_path.open(encoding="utf-8") as file:
    inventory = json.load(file)  # Convertit le JSON en dictionnaire Python.
findings = []  # Stocke les risques détectés.
benign_decisions = []  # Stocke les occurrences exclues de S1 avec leur justification.

# --- 3. Afficher les identifiants et les états, sans afficher les valeurs ---

for token in inventory["tokens"]:  # Parcourt chaque token de la liste "tokens".
    token_id = token["token_id"]  # Récupère son identifiant, par exemple "release-active".
    state = token["state"]  # Récupère son état déclaré dans l’inventaire.

    if state == "active_in_fixture":  # Vérifie si le token est actif dans l’exercice.
        print(f"{token_id} : ACTIF — à protéger")  # Affiche son identifiant et son statut.

    elif state == "revoked_in_fixture":  # Sinon, vérifie si le token est révoqué.
        print(f"{token_id} : RÉVOQUÉ")  # Indique qu’il n’est plus actif.

    elif state == "test_only":  # Sinon, vérifie si le token est réservé aux tests.
        print(f"{token_id} : TEST")  # Indique qu’il s’agit d’un marqueur de test.

    else:  # Traite tout état différent des trois états reconnus.
        raise ValueError(f"État inconnu pour {token_id}")  # Arrête le script avec une erreur.


# --- 4. Préparer la recherche des expositions S1 ---

# "\n" ajoute un saut de ligne avant le titre.
print("\n--- Recherche des secrets actifs : S1 ---")

finding_count = 0  # Initialise à zéro le nombre de constats S1.


# --- 5. Parcourir uniquement les dossiers autorisés ---

for folder_name in ("app", "tests", "docs", "build"):  # Parcourt les quatre noms de dossiers.
    folder = snapshot / folder_name  # Construit le chemin du dossier courant.

    # rglob("*") recherche les éléments du dossier et de ses sous-dossiers.
    # sorted() les trie pour obtenir un ordre de traitement stable.
    for file_path in sorted(folder.rglob("*")):

        if not file_path.is_file():  # Vérifie si l’élément n’est pas un fichier.
            continue  # Ignore cet élément et passe au suivant.

        # Retire le début du chemin correspondant au snapshot.
        # as_posix() utilise "/" comme séparateur, même sous Windows.
        # Exemple de résultat : "app/env.txt".
        relative_path = file_path.relative_to(snapshot).as_posix()

        # Lit le fichier en UTF-8 et le découpe en une liste de lignes.
        lines = file_path.read_text(encoding="utf-8").splitlines()


        # --- 6. Chercher les tokens actifs dans chaque ligne ---

        # enumerate() fournit le numéro et le contenu de chaque ligne.
        # start=1 fait commencer les numéros à 1, comme dans un éditeur de texte.
        for line_number, line in enumerate(lines, start=1):

            for token in inventory["tokens"]:  # Compare la ligne avec chaque token connu.

                if token["state"] != "active_in_fixture":  # Si le token n’est pas actif...
                    continue  # ...passe au token suivant : aucune violation S1 pour celui-ci.

                # Vérifie que la valeur n’est pas vide ET qu’elle apparaît dans la ligne.
                # "in" recherche ici une sous-chaîne exacte, sensible aux majuscules.
                if token["value"] and token["value"] in line:

                    finding_count += 1  # Ajoute un constat pour ce token actif sur cette ligne.


                    # --- 7. Masquer les valeurs dans la preuve ---

                    evidence = line  # Prend la ligne comme point de départ de la preuve.

                    # Parcourt tous les tokens connus, même ceux de test ou révoqués,
                    # pour masquer également leurs valeurs si elles figurent sur cette ligne.
                    for known_token in sorted(
                        inventory["tokens"],  # Liste des tokens à trier.
                        key=lambda item: len(item["value"]),  # Trie selon la longueur de leur valeur.
                        reverse=True,  # Traite les valeurs les plus longues en premier.
                    ):  # Début de la boucle sur les tokens triés.

                        # Masquer les longues valeurs d’abord évite qu’une valeur courte
                        # incluse dans une longue perturbe le masquage de cette dernière.

                        if known_token["value"]:  # Ignore les valeurs vides.

                            evidence = evidence.replace(  # Remplace la valeur dans la preuve.
                                known_token["value"],  # Valeur exacte à masquer.
                                f"[REDACTED:{known_token['token_id']}]",  # Marqueur conservant l’identifiant.
                            )  # Stocke le texte modifié dans evidence, sans modifier le fichier.


                    # --- 8. Afficher le constat ---
                    findings.append({  # Ajoute un constat structuré à la liste.
                    "rule_id": "S1",  # Règle déclenchée.
                    "path": relative_path,  # Fichier concerné.
                    "line": line_number,  # Numéro de ligne.
                    "token_id": token["token_id"],  # Identifiant du token, pas sa valeur.
                    "evidence": evidence,  # Preuve déjà masquée.
                    "rationale": "Un token actif apparaît en clair.",
                    "next_action": "Retirer la copie et prévoir le remplacement du token exposé."
                    })
                    # Affiche la règle, le chemin relatif et le numéro de ligne.
                    print(f"\n[S1] {relative_path}, ligne {line_number}")

                    print(f"Token : {token['token_id']}")  # Identifie le token concerné.
                    print(f"Preuve : {evidence}")  # Affiche la ligne avec les valeurs masquées.
                    print("Raison : un token actif apparaît en clair.")  # Explique le constat.

                    print(  # Affiche une suggestion de correction.
                        "Action : retirer la copie et prévoir le remplacement "  # Première partie du texte.
                        "du token exposé dans le scénario."  # Python joint ces deux chaînes adjacentes.
                    )  # Termine l’appel à print.


# Cette ligne n’est dans aucune boucle : elle s’exécute après toute l’analyse.
print(f"\nTotal S1 : {finding_count}")  # Affiche le nombre total de constats S1.





# --- 9. Charger la configuration CI ---

print("\n--- Analyse des workflows : S2, S3 et S4 ---")  # Affiche le titre.

ci_path = snapshot / "ci.json"  # Construit le chemin du fichier de configuration.

with ci_path.open(encoding="utf-8") as file:  # Ouvre le fichier en lecture.
    ci_data = json.load(file)  # Convertit son contenu JSON en dictionnaire Python.

# Crée un dictionnaire permettant de retrouver un token par son identifiant.
# Exemple d’accès : tokens_by_id["release-active"].
tokens_by_id = {
    token["token_id"]: token  # Associe chaque identifiant au token complet.
    for token in inventory["tokens"]  # Parcourt les tokens de l’inventaire.
}

ci_finding_count = 0  # Initialise le compteur des violations S2, S3 et S4.


# --- 10. Examiner chaque workflow ---

for workflow in ci_data["workflows"]:  # Parcourt les workflows de ci.json.

    workflow_id = workflow["workflow_id"]  # Récupère le nom du workflow.
    active_refs = []  # Prépare la liste de ses références à des tokens actifs.

    for token_id in workflow["secret_refs"]:  # Parcourt les identifiants référencés.

        token = tokens_by_id.get(token_id)  # Cherche le token ; renvoie None s’il est inconnu.

        if token is None:  # Si l’identifiant n’existe pas dans l’inventaire...
            print(
                f"[À VÉRIFIER] {workflow_id} : référence inconnue {token_id}"
            )  # Signale l’incertitude sans inventer l’état du token.
            continue  # Passe à la référence suivante.

        if token["state"] == "active_in_fixture":  # Vérifie si ce token est actif.
            active_refs.append(token_id)  # Ajoute uniquement son identifiant à la liste.

    # Transforme les identifiants en texte lisible, sans afficher leurs valeurs.
    active_refs_text = ", ".join(active_refs)


    # --- S2 : code non fiable avec accès à un secret actif ---

    # Une liste non vide est considérée comme vraie dans une condition Python.
    if workflow["runs_untrusted_code"] and active_refs:
        ci_finding_count += 1  # Compte cette violation S2.




    

        findings.append({
            "rule_id": "S2",
            "path": "ci.json",
            "workflow_id": workflow_id,
            "evidence": {
                "runs_untrusted_code": workflow["runs_untrusted_code"],
                "active_secret_refs": active_refs.copy()
            },
            "rationale": "Du code non fiable dispose d'un secret actif.",
            "next_action": "Retirer les secrets actifs ou isoler leur utilisation dans un workflow fiable."
        })



        print(f"\n[S2] Workflow : {workflow_id}")  # Identifie le workflow concerné.
        print(
            f"Preuve : runs_untrusted_code=true ; active secret_refs={active_refs_text}"
        )  # Affiche les deux conditions qui justifient le constat.
        print(
            "Raison : du code non fiable dispose d'un secret actif."
        )  # Explique le risque, sans prétendre qu’une attaque a eu lieu.
        print(
            "Action : retirer les secrets actifs de ce workflow "
            "ou isoler leur utilisation dans un workflow fiable."
        )  # Propose une correction.


    # --- S3 : vérifier les permissions ---

    permissions = workflow["permissions"]  # Récupère les permissions configurées.

    # L’exception release-write exige simultanément ces deux conditions.
    release_write_allowed = (
        workflow["trigger"] == "tag"  # Le workflow est déclenché sur un tag.
        and not workflow["runs_untrusted_code"]  # Il n’exécute pas de code non fiable.
    )

    # read-only est toujours accepté par la politique.
    # release-write est accepté uniquement lorsque l’exception s’applique.
    permissions_allowed = (
        permissions == "read-only"
        or (permissions == "release-write" and release_write_allowed)
    )

    if not permissions_allowed:  # Si les permissions ne respectent pas la politique...
        ci_finding_count += 1  # ...compte une violation S3.


        findings.append({
        "rule_id": "S3",
        "path": "ci.json",
        "workflow_id": workflow_id,
        "evidence": {
            "permissions": permissions,
            "trigger": workflow["trigger"],
            "runs_untrusted_code": workflow["runs_untrusted_code"]
        },
        "rationale": "Les permissions ne respectent pas la politique S3.",
        "next_action": "Utiliser read-only, ou release-write uniquement sur tag sans code non fiable."
        })




        print(f"\n[S3] Workflow : {workflow_id}")  # Identifie le workflow concerné.
        print(
            f"Preuve : permissions={permissions} ; "
            f"trigger={workflow['trigger']} ; "
            f"runs_untrusted_code={workflow['runs_untrusted_code']}"
        )  # Affiche les paramètres ayant servi à la décision.
        print(
            "Raison : les permissions ne respectent pas la politique S3."
        )  # Explique le constat.
        print(
            "Action : utiliser read-only ; release-write est permis "
            "uniquement sur tag sans code non fiable."
        )  # Rappelle les permissions autorisées.


    # --- S4 : journalisation de l’environnement avec un secret actif ---

    if workflow["log_environment"] and active_refs:  # Vérifie les deux conditions S4.
        ci_finding_count += 1  # Compte cette violation S4.



        findings.append({
        "rule_id": "S4",
        "path": "ci.json",
        "workflow_id": workflow_id,
        "evidence": {
            "log_environment": workflow["log_environment"],
            "active_secret_refs": active_refs.copy()
        },
        "rationale": "La journalisation complète de l'environnement risque d'exposer un secret actif.",
        "next_action": "Désactiver la journalisation complète de l'environnement."
        })



        print(f"\n[S4] Workflow : {workflow_id}")  # Identifie le workflow concerné.
        print(
            f"Preuve : log_environment=true ; active secret_refs={active_refs_text}"
        )  # Affiche des identifiants, jamais les valeurs des tokens.
        print(
            "Raison : l'affichage de l'environnement risque d'exposer un secret actif."
        )  # Explique le risque modélisé par l’exercice.
        print(
            "Action : désactiver la journalisation complète de l'environnement."
        )  # Propose une correction.


# Ces lignes sont hors de la boucle : elles s’exécutent après tous les workflows.
print(f"\nTotal S2–S4 : {ci_finding_count}")  # Affiche le total des violations CI.
print(
    f"Total S1–S4 : {finding_count + ci_finding_count}"
)  # Additionne les constats texte et CI ; S5 n’est pas encore implémentée.



# --- 11. Vérifier les fichiers publiés comme artefacts : S5 ---

print("\n--- Analyse des artefacts : S5 ---")  # Affiche le titre.

# Ces deux chemins sont déclarés sensibles par la politique de l’exercice.
sensitive_paths = {"app/env.txt", "docs/rotation.txt"}

content_paths = set()  # Prépare un ensemble de chemins uniques.

for folder_name in ("app", "tests", "docs", "build"):  # Parcourt les dossiers autorisés.
    folder = snapshot / folder_name  # Construit le chemin du dossier.

    for file_path in folder.rglob("*"):  # Explore aussi ses sous-dossiers.
        if file_path.is_file():  # Conserve uniquement les fichiers.
            relative_path = file_path.relative_to(snapshot).as_posix()  # Uniformise le chemin.
            content_paths.add(relative_path)  # Ajoute le chemin à l’ensemble.

artifact_finding_count = 0  # Initialise le compteur S5.

for workflow in ci_data["workflows"]:  # Examine chaque workflow.
    workflow_id = workflow["workflow_id"]  # Récupère son identifiant.

    for relative_path in sorted(content_paths):  # Parcourt les fichiers fournis dans un ordre stable.

        if relative_path not in sensitive_paths:  # Si le fichier n’est pas déclaré sensible...
            continue  # ...passe au suivant.

        matching_patterns = []  # Prépare les motifs qui publient ce fichier sensible.

        for pattern in workflow["artifact_paths"]:  # Examine chaque motif d’artefact.
            if fnmatch.fnmatchcase(relative_path, pattern):  # Compare le chemin complet au motif.
                matching_patterns.append(pattern)  # Conserve le motif correspondant.

        if matching_patterns:  # Au moins un motif publie ce fichier sensible.
            artifact_finding_count += 1  # Compte un constat par workflow et fichier sensible.


            findings.append({
            "rule_id": "S5",
            "path": "ci.json",
            "workflow_id": workflow_id,
            "evidence": {
                "sensitive_path": relative_path,
                "matching_patterns": matching_patterns.copy()
            },
            "rationale": "Un fichier déclaré sensible est publié comme artefact.",
            "next_action": "Limiter les artefacts aux fichiers non sensibles nécessaires."
            })

            print(f"\n[S5] Workflow : {workflow_id}")  # Identifie le workflow.
            print(f"Fichier sensible : {relative_path}")  # Identifie le fichier publié.
            print(
                f"Preuve : artifact_paths={matching_patterns} correspond à {relative_path}"
            )  # Montre les motifs responsables.
            print(
                "Raison : la politique interdit de publier ce fichier sensible, "
                "même si son token actuel est révoqué."
            )  # Explique pourquoi la rotation ne supprime pas ce risque.
            print(
                "Action : limiter les artefacts aux fichiers non sensibles nécessaires, "
                "par exemple build/report.txt."
            )  # Propose une liste de fichiers explicitement autorisés.

print(f"\nTotal S5 : {artifact_finding_count}")  # Affiche le nombre de constats S5.

# Additionne les résultats des cinq règles.
total_findings = finding_count + ci_finding_count + artifact_finding_count

print(f"Total S1–S5 : {total_findings}")  # Affiche le total général.



# --- 12. Documenter les occurrences bénignes ---

print("\n--- Décisions bénignes : aucune exposition active S1 ---")  # Affiche le titre.

benign_count = 0  # Compte les occurrences bénignes trouvées.

for relative_path in sorted(content_paths):  # Réutilise les chemins collectés pour S5.
    file_path = snapshot / relative_path  # Reconstruit le chemin du fichier.
    lines = file_path.read_text(encoding="utf-8").splitlines()  # Lit ses lignes.

    for line_number, line in enumerate(lines, start=1):  # Numérote les lignes dès 1.
        for token in inventory["tokens"]:  # Examine chaque token connu.

            # Ne retient que les deux états explicitement bénins pour S1.
            if token["state"] not in ("revoked_in_fixture", "test_only"):
                continue  # Ignore les tokens actifs dans cette partie.

            if not token["value"] or token["value"] not in line:
                continue  # Ignore les valeurs vides ou absentes de la ligne.

            benign_count += 1  # Compte cette occurrence bénigne.

            evidence = line  # Prépare une copie de la ligne pour la preuve.

            # Masque toutes les valeurs connues, y compris un éventuel token actif
            # qui pourrait apparaître sur la même ligne.
            for known_token in sorted(
                inventory["tokens"],  # Liste des tokens connus.
                key=lambda item: len(item["value"]),  # Trie par longueur de valeur.
                reverse=True,  # Masque les valeurs longues en premier.
            ):
                if known_token["value"]:  # Évite les remplacements de chaînes vides.
                    evidence = evidence.replace(
                        known_token["value"],  # Valeur à masquer.
                        f"[REDACTED:{known_token['token_id']}]",  # Conserve l’identifiant.
                    )

            if token["state"] == "test_only":  # Cas d’un marqueur de test.
                reason = "L'inventaire classe ce token comme marqueur de test."
            else:  # L’autre état autorisé dans cette boucle est revoked_in_fixture.
                reason = "L'inventaire indique que ce token est révoqué."

            print(f"\n[BÉNIN POUR S1] {relative_path}, ligne {line_number}")  # Localisation.
            benign_decisions.append({
                "rule_id": "S1",
                "decision": "suppressed",  # Indique que cette occurrence ne déclenche pas S1.
                "path": relative_path,
                "line": line_number,
                "token_id": token["token_id"],
                "state": token["state"],
                "evidence": evidence,  # Preuve déjà masquée.
                "rationale": reason  # Justification déjà calculée.
            })
            print(f"Token : {token['token_id']}")  # Identifiant uniquement.
            print(f"Preuve : {evidence}")  # Ligne avec valeurs masquées.
            print(f"Justification : {reason}")  # Explique la décision.

print(f"\nTotal des occurrences bénignes : {benign_count}")  # Affiche le bilan.
# --- 13. Exporter les résultats ---

output_dir = Path("outputs") / snapshot.name  # Sépare les sorties des deux snapshots.
output_dir.mkdir(parents=True, exist_ok=True)  # Crée les dossiers s’ils n’existent pas.

report = {  # Assemble uniquement les résultats, sans exporter l’inventaire sensible.
    "snapshot": snapshot.name,
    "finding_count": len(findings),
    "findings": findings,
    "benign_decision_count": len(benign_decisions),
    "benign_decisions": benign_decisions
}

report_path = output_dir / "findings.json"  # Définit le chemin du rapport.

with report_path.open("w", encoding="utf-8") as file:  # Ouvre le fichier en écriture.
    json.dump(
        report,  # Données à enregistrer.
        file,  # Fichier de destination.
        ensure_ascii=False,  # Conserve les accents.
        indent=2  # Rend le JSON lisible.
    )
    file.write("\n")  # Termine le fichier par un saut de ligne.

print(f"\nRapport JSON enregistré : {report_path}")  # Confirme l’emplacement.


# --- 14. Enregistrer un résumé lisible ---

summary_path = output_dir / "summary.txt"  # Chemin du résumé.

with summary_path.open("w", encoding="utf-8") as file:
    file.write(f"Audit : {snapshot.name}\n")  # Identifie le snapshot.
    file.write(f"Risques détectés : {len(findings)}\n")
    file.write(f"Décisions bénignes : {len(benign_decisions)}\n")

    for finding in findings:  # Présente chaque risque.
        file.write(f"\n[{finding['rule_id']}] {finding['path']}\n")

        if "line" in finding:  # Ajoute la ligne pour les constats texte.
            file.write(f"Ligne : {finding['line']}\n")

        if "workflow_id" in finding:  # Identifie le workflow pour les constats CI.
            file.write(f"Workflow : {finding['workflow_id']}\n")

        # Convertit la preuve en texte, qu’elle soit une chaîne ou un dictionnaire.
        evidence_text = json.dumps(finding["evidence"], ensure_ascii=False)
        file.write(f"Preuve : {evidence_text}\n")
        file.write(f"Raison : {finding['rationale']}\n")
        file.write(f"Action : {finding['next_action']}\n")

    file.write("\n--- Décisions bénignes pour S1 ---\n")

    for decision in benign_decisions:  # Explique les occurrences exclues de S1.
        file.write(
            f"\n{decision['path']}, ligne {decision['line']} "
            f"— {decision['token_id']}\n"
        )
        file.write(f"Preuve : {decision['evidence']}\n")
        file.write(f"Justification : {decision['rationale']}\n")

print(f"Résumé enregistré : {summary_path}")  # Confirme l’enregistrement.