import argparse  # Permet de récupérer les arguments écrits dans le terminal.
import json  # Permet de convertir le contenu JSON en objets Python.
from pathlib import Path  # Permet de manipuler les chemins des fichiers et dossiers.


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