# Secrets and CI Audit

## Objectif

Auditeur Python hors ligne appliquant les règles S1 à S5 de la politique
PineBuild aux snapshots fournis.

Il produit un rapport JSON et un résumé texte avec des preuves masquées.
Les fichiers d’entrée ne sont pas modifiés.

## Prérequis

- Python 3.10 ou supérieur.
- Bibliothèque standard uniquement.
- Aucun compte, accès réseau ou installation de dépendances nécessaire.

La version exacte utilisée pour la validation est enregistrée dans
outputs/python-version.txt.

## Organisation

- auditor.py : script d’audit.
- candidate/README.md : énoncé fourni.
- candidate/inputs/policy.md : politique et schéma de référence.
- candidate/inputs/snapshot-one/ : premier état du dépôt.
- candidate/inputs/snapshot-two/ : second état du dépôt.
- tests/test_auditor.py : tests automatiques.
- outputs/ : rapports et preuves de vérification.
- REMEDIATION.md : priorités et comparaison des snapshots.
- WORK_LOG.md : décisions, difficultés, validation et utilisation de l’IA.

## Exécuter les analyses

Depuis le dossier contenant auditor.py :

```powershell
python auditor.py candidate/inputs/snapshot-one
python auditor.py candidate/inputs/snapshot-two
```

Chaque commande affiche les résultats dans le terminal et génère :

- outputs/<nom-du-snapshot>/findings.json
- outputs/<nom-du-snapshot>/summary.txt

Une nouvelle exécution remplace les rapports du même nom.
Les résultats sont enregistrés relativement au dossier courant.

## Analyser un autre snapshot

```powershell
python auditor.py chemin/vers/nouveau-snapshot
```

Le snapshot doit respecter le schéma fourni : inventory.json, ci.json
et les dossiers de contenu app/, tests/, docs/ et build/.

Les règles restent inchangées. Les chemins sensibles fixés par la
politique sont app/env.txt et docs/rotation.txt.

## Exécuter les tests

```powershell
python -m unittest discover -s tests -v
```

Les six tests vérifient :

1. La détection d’un token actif dans la documentation.
2. L’exclusion des tokens révoqués et des marqueurs de test.
3. Les douze combinaisons de déclenchement, confiance et permissions.
4. La publication d’un fichier sensible via un motif, sans token actif.
5. Les conditions combinées de disponibilité des secrets et de logging.
6. Le masquage des valeurs dans le terminal et le rapport JSON.

Ils créent leurs propres données dans des dossiers temporaires et
exécutent le véritable script. Les snapshots fournis restent inchangés.

La sortie de vérification est conservée dans outputs/verification.txt.

## Résultats attendus sur les entrées fournies

| Snapshot | Risques | Décisions bénignes | Règles déclenchées |
|---|---:|---:|---|
| snapshot-one | 5 | 2 | S1, S2, S3, S4, S5 |
| snapshot-two | 2 | 3 | S1, S5 |

Une décision bénigne pour S1 ne signifie pas que le fichier peut être
publié : S5 reste indépendante de l’état des tokens.

## Présentation écrite du fonctionnement

1. Le script charge l’inventaire pour connaître les valeurs et états
   des tokens. L’inventaire lui-même n’est pas traité comme une fuite.

2. Il parcourt uniquement app/, tests/, docs/ et build/.
   Les correspondances avec des tokens actifs produisent des constats S1.
   Les occurrences de tokens révoqués ou de test sont documentées
   séparément comme décisions bénignes.

3. Il examine les workflows dans ci.json. Les secret_refs sont des
   identifiants consultés dans l’inventaire, pas des valeurs recherchées
   dans le texte. S2, S3 et S4 sont évaluées séparément.

4. Il compare les motifs d’artefacts aux chemins relatifs des fichiers
   fournis avec fnmatchcase. Un fichier sensible correspondant déclenche S5.

5. Il masque les valeurs connues avant de présenter les preuves,
   puis exporte les résultats en JSON et en texte.

Le second snapshot montre pourquoi une rotation ne suffit pas :
le nouveau token actif apparaît dans la documentation et app/* publie
toujours un fichier sensible.

## Limites

- L’outil applique une politique fictive, pas la syntaxe réelle d’un
  fournisseur CI.
- Il suppose des fichiers conformes au schéma et du contenu texte UTF-8.
- Il recherche les valeurs connues de l’inventaire ; il ne découvre pas
  des secrets inconnus par heuristique.
- Il n’analyse pas l’historique Git, les logs réels ou les services externes.
- Les références inconnues sont signalées dans le terminal, mais ne sont
  pas encore exportées dans une liste structurée dédiée.
- Le test de masquage couvre le terminal et le JSON ; le résumé texte
  réutilise les mêmes preuves masquées.