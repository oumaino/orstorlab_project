# Journal de travail et utilisation de l’IA

## Approche

Développement progressif d’un auditeur hors ligne :
- Lecture de l’inventaire.
- Détection des expositions de tokens actifs avec S1.
- Analyse des workflows avec S2, S3 et S4.
- Vérification des artefacts avec S5.
- Ajout des décisions bénignes et des preuves masquées.
- Export JSON, puis résumé texte.
- Ajout de tests automatiques et de la documentation.

## Décisions

J’ai utilisé Python et sa bibliothèque standard pour éviter les
dépendances et permettre une exécution locale simple.

L’état déclaré dans inventory.json fait autorité, même lorsqu’une
valeur contient un mot trompeur comme ACTIVE.

Les occurrences textuelles et les références CI sont analysées
séparément. Une référence CI désigne un token_id, pas sa valeur.

La règle S5 reste indépendante de l’état des tokens : un fichier
déclaré sensible ne doit pas être publié, même après révocation.

Les corrections proposées ciblent d’abord pr-build, puis le nettoyage
du dépôt, conformément à la capacité d’intervention indiquée.

## Obstacles et réponses

### Chemin des entrées

La première commande cherchait inputs/snapshot-one depuis la racine
du projet, alors que les entrées étaient dans candidate/inputs.

J’ai corrigé l’argument fourni au script pour utiliser :
candidate/inputs/snapshot-one.

### Placement du bloc S2

Pendant l’intégration de l’export JSON, une condition S3 a été placée
par erreur dans la partie S2, avant la définition de permissions_allowed.

La revue assistée par IA a identifié un NameError et les deux lignes
à supprimer. Après correction, j’ai relancé les deux analyses et
vérifié les constats exportés.

### Découverte des tests

La première commande unittest ne trouvait pas de dossier tests
utilisable depuis le répertoire courant.

Après correction de l’emplacement du fichier de test, les six tests
ont été découverts et exécutés avec succès.

## Validation et amélioration

Les résultats sur les entrées fournies ont été comparés à la politique :
- Snapshot-one : 5 risques et 2 occurrences bénignes.
- Snapshot-two : 2 risques et 3 occurrences bénignes.

J’ai vérifié les règles, les chemins, les lignes, les identifiants,
les justifications et les valeurs masquées dans les exports JSON.

La validation a ensuite été étendue à des données synthétiques :
- Token actif dans la documentation.
- Tokens révoqués et de test exclus de S1.
- Douze combinaisons de permissions, déclenchement et confiance.
- Motif app/* publiant un fichier sensible sans token actif.
- Références actives nécessaires pour déclencher S2 et S4.
- Absence des valeurs complètes dans le terminal et le JSON.

Les six tests ont réussi. La sortie enregistrée de la vérification
figure dans outputs/verification.txt.

Le résumé texte a ensuite été ajouté en réutilisant les preuves
déjà masquées.

## Utilisation de l’IA

J’ai utilisé ChatGPT pour :
- Comprendre l’énoncé et les règles.
- Générer des propositions de code commenté.
- M’aider à intégrer et expliquer les différentes parties.
- Relire le script et diagnostiquer les erreurs.
- Proposer les tests automatiques et les brouillons de documentation.

Le code et les tests ont été développés avec une assistance importante
de l’IA. J’ai exécuté les commandes localement et comparé les résultats
aux règles et aux fichiers fournis.

### Exemple de proposition acceptée et vérifiée

L’IA a proposé fnmatch.fnmatchcase pour comparer les motifs d’artefacts
aux chemins relatifs.

J’ai vérifié cette proposition avec :
- Le second snapshot, où app/* correspond à app/env.txt.
- Un test synthétique où app/env.txt ne contient aucun token actif.

Dans les deux situations, S5 est détectée, conformément à la politique.

Les tests proposés par l’IA sont un moyen de vérification supplémentaire,
pas une preuve exhaustive de l’absence de défauts.

## Limites et prochaine étape

L’auditeur suppose des entrées conformes au schéma et du texte UTF-8.
Il ne recherche que les valeurs connues de l’inventaire.

Les références CI inconnues sont signalées dans le terminal mais ne
sont pas encore exportées sous forme structurée.

Le test de masquage couvre le terminal et le JSON. Une amélioration
serait de vérifier automatiquement le résumé texte également.

Avant livraison : vérifier l’archive extraite dans un dossier propre,
relancer les analyses et les tests, puis contrôler la taille du ZIP.