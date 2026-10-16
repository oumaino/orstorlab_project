# Priorités de remédiation

## Périmètre

L’analyse applique uniquement la politique fournie dans
candidate/inputs/policy.md aux deux snapshots fictifs.

Les tokens sont des marqueurs non fonctionnels. Les constats décrivent
des configurations dangereuses, sans démontrer une exploitation réelle.
Aucune modification de pipeline ni rotation réelle n’a été effectuée.

## Priorité 1 — Corriger le workflow pr-build

Responsable proposé : équipe CI / plateforme.
Ordre : intervention immédiate, avant la prochaine exécution.

Dans snapshot-one, pr-build cumule quatre violations :
- S2 : du code non fiable dispose du token actif release-active.
- S3 : les permissions write-all sont interdites.
- S4 : la journalisation complète de l’environnement est activée
  alors qu’un secret actif est disponible.
- S5 : app/env.txt est publié comme artefact.

Modifications proposées dans cet unique workflow :
- Retirer les références aux secrets actifs.
- Utiliser les permissions read-only.
- Désactiver log_environment.
- Limiter artifact_paths à build/report.txt.

Cet ordre respecte la capacité de l’équipe : un workflow peut être
modifié immédiatement. Il réduit plusieurs voies d’exposition avant
le nettoyage des copies de secrets.

Dans snapshot-two, S2, S3 et S4 sont déjà corrigées. La modification
restante concerne artifact_paths : app/* inclut toujours app/env.txt.
La révocation du token présent dans ce fichier ne constitue pas une
exception à S5.

Critère de validation : aucune violation S2 à S5 pour pr-build
après analyse d’un snapshot corrigé.

## Priorité 2 — Nettoyer les copies de secrets du dépôt

Responsable proposé : mainteneur du dépôt, avec le propriétaire du secret.
Ordre : programmer le nettoyage après la correction du workflow.

Occurrences actives à traiter selon le snapshot :
- Snapshot-one : release-active dans app/env.txt, ligne 2.
- Snapshot-two : release-rotated dans docs/rotation.txt, ligne 2.

Retirer les valeurs actives du contenu versionné et prévoir le
remplacement/révocation des tokens exposés dans le scénario.
Le remplacement ne doit pas être recopié dans la documentation.

Dans le second snapshot, release-active est déjà révoqué :
ne pas le présenter comme un secret encore actif.
La priorité porte sur release-rotated.

Les marqueurs test_only ne nécessitent pas de rotation.
Les copies révoquées peuvent être nettoyées sans les traiter comme
des expositions actives.

Critère de validation : aucune violation S1 après nettoyage et mise
à jour cohérente de l’inventaire fictif.

## Comparaison des snapshots

| Règle | Snapshot-one | Snapshot-two |
|---|---|---|
| S1 | release-active dans app/env.txt:2 | release-rotated dans docs/rotation.txt:2 |
| S2 | Violation dans pr-build | Corrigée |
| S3 | Violation dans pr-build | Corrigée |
| S4 | Violation dans pr-build | Corrigée |
| S5 | Publication de app/env.txt | Publication maintenue via app/* |
| Total des constats | 5 | 2 |

Le nombre de constats diminue, mais ne mesure pas à lui seul le niveau
de risque. Un nouveau token actif reste exposé, et la publication
d’un fichier sensible persiste.

## Limites

L’analyse porte sur les fichiers fournis et la configuration exportée.
Elle n’inspecte ni historique Git, ni logs réels, ni services externes.
L’inventaire constitue la source de référence pour l’état des tokens.
