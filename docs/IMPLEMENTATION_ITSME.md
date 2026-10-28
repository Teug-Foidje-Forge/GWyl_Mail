# Implémentation itsme

Décision figée. Ce document dit comment le code la réalise.

## Règle

itsme s'affiche sur le téléphone. L'appelant ne répond pas à la place de la personne. Les deux réponses sont signées, donc l'expéditeur est attesté dans les deux cas.

| Réponse | Preuve de contenu | Ce que reçoit le destinataire | Ce qui reste sur la machine |
|---|---|---|---|
| Oui | Générée | Le message et la preuve | La même attestation |
| Non | Pas générée | Le message, non signé | L'attestation du refus |

Le refus n'ajoute pas de valeur légale. L'acceptation est le choix d'officialiser cet envoi. L'identité ne change pas.

## Étape en cours

Sans contrat avec itsme, le logiciel ne peut pas ouvrir l'application ni vérifier sa signature. Il ne doit pas prétendre le contraire.

- `gwyl-mail notarize` appelle une application. Aujourd'hui cette application est `UnavailableApp`. La commande s'arrête, code 2, et n'écrit aucune preuve.
- Une application de test, invisible dans la commande, signe un oui ou un non. Elle ne peut pas être activée par un argument.
- Toute réponse signée est enregistrée dans `.gwyl_mail/attestations/<hash>.json`. Pas d'adresse dedans.
- Un oui ajoute la pièce `gwylitsme.json`, liée à l'empreinte canonique. `check` vérifie cette liaison. La signature est marquée `unverified` : ce n'est pas une signature qualifiée tant que le certificat itsme n'est pas vérifié.
- Un non réécrit le message tel qu'il était. `check` n'y trouve pas de preuve. Si un refus est quand même joint au message, `check` le refuse.

## Étape suivante, pas maintenant

Brancher l'application réelle, vérifier la signature avec son certificat, et seulement alors écrire `signer.assurance = qualified` sur un oui. Le numéro de registre national ne part pas.
