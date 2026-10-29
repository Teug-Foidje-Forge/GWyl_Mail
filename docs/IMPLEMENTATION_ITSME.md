# Implémentation itsme

Décision figée. Ce document dit comment le code la réalise.

## Règle

itsme est une option. Désactivée, `sign` et `check` fonctionnent comme aujourd'hui, sans vérification d'identité. L'utilisateur l'active avec `gwyl-mail itsme on`, et s'en sert message par message.

Une fois activée, la question s'affiche sur le téléphone. L'appelant ne répond pas à la place de la personne. Les deux réponses sont signées, donc l'expéditeur est attesté dans les deux cas.

| Réponse | Preuve de contenu | Ce que reçoit le destinataire | Ce qui reste sur la machine |
|---|---|---|---|
| Oui | Générée | Le message et la preuve | La même attestation |
| Non | Pas générée | Le message, non signé | L'attestation du refus |

Le refus n'ajoute pas de valeur légale. L'acceptation est le choix d'officialiser cet envoi. L'identité ne change pas.

## Étape en cours

Sans contrat avec itsme, le logiciel ne peut pas ouvrir l'application ni vérifier sa signature. Il ne doit pas prétendre le contraire.

- `gwyl-mail itsme` est désactivé par défaut. `notarize` n'écrit rien et ne bloque pas `sign`.
- Une fois activé, `notarize` appelle l'application. Aujourd'hui cette application est `UnavailableApp` : la commande s'arrête, code 2, et n'écrit aucune preuve.
- Une application de test, invisible dans la commande, signe un oui ou un non. Elle ne peut pas être activée par un argument.
- Toute réponse signée est enregistrée dans `.gwyl_mail/attestations/<hash>.json`. Pas d'adresse dedans.
- Un oui ajoute la pièce `gwylitsme.json`, liée à l'empreinte canonique. `check` vérifie cette liaison.
- `qualified` n'est écrit que si la signature vérifie avec le certificat, et que ce certificat est émis par une ancre présente dans `.gwyl_mail/itsme-trust/*.pem`. L'ancre n'est jamais prise dans le message. Sans ancre, ou si la signature ne vérifie pas, le résultat reste `unverified`.
- Un non réécrit le message tel qu'il était. `check` n'y trouve pas de preuve. Si un refus est quand même joint au message, `check` le refuse.

## Étape suivante, pas maintenant

Ouvrir l'application itsme réelle demande les identifiants partenaire (contrat itsme Sign, hash envoyé à leur API, certificat renvoyé). Ce dépôt ne les invente pas. Quand ils sont là, le certificat d'émission itsme se place dans `.gwyl_mail/itsme-trust/`. Le numéro de registre national ne part pas.
