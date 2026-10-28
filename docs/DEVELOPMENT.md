# GWyl Mail — document de développement

Version du document : 2026-10-28
Code visé : 0.3.1, branche `main`
Statut : décisions de développement. En cas de conflit avec `docs/SUMMARY.md`, `PROJECT_TREE.txt` ou une spec v0 non réécrite, ce document gagne jusqu'à mise à jour de la spec.

Ce n'est pas un avis juridique. Les noms de règlements servent à borner ce que le logiciel a le droit d'affirmer.

## 1. Objet

GWyl produit et vérifie une preuve d'intégrité sur un message, transportée par le courrier existant.

Trois faits, trois champs, jamais un seul verdict :

| Fait | Champ | Source acceptée |
|---|---|---|
| Intégrité du contenu | `integrity` | Hash canonique versionné |
| Identité du signataire | `signer` | Certificat vérifié, avec un niveau annoncé |
| Existence avant une date | `time` | OpenTimestamps, et plus tard un jeton RFC 3161 |

GWyl n'est pas un office notarial, pas un prestataire de confiance qualifié, et pas un client mail.

## 2. Ce que l'interface a le droit d'afficher

Autorisé :

- « Le contenu correspond au hash. »
- « La preuve est signée par cette identité, via cet émetteur. »
- « Un calendrier OpenTimestamps a ancré ce hash dans Bitcoin. Existence corroborée, sans présomption légale. »
- « Un prestataire de la Trusted List a émis un horodatage qualifié sur ce hash. » Uniquement quand le jeton RFC 3161 est présent et vérifié.

Interdit, y compris dans les journaux, le JSON et le README :

- `legal_grade`, « notarisé », « valeur probante », « preuve légale », « non-répudiation » comme propriété déjà obtenue.
- Présenter OpenTimestamps ou Rekor comme un horodatage qualifié.
- Un score unique `LOW` / `MEDIUM` / `HIGH` qui additionne des faits de nature différente.

Les preuves déjà émises peuvent contenir `legal_grade` et `trust_level`. Le vérificateur les ignore. Il ne rejette pas l'ancienne preuve pour ces champs. Les preuves nouvelles ne les émettent plus.

## 3. Invariants

1. Un changement du jeu d'octets hashé est une nouvelle valeur `canonical.algorithm`. Les preuves anciennes restent vérifiables avec leur algorithme. Pas de réécriture silencieuse.
2. `gwyl-canonical-v0.3` est gelé : en-têtes `from`, `to`, `subject`, `date`, `message-id` ; corps visible `text/plain` et `text/html` ; pièces jointes hors pièces de preuve. Ne plus y ajouter `cc`.
3. Le prochain algorithme sera `gwyl-canonical-v0.4`. Il ajoute `cc`, normalisé comme `to`. `bcc` n'est jamais hashé : il ne survit pas au transit.
4. Le profil de notarisation est strict. `--allow-degraded`, `--no-dsse` et `identity_policy.mode: warn` sont des outils de laboratoire. Une commande de notarisation les refuse.
5. La preuve couvre le message sans ses propres pièces jointes. Deux pièces de même nom de preuve rendent le message ambigu : `check` refuse.
6. L'interface et l'API n'écoutent que `127.0.0.1`.
7. `diagnostic.plain` (`gwyl-plain-v0.3`) couvre les mêmes en-têtes et pièces, sans le HTML. `decides` vaut `false`. Si le HTML seul a changé, `check` refuse et dit `html_differs`. Le chemin SMTP ne choisit pas cette règle.

## 4. État au 0.3.1

Fait : hash v0.3, enveloppe DSSE, refus d'une enveloppe non signée et d'un écart d'identité sauf `--allow-degraded`, pièces `gwylproof.json`, `gwylproof.ots`, `gwylbundle.json`, en-tête consultatif `X-GWyl-Proof`, `gwyl-mail ui`, extensions navigateur et Thunderbird, Postfix mesuré.

Pas fait, et dans cet ordre : vocabulaire, v0.4, paquet hybride, RFC 3161, identité stricte par profil, Gmail et Outlook, journal de conservation.

Ne pas développer en parallèle le portefeuille EUDI, le proxy SMTP, le filtre Postfix, la session de rédaction et le chiffrement de bout en bout.

## 5. Phase 0 — dire vrai

But : le dépôt ne prétend plus à une valeur qu'il n'a pas.

- `gwyl_mail/dual_proof.py` : ne plus écrire `legal_grade` ni un `trust_level` synthétique. Écrire `integrity`, `signer`, `time` (voir section 6).
- `gwyl_mail/cli.py` et `gwyl_mail/ui_static/index.html` : afficher les trois faits. Pas de pastille unique.
- `gwyl_mail/__init__.py` : remplacer « non-répudiation » et « preuve légale » par la phrase de la section 1.
- Specs : `docs/specs/CANONICALIZATION_v0.md` dit encore que le HTML est réduit à son texte. Le réécrire pour décrire v0.3, ou ajouter en tête un renvoi daté vers ce document et marquer le passage HTML comme caduc. Même traitement pour `legal_grade` dans `docs/specs/PROOF_SCHEMA_v0.md`.
- Archiver, en une ligne en tête, `docs/SUMMARY.md` et `PROJECT_TREE.txt` : « Phase 0, 2025. Ne décrit pas le code. »
- `tests/` : une preuve nouvelle n'a pas `legal_grade`. Une preuve ancienne qui l'a passe encore `check` si le hash et la signature tiennent.
- Anti-rejeu : retirer l'exigence d'un nonce de cinq minutes du schéma actif. Le champ peut rester ignoré en lecture. Ne pas construire de registre de nonces.

Fini quand : `rg legal_grade gwyl_mail` ne trouve que le commentaire « ignoré en lecture », et la suite de tests passe.

## 6. Forme de la preuve nouvelle

Conserver l'enveloppe DSSE. Le payload JSON gagne ces objets et perd `legal_grade` et `trust_level`.

```json
{
  "version": "0.3.1",
  "canonical": {
    "algorithm": "gwyl-canonical-v0.3",
    "content_hash": "<hex sha256>"
  },
  "integrity": { "match": null },
  "signer": {
    "identity": null,
    "issuer": null,
    "assurance": "oidc-sigstore",
    "matches_requested": null
  },
  "time": {
    "opentimestamps": { "status": "PENDING", "proof_file": "gwylproof.ots" },
    "rfc3161": null
  }
}
```

`integrity.match` est rempli par `check`, pas à la création. `signer.assurance` vaut `oidc-sigstore` aujourd'hui, `qualified` seulement avec un certificat qualifié vérifié. `time.rfc3161` reste `null` tant que la phase 2 n'est pas livrée.

`signer.assurance` et les statuts de temps ne sont pas additionnés.

## 7. Phase 1 — le paquet qui survit au relay

But : si un filtre retire les pièces jointes, le destinataire peut encore retrouver la preuve, et voit l'échec si le corps a changé.

Trois supports du même payload signé :

| Support | Contenu | Rôle |
|---|---|---|
| Pièces jointes actuelles | Preuve, timbre, bundle | Vérification sans réseau |
| En-tête `GWyl-Proof-Ref` | Référence courte | Survivre quand les pièces sont retirées |
| Copie locale adressée par le hash | Le même paquet | Récupération |

En-tête, une seule ligne, ASCII :

```text
GWyl-Proof-Ref: v1; alg=gwyl-canonical-v0.3; sha256=<64 hex>; rekor=<index ou ->; ots=<16 premiers hex du timbre ou ->
```

Pas de preuve Base64 dans un en-tête. `X-GWyl-Proof: v1` reste un marqueur consultatif.

Copie locale : `.gwyl_mail/packages/<sha256>.json` plus les binaires du timbre et du bundle à côté. Écriture à `sign`. `check`, si les pièces manquent et que l'en-tête est présent, cherche cette copie puis échoue avec `proof_not_local` s'il ne l'a pas. Pas d'appel réseau implicite.

IPFS, et tout autre réseau public, n'est pas un stockage de preuve : la preuve contient des adresses mail. Un cache content-addressed ne se discute qu'après un paquet chiffré, et ce n'est pas cette phase.

Tests obligatoires :

- Pièces retirées, en-tête intact, copie locale présente, corps intact : succès, raison `proof_recovered_locally`.
- Pièces retirées, corps modifié : échec d'intégrité, jamais un succès sur la copie.
- Deux `gwylproof.json` : échec `ambiguous_proof`, déjà en place.
- L'en-tête ne contient pas `@` ni le corps du message.

Fini quand ces quatre tests passent et que `sign` émet l'en-tête.

## 8. Phase 2 — le temps qualifié

But : un horodatage que l'on a le droit d'appeler qualifié, posé sur le même `content_hash`.

- Nouveau module `gwyl_mail/rfc3161.py`. Entrée : les octets hex du hash. Sortie : jeton brut, horodatage, nom du prestataire, empreinte du certificat.
- Le prestataire vient de la configuration, un seul URL par défaut, documenté. Le certificat du jeton doit chaîner vers un prestataire présent dans la Trusted List de l'UE au moment de la vérification. Si la liste n'est pas disponible, le résultat est `rfc3161: unverified`, pas `qualified`.
- OpenTimestamps ne change pas de rôle. Il reste `time.opentimestamps`.
- Les deux horloges sont affichées l'une sous l'autre. Aucune ne « valide » l'autre.
- Échec réseau du prestataire : la preuve Sigstore et OpenTimestamps part quand même, `rfc3161` vaut `null`, et `sign` le dit sur stderr. Ce n'est pas un mode dégradé silencieux, et ce n'est pas `--allow-degraded`.

Ne pas créer un prestataire de confiance. Ne pas générer l'heure localement et la signer avec la clé du projet.

Fini quand un vecteur de test rejoue un jeton figé sans réseau et que le vérificateur refuse un jeton dont la chaîne ne mène pas à la Trusted List.

## 9. Phase 3 — identité

Trois profils de commande, pas un booléen de plus.

| Profil | Commande | Règle |
|---|---|---|
| `lab` | celles d'aujourd'hui | OIDC Sigstore. `--allow-degraded` permis. L'UI affiche « laboratoire ». |
| `org` | `gwyl-mail notarize` | Identité demandée égale au certificat, politique `strict`, cosign et ots présents. Sinon refus, code 2. |
| `qualified` | non implémenté | Réservé dans `signer.assurance`. Pas d'appel EUDI tant que le portefeuille n'est pas là. Échéance des États : 24 décembre 2026. |

`notarize` est un alias de `sign` qui force le profil `org` et `gwyl-canonical-v0.4` dès que v0.4 existe. Avant v0.4, il reste sur v0.3 et l'annonce.

`From` n'a pas à être égal à l'identité du certificat : un envoi pour le compte d'une boîte fonctionnelle est réel. Le profil `org` exige l'égalité, le profil `lab` non. Le documenter dans la sortie, pas le deviner.

## 10. Phase 4 — traversée

Mesurer, ne pas assouplir le hash pour faire passer le test.

Messages : texte seul, texte plus HTML, une pièce jointe, pied de page ajouté par le webmail, pièces de preuve retirées. Providers : Postfix (déjà fait), Gmail, Outlook. Le script existe : `scripts/interop_postfix.py`. Le généraliser sans Docker obligatoire pour les deux webmails : dépôt d'un `.eml` envoyé, relevé du `.eml` reçu, `check`.

Résultat attendu et à publier dans `docs/PERFORMANCE.md` :

- En-têtes `Received`, `ARC`, `DKIM` : le hash tient.
- Pied de page ou HTML réécrit : le hash ne tient pas. C'est le résultat juste. Le noter, ne pas ouvrir un profil qui ignore le pied de page.
- Pièces de preuve retirées : couvert par la phase 1.

Le profil `relaxed` actuel ne fait pas ce que la spec v1 promettait. Ne pas l'étendre. Le laisser pour la compatibilité des preuves déjà créées avec, et écrire dans l'aide de la commande : « ne retire pas les pieds de page ».

## 11. Phase 5 — usage

Le chemin supporté est le suivant.

1. Le message est rédigé dans le client habituel.
2. `gwyl-mail notarize brouillon.eml -o pret.eml` ou la page locale.
3. `pret.eml` est envoyé par ce client.
4. Le destinataire ouvre Thunderbird ou la page locale et lance la vérification.

L'extension ne calcule rien. Elle poste le brut sur `http://127.0.0.1:8765/api/check` avec `X-GWyl-Client: 1`.

Pas de proxy SMTP. Pas d'accusé d'ouverture : un relais peut lire le message. Le chiffrement de bout en bout n'est pas au programme de cette version.

## 12. Phase 6 — conservation

Implémenter le journal déjà décrit dans `docs/specs/RECEIPT_LOG_v0.md`, avec les corrections suivantes.

- Fichier : `.gwyl_mail/mail_proofs.jsonl`, une ligne JSON, ouverture en ajout, `fsync`.
- La ligne pointe vers le hash, le paquet, le statut OpenTimestamps et le statut RFC 3161. Pas d'adresse en clair : hash salé, le sel reste local.
- La durée de conservation est un argument de `notarize` (`--keep 5y`, `--keep 10y`). Pas de défaut à vingt-quatre mois.
- La copie de secours est un dossier choisi par l'utilisateur, chiffré. Pas un réseau public.
- Quand un certificat du paquet approche de l'expiration, `gwyl-mail preserve <hash>` redemande un jeton RFC 3161 sur le paquet entier et ajoute une ligne. Il ne réécrit pas la ligne ancienne.

La session de rédaction (`docs/specs/DRAFT_SESSION_v0.md`) n'est pas implémentée dans cette version.

## 13. CRA

Le règlement (UE) 2024/2847 ne change pas le code tant que GWyl n'est pas mis sur le marché comme produit. Un dépôt GPL utilisé hors activité commerciale n'est pas traité ici comme un fabricant.

Le jour où il est vendu, hébergé commercialement ou intégré dans un produit :

- Les obligations de signalement de l'article 14 sont déjà applicables depuis le 11 septembre 2026 pour un fabricant : alerte sous 24 heures, notification sous 72 heures, plateforme ENISA.
- Le reste du règlement s'applique le 11 décembre 2027.
- Avant cette mise sur le marché, le dépôt doit avoir un SBOM, une adresse de signalement, et une durée de support écrite. Pas de téléchargement de binaire sans empreinte.

Ce chantier ne précède pas les phases 0 à 2.

## 14. Ordre et hors sujet

Ordre : phase 0, phase 1, v0.4 à l'intérieur de la phase 3, phase 2, phase 4, phase 5, phase 6.

Hors sujet jusqu'à la fin de la phase 4 : EUDI, PGP, S/MIME, proxy SMTP, filtre de contenu Postfix, IPFS, registre de nonces, profil qui ignore les pieds de page, nouveau niveau de confiance unique.

## 15. Références qui restent valables

- Traversée : `docs/Traversal_Concept.md` (pièce jointe, en-tête court, copie hors du message). La copie n'est pas IPFS.
- Intégration actuelle : `docs/INTEGRATION.md`.
- Journal : `docs/specs/RECEIPT_LOG_v0.md`, corrigé par la section 12.
- Identité : `docs/specs/IDENTITY_POLICY_v0.md`, pour les modes `strict` et les émetteurs. Le mode `warn` ne s'applique qu'au profil `lab`.
- KPI de performance déjà mesurés : `docs/PERFORMANCE.md`. Les objectifs Gmail et Outlook de `docs/specs/KPI_POC.md` restent ouverts, et la phase 4 les reprend.
