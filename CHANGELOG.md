# Changelog - GWyl Mail

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère à [Semantic Versioning](https://semver.org/lang/fr/).

---

## [Unreleased]

## [0.3.1] - 2026-10-28

### Changé
- Le hash couvre chaque partie visible `text/plain` et `text/html`. Un message à un seul corps reste identique à `gwyl-canonical-v0.2`. Les nouvelles preuves portent `gwyl-canonical-v0.3`.
- `verify` et `check` refusent une enveloppe DSSE sans signature, sauf `--allow-degraded`.
- Une identité demandée différente de celle du certificat est refusée à la création, sauf `--allow-degraded`.
- Deux pièces jointes de preuve dans le même message sont refusées (`ambiguous_proof`).
- Les URL du paquet pointent vers `Teug-Foidje-Forge/GWyl_Mail`.

### Ajouté
- `gwyl-mail ui` : interface locale sur 127.0.0.1.
- Extensions navigateur (MV3) et Thunderbird 115 dans `extensions/`.
- `tests/test_adversarial.py`.

## [0.3.0] - 2026-09-17

### Sprint 10: KPIs mesurés & préparation pilote (2026-09-17)

#### Ajouté
- **scripts/benchmark.py**: harnais de mesure (hash canonique S→25 Mo, création,
  vérification offline vs avec binaire ots, overhead, soumission OTS réelle)
  avec sortie JSON/markdown et seuils KPI_POC.md intégrés.
- **scripts/interop_postfix.py**: test d'interopérabilité RÉEL — signature →
  SMTP Postfix (conteneur Docker) → livraison locale → 'check' sur chaque
  message délivré ; taux mesuré vs KPI ≥95%.
- **tests/test_performance.py** (3 tests): gardes KPI (vérification <150 ms,
  overhead <50 Ko, hash 25 Mo borné).
- **docs/PERFORMANCE.md**: chiffres réels mesurés vs seuils Go/NoGo.
- **docs/PILOT_GUIDE.md** + **docs/PILOT_FEEDBACK_TEMPLATE.md**: guide
  destinataire une page, procédure Gmail/Outlook reproductible, formulaire.
- **.github/workflows/release.yml**: tag v* → tests → build sdist/wheel →
  release GitHub avec notes auto-générées.

#### KPIs mesurés (résumé — détails dans docs/PERFORMANCE.md)

- Vérification offline: **4,5 ms** (< 150 ms) ✅
- Overhead embarqué (avec vrai timbre OTS): **4,4 Ko** (< 50 Ko) ✅
- Soumission OTS réelle: **1,5 s** (< 5 s) ✅
- Interopérabilité Postfix réel: **100% (50/50)** (≥ 95%) ✅
- Hash canonique 25 Mo: ~171 ms (info)
- Non mesurés (OIDC interactif / fenêtre 48h): création Sigstore <1 s,
  confirmation OTS ≥90% — planifiés au pilote.

#### Modifié
- Version **0.3.0** (pyproject + __init__), package-data complété
  (schemas/*.json, *.yml inclus dans la wheel — vérifié par build).

### Sprint 9: Intégration mail réelle — la preuve voyage avec le message (2026-09-17)

Le gain d'utilisabilité majeur : plus aucun fichier annexe à transférer à la
main entre expéditeur et destinataire.

#### Ajouté
- **gwyl_mail/eml_io.py**: inject_proof / extract_proof / strip_proof — la
  preuve est embarquée dans le .eml (pièces jointes gwylproof.json,
  gwylproof.ots, gwylbundle.json + en-tête X-GWyl-Proof: v1). Détection par
  pièce jointe (l'en-tête peut être retiré par un MTA). Invariant de hash
  canonique garanti et testé (plain/HTML/attachments).
- **CLI `gwyl-mail sign`**: produit un .eml prêt à envoyer depuis n'importe
  quel client, avec preuve portable embarquée (même gating honnête que
  create-proof: refus sans outils, --allow-degraded).
- **CLI `gwyl-mail check`**: le destinataire vérifie le message reçu SEUL —
  extraction, strip des pièces de preuve, matérialisation dans
  .gwyl_mail/inbox/<ts>/, délégation au cœur de vérification.
- **Preuves portables** (dual_proof portable=True + ProofArtifacts): les
  références internes (bundle_path, proof_file) deviennent des noms de pièces
  jointes, résolus via --lookup-dir à la vérification.
- **docs/INTEGRATION.md** et **examples/use_cases/USE_CASES.md** (livrables
  Sprint 6 jamais faits).
- **tests/test_eml_io.py** (10 tests): roundtrip, invariant de hash,
  suppression d'en-tête par MTA, mutations MTA, falsification de corps
  détectée, boucle complète sign → check.

#### Modifié
- **examples/run_examples.sh**: retrait de conda GWYL_Env et du chemin externe
  /home/zack/GWyl_Integrity ; ajout de la démo sign/check ; doctor en étape 1.
- **verify_proof_dsse**: paramètre lookup_dir (résolution du bundle portable).

#### Mesures
- Overhead embarqué (preuve dégradée, non signée): **3,0 Ko** — seuil KPI
  (50 Ko) largement respecté ; mesure preuve complète prévue Sprint 10.
- Suite: **134/134 tests**, coverage 69%, ruff/black/mypy propres.

### Sprint 8: Solidité du noyau (2026-09-17)

#### Ajouté
- **tests/test_sigstore_timestamp.py** (16 tests): chemins de dégradation de
  `sign_and_timestamp` (cosign absent, échec returncode, bundle non créé,
  timeout), parsing des variantes rekorEntry/rekorEntry, succès DSSE et
  échecs de vérification d'enveloppe.
- **gwyl_mail/identity_policy.py**: `allowed_identities` enfin appliqué
  (chargé depuis Sprint 2 mais jamais vérifié) — allowlist du sujet
  certificat, vide = tout accepter (compat). Résultat étendu avec `identity`.
- **gwyl_mail/cli.py**: `REASON_DESCRIPTIONS` — explications humaines des
  codes de raison normalisés (KPI_POC §6), affichées sur stderr après le
  JSON de vérification (stdout reste pur JSON).
- **Makefile**: cibles `test-poc` (référencée par KPI_POC.md, exister enfin)
  et `doctor`.
- **.github/workflows/ci.yml**: job lint (ruff + black --check + mypy),
  matrix de tests Python 3.9→3.12, job dédié avec opentimestamps-client.

#### Modifié
- **gwyl_mail/schemas/proof-v0.2.0.json**: durci — `required` sur les
  sous-champs structuraux de sigstore/opentimestamps, enums sur `status` et
  `trust_level`, `signer.matches_requested` dans le schéma. Les preuves
  dégradées légitimes restent valides (test de non-régression).
- **Codebase entier**: formatage black + ruleset ruff explicite
  (E/F/W/I/B) + mypy propre (21 erreurs résolues: casts ciblés, annotations,
  collision de variable `res` dans cmd_verify, `raise ... from`).
- **pyproject.toml**: mypy python_version 3.10 (mypy ≥1.19 ne supporte plus
  3.9; le runtime reste 3.9+).

#### Résultat
124/124 tests, coverage 68%, ruff/black/mypy propres (la CI les exige désormais).

### Sprint 7: Vérité & Onboarding (2026-09-17)

#### Corrigé
- **gwyl_mail/cli.py**: `verify` rapportait `dsse_signed: true` pour une enveloppe
  DSSE sans signature. Désormais : `dsse_signed: false` + raison
  `dsse_unsigned_envelope` + avertissement stderr explicite.
- **gwyl_mail/cli.py**: `create-proof` réussissait silencieusement sans cosign/ots
  avec un message mensonger ("DSSE-signed proof written"). Désormais :
  - refus par défaut (exit 2) avec diagnostic si cosign ou ots manque
  - `--allow-degraded` pour passer outre, avec bandeau d'avertissement
  - message final basé sur le contenu réellement produit (vérification
    post-création : signatures de l'enveloppe + statut OTS)

#### Ajouté
- **gwyl_mail/doctor.py** + sous-commande `gwyl-mail doctor`: vérification de
  l'environnement (binaires cosign/ots, paquets Python, réseau best-effort),
  sortie `--json`, `--skip-network` ; exit 1 si un prérequis manque.
- **gwyl_mail/dual_proof.py**: détection de divergence entre l'identité demandée
  (`--identity`) et l'identité effective du certificat (session OIDC cosign) ;
  champ `signer.matches_requested` dans la preuve + avertissement stderr.
- **tests/test_cli_usability.py** (10 tests) et **tests/test_ots_manager.py**
  (17 tests, dette Sprint 5) — suite totale : 104 tests, coverage 62%.

#### Documentation
- **GETTING_STARTED.md**: réécriture complète — prérequis réels documentés
  (cosign = binaire Go des releases Sigstore, ots = pip opentimestamps-client),
  `doctor` en étape 1, suppression des chemins locaux obsolètes.
- **pyproject.toml**: URLs du dépôt réelles (Kenchan1111/GWyl_Mail), maintainers
  corrigés (les IA contributrices restent créditées dans CONTRIBUTORS.md).

### Sprint 6 (partiel, livré avant ce changelog): Relaxed canonicalization (2025-10-13)
- Profils `strict`/`relaxed` (`--profile`), liste étendue d'en-têtes MTA exclus,
  `--profile-override` à la vérification, `canonical_profiles.yml`.

### Sprint 5: DSSE & Identity (livré avant ce changelog, 2025-10-13)
- Signature DSSE de la preuve (dsse_signer.py), extraction d'identité à la
  création, issuer matching strict (suffixe avec frontière de point), path
  traversal bloqué (symlinks), détails de cohérence Rekor↔OTS, privacy metadata.

### Sprint 4: Polish & Refinement (2025-10-12)

#### Modifié
- **gwyl_mail/canonical.py**: Fix type hints `GWylCanonical.hash()` to accept `EmailMessage | bytes | str`
- **gwyl_mail/cli.py**:
  - Use `tempfile.NamedTemporaryFile` instead of fixed path to avoid collisions
  - Expose `identity` and `issuer` in verify output JSON and audit log
- **pyproject.toml**: Remove unused dependencies (`click`, `rich`, `canonicaljson`)
- **Temporary_Integrity/commit_with_integrity.sh**: Enhanced integrity commit script
  - Implement baseline snapshot strategy (`.committed` in git + `.sha256` local)
  - Solve auto-reference problem (baseline can't contain its own hash)
  - Add verbose 7-step chain-of-trust verification
  - Show SHA256 hashes, file delta (unchanged/modified/added/removed)
  - Verify old = old before committing (chain integrity)
  - Complete audit trail: git diff, git log commands

#### Documentation
- **PROJECT_STATUS.md**: Complete update reflecting Sprint 1-4 achievements
- **CHANGELOG.md**: Update with Sprint 3 and Sprint 4 changes
- **.gitignore**: Exclude local baseline file (`SECURITY_INTEGRITY_BASELINE.sha256`)

#### Résultat ChatGPT Review Post-Sprint 4

**Points résolus** ✅:
1. Extraction identité Sigstore robuste (X.509 + SAN + issuer)
2. Timestamp OTS réel (ots info parsing, 3 formats)
3. Temp file unique (NamedTemporaryFile)
4. Identity/issuer exposés (verify output + audit)
5. Type hints corrects (EmailMessage | bytes | str)
6. Dependencies cleanup (click, rich, canonicaljson removed)

**Points critiques restants** ⚠️ (Sprint 5):
- P1: DSSE signature manquante (proof JSON pas signé)
- P1: Identity pas extraite à create_proof() (seulement à verify)
- P2: Issuer substring match trop permissif
- P2: Path traversal symlink possible
- P2: OTS parsing fragile
- P3: Coherence delta Rekor↔OTS pas visible
- P3: Privacy metadata incomplet

**Security Score**: 9.0/10 (Sprint 3-4)

---

## [0.1.0] - 2025-10-12

### Sprint 3: Security Hardening (2025-10-12)

#### Ajouté
- **gwyl_mail/sigstore_identity.py** (269 lignes): Robust Sigstore identity extraction
  - Proper X.509 certificate parsing using `cryptography` library
  - SAN (Subject Alternative Name) email extraction
  - Fulcio OIDC issuer extraction from OID `1.3.6.1.4.1.57264.1.1`
  - Rekor log index + integrated timestamp extraction
  - Replaces fragile heuristic extraction (ChatGPT Critical Issue #1)

- **tests/test_sigstore_identity.py** (217 lignes): 14 tests for identity extraction
  - Bundle parsing validation
  - X.509 certificate parsing
  - SAN email extraction
  - OIDC issuer extraction
  - Policy validation integration

#### Modifié
- **gwyl_mail/ots_manager.py**: Real OTS timestamp extraction
  - New method `_extract_real_timestamp()` parsing `ots info` output
  - Supports 3 timestamp formats: human-readable, ISO, Unix
  - Removes `datetime.now()` approximation (ChatGPT Critical Issue #2)
  - Enables reliable Rekor/OTS coherence check (24h threshold)

- **gwyl_mail/cli.py**:
  - Integrate robust identity extraction in `cmd_verify()`
  - Fallback to heuristic if robust extraction fails
  - Enhanced audit logging with extracted identity/issuer

#### Sécurité
- **Identity Policy now enforceable**: Certificate identity properly validated
- **Coherence check now reliable**: Real OTS timestamps enable accurate Rekor/OTS delta
- Security score: **8.5/10 → 9.0/10**

#### Tests
- 49/49 tests passing (vs 35/35 in Sprint 2)
- 50% code coverage

---

### Sprint 2: Identity Policy & Coherence (2025-01-11)

#### Ajouté
- **gwyl_mail/identity_policy.py** (~200 lignes): Identity policy validation
  - Exact match, domain match, alias support
  - OIDC issuer whitelist validation
  - Enforcement modes: strict/warn
  - Policy hash computation (SHA-256 over YAML)

- **gwyl_mail/policy_utils.py**: Policy utilities
  - `compute_policy_hash()`: SHA-256 over canonical YAML
  - `extract_policy_metadata()`: Extract policy_id, policy_url

- **Coherence check** in `gwyl_mail/cli.py`:
  - Rekor timestamp vs OTS timestamp delta
  - Threshold: 24 hours
  - Reports `coherence_ok`, `coherence_failed`, `coherence_unknown`

- **tests/test_identity_policy.py** (8 tests): Policy validation
- **tests/test_verify.py** (7 tests): End-to-end verification with policy

#### Modifié
- **gwyl_mail/canonical.py**: Unicode NFC normalization
  - Headers: `unicodedata.normalize('NFC', v)` (line 61)
  - Body: `unicodedata.normalize('NFC', normalized)` (line 82)
  - Prevents Unicode equivalence attacks

- **gwyl_mail/dual_proof.py**:
  - Add `policy` section in proof JSON
  - Compute `policy_hash` if policy provided
  - Include `policy_id` and `policy_url`

#### Tests
- 35/35 tests passing (vs 10/10 in Sprint 1)
- Policy validation: exact/domain/issuer matching
- Coherence: timestamp delta validation

---

### Sprint 1: Canonicalisation (2025-01-11)

#### Ajouté

**Phase 0: Spécifications**
- ✅ **CANONICALIZATION_v0.md** (v0.2.0): Algorithme normatif de canonicalisation DKIM-inspired
  - RFC 2047 (encoded-words) décodage complet
  - RFC 5322 (header folding) unfolding normalisé
  - Unicode NFC normalization (headers + filenames)
  - Profils strict/relaxed définis
  - 8 test cases détaillés
  - Effets MTA par provider (Gmail, Outlook, Postfix)

- ✅ **PROOF_SCHEMA_v0.md** (v0.2.0): Schéma de preuve cryptographique dual timestamping
  - Normalisation JSON (JCS - RFC 8785)
  - Signature proof (DSSE - Dead Simple Signing Envelope)
  - Champ `policy` avec `policy_id` + `policy_hash`
  - Cohérence temporelle précisée (delta_seconds, threshold_hours)
  - Anti-replay enrichi (created_at, ttl_seconds)

- ✅ **IDENTITY_POLICY_v0.md** (v0.1.0): Politique de mapping identité email ↔ certificat
  - Enforcement modes: warn / strict
  - Tolérances: exact / domain / alias
  - Whitelist issuers/domains
  - Alias management avec signature admin

- ✅ **KPI_POC.md** (v0.1.0): KPIs et critères de succès du PoC
  - Interopérabilité: ≥95% (Gmail, Outlook, Postfix)
  - Performance: <50KB overhead, <150ms vérification
  - Fiabilité: ≥90% confirmation OTS sous 48h
  - Sécurité: 100% détection tampering

- ✅ **TEST_VECTORS_v0.md** (v0.1.0): 7 vecteurs de test avec SHA-256 attendus
  - TV1-TV5: Messages avec résultats calculés
  - TV6-TV7: Cas edge (HTML-only, footer MTA)

**Phase 1: Implémentation Core**

- **gwyl_mail/canonical.py** (122 lignes): Canonicalisation DKIM-inspired
  - Headers: RFC 2047 decode, RFC 5322 unfold, Unicode NFC
  - Body: CRLF→LF, trailing space trim, Unicode NFC
  - Attachments: SHA-256 hash, sorted
  - Function `canonicalize()`, `compute_hash()`
  - Class `GWylCanonical` with static method `hash()`

- **gwyl_mail/sigstore_timestamp.py** (158 lignes): Sigstore timestamping
  - Function `sign_and_timestamp()`: Sign blob with cosign
  - Generates Sigstore bundle (Rekor transparency log)
  - Graceful fallback if cosign unavailable
  - Returns `SigstoreProof` dataclass

- **gwyl_mail/ots_manager.py** (158 lignes): OpenTimestamps manager
  - Class `OTSManager`: Submit, verify, upgrade
  - Status tracking: PENDING, CONFIRMED, FAILED
  - Bitcoin block height extraction
  - Graceful fallback if `ots` CLI unavailable

- **gwyl_mail/dual_proof.py** (125 lignes): Dual proof orchestration
  - Function `create_proof()`: Generate complete proof JSON
  - Combines canonical hash + Sigstore + OTS
  - Validates against JSON Schema (gwyl_mail/schemas/proof-v0.2.0.json)
  - Computes `proof_canonical_digest`

- **gwyl_mail/validation.py** (~150 lignes): JSON Schema validation
  - Class `ProofValidator`: Strict schema validation
  - Schema: proof-v0.2.0.json (comprehensive)
  - Returns `ValidationResult` with detailed errors

- **gwyl_mail/cli.py** (300 lignes): Command-line interface
  - Commands:
    - `canonical-hash <eml>`: Compute canonical hash
    - `create-proof <eml> --identity <email>`: Create proof
    - `verify --eml <eml> --proof <json>`: Verify proof
    - `upgrade-ots <proof>`: Upgrade OTS proof
  - Audit logging: `logs/verification_audit.jsonl`
  - Path safety validation
  - Subprocess timeout protection

- **gwyl_mail/schemas/proof-v0.2.0.json**: JSON Schema for proof validation

#### Tests

- **tests/test_canonical.py** (10 tests): Canonicalisation
  - Simple message (plain text)
  - Encoding: UTF-8, Latin-1, ASCII
  - Unicode normalization (NFC)
  - Header folding/unfolding
  - Attachments ordering
  - Empty message edge case

- **tests/test_vectors.py** (5 tests): RFC compliance
  - Validates against TEST_VECTORS_v0.md
  - Ensures canonical hash reproducibility

#### Infrastructure projet
- Structure de projet Python moderne (`pyproject.toml`)
- Configuration développement (Makefile, .gitignore)
- Documentation complète (README.md)
- Licence GPL-3.0
- Contributeurs reconnus (CONTRIBUTORS.md)
- Integrity system: `Temporary_Integrity/` (baseline verification, Merkle tree)

#### Résultat
- **10/10 tests passing** (Sprint 1)
- Canonicalisation validée RFC-compliant
- Sigstore + OTS integration fonctionnelle
- CLI opérationnelle pour workflows de base

---

## Contexte

**Origine**: Specs développées dans le cadre du projet GWyl_Integrity, puis extraites vers projet dédié GWyl_Mail.

**Contributions**:
- **Zack**: Vision et direction projet
- **Claude (Anthropic)**: Rédaction specs, implémentation, tests, documentation
- **ChatGPT (OpenAI)**: Revue critique et recommandations architecturales
  - Sprint 0: Identification canonicalisation comme priorité #1
  - Sprint 0: Simplification architecture (élimination dépendance Roughtime)
  - Sprint 0: Recommandations DSSE, JCS, policy_hash
  - Sprint 3: Critical security issues (Sigstore identity, OTS timestamp)
  - Sprint 4: Code quality recommendations (type hints, temp files, cleanup)

---

## À venir

### Sprint 5: Production Readiness (optional)

#### Prévu
- DSSE signature for proof JSON (prevents metadata tampering)
- Relaxed canonicalization profile (handle MTA transformations)
- Performance benchmarks (KPI validation)
- Integration tests (Gmail, Outlook, Postfix)
- Documentation updates (README, examples)

#### Phase 3: Pilote
- Déploiement pilote (10 utilisateurs, 1 mois)
- Monitoring & métriques
- Feedback & ajustements

---

**Format**: [Unreleased] | [X.Y.Z] - AAAA-MM-JJ
**Types**: Ajouté | Modifié | Déprécié | Supprimé | Corrigé | Sécurité
