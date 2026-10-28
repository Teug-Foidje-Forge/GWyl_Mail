# GWyl Mail - État du Projet

**Date**: 2026-10-28
**Version**: 0.3.1
**Status**: noyau 0.3.0 durci — HTML couvert, preuves non signées refusées par défaut, interface locale et extensions. Pilote pas encore tagué.

---

## ✅ Phase 0: Spécifications - COMPLÉTÉE

### Documents de spécification (docs/specs/)

| Document | Version | Status | Lignes | Description |
|----------|---------|--------|--------|-------------|
| **CANONICALIZATION_v0.md** | v0.2.0 | ✅ Specification | ~1150 | Algorithme normatif de canonicalisation |
| **PROOF_SCHEMA_v0.md** | v0.2.0 | ✅ Specification | ~1050 | Schéma de preuve cryptographique |
| **IDENTITY_POLICY_v0.md** | v0.1.0 | ✅ Implemented | ~730 | Politique d'identité |
| **KPI_POC.md** | v0.1.0 | 🔄 Draft | ~610 | KPIs et critères de succès |
| **TEST_VECTORS_v0.md** | v0.1.0 | ✅ Complete | ~184 | Vecteurs de test avec résultats |

**Total**: ~3700 lignes de spécifications techniques détaillées

---

## ✅ Phase 1: Implémentation Core - COMPLÉTÉE

### Modules implémentés (gwyl_mail/)

| Module | Fichier | Status | Lignes | Tests |
|--------|---------|--------|--------|-------|
| **Canonicalisation** | `canonical.py` | ✅ Implémenté | 122 | ✅ 10 tests |
| **Sigstore Timestamp** | `sigstore_timestamp.py` | ✅ Implémenté | 158 | ✅ Intégré |
| **Sigstore Identity** | `sigstore_identity.py` | ✅ Implémenté (Sprint 3) | 269 | ✅ 14 tests |
| **OTS Manager** | `ots_manager.py` | ✅ Implémenté | 158 | ✅ Intégré |
| **Dual Proof** | `dual_proof.py` | ✅ Implémenté | 125 | ✅ Intégré |
| **Identity Policy** | `identity_policy.py` | ✅ Implémenté | ~200 | ✅ 8 tests |
| **Validation** | `validation.py` | ✅ Implémenté | ~150 | ✅ Intégré |
| **CLI** | `cli.py` | ✅ Implémenté | 300 | ✅ 7 tests |

**Total**: ~1482 lignes de code production

---

## ✅ Sprint 1: Canonicalisation - COMPLÉTÉ

**Date**: 2025-01-11

### Implémentation
- ✅ `gwyl_mail/canonical.py` (122 lignes)
- ✅ Headers normalisés (RFC2047, unfolding, NFC)
- ✅ Body: CRLF→LF, trim fin de ligne, NFC
- ✅ Attachments: hash SHA-256 trié
- ✅ Type hints complets

### Tests
- ✅ `tests/test_canonical.py` (10 tests)
- ✅ Encoding UTF-8, Latin-1, ASCII
- ✅ Unicode normalization (NFC)
- ✅ Header folding/unfolding
- ✅ Attachments ordering

**Résultat**: 10/10 tests passing

---

## ✅ Sprint 2: Identity Policy & Coherence - COMPLÉTÉ

**Date**: 2025-01-11

### Implémentation
- ✅ `gwyl_mail/identity_policy.py` (~200 lignes)
- ✅ Policy validation (exact match, domain match, OIDC issuer whitelist)
- ✅ Enforcement modes (strict/warn)
- ✅ Coherence check Rekor/OTS (24h threshold)

### Tests
- ✅ `tests/test_identity_policy.py` (8 tests)
- ✅ `tests/test_verify.py` (7 tests)
- ✅ Policy exact/domain/issuer matching
- ✅ Coherence timestamp validation

**Résultat**: 35/35 tests passing

---

## ✅ Sprint 3: Security Hardening - COMPLÉTÉ

**Date**: 2025-10-12

### Implémentation (Critical Issues - ChatGPT Review)

**P1 - Robust Sigstore Identity Extraction**:
- ✅ New module `gwyl_mail/sigstore_identity.py` (269 lignes)
- ✅ Proper X.509 certificate parsing (cryptography library)
- ✅ SAN email extraction
- ✅ Fulcio OIDC issuer extraction (OID 1.3.6.1.4.1.57264.1.1)
- ✅ Rekor log index + integrated timestamp
- ✅ Replaces fragile heuristic extraction in CLI

**P1 - Real OTS Timestamp Extraction**:
- ✅ Enhanced `gwyl_mail/ots_manager.py`
- ✅ Parse `ots info` output for real Bitcoin block timestamp
- ✅ Supports 3 timestamp formats (human-readable, ISO, Unix)
- ✅ Removes `datetime.now()` approximation
- ✅ Enables reliable Rekor/OTS coherence check (24h)

### Tests
- ✅ `tests/test_sigstore_identity.py` (14 tests)
- ✅ `tests/test_security.py` (security-specific tests)
- ✅ All previous tests still passing

**Résultat**: 49/49 tests passing, 50% coverage

**Security Score Evolution**:
- Sprint 1: 8.0/10
- Sprint 2: 8.5/10
- Sprint 3: **9.0/10** ✅

---

## ✅ Sprint 4: Polish & Refinement - COMPLÉTÉ

**Date**: 2025-10-12
**Commits**: `1ad55f1`, `3ad647c`, `8da2554`

### Implémentation (ChatGPT Review P2/P3)

**P2 - Code Quality**:
- ✅ Fix `GWylCanonical.hash()` type hints (`EmailMessage | bytes | str`)
- ✅ Use `tempfile.NamedTemporaryFile` in CLI (avoid collisions)
- ✅ Expose identity/issuer in verify output and audit log

**P3 - Project Hygiene**:
- ✅ Remove unused dependencies (click, rich, canonicaljson)
- ✅ Update PROJECT_STATUS.md (this file)
- ✅ Update CHANGELOG.md
- ✅ Enhanced baseline snapshot strategy (solve auto-reference)
- ✅ Verbose chain-of-trust verification (7-step detailed output)

**Integrity System Improvements**:
- ✅ `SECURITY_INTEGRITY_BASELINE.sha256.committed` → git history
- ✅ `SECURITY_INTEGRITY_BASELINE.sha256` → local working copy
- ✅ Commit script shows: SHA256 hashes, delta, chain verification
- ✅ Complete audit trail: `git diff`, `git log` on baseline history

**Résultat**: 49/49 tests passing, 50% coverage

### ChatGPT Review Post-Sprint 4

**Points résolus** ✅:
1. Extraction identité Sigstore robuste (X.509 + SAN + issuer)
2. Timestamp OTS réel (ots info parsing, 3 formats)
3. Temp file unique (NamedTemporaryFile)
4. Identity/issuer exposés (verify output + audit)
5. Type hints corrects (EmailMessage | bytes | str)
6. Dependencies cleanup (click, rich, canonicaljson removed)

**Points critiques restants** ⚠️:

**P1 - Bloquants production:**
- DSSE signature manquante (proof JSON pas signé → risque modification)
- Identity pas extraite à `create_proof()` (seulement à verify)

**P2 - Sécurité à renforcer:**
- Issuer substring match trop permissif (`"google.com" in "evil-accounts.google.com"`)
- Path traversal symlink possible (`_safe_in_dir` fallback)
- OTS parsing fragile (dépend de patterns texte)

**P3 - UX/Audit:**
- Coherence delta Rekor↔OTS pas visible en détail
- Privacy metadata incomplet (`from_hash` manquant du vrai From EML)

**Security Score**: 9.0/10 (Sprint 3-4)

---

## ✅ Sprint 5: DSSE Signature & Identity - COMPLÉTÉ (2025-10-13)

- Signature DSSE de la preuve JSON (`gwyl_mail/dsse_signer.py`)
- Extraction d'identité à la création (`signer` dans la preuve)
- Issuer matching sécurisé (exact ou suffixe avec frontière de point)
- Path hardening (symlinks bloqués dans `_safe_in_dir`)
- Coherence details Rekor↔OTS + privacy metadata (`from_hash`)

## ✅ Sprint 6 (partiel): Relaxed Canonicalization - COMPLÉTÉ (2025-10-13)

- Profils `strict`/`relaxed` avec `canonical_profiles.yml`
- Flag `--profile` (création) et `--profile-override` (vérification)
- Liste étendue d'en-têtes MTA exclus en relaxed
- Non livré (reporté) : tests performance, benchmarks, tests intégration MTA,
  docs INTEGRATION/PERFORMANCE, workflow release — repris dans le plan Sprint 8-10

## ✅ Sprint 10: KPIs mesurés & préparation pilote - COMPLÉTÉ (2026-09-17)

- scripts/benchmark.py + scripts/interop_postfix.py + tests/test_performance.py
- **KPIs réels mesurés**: vérification offline 4,5 ms (<150ms ✅), overhead
  4,4 Ko avec vrai timbre OTS (<50 Ko ✅), soumission OTS 1,5 s (<5 s ✅),
  **interopérabilité Postfix réel 100% (50/50, ≥95% ✅)**, hash 25 Mo ~171 ms
- docs/PERFORMANCE.md (chiffres réels), docs/PILOT_GUIDE.md,
  docs/PILOT_FEEDBACK_TEMPLATE.md
- release.yml (tag → tests → build → GitHub release), version 0.3.0,
  package-data vérifié par build de wheel
- Reste au pilote: création Sigstore <1s (OIDC interactif), confirmation
  OTS ≥90%/48h, Gmail/Outlook manuels
- Tests: **137/137**, coverage 69%, ruff/black/mypy propres

## ✅ Sprint 9: Intégration mail réelle - COMPLÉTÉ (2026-09-17)

**La preuve voyage avec le message.**

- `gwyl_mail/eml_io.py`: injection/extraction/strip de preuve dans le .eml
  (gwylproof.json + gwylproof.ots + gwylbundle.json, en-tête X-GWyl-Proof)
- CLI `sign`: .eml signé prêt à envoyer depuis n'importe quel client
- CLI `check`: le destinataire vérifie le message reçu seul
  (canonical + DSSE + bundle + OTS), artifacts matérialisés dans .gwyl_mail/inbox/
- Preuves portables (références par nom de pièce jointe, résolution --lookup-dir)
- Invariant de hash canonique testé (plain/HTML/attachments, retrait
  d'en-tête par MTA, mutations Received/X-Spam tolérées même en strict)
- Falsification du corps détectée de bout en bout (exit 1)
- docs/INTEGRATION.md, examples/use_cases/, run_examples.sh sans conda ni
  chemins externes
- Overhead mesuré: 3,0 Ko (seuil KPI: 50 Ko) — preuve dégradée; mesure
  complète Sprint 10
- Tests: +10 → **134/134, coverage 69%**

## ✅ Sprint 8: Solidité du noyau - COMPLÉTÉ (2026-09-17)

- +16 tests sigstore_timestamp/dsse_signer (chemins de dégradation, parsing)
- allowed_identities appliqué (allowlist certificat, vide = compat)
- Raisons lisibles (REASON_DESCRIPTIONS, KPI_POC §6)
- Schéma durci (required structuraux, enums) sans casser les preuves dégradées
- Codebase formaté black, ruff explicite (E/F/W/I/B), mypy 0 erreur
- CI: lint job + matrix 3.9→3.12 + job avec opentimestamps-client
- Makefile: test-poc + doctor — **124/124 tests, coverage 68%**

## ✅ Sprint 7: Vérité & Onboarding - COMPLÉTÉ (2026-09-17)

**Problème corrigé** : l'outil se taisait ou mentait en mode dégradé.

- `verify`: enveloppe DSSE sans signature → `dsse_signed: false` + raison
  `dsse_unsigned_envelope` (avant: `true` mensonger)
- `create-proof`: refus par défaut sans cosign/ots (exit 2), `--allow-degraded`
  pour opt-in explicite avec bandeau d'avertissement, message final basé sur le
  contenu réellement produit
- Nouvelle commande `doctor`: diagnostic environnement (cosign, ots, paquets,
  réseau) avec `--json`
- Divergence identité demandée ↔ identité effective du certificat détectée
  (`signer.matches_requested`)
- GETTING_STARTED.md réécrit (prérequis réels: cosign binaire Go, ots pip)
- pyproject.toml corrigé (URLs dépôt, maintainers)
- Tests: +27 (test_cli_usability.py, test_ots_manager.py) → **104/104,
  coverage 62%** (ots_manager: 21% → 86%)

**Security Score**: 9.5/10 (honnêteté des sorties en mode dégradé)

---

## 🧪 Tests - État Actuel

### Tests unitaires (tests/)

| Fichier | Tests | Status | Coverage |
|---------|-------|--------|----------|
| `test_canonical.py` | 11 | ✅ Pass | Headers, body, attachments |
| `test_canonical_relaxed.py` | 11 | ✅ Pass | Profil relaxed, en-têtes MTA |
| `test_identity_policy.py` | 17 | ✅ Pass | Policy validation |
| `test_sigstore_identity.py` | 14 | ✅ Pass | X.509, SAN, issuer |
| `test_security.py` | 6 | ✅ Pass | Security edge cases |
| `test_vectors.py` | 5 | ✅ Pass | RFC compliance |
| `test_verify.py` | 2 | ✅ Pass | Path safety, OTS pending |
| `test_dsse_signer.py` | 11 | ✅ Pass | DSSE sign/verify |
| `test_cli_usability.py` | 10 | ✅ Pass | Refus dégradé, honnêteté sorties, doctor |
| `test_ots_manager.py` | 17 | ✅ Pass | Submit/verify/upgrade, parsing timestamps |

**Total**: 104/104 tests passing, 62% coverage (ots_manager 86%)

---

## 📊 Métriques Projet

### Code (actuel)
- **Spécifications**: ~3700 lignes
- **Code production**: ~1482 lignes (gwyl_mail/)
- **Tests**: ~800 lignes (tests/)
- **Total**: ~6000 lignes

### Effort réel

| Phase | Tâches | Effort estimé | Effort réel | Status |
|-------|--------|---------------|-------------|--------|
| **Phase 0** | Specs | ~40h | ~50h | ✅ Complété |
| **Sprint 1** | Canonicalisation | ~15h | ~12h | ✅ Complété |
| **Sprint 2** | Identity/Policy | ~15h | ~10h | ✅ Complété |
| **Sprint 3** | Security Hardening | ~20h | ~15h | ✅ Complété |
| **Sprint 4** | Polish | ~10h | ~5h (en cours) | 🔄 En cours |
| **TOTAL** | | ~100h | ~92h | 80% complété |

### Dépendances externes

**Python packages** (production):
- `sigstore>=2.0.0` (cryptographie, Rekor)
- `cryptography>=41.0.0` (X.509 parsing)
- `opentimestamps-client>=0.7.0` (blockchain Bitcoin)
- `pyyaml>=6.0` (configuration)
- `jsonschema>=4.0.0` (validation)

**Python packages** (dev):
- `pytest>=7.0.0`
- `pytest-cov>=4.0.0`
- `black>=23.0.0`
- `ruff>=0.1.0`
- `mypy>=1.0.0`

**Services externes**:
- Sigstore Rekor (public transparency log)
- OpenTimestamps calendars (public, gratuit)
- OIDC providers (Google, Microsoft, GitHub)

---

## 🎯 Prochaines Étapes

### Pilote multi-utilisateurs (Phase 3 du README — current)

1. Tag v0.3.0 + release (workflow release.yml; intégrité interne réactivée au
   tag via make integrity-commit si souhaité)
2. Recruter 5-10 testeurs; remettre PILOT_GUIDE.md + formulaire de retour
3. Mesures longues: confirmation OTS ≥90%/48h, création Sigstore <1s (OIDC),
   interop Gmail/Outlook manuelle
4. Analyse des retours → backlog v0.4 (SMTP direct, UI destinataire?)

### Backlog identifié (post-pilote)

- Mesure "création Sigstore <1s" à documenter avec cosign + OIDC réel
- Améliorations UX sorties CLI selon retours pilote
- Publication PyPI publique si le pilote est concluant

---

## 👥 Équipe & Contributions

**Core Team**:
- **Zack**: Project Lead, vision, direction
- **Claude (Anthropic)**: Implementation, tests, documentation
- **ChatGPT (OpenAI)**: Security review, architecture recommendations

**Contributions clés ChatGPT**:
1. Sprint 3 Critical Issues identification (Sigstore identity, OTS timestamp)
2. P2/P3 recommendations (type hints, temp files, cleanup)
3. Security score tracking methodology

---

## 📜 Licence & Références

**Licence**: GPL-3.0

**Standards**:
- RFC 6376 (DKIM)
- RFC 2047 (Encoded-words)
- RFC 5322 (Email format)
- RFC 8785 (JCS)
- DSSE (Sigstore/in-toto)

**Projets connexes**:
- Sigstore (sigstore.dev)
- OpenTimestamps (opentimestamps.org)
- DKIM (RFC 6376)

---

**Dernière mise à jour**: 2025-10-12 11:30 UTC
**Prochaine revue**: Après Sprint 4 completion
