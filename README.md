# GWyl Mail - Système de Courrier Vérifié

**Privacy Infrastructure Layer pour Email**

Version: 0.3.1
License: GPL-3.0-only
Status: Alpha — noyau mesuré, interface locale, pas encore un client mail

Le document de développement est [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Il prime sur les textes de la phase 0.

---

## 🎯 Vue d'ensemble

GWyl Mail est une couche de confidentialité et d'intégrité qui s'ajoute au système de courrier électronique classique. Elle fournit:

- **Intégrité** : hash canonique versionné du message
- **Identité** : certificat OIDC Sigstore, niveau annoncé, pas un certificat qualifié
- **Temps** : OpenTimestamps corroboré dans Bitcoin, sans présomption d'horodatage qualifié
- **Transport** : la preuve voyage dans le message, sur le courrier existant

---

## 📋 Architecture

```
Message Email (SMTP/IMAP)
    ↓
Canonicalisation (DKIM-inspired)
    ↓
Content Hash (SHA-256)
    ↓
┌─────────────────────────────────┐
│   DUAL TIMESTAMPING             │
├─────────────────────────────────┤
│  Sigstore (immédiat)            │
│    - Identité OIDC              │
│    - Rekor timestamp            │
│    → Trust: MEDIUM              │
│                                 │
│  OpenTimestamps (différé)       │
│    - Bitcoin blockchain         │
│    - Preuve légale              │
│    → Trust: HIGH                │
│                                 │
│  Politique d'identité           │
│    - Mapping From ↔ Cert        │
│    - Enforcement (warn/strict)  │
└─────────────────────────────────┘
```

---

## 📚 Documentation

### Spécifications (docs/specs/)

- **[CANONICALIZATION_v0.md](docs/specs/CANONICALIZATION_v0.md)** (v0.2.0): Algorithme de canonicalisation DKIM-inspired
- **[PROOF_SCHEMA_v0.md](docs/specs/PROOF_SCHEMA_v0.md)** (v0.2.0): Schéma de preuve cryptographique (dual timestamping)
- **[IDENTITY_POLICY_v0.md](docs/specs/IDENTITY_POLICY_v0.md)** (v0.1.0): Politique de mapping identité email ↔ certificat
- **[KPI_POC.md](docs/specs/KPI_POC.md)** (v0.1.0): KPIs et critères de succès du PoC
- **[TEST_VECTORS_v0.md](docs/specs/TEST_VECTORS_v0.md)** (v0.1.0): Vecteurs de test avec résultats attendus

### Guides (à venir)

- Installation & Configuration
- Guide d'utilisation
- Guide d'intégration
- FAQ

---

## 🚀 Roadmap PoC

### Phase 0: Spécifications ✅
- ✅ Canonicalisation v0.2.0
- ✅ Proof Schema v0.2.0
- ✅ Identity Policy v0.1.0
- ✅ KPIs PoC
- ✅ Test Vectors

### Phase 1: Implémentation Core ✅
- ✅ Canonicalisation, y compris texte et HTML quand les deux sont présents (`gwyl-canonical-v0.3`, un seul corps reste compatible v0.2)
- ✅ Sigstore, OpenTimestamps, preuve DSSE, politique d'identité
- ✅ La preuve voyage dans le `.eml` (`sign` / `check`)

### Phase 2: CLI, interface, tests ✅
- ✅ CLI, `gwyl-mail doctor`, `gwyl-mail ui` (127.0.0.1 seulement)
- ✅ Extensions navigateur et Thunderbird (`extensions/`)
- ✅ Tests unitaires et tests adversariaux
- ⏳ Interop Gmail et Outlook encore manuelle

### Phase 3: Pilote
- ⏳ Tag et recrutement de testeurs
- ⏳ Confirmation OpenTimestamps sur 48 h, Sigstore avec OIDC réel

Une preuve sans signature, ou dont l'identité demandée ne correspond pas au certificat, est refusée. `--allow-degraded` est l'opt-in explicite.

---

## 🔐 Integrity Commit Flow

Prérequis
- Environnement Conda: `GWYL_Env`
- OTS installé (`ots`) et cosign optionnel (`cosign`)

Scripts et hooks
- Script de commit sécurisé: `Temporary_Integrity/commit_with_integrity.sh`
  - Vérifie la baseline avant/après commit (Conda `GWYL_Env`)
  - Upgrade OTS best‑effort
- Hooks Git
  - `pre-commit`: vérification intégrité
  - `pre-push`: upgrade OTS

Usage
```bash
# Commit avec vérification baseline
./Temporary_Integrity/commit_with_integrity.sh "Votre message"

# Ou commit standard (hook pre-commit lancera l’intégrité)
git commit -m "Votre message"

# Push (hook pre-push upgrade OTS)
git push
```

Notes
- L’outil d’intégrité utilisé est `/home/zack/GWyl_Integrity/unified_integrity.py`
- Le profil “strict” (V0) est utilisé pour la canonicalisation.


## 🛠️ Stack Technique

**Langage**: Python 3.9+

**Dépendances core**:
- `sigstore` - Signature et timestamping via Rekor
- `opentimestamps-client` - Ancrage blockchain Bitcoin
- `pyyaml` - Configuration politique
- `canonicaljson` - Normalisation JSON (JCS RFC 8785)
- `email` (stdlib) - Parsing email

**Standards**:
- RFC 6376 (DKIM) - Inspiration canonicalisation
- RFC 2047 (Encoded-words) - Décodage headers
- RFC 5322 (Email format) - Structure email
- RFC 8785 (JCS) - Canonicalisation JSON
- DSSE (Dead Simple Signing Envelope) - Signature proof

---

## 🎯 KPIs PoC

Critères de succès (détails dans [KPI_POC.md](docs/specs/KPI_POC.md)):

- **Interopérabilité**: ≥95% (Gmail, Outlook, Postfix)
- **Performance**: <50KB overhead, <150ms vérification
- **Fiabilité**: ≥90% confirmation OTS sous 48h
- **Sécurité**: 100% détection tampering

---

## 🔐 Sécurité & Privacy

### Menaces couvertes
- ✅ Modification silencieuse du message
- ✅ Usurpation d'identité expéditeur
- ✅ Backdating / timestamping frauduleux
- ✅ Replay attacks
- ✅ Divulgation métadonnées (minimal disclosure)

### Privacy by design
- Hash des adresses email (pas de PII en clair)
- Preuves portables (vérification offline)
- Sélection profil canonicalisation (strict/relaxed)
- Politique d'identité configurable

---

## 👥 Contributeurs

Voir [CONTRIBUTORS.md](CONTRIBUTORS.md)

- **Zack**: Project Lead & Principal Developer
- **Claude (Anthropic)**: Development Assistant & Documentation
- **ChatGPT (OpenAI)**: Technical Advisor & Architecture Review

---

## 📜 Licence

GPL-3.0 - Voir [LICENSE](LICENSE)

---

## 🙏 Remerciements

- **Sigstore**: Infrastructure de signature sans clé
- **OpenTimestamps**: Ancrage blockchain gratuit
- **DKIM (RFC 6376)**: Inspiration canonicalisation
- **DSSE**: Standard signature envelope

---

**🔒 Privacy-first email integrity 🔒**
