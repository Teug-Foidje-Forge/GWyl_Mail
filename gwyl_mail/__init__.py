"""
SPDX-License-Identifier: GPL-3.0-only
GWyl Mail - Privacy Infrastructure Layer pour Email

Système de courrier vérifié avec:
- Intégrité cryptographique (DKIM-inspired canonicalisation)
- Non-répudiation (dual timestamping: Sigstore + OpenTimestamps)
- Identité vérifiée (OIDC via Sigstore)
- Privacy by design (minimal disclosure)
"""

__version__ = "0.3.1"
__author__ = "Zack, Claude, ChatGPT"
__license__ = "GPL-3.0-only"

from .canonical import GWylCanonical

__all__ = ["GWylCanonical"]
