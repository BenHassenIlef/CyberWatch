"""Agent de vérification des sources — vérification à deux niveaux.

Niveau 1 (technique)   : accessibilité HTTP, HTTPS/TLS, code de réponse, cohérence du contenu.
Niveau 2 (crédibilité) : domaine officiel, réputation (whitelist/blacklist), présence et
                         existence d'un CVE, métadonnées (titre/date/auteur), indicateurs de
                         faible crédibilité, recoupement multi-sources.

Point d'entrée public : `verify_source(source, corroborator=None)` et `test_connection(source)`.
L'architecture est modulaire pour brancher plus tard des API externes (NVD, MITRE, CISA,
VirusTotal, MISP, OpenCTI…) — voir `cve.py` (validateur d'existence) et `credibility.py`
(recoupement).
"""
from app.backend.services.verification.agent import test_connection, verify_source

__all__ = ["verify_source", "test_connection"]
