"""Détection et validation des identifiants CVE.

- `extract_cve_ids`   : extraction réelle des identifiants CVE depuis le contenu.
- `CveExistenceValidator` : interface pour vérifier qu'un CVE existe vraiment.
- `NvdCveValidator`   : implémentation RÉELLE via l'API officielle NVD (dégradation gracieuse).
- `NullCveValidator`  : implémentation neutre (désactivée), utile en test/hors-ligne.

Pour brancher MITRE, un cache, ou VirusTotal plus tard : créer une nouvelle sous-classe de
`CveExistenceValidator` et l'injecter dans l'orchestrateur.
"""
import re

import httpx

# Un identifiant CVE : CVE-AAAA-NNNN (4 à 7 chiffres pour le numéro).
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 8.0

# Interrupteur global : mettre à False pour désactiver l'appel réseau vers NVD.
NVD_LOOKUP_ENABLED = True


def extract_cve_ids(text: str) -> list[str]:
    """Retourne la liste (dédupliquée, en majuscules) des identifiants CVE trouvés."""
    if not text:
        return []
    seen: dict[str, None] = {}
    for match in CVE_PATTERN.findall(text):
        seen.setdefault(match.upper(), None)
    return list(seen.keys())


class CveExistenceValidator:
    """Interface : vérifie l'existence réelle d'un CVE. Retourne True / False / None (indéterminé)."""

    async def exists(self, cve_id: str) -> bool | None:  # pragma: no cover - interface
        raise NotImplementedError


class NullCveValidator(CveExistenceValidator):
    """Ne vérifie rien (toujours indéterminé). Utile hors-ligne ou en test."""

    async def exists(self, cve_id: str) -> bool | None:
        return None


class NvdCveValidator(CveExistenceValidator):
    """Vérifie l'existence d'un CVE via l'API officielle NVD (NIST).

    Robuste : en cas d'erreur réseau, de limitation de débit (403/429) ou de timeout,
    renvoie None (indéterminé) plutôt que d'échouer — l'agent ne pénalise pas la source
    pour un problème côté NVD.
    """

    async def exists(self, cve_id: str) -> bool | None:
        try:
            async with httpx.AsyncClient(timeout=NVD_TIMEOUT) as client:
                response = await client.get(NVD_API_URL, params={"cveId": cve_id})
        except Exception:  # noqa: BLE001 - toute erreur réseau => indéterminé
            return None

        if response.status_code == 404:
            return False
        if response.status_code != 200:
            # 403 / 429 (rate limit) ou 5xx => on ne peut pas conclure.
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        return int(data.get("totalResults", 0)) > 0


def get_default_validator() -> CveExistenceValidator:
    return NvdCveValidator() if NVD_LOOKUP_ENABLED else NullCveValidator()
