"""Accès réseau partagé pour les collecteurs (fetch générique + API NVD à débit maîtrisé)."""
import asyncio
import time

import httpx

from app.backend.core.config import settings

UA = "CyberWatchAI-Collector/3.0"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Limite de débit NVD : ~5 req/30 s sans clé, ~50 req/30 s avec clé.
_RATE_SPACING = 0.7 if settings.NVD_API_KEY else 6.5
_last_nvd = 0.0
_nvd_lock = asyncio.Lock()  # sérialise l'accès NVD même en collecte parallèle


async def get(url: str, headers: dict | None = None, timeout: float = 40.0) -> httpx.Response | None:
    """GET générique, ne lève jamais (renvoie None en cas d'erreur réseau)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     headers={"User-Agent": UA, **(headers or {})}) as c:
            return await c.get(url)
    except Exception:  # noqa: BLE001
        return None


async def nvd_get(url: str, retries: int = 2) -> httpx.Response | None:
    """GET NVD avec respect de la limite de débit et reprise sur 403/429."""
    global _last_nvd
    headers = {"User-Agent": UA}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
    for attempt in range(retries):
        async with _nvd_lock:  # respect strict du débit, y compris en parallèle
            wait = _RATE_SPACING - (time.monotonic() - _last_nvd)
            if wait > 0:
                await asyncio.sleep(wait)
            resp = await get(url, headers=headers, timeout=45)
            _last_nvd = time.monotonic()
        if resp is not None and resp.status_code == 200:
            return resp
        await asyncio.sleep(4 * (attempt + 1))
    return None
