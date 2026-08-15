"""Rendu d'une page avec exécution du JavaScript (navigateur headless Chromium).

Certaines sources (bases de CVE modernes : cvefind.com, NVD, MSRC…) chargent leur contenu
dynamiquement via JavaScript. Un simple téléchargement HTTP (voir `http_client.py`) ne voit
alors que la coquille vide de l'application. Ce module rend la page comme un vrai navigateur
afin d'obtenir le HTML *après* exécution du JavaScript, pour l'extraction de CVE/métadonnées.

Robuste : en cas d'erreur (navigateur indisponible, timeout), renvoie None et l'agent
retombe sur le HTML brut.
"""
import asyncio
import re

from app.backend.core.config import settings

RENDER_TIMEOUT_MS = 40000
# User-Agent d'un vrai navigateur : certaines SPA servent un contenu différent aux robots.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
BODY_CAP = 400000  # le HTML rendu d'une SPA peut être volumineux (listes de CVE)

# Motif d'un identifiant CVE, pour attendre son apparition dans le DOM.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def looks_like_spa(fetched) -> bool:
    """Heuristique : la page est-elle une application JavaScript au contenu vide côté HTML brut ?

    On ne rend au navigateur que si ça en vaut la peine : page HTML, plusieurs scripts, et
    peu de texte visible OU aucun identifiant CVE dans le HTML brut.
    """
    if fetched is None or not fetched.reached:
        return False
    ctype = (fetched.content_type or "").lower()
    if "html" not in ctype and "<html" not in fetched.body_lower:
        return False
    body = fetched.body
    script_count = body.lower().count("<script")
    visible_text = re.sub(r"<[^>]+>", " ", body)
    has_cve = bool(_CVE_RE.search(body))
    spa_markers = any(m in body for m in ('id="root"', "id='root'", 'id="app"', "id='app'", "__NEXT_DATA__", "__NUXT__"))
    return script_count >= 3 and (spa_markers or len(visible_text.strip()) < 3000 or not has_cve)


async def _render_on_context(context, url: str, wait_for_cve: bool) -> str | None:
    """Rend une page dans un contexte navigateur EXISTANT (réutilisable). Renvoie le HTML ou None.

    `wait_for_cve` : pour les pages de DÉTAIL d'avis (maCERT, ANCS…), le corps « coquille »
    dépasse 1500 caractères AVANT que la liste des CVE ne soit injectée par le JS. On attend
    donc en priorité l'apparition d'un identifiant CVE (jusqu'à 8 s), sinon on se rabat sur la
    présence de texte. Pour les pages de LISTE (sans CVE), passer `wait_for_cve=False` évite
    d'attendre inutilement une CVE qui n'y figure pas.
    """
    page = await context.new_page()
    try:
        # « commit » : on n'attend que la 1re réponse (robuste sur les sites lents/bloquants).
        await page.goto(url, wait_until="commit", timeout=RENDER_TIMEOUT_MS)
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=12000)
        except Exception:
            pass
        got_cve = False
        if wait_for_cve:
            try:
                await page.wait_for_function(
                    "() => /CVE-\\d{4}-\\d{4,7}/i.test(document.body.innerText)", timeout=8000)
                got_cve = True
            except Exception:
                got_cve = False
        if not got_cve:
            try:
                await page.wait_for_function("() => document.body.innerText.length > 1500", timeout=3000)
            except Exception:
                await page.wait_for_timeout(2000)
        content = await page.content()
        return content[:BODY_CAP]
    finally:
        await page.close()


# --------------------------------------------------------------------------------------
# Navigateur Chromium PARTAGÉ + plafond de concurrence.
#
# CAUSE RACINE des timeouts de sources HTML (cvemon/cvefind…) : chaque page lançait un
# navigateur Chromium NEUF, et ~9 sources HTML en parallèle × jusqu'à 20 pages de détail
# faisaient exploser le nombre de process Chromium simultanés → épuisement CPU/RAM → un rendu
# de 3 s dépassait le timeout de 150 s. Solution (sans augmenter aveuglément le timeout) :
#   1) UN SEUL navigateur Chromium réutilisé (contextes légers par page) ;
#   2) un SÉMAPHORE global plafonnant les rendus simultanés (RENDER_CONCURRENCY).
# Les deux ressources sont indexées par boucle d'événements (robuste aux tests multi-loop).
# --------------------------------------------------------------------------------------
_shared: dict = {"loop": None, "pw": None, "browser": None}
_shared_lock = asyncio.Lock()
_sems: dict = {}


def _sem() -> asyncio.Semaphore:
    loop = asyncio.get_event_loop()
    s = _sems.get(loop)
    if s is None:
        s = asyncio.Semaphore(max(1, int(settings.RENDER_CONCURRENCY)))
        _sems[loop] = s
    return s


async def _get_shared_browser():
    """Lance (une seule fois par boucle) et renvoie le navigateur Chromium partagé, ou None."""
    loop = asyncio.get_event_loop()
    br = _shared.get("browser")
    if br is not None and _shared.get("loop") is loop:
        try:
            if br.is_connected():
                return br
        except Exception:  # noqa: BLE001
            pass
    async with _shared_lock:
        br = _shared.get("browser")
        if br is not None and _shared.get("loop") is loop:
            try:
                if br.is_connected():
                    return br
            except Exception:  # noqa: BLE001
                pass
        try:
            from playwright.async_api import async_playwright
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(args=["--no-sandbox", "--ignore-certificate-errors"])
            _shared.update({"loop": loop, "pw": pw, "browser": browser})
            return browser
        except Exception:  # noqa: BLE001 - Playwright indisponible : on retombera sur None.
            _shared.update({"loop": loop, "pw": None, "browser": None})
            return None


async def close_shared() -> None:
    """Ferme proprement le navigateur partagé (à appeler en fin de process one-shot)."""
    async with _shared_lock:
        br, pw = _shared.get("browser"), _shared.get("pw")
        _shared.update({"loop": None, "pw": None, "browser": None})
    for closer in (getattr(br, "close", None), getattr(pw, "stop", None)):
        if closer:
            try:
                await closer()
            except Exception:  # noqa: BLE001
                pass


async def render_html(url: str, wait_for_cve: bool = True) -> str | None:
    """Rend une page (JavaScript exécuté) via le navigateur Chromium PARTAGÉ, sous plafond de
    concurrence global. Renvoie le HTML rendu, ou None (l'agent retombe sur le HTML brut)."""
    async with _sem():
        browser = await _get_shared_browser()
        if browser is None:
            return None
        context = None
        try:
            context = await browser.new_context(user_agent=USER_AGENT, ignore_https_errors=True)
            return await _render_on_context(context, url, wait_for_cve)
        except Exception:  # noqa: BLE001 - rendu best-effort
            return None
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:  # noqa: BLE001
                    pass


async def render_pdf(html: str, *, landscape: bool = False) -> bytes | None:
    """Convertit un document HTML autonome en PDF A4 via le Chromium PARTAGÉ. Renvoie les octets
    du PDF, ou None si Playwright est indisponible (l'appelant renvoie alors une erreur claire).

    `set_content` charge le HTML depuis la mémoire : aucune navigation réseau n'est nécessaire.
    Par sécurité, toute requête sortante est BLOQUÉE — un bulletin ne doit jamais provoquer
    d'appel réseau depuis le serveur. Les images doivent donc être intégrées en data: URI.
    """
    async with _sem():
        browser = await _get_shared_browser()
        if browser is None:
            return None
        context = None
        try:
            context = await browser.new_context()
            page = await context.new_page()
            # Seules les URL en data: (logo intégré) sont autorisées ; le reste est abandonné.
            await page.route("**/*", lambda route: (
                route.continue_() if route.request.url.startswith("data:") else route.abort()))
            await page.set_content(html, wait_until="domcontentloaded")
            return await page.pdf(
                format="A4", print_background=True, prefer_css_page_size=False,
                landscape=landscape,
                margin={"top": "12mm", "bottom": "14mm", "left": "10mm", "right": "10mm"})
        except Exception:  # noqa: BLE001 - export best-effort : l'appelant gère l'échec
            return None
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:  # noqa: BLE001
                    pass


class RenderSession:
    """Session de rendu d'un crawl : réutilise le navigateur Chromium PARTAGÉ (un seul pour tout
    le process) et respecte le plafond global de concurrence. Un CONTEXTE dédié est ouvert pour la
    session (isolation cookies/état) puis fermé à la sortie. Robuste : si Playwright est
    indisponible, `render()` se rabat sur `render_html`, et à défaut sur None. Utilisation :

        async with RenderSession() as session:
            html = await session.render(url, wait_for_cve=True)
    """

    def __init__(self):
        self._ctx = None

    async def __aenter__(self):
        try:
            browser = await _get_shared_browser()
            if browser is not None:
                self._ctx = await browser.new_context(user_agent=USER_AGENT, ignore_https_errors=True)
        except Exception:  # noqa: BLE001 - mode dégradé : render() retombera sur render_html
            self._ctx = None
        return self

    async def render(self, url: str, wait_for_cve: bool = True) -> str | None:
        if self._ctx is None:
            return await render_html(url, wait_for_cve)  # repli : navigateur éphémère (partagé)
        async with _sem():
            try:
                return await _render_on_context(self._ctx, url, wait_for_cve)
            except Exception:  # noqa: BLE001
                return None

    async def __aexit__(self, *exc):
        if self._ctx is not None:
            try:
                await self._ctx.close()
            except Exception:  # noqa: BLE001
                pass
