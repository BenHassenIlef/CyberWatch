"""SYNTHÈSE APPROFONDIE d'une CVE — lecture des pages sources, résumé et meilleure solution.

Principe : la fiche CVE ne contient que ce que les collecteurs ont su extraire. Les pages
RÉFÉRENCÉES (avis éditeur, NVD, CVE.org, bulletins) contiennent souvent bien davantage —
notamment la remédiation, renseignée sur seulement 36 % des CVE en base. Ce module va les
lire, puis produit une synthèse ANCRÉE sur leur contenu réel.

    CVE → sélection des pages par autorité → extraction du texte → UN appel LLM
        → validation → stockage (fiche + bulletin)

RÈGLES DE SÛRETÉ, non négociables dans un outil de sécurité :

  • La solution retenue est TOUJOURS ATTRIBUÉE à la page qui la publie (nom + URL). Un
    consultant applique une remédiation sur un système réel : il doit savoir qui la prescrit.
    Jamais de conseil anonyme reformulé.
  • Si aucune page ne fournit de remédiation exploitable, le champ reste VIDE. On n'invente pas.
  • Les valeurs techniques (identifiants, versions, CVSS, URL) doivent se retrouver à
    l'identique dans la synthèse, sinon elle est rejetée (`translation.validate`).
  • Les DÉSACCORDS entre sources sont exposés, jamais arbitrés silencieusement.

COÛT MAÎTRISÉ : appelé À LA DEMANDE (bouton de la fiche), jamais pendant la collecte —
6 requêtes HTTP + 1 appel LLM par CVE sur 1 300 CVE seraient ingérables. Le résultat est mis
en cache dans le document CVE.
"""
import asyncio
import json
import logging
import re
from datetime import datetime, timedelta

from app.backend.services.assistant import llm
from app.backend.services.collection import net, translation
from app.backend.services.collection.advisory_bulletin import (_source_name, _text,
                                                               _pdf_text, official_reference)
from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.assistant.deep_synthesis")

MAX_PAGES = 6            # pages lues par CVE (au-delà : rendement décroissant, coût réel)
PAGE_TIMEOUT = 20.0      # une page lente ne doit pas bloquer la synthèse
MIN_TEXT = 200           # en deçà : page vide ou coquille JavaScript
MAX_TEXT_PER_PAGE = 6000 # borne le budget de jetons
CACHE_DAYS = 14          # au-delà, la synthèse est considérée périmée

COMPLETED, INSUFFICIENT, FAILED = "completed", "insufficient", "failed"

# Pages qui n'apportent jamais de contenu exploitable (redirections, listes, dépôts bruts).
_SKIP_RE = re.compile(r"/cvelistV5/|/advisories/GHSA-|\.json$|\.xml$|/CVERecord\?", re.I)


# --------------------------------------------------------------------------------------
# 1) Sélection des pages — par AUTORITÉ décroissante
# --------------------------------------------------------------------------------------

def select_pages(cve: dict, limit: int = MAX_PAGES) -> list[str]:
    """URL à lire, de la plus faisant autorité à la moins. La source officielle d'abord :
    c'est elle qui publie la remédiation de référence."""
    vendor = cve.get("vendor")
    produits = [p for p in [cve.get("product")] if p]
    ordered: list[str] = []

    officielle = (cve.get("official_source") or {}).get("url") \
        or official_reference(cve.get("references"), vendor, produits)
    if officielle:
        ordered.append(officielle)

    # Puis les autres références, en conservant l'ordre de priorité déjà établi par le
    # sélecteur de source officielle (avis éditeur > autorité publique).
    restantes = [r for r in (cve.get("references") or []) if isinstance(r, str)]
    while restantes and len(ordered) < limit * 3:
        meilleure = official_reference(restantes, vendor, produits)
        if not meilleure:
            break
        restantes.remove(meilleure)
        if meilleure not in ordered:
            ordered.append(meilleure)

    out = []
    for u in ordered:
        if u.startswith(("http://", "https://")) and not _SKIP_RE.search(u) and u not in out:
            out.append(u)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------------------
# 2) Extraction du texte d'une page
# --------------------------------------------------------------------------------------

def extrait_pertinent(texte: str, cve_id: str | None) -> str:
    """Ramène le texte au budget d'une page, en le CENTRANT sur la CVE recherchée.

    Un avis de type « Critical Patch Update » couvre des centaines de vulnérabilités. En
    tronquer les premiers caractères ne retient que l'en-tête et les généralités : la ligne
    qui concerne RÉELLEMENT la CVE consultée — et la version corrective associée — se trouve
    bien plus loin. On conserve donc le début (titre, portée, date) PUIS la fenêtre entourant
    l'identifiant, ce qui donne au modèle le contexte de l'avis et le détail qui compte.
    """
    if len(texte) <= MAX_TEXT_PER_PAGE:
        return texte
    position = texte.upper().find((cve_id or "").upper()) if cve_id else -1
    if position < 0:
        return texte[:MAX_TEXT_PER_PAGE]

    entete = MAX_TEXT_PER_PAGE // 4
    if position < entete:                     # la CVE est deja dans l'en-tete : rien a faire
        return texte[:MAX_TEXT_PER_PAGE]
    fenetre = MAX_TEXT_PER_PAGE - entete
    debut = max(entete, position - fenetre // 3)
    return texte[:entete] + " […] " + texte[debut:debut + fenetre]


async def fetch_text(url: str, cve_id: str | None = None) -> str | None:
    """Texte exploitable d'une page, ou None. Gère HTML, PDF, et pages rendues en JavaScript."""
    try:
        if url.lower().endswith(".pdf"):
            texte = await _pdf_text(url)
            return extrait_pertinent(texte, cve_id) if texte and len(texte) >= MIN_TEXT else None

        resp = await net.get(url, timeout=PAGE_TIMEOUT)
        if resp is None or resp.status_code != 200:
            return None
        texte = _text(resp.text)

        # Coquille JavaScript (NVD, portails modernes) : le HTML brut ne contient rien.
        if len(texte) < MIN_TEXT:
            from app.backend.services.verification import browser_client
            rendu = await browser_client.render_html(url, wait_for_cve=False)
            texte = _text(rendu) if rendu else texte
        return extrait_pertinent(texte, cve_id) if len(texte) >= MIN_TEXT else None
    except Exception as exc:  # noqa: BLE001 - une page illisible n'interrompt pas la synthèse
        logger.info("Page ignorée (%s) : %s", url[:70], str(exc)[:100])
        return None


async def read_pages(urls: list[str], cve_id: str | None = None) -> list[dict]:
    """Lit les pages EN PARALLÈLE. Renvoie [{url, source, texte}] pour celles exploitables."""
    textes = await asyncio.gather(*[fetch_text(u, cve_id) for u in urls],
                                  return_exceptions=True)
    out = []
    for url, texte in zip(urls, textes):
        if isinstance(texte, str) and texte:
            out.append({"url": url, "source": _source_name(url, None), "texte": texte})
    return out


# --------------------------------------------------------------------------------------
# 3) Appel LLM — un seul, entrée et sortie JSON
# --------------------------------------------------------------------------------------

SYNTHESIS_SYSTEM = (
    "Tu es analyste en cybersécurité. On te fournit le texte RÉEL de plusieurs pages officielles "
    "concernant UNE vulnérabilité. Tu produis une synthèse en FRANÇAIS.\n"
    "RÈGLES ABSOLUES :\n"
    "- Tu n'utilises QUE le contenu des pages fournies. Aucune connaissance extérieure.\n"
    "- La SOLUTION provient d'UNE page precise, dont tu indiques l'URL exacte dans "
    "« solution_source_url ». Si AUCUNE page ne decrit de remediation concrete, tu mets "
    "null - ne propose JAMAIS de conseil generique.\n"
    "- La solution est REDIGEE EN FRANCAIS, meme si la page source est en anglais. Tu "
    "traduis la consigne sans jamais en changer la substance, et tu laisses TELS QUELS "
    "les numeros de version, noms de correctifs, identifiants et URL.\n"
    "- Tu laisses inchangés les identifiants (CVE-…, CWE-…), versions, scores CVSS, URL et "
    "noms de produits ou d'éditeurs.\n"
    "- Si deux pages se CONTREDISENT (versions corrigées différentes, scores divergents), tu "
    "le signales dans « conflits » au lieu de choisir.\n"
    "- Tu réponds UNIQUEMENT par un objet JSON valide, sans texte autour."
)

_SCHEMA = ('{"resume": "...", "solution": "..." ou null, "solution_source_url": "..." ou null, '
           '"conflits": ["..."]}')


# Budget TOTAL de texte envoye au modele, toutes pages confondues.
# Six pages a 6 000 caracteres produisaient jusqu'a 36 000 caracteres, et le fournisseur
# repondait « 413 Payload Too Large » : la synthese echouait alors entierement.
# On repartit donc un budget global, les pages les PLUS AUTORITAIRES servies en premier.
# Cale sur la limite de DEBIT du fournisseur, exprimee en jetons par minute (8 000 chez
# Groq). A ~3,5 caracteres par jeton, 9 000 caracteres pesent ~2 600 jetons ; avec la sortie
# le total reste sous le seuil, ce qui autorise deux syntheses par minute. Un budget plus
# genereux saturait le seau des le deuxieme appel et renvoyait « 429 » en boucle.
MAX_TOTAL_TEXT = 9000


def _budget(pages: list[dict]) -> list[dict]:
    """Tronque les pages pour tenir dans le budget, en privilegiant les premieres.

    `select_pages` les a deja classees par autorite : l'avis editeur arrive avant NVD, qui
    arrive avant le reste. Rogner par la fin preserve donc l'information la plus fiable.
    """
    reste, retenues = MAX_TOTAL_TEXT, []
    for page in pages:
        if reste <= 500:          # sous 500 caracteres un extrait n'apprend plus rien
            break
        texte = (page.get("texte") or "")[:reste]
        reste -= len(texte)
        retenues.append({**page, "texte": texte})
    return retenues


def _prompt(cve: dict, pages: list[dict]) -> str:
    payload = {
        "cve_id": cve.get("cve_id"),
        "produit": cve.get("product"),
        "editeur": cve.get("vendor"),
        "pages": [{"url": p["url"], "source": p["source"], "contenu": p["texte"]}
                  for p in _budget(pages)],
    }
    return (
        "Voici le contenu réel des pages officielles concernant cette vulnérabilité :\n\n"
        + json.dumps(payload, ensure_ascii=False)[:MAX_TOTAL_TEXT + 2000]
        + f"\n\nProduis un objet JSON de la forme : {_SCHEMA}\n"
        "« resume » : 4 à 8 phrases — nature de la faille, condition d'exploitation, impact "
        "concret, périmètre affecté.\n"
        "« solution » : la remédiation telle que publiée (version corrective, contournement, "
        "correctif). null si aucune page n'en donne.\n"
        "« conflits » : divergences entre pages. Liste vide s'il n'y en a pas."
    )


def _parse(raw: str | None) -> dict | None:
    if not raw:
        return None
    txt = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", txt, re.S)
    if fence:
        txt = fence.group(1).strip()
    if not txt.startswith("{"):
        d, f = txt.find("{"), txt.rfind("}")
        if d == -1 or f <= d:
            return None
        txt = txt[d:f + 1]
    try:
        data = json.loads(txt)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------------------
# 4) Point d'entrée
# --------------------------------------------------------------------------------------

def is_fresh(cve: dict) -> bool:
    """Synthèse déjà présente et non périmée ?"""
    d = cve.get("deep_synthesis") or {}
    gen = d.get("generated_at")
    if d.get("status") != COMPLETED or not isinstance(gen, datetime):
        return False
    # `utcnow()` est « aware », mais une date relue de MongoDB est NAÏVE : on ramène les deux
    # au même référentiel, sinon la comparaison lève TypeError et le cache ne sert jamais.
    def _naif(d0: datetime) -> datetime:
        return d0.replace(tzinfo=None) if d0.tzinfo else d0
    return (_naif(utcnow()) - _naif(gen)) < timedelta(days=CACHE_DAYS)


async def synthesize(db, cve: dict, refresh: bool = False) -> dict:
    """Lit les pages sources de la CVE et produit {resume, solution, source, conflits}.

    Ne lève jamais. Persiste le résultat dans `cve.deep_synthesis` et renvoie ce sous-document.
    """
    if not refresh and is_fresh(cve):
        return cve["deep_synthesis"]

    base = {"generated_at": utcnow(), "pages_read": [], "conflicts": [],
            "summary": None, "solution": None, "solution_source": None}

    if not llm.available():
        result = {**base, "status": FAILED, "error": "Aucun modèle LLM configuré."}
        await _store(db, cve, result)
        return result

    urls = select_pages(cve)
    # L identifiant est transmis : il sert a CENTRER la lecture des avis volumineux.
    pages = await read_pages(urls, cve.get("cve_id")) if urls else []
    base["pages_read"] = [{"url": p["url"], "source": p["source"], "chars": len(p["texte"])}
                          for p in pages]
    if not pages:
        result = {**base, "status": INSUFFICIENT,
                  "error": "Aucune page source n'a pu être lue (indisponibles ou sans contenu)."}
        await _store(db, cve, result)
        return result

    data = _parse(await llm.generate(_prompt(cve, pages), system=SYNTHESIS_SYSTEM, max_tokens=1200))
    if data is None:
        result = {**base, "status": FAILED, "error": "Réponse du modèle inexploitable."}
        await _store(db, cve, result)
        return result

    corpus = "\n".join(p["texte"] for p in pages)
    resume = (data.get("resume") or "").strip() or None
    # SENS DE LA VÉRIFICATION : toute valeur technique CITÉE DANS LE RÉSUMÉ doit exister dans
    # les pages lues (détection d'invention). L'inverse serait absurde ici : un résumé est plus
    # court que ses sources et ne peut évidemment pas en reprendre tous les identifiants.
    if resume:
        ok, inventes = translation.validate(resume, corpus)
        if not ok:
            logger.info("Synthèse %s : résumé rejeté — valeurs absentes des sources : %s",
                        cve.get("cve_id"), inventes[:3])
            resume = None

    # SOLUTION : retenue UNIQUEMENT si elle cite une page réellement lue. Une remédiation
    # non attribuable n'est pas exploitable par un consultant, et potentiellement dangereuse.
    solution = (data.get("solution") or "").strip() or None
    src_url = (data.get("solution_source_url") or "").strip() or None

    # La solution subit le MEME controle que le resume. C'est le champ le plus sensible de
    # la fiche : une version corrective inventee enverrait un consultant appliquer un
    # correctif inexistant. Mieux vaut « Non disponible » qu'une remediation fausse.
    if solution:
        ok_sol, inventes_sol = translation.validate(solution, corpus)
        if not ok_sol:
            logger.info("Synthese %s : solution rejetee - valeurs absentes des sources : %s",
                        cve.get("cve_id"), inventes_sol[:3])
            solution, src_url = None, None
    lues = {p["url"]: p["source"] for p in pages}
    if solution and src_url not in lues:
        logger.info("Synthèse %s : solution écartée (source « %s » non lue).",
                    cve.get("cve_id"), (src_url or "absente")[:60])
        solution, src_url = None, None

    result = {
        **base,
        "summary": resume,
        "solution": solution,
        "solution_source": {"name": lues.get(src_url), "url": src_url} if solution else None,
        "conflicts": [c for c in (data.get("conflits") or []) if isinstance(c, str)][:5],
        "status": COMPLETED if (resume or solution) else INSUFFICIENT,
        "error": None if (resume or solution) else "Les pages lues ne contiennent pas "
                                                   "d'information exploitable.",
    }
    await _store(db, cve, result)
    return result


async def _store(db, cve: dict, result: dict) -> None:
    if cve.get("_id") is None:
        return
    try:
        await db.cves.update_one({"_id": cve["_id"]}, {"$set": {"deep_synthesis": result}})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Synthèse non persistée : %s", exc)
