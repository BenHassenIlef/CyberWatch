"""DISCUSSIONS COMMUNAUTAIRES d'UNE CVE — couche d'enrichissement, jamais une source officielle.

Ce module cherche, pour un identifiant CVE donné, les discussions publiques qui le mentionnent
EXPLICITEMENT, en vérifie la pertinence, puis les range dans une collection DISTINCTE.

    CVE ──► sources communautaires ──► vérification de pertinence ──► `community_discussions`

SÉPARATION STRICTE, non négociable
Rien de ce qui est collecté ici n'alimente les champs officiels d'une CVE : ni la solution,
ni les produits affectés, ni les références, ni le score. Une discussion de forum peut être
juste, fausse, ou spéculative ; la présenter au même rang qu'un avis éditeur conduirait un
consultant à agir sur une rumeur. Elle est donc stockée à part, et affichée à part.

SOURCES — registre EXTENSIBLE
Chaque source est une coroutine `(cve_id) -> list[dict]` enregistrée dans `SOURCES`. Ajouter
une communauté n'exige aucune modification du reste : ni du stockage, ni de l'API, ni de
l'interface. Seules des API PUBLIQUES et documentées sont interrogées ; aucun contournement
d'authentification, aucune protection technique franchie.

PERTINENCE
Une discussion n'est retenue que si elle cite l'identifiant EXACT. Un billet qui parle du même
produit, ou d'une CVE voisine, est rejeté : le rapprochement par sujet fabriquerait des liens
que personne n'a établis.
"""
import asyncio
import html
import logging
import re
from datetime import datetime, timezone

from app.backend.services.collection import net
from app.backend.services.community import agent

logger = logging.getLogger("cyberwatch.community.discussions")

# Niveaux de pertinence exposés à l'interface.
HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
# En deçà, la discussion n'est pas montrée : un lien faible coûte plus qu'il ne rapporte.
SEUIL_AFFICHAGE = 0.45

VERIFIED, REJECTED = "verified", "rejected"

# Etat d une source apres une recherche. Les trois sont IRREDUCTIBLES l un a l autre :
#   COMPLETED    la recherche a abouti — « results: 0 » signifie que rien n existe.
#   UNAVAILABLE  la recherche n a pas pu aboutir (reseau, quota, erreur de l API).
#   UNCONFIGURED la source existe mais attend ses identifiants.
COMPLETED, UNAVAILABLE, UNCONFIGURED = "completed", "unavailable", "unconfigured"


class SourceNonConfiguree(RuntimeError):
    """La source existe mais n a pas ete configuree (identifiants absents).

    Troisieme etat, distinct des deux autres : « aucun resultat » est un FAIT, « indisponible »
    une panne passagere, « non configuree » une action attendue de l administrateur. Les
    confondre ferait croire au consultant que la communaute n a rien publie.
    """


class SourceIndisponible(RuntimeError):
    """La communaute n a pas pu etre interrogee (reseau, quota, acces ferme).

    Distinguee d une absence de resultat : l une signale une limite technique, l autre un
    fait. Les confondre ferait ecrire a l application que personne n a discute de la faille.
    """

MAX_PAR_SOURCE = 8         # borne par source : une communauté ne peut pas noyer l'onglet
TIMEOUT = 12.0

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Termes qui signalent une discussion TECHNIQUE plutôt qu'une simple mention.
_TERMES_TECHNIQUES = ("exploit", "poc", "proof of concept", "patch", "mitigation",
                      "workaround", "vulnerab", "attack", "payload", "advisory",
                      "remediation", "detection", "analysis", "correctif", "faille")


def _texte(d: dict) -> str:
    return " ".join(str(d.get(k) or "") for k in ("title", "summary", "content"))


def propre(valeur: str | None, limite: int = 600) -> str | None:
    """Texte affichable : balises retirées, entités décodées, espaces normalisés.

    Les API communautaires renvoient du HTML échappé (`&quot;`, `&gt;`, `<p>`). Affiché tel
    quel, un titre devenait « Does Log4Shell (&quot;CVE-2021-44228&quot;) affect… ». Le
    décodage a lieu ICI, avant l'évaluation de pertinence : une entité non décodée pourrait
    masquer l'identifiant CVE lui-même et faire rejeter une discussion parfaitement valide.
    """
    if not valeur:
        return None
    texte = re.sub(r"<[^>]+>", " ", str(valeur))
    texte = html.unescape(texte)
    texte = re.sub(r"\s+", " ", texte).strip()
    return texte[:limite] or None


def cite_la_cve(d: dict, cve_id: str) -> bool:
    """La discussion cite-t-elle CET identifiant, et non un autre ?

    Condition NÉCESSAIRE à toute association. Sans elle, une recherche par mots-clés
    rattacherait à une CVE les discussions de tout son produit — des dizaines de billets
    sans rapport avec la vulnérabilité consultée.
    """
    cites = {c.upper() for c in _CVE_RE.findall(_texte(d))}
    return cve_id.upper() in cites


def score_pertinence(d: dict, cve_id: str) -> float:
    """Note de 0 à 1. Déterministe, explicable, sans modèle de langage.

    Trois signaux, du plus fort au plus faible : l'identifiant dans le TITRE (la discussion
    porte sur cette CVE), la présence de vocabulaire technique (analyse plutôt que reprise
    d'actualité), et l'activité de la discussion (des réponses valent mieux qu'un billet
    isolé).
    """
    if not cite_la_cve(d, cve_id):
        return 0.0
    note = 0.5                                   # l'identifiant est cité : socle
    titre = (d.get("title") or "").upper()
    # UN COMMENTAIRE N'A PAS DE TITRE PROPRE : il porte celui du billet dont il dépend. Lui
    # accorder le bonus « la discussion porte sur cette CVE » le hisserait mécaniquement au
    # niveau du billet lui-même, alors qu'il peut n'être qu'une remarque en passant.
    if cve_id.upper() in titre and not d.get("is_comment"):
        note += 0.3                              # la discussion PORTE sur cette CVE
    texte = _texte(d).lower()
    if any(t in texte for t in _TERMES_TECHNIQUES):
        note += 0.15
    if (d.get("answers") or 0) > 0 or (d.get("comments") or 0) >= 3:
        note += 0.05
    # Une discussion qui cite BEAUCOUP d'autres CVE est une revue d'actualité, pas une
    # analyse de celle-ci : sa pertinence propre est diluée.
    autres = len({c.upper() for c in _CVE_RE.findall(texte)} - {cve_id.upper()})
    if autres >= 5:
        note -= 0.2
    return max(0.0, min(1.0, round(note, 2)))


def niveau(score: float) -> str:
    return HIGH if score >= 0.8 else (MEDIUM if score >= SEUIL_AFFICHAGE else LOW)


# --------------------------------------------------------------------------------------
# Sources communautaires — API PUBLIQUES uniquement
# --------------------------------------------------------------------------------------

# Flux Atom PUBLIC de Reddit. Distinct de l'API JSON, qui exige OAuth : celui-ci est ouvert.
_REDDIT_FLUX = "https://www.reddit.com/search.rss"
# Reddit exige un agent utilisateur descriptif et refuse les valeurs génériques.
_REDDIT_AGENT = "python:cyberwatch-ai:1.0 (veille de vulnerabilites)"
_ATOM = {"a": "http://www.w3.org/2005/Atom"}


async def _reddit_flux_public(cve_id: str) -> list[dict]:
    """Discussions Reddit via le flux Atom public, quand OAuth n'est pas configuré.

    Renvoie la MÊME forme que l'adaptateur OAuth : la vérification de pertinence reste commune
    et Reddit ne gagne aucune règle particulière selon la voie empruntée.
    """
    import xml.etree.ElementTree as ET

    # Reddit limite le débit du flux et répond « 429 » sans préavis. Une seule reprise
    # espacée suffit en pratique ; insister davantage reviendrait à forcer une porte que
    # l'hébergeur vient de fermer.
    contenu = None
    for tentative in (1, 2):
        reponse = await net.get(
            f"{_REDDIT_FLUX}?q=%22{cve_id}%22&sort=relevance&limit={MAX_PAR_SOURCE * 2}",
            headers={"User-Agent": _REDDIT_AGENT}, timeout=25)
        if reponse is not None and reponse.status_code == 200 and reponse.content:
            contenu = reponse.content
            break
        if tentative == 1:
            await asyncio.sleep(20)
    if contenu is None:
        raise SourceIndisponible(
            "Le flux public de Reddit a refusé la requête (limite de débit atteinte).")

    try:
        racine = ET.fromstring(contenu)
    except ET.ParseError as exc:
        raise SourceIndisponible(f"Flux Reddit illisible : {exc}") from exc

    resultats = []
    for entree in racine.findall("a:entry", _ATOM):
        lien = entree.find("a:link", _ATOM)
        url = lien.get("href") if lien is not None else None
        # SEULES LES PUBLICATIONS COMPTENT. Le flux mêle aux billets des SOUS-REDDITS entiers
        # (« r/netsec », « r/cybersecurity ») : ce sont des communautés, pas des discussions.
        # Les retenir afficherait « r/cybersecurity » comme s'il s'agissait d'un échange sur
        # la vulnérabilité. Seule une publication porte « /comments/ » dans son adresse.
        if not url or "/comments/" not in url:
            continue

        publiee = None
        brut = entree.findtext("a:updated", "", _ATOM) or ""
        if brut:
            try:
                publiee = datetime.fromisoformat(brut.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                publiee = None

        categorie = entree.find("a:category", _ATOM)
        auteur = entree.findtext("a:author/a:name", "", _ATOM) or ""
        resultats.append({
            "source": "Reddit",
            "community": categorie.get("label") if categorie is not None else None,
            "title": propre(entree.findtext("a:title", "", _ATOM), 200),
            "url": url,
            "author": auteur or None,
            "published_at": publiee,
            # Le flux ne porte que le HTML de rendu du billet : `propre()` en retire le
            # balisage. Ni commentaires ni décompte — c'est le prix de la voie publique.
            "summary": propre(entree.findtext("a:content", "", _ATOM)),
            "comments": 0,
        })
        if len(resultats) >= MAX_PAR_SOURCE:
            break

    logger.info("Reddit (flux public) : %d publication(s) pour %s.", len(resultats), cve_id)
    return resultats


async def _reddit(cve_id: str) -> list[dict]:
    """Recherche dans les communautés sécurité de Reddit, via son API OFFICIELLE (OAuth).

    L'accès anonyme est fermé et n'est pas contourné : sans identifiants d'application, la
    source se déclare NON CONFIGURÉE — une information, pas une panne. La normalisation
    ci-dessous produit exactement la même forme que les autres adaptateurs, de sorte que la
    vérification de pertinence reste commune : Reddit n'a pas sa propre règle.
    """
    from app.backend.services.community import reddit_oauth

    if not reddit_oauth.est_configure():
        # REPLI SUR LE FLUX PUBLIC DE REDDIT, faute d'identifiants d'application.
        #
        # Ce n'est pas un contournement : l'API JSON exige OAuth et refuse l'anonyme (403),
        # mais Reddit publie EN PARALLÈLE un flux Atom (`search.rss`) ouvert et destiné à la
        # consommation publique. On emprunte la porte prévue pour cela, pas une porte dérobée.
        #
        # Le flux est plus pauvre — ni commentaires, ni corps de billet — d'où le maintien
        # d'OAuth comme voie principale. Mais un résultat partiel vaut mieux que « source non
        # configurée » : le consultant voit les discussions qui existent, au lieu d'un message
        # d'administration qui ne l'aide en rien.
        return await _reddit_flux_public(cve_id)

    try:
        data = await reddit_oauth.appeler(
            "/r/netsec+cybersecurity+blueteamsec+sysadmin/search",
            {"q": f'"{cve_id}"', "restrict_sr": "1", "sort": "relevance",
             "limit": MAX_PAR_SOURCE, "t": "year"})
    except reddit_oauth.RedditNonConfigure as exc:
        raise SourceNonConfiguree(str(exc)) from exc
    except reddit_oauth.RedditIndisponible as exc:
        raise SourceIndisponible(str(exc)) from exc

    out = []
    billets = []
    for e in ((data.get("data") or {}).get("children") or [])[:MAX_PAR_SOURCE]:
        p = e.get("data") or {}
        if not p.get("permalink"):
            continue
        billets.append(p)
        out.append({
            "source": "Reddit",
            "community": f"r/{p.get('subreddit')}" if p.get("subreddit") else None,
            "title": propre(p.get("title"), 200),
            "url": "https://www.reddit.com" + p["permalink"],
            "author": (f"u/{p['author']}" if p.get("author") and p["author"] != "[deleted]"
                       else None),
            "published_at": (datetime.fromtimestamp(p["created_utc"], timezone.utc)
                             .replace(tzinfo=None) if p.get("created_utc") else None),
            "summary": propre(p.get("selftext")),
            "comments": p.get("num_comments") or 0,
        })

    # COMMENTAIRES : c'est là que se trouve l'analyse technique. Un billet n'apporte souvent
    # que le titre de l'avis ; ce sont les réponses qui rapportent les tentatives
    # d'exploitation, les contournements et les désaccords entre praticiens.
    out.extend(await _reddit_commentaires(cve_id, billets))
    return out


# Billets dont on descend l'arbre de commentaires. Chaque billet coûte un appel : au-delà de
# quelques-uns, on épuiserait la limite de débit de Reddit sans gain de pertinence — les
# billets suivants sont de toute façon moins bien classés par la recherche.
MAX_BILLETS_COMMENTES = 3
MAX_COMMENTAIRES_PAR_BILLET = 4


async def _reddit_commentaires(cve_id: str, billets: list[dict]) -> list[dict]:
    """Commentaires LES PLUS RÉCENTS des billets trouvés, filtrés sur la citation de la CVE.

    Un échec ici ne doit pas priver le consultant des billets déjà obtenus : les commentaires
    enrichissent, ils ne conditionnent pas. Toute erreur est donc absorbée par billet.
    """
    from app.backend.services.community import reddit_oauth

    sorties: list[dict] = []
    for p in billets[:MAX_BILLETS_COMMENTES]:
        identifiant = str(p.get("id") or "")
        subreddit = p.get("subreddit")
        if not identifiant or not subreddit:
            continue
        try:
            data = await reddit_oauth.appeler(
                f"/r/{subreddit}/comments/{identifiant}",
                {"sort": "new", "limit": MAX_COMMENTAIRES_PAR_BILLET * 3, "depth": 1})
        except Exception as exc:  # noqa: BLE001 - un billet muet n'annule pas les autres
            logger.info("Commentaires Reddit indisponibles pour %s : %s",
                        identifiant, str(exc)[:120])
            continue

        # La réponse est un TABLEAU : [listing du billet, listing des commentaires].
        listings = data if isinstance(data, list) else []
        enfants = (listings[1].get("data", {}).get("children") or []) if len(listings) > 1 else []
        retenus = 0
        for enfant in enfants:
            if retenus >= MAX_COMMENTAIRES_PAR_BILLET:
                break
            c = enfant.get("data") or {}
            corps = propre(c.get("body"))
            # « more » (repli de fil) et commentaires supprimés n'ont rien à afficher.
            if not corps or not c.get("permalink") or enfant.get("kind") != "t1":
                continue
            sorties.append({
                "source": "Reddit",
                "community": f"r/{subreddit} — commentaires",
                "title": f"Commentaire sur « {propre(p.get('title'), 120)} »",
                "url": "https://www.reddit.com" + c["permalink"],
                "author": (f"u/{c['author']}" if c.get("author") and c["author"] != "[deleted]"
                           else None),
                "published_at": (datetime.fromtimestamp(c["created_utc"], timezone.utc)
                                 .replace(tzinfo=None) if c.get("created_utc") else None),
                "summary": corps,
                "comments": 0,
                "is_comment": True,
            })
            retenus += 1
    return sorties


async def _stack_exchange(cve_id: str) -> list[dict]:
    """Recherche sur Information Security (Stack Exchange), via son API publique."""
    url = ("https://api.stackexchange.com/2.3/search/advanced"
           f"?order=desc&sort=relevance&q=%22{cve_id}%22&site=security"
           f"&pagesize={MAX_PAR_SOURCE}&filter=withbody")
    resp = await net.get(url, timeout=TIMEOUT)
    if resp is None:
        raise SourceIndisponible("Stack Exchange injoignable.")
    if resp.status_code != 200:
        raise SourceIndisponible(f"Stack Exchange a repondu HTTP {resp.status_code}.")
    out = []
    for q in (resp.json().get("items") or [])[:MAX_PAR_SOURCE]:
        if not q.get("link"):
            continue
        out.append({
            "source": "Stack Exchange",
            "community": "Information Security",
            # L'API renvoie des titres ÉCHAPPÉS : sans décodage, « Does Log4Shell
            # (&quot;CVE-2021-44228&quot;) affect… » s'affichait tel quel au consultant.
            "title": propre(q.get("title"), 200),
            "url": q.get("link"),
            "author": propre((q.get("owner") or {}).get("display_name"), 80),
            "published_at": (datetime.fromtimestamp(q["creation_date"], timezone.utc)
                             .replace(tzinfo=None) if q.get("creation_date") else None),
            "summary": propre(q.get("body")),
            "answers": q.get("answer_count") or 0,
        })
    return out


async def _hacker_news(cve_id: str) -> list[dict]:
    """Recherche sur Hacker News via l'API Algolia PUBLIQUE et documentée (aucune clé requise).

    Deux natures de contenu, interrogées séparément parce qu'elles n'ont pas la même valeur :

      • les BILLETS (`story`) — le sujet a été soumis à la communauté ;
      • les COMMENTAIRES (`comment`) — c'est là que se trouve l'analyse technique réelle,
        souvent la plus utile : retours d'exploitation, contournements, désaccords entre
        praticiens. Une source qui n'indexerait que les titres passerait à côté de l'essentiel.

    Les commentaires sont triés du plus RÉCENT au plus ancien : sur une vulnérabilité en
    cours, ce qui a été écrit hier vaut mieux que ce qui l'a été il y a deux ans.
    """
    quete = f'"{cve_id}"'
    sorties: list[dict] = []

    for tag, tri in (("story", "search"), ("comment", "search_by_date")):
        url = (f"https://hn.algolia.com/api/v1/{tri}"
               f"?query={quete}&tags={tag}&hitsPerPage={MAX_PAR_SOURCE}")
        resp = await net.get(url, timeout=TIMEOUT)
        if resp is None:
            raise SourceIndisponible("Hacker News injoignable.")
        if resp.status_code != 200:
            raise SourceIndisponible(f"Hacker News a repondu HTTP {resp.status_code}.")

        for h in (resp.json().get("hits") or [])[:MAX_PAR_SOURCE]:
            objet = h.get("objectID")
            if not objet:
                continue
            est_commentaire = tag == "comment"
            titre = propre(h.get("title") or h.get("story_title"), 200)
            corps = propre(h.get("comment_text") or h.get("story_text"))
            # Un commentaire n'a pas de titre propre : on le rattache au billet qui le porte,
            # sinon la discussion s'afficherait sans contexte lisible.
            if est_commentaire and titre:
                titre = f"Commentaire sur « {titre} »"
            sorties.append({
                "source": "Hacker News",
                "community": "Commentaires" if est_commentaire else "Billets",
                "title": titre or (corps or "")[:120] or None,
                "url": f"https://news.ycombinator.com/item?id={objet}",
                "author": h.get("author"),
                "published_at": (datetime.fromtimestamp(h["created_at_i"], timezone.utc)
                                 .replace(tzinfo=None) if h.get("created_at_i") else None),
                "summary": corps,
                "comments": h.get("num_comments") or 0,
                "is_comment": est_commentaire,
            })
    return sorties


# Registre EXTENSIBLE : ajouter une communauté se limite à une entrée ici.
# REGISTRE des sources. Chaque entree decrit son adaptateur, son libelle affiche et si elle
# exige une authentification. Ajouter une communaute se limite a une entree ici : ni le
# stockage, ni la verification de pertinence, ni l API, ni l interface ne changent.
SOURCES = {
    "reddit": {"adapter": _reddit, "label": "Reddit", "requires_auth": True},
    "stack_exchange": {"adapter": _stack_exchange, "label": "Stack Exchange",
                       "requires_auth": False},
    "hacker_news": {"adapter": _hacker_news, "label": "Hacker News", "requires_auth": False},
}


# --------------------------------------------------------------------------------------
# Recherche, vérification, stockage
# --------------------------------------------------------------------------------------

def cle_unique(cve_id: str, d: dict) -> str:
    """Identité STABLE d'une discussion : la CVE, sa source et son URL.

    Rejouer la recherche ne crée donc aucun doublon, et une même discussion peut légitimement
    être rattachée à deux CVE différentes si elle cite les deux.
    """
    url = (d.get("url") or "").strip().lower().rstrip("/")
    return f"{cve_id.upper()}|{(d.get('source') or '').lower()}|{url}"


async def rechercher(cve_id: str) -> tuple[list[dict], list[dict]]:
    """Interroge TOUTES les sources en parallele. Renvoie (discussions, etat de chaque source).

    L'échec d'une communauté — indisponible, limitée en débit, format inattendu — n'empêche
    jamais les autres d'aboutir : chaque source est isolée, et son échec est signalé sans
    faire échouer la recherche.
    """
    noms = list(SOURCES)
    resultats = await asyncio.gather(*[SOURCES[n]["adapter"](cve_id) for n in noms],
                                     return_exceptions=True)
    retenues: list[dict] = []
    etats: list[dict] = []
    vues: set[str] = set()

    for nom, res in zip(noms, resultats):
        libelle = SOURCES[nom]["label"]
        if isinstance(res, SourceNonConfiguree):
            # NI un echec, NI une absence : une action attendue de l administrateur.
            logger.info("Source « %s » non configuree.", nom)
            etats.append({"source": libelle, "status": UNCONFIGURED,
                          "reason": "Identifiants d acces non configures."})
            continue
        if isinstance(res, Exception):
            logger.info("Source communautaire « %s » indisponible pour %s : %s",
                        nom, cve_id, str(res)[:120])
            etats.append({"source": libelle, "status": UNAVAILABLE,
                          "reason": "La recherche n a pas pu aboutir sur cette source."})
            continue
        retenues_source = 0
        for d in res:
            cle = cle_unique(cve_id, d)
            if cle in vues or not d.get("url"):
                continue
            vues.add(cle)
            score = score_pertinence(d, cve_id)
            if score < SEUIL_AFFICHAGE:
                continue          # hors sujet, ou mention trop faible : on n'affiche pas
            retenues.append({**d, "cve_id": cve_id.upper(), "_id": cle,
                             "relevance_score": score, "relevance_level": niveau(score),
                             "verification_status": VERIFIED,
                             "source_type": agent.COMMUNITY})
            retenues_source += 1
        # La recherche a ABOUTI : zero resultat est un fait, pas une panne.
        etats.append({"source": libelle, "status": COMPLETED, "results": retenues_source})
    retenues.sort(key=lambda d: (-d["relevance_score"],
                                 -(d.get("published_at") or datetime.min).timestamp()
                                 if d.get("published_at") else 0))
    return retenues, etats


async def enregistrer(db, discussions: list[dict]) -> int:
    """Écrit dans `community_discussions`. Idempotent : la clé unique interdit le doublon."""
    from app.backend.utils import utcnow

    ecrites = 0
    for d in discussions:
        doc = {**d, "collected_at": utcnow()}
        await db.community_discussions.replace_one({"_id": d["_id"]}, doc, upsert=True)
        ecrites += 1
    return ecrites


AUCUNE_DISCUSSION = ("Aucune discussion communautaire pertinente n'a été trouvée pour cette "
                     "vulnérabilité.")

_RESUME_SYSTEM = (
    "Tu es analyste cybersécurité. On te donne les TITRES et EXTRAITS de discussions "
    "PUBLIQUES portant sur une vulnérabilité. Tu rédiges en FRANÇAIS une synthèse de ce que "
    "la communauté en dit.\n"
    "RÈGLES ABSOLUES :\n"
    "- Tu ne t'appuies QUE sur les extraits fournis ; tu n'ajoutes aucune connaissance.\n"
    "- Tu n'inventes ni score, ni version, ni correctif, ni date, ni identifiant.\n"
    "- Tu RAPPORTES des propos (« plusieurs participants indiquent… ») : tu ne les valides "
    "jamais, et tu ne formules aucune recommandation en ton nom.\n"
    "- Ces propos ne sont pas des faits établis : ton texte doit rester au conditionnel dès "
    "qu'il s'agit d'impact, d'exploitation ou de contournement.\n"
    "- 2 à 4 phrases, sans titre, sans puces. Registre sobre.")


async def resume_communautaire(discussions: list[dict]) -> tuple[str, str]:
    """Synthèse FRANÇAISE des discussions. Renvoie (texte, origine : llm | deterministe).

    Le repli déterministe n'est pas un pis-aller : il énonce ce qui est mesurable — combien
    de discussions, sur quelles communautés, à quel niveau de pertinence — sans rien
    interpréter. Aucun modèle n'est nécessaire pour cela, et l'onglet reste exploitable quand
    le quota du fournisseur est épuisé.
    """
    from app.backend.services.assistant import llm

    if not discussions:
        return AUCUNE_DISCUSSION, "deterministe"

    communautes = list(dict.fromkeys(
        f"{d.get('source')}{' – ' + d['community'] if d.get('community') else ''}"
        for d in discussions if d.get("source")))
    hautes = sum(1 for d in discussions if d.get("relevance_level") == HIGH)
    n = len(discussions)
    deterministe = (
        f"{n} discussion{'s' if n > 1 else ''} publique{'s' if n > 1 else ''} "
        f"mentionne{'nt' if n > 1 else ''} cette vulnérabilité"
        + (f", dont {hautes} d'une pertinence élevée" if hautes else "")
        + f". Source{'s' if len(communautes) > 1 else ''} : {', '.join(communautes)}. "
        "Ces échanges sont rapportés à titre indicatif et ne remplacent pas l'avis officiel "
        "de l'éditeur.")

    extraits = "\n\n".join(
        f"[{d.get('source')}{' / ' + d['community'] if d.get('community') else ''}] "
        f"{d.get('title')}\n{(d.get('summary') or '')[:400]}"
        for d in discussions[:6])

    # MATIÈRE SUFFISANTE avant d'appeler le modèle.
    #
    # Des discussions sans titre exploitable ni extrait ne lui donnent rien à synthétiser :
    # il répond alors par une remarque sur sa propre tâche (« aucun extrait n'a été
    # fourni »), qui se retrouvait publiée telle quelle comme analyse de la communauté.
    # Le décompte déterministe, lui, reste exact dans ce cas.
    if not llm.available() or len(extraits.strip()) < 80:
        return deterministe, "deterministe"
    try:
        # BUDGET LARGE À DESSEIN : les modèles à raisonnement (GPT-OSS, o-series) dépensent
        # une part de l'enveloppe en réflexion AVANT d'écrire. Avec 700 jetons, la synthèse
        # s'arrêtait en plein mot — un texte tronqué se lit comme une panne, pas comme une
        # analyse. La consigne de longueur reste dans le prompt : c'est elle qui borne le texte.
        texte = await llm.generate(
            "Discussions publiques relevées :\n\n" + extraits
            + "\n\nRédige la synthèse en respectant les règles.",
            system=_RESUME_SYSTEM, max_tokens=1600)
    except Exception:  # noqa: BLE001 - l'onglet ne doit jamais échouer à cause du modèle
        texte = None
    texte = (texte or "").strip()
    # Réponse MÉTA : le modèle commente sa tâche au lieu de la faire. Elle passerait le
    # contrôle de longueur et s'afficherait comme l'analyse de la communauté.
    meta = ("aucun extrait", "n'a été fourni", "n’a été fourni", "pas possible de rédiger",
            "en tant que modèle", "je ne peux pas")
    if len(texte) < 40 or any(m in texte.lower() for m in meta):
        return deterministe, "deterministe"
    return texte, "llm"


async def lire(db, cve_id: str) -> list[dict]:
    """Discussions DÉJÀ vérifiées pour cette CVE, les plus pertinentes d'abord."""
    return await db.community_discussions.find(
        {"cve_id": cve_id.upper(), "verification_status": VERIFIED}
    ).sort("relevance_score", -1).to_list(30)
