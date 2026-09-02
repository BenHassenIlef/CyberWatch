"""Reddit via l'API OFFICIELLE (OAuth) — authentification, cache de jeton, statuts.

L'accès anonyme de Reddit est fermé (HTTP 403). Plutôt que de chercher à le contourner, on
emprunte le flux serveur-à-serveur prévu pour cela. Ces tests verrouillent ce qui doit rester
vrai quoi qu'il arrive :

  • sans identifiants, la source se déclare NON CONFIGURÉE — l'application ne tombe pas ;
  • le jeton est réutilisé tant qu'il vaut, renouvelé une seule fois après un « 401 » ;
  • un secret ou un jeton ne quitte jamais le serveur ;
  • une panne de Reddit ne prive jamais le consultant des autres communautés.

Aucun appel réel n'est effectué : le réseau est simulé.
"""
import asyncio
import time

import pytest

from app.backend.core.config import settings
from app.backend.services.collection import net
from app.backend.services.community import discussions as dc
from app.backend.services.community import reddit_oauth as ro

CVE = "CVE-2024-3094"


class FausseReponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        if self._payload is None:
            raise ValueError("corps illisible")
        return self._payload


@pytest.fixture
def identifiants(monkeypatch):
    """Application configurée, cache de jeton vide."""
    monkeypatch.setattr(settings, "REDDIT_CLIENT_ID", "identifiant-test", raising=False)
    monkeypatch.setattr(settings, "REDDIT_CLIENT_SECRET", "secret-test", raising=False)
    ro.oublier_jeton()
    yield
    ro.oublier_jeton()


@pytest.fixture
def sans_identifiants(monkeypatch):
    monkeypatch.setattr(settings, "REDDIT_CLIENT_ID", "", raising=False)
    monkeypatch.setattr(settings, "REDDIT_CLIENT_SECRET", "", raising=False)
    ro.oublier_jeton()
    yield
    ro.oublier_jeton()


def _post_jeton(valeur="jeton-abc", duree=3600, status=200):
    async def _post(url, data=None, headers=None, timeout=None):
        return FausseReponse(status, {"access_token": valeur, "expires_in": duree})
    return _post


# ---------------------------------------------------------------------------------------
# 1. Absence d'identifiants — une information, pas une panne.
# ---------------------------------------------------------------------------------------

def test_sans_identifiants_la_source_est_non_configuree(sans_identifiants):
    assert not ro.est_configure()
    with pytest.raises(ro.RedditNonConfigure):
        asyncio.run(ro.obtenir_jeton())


def test_sans_identifiants_l_adaptateur_bascule_sur_le_flux_public(sans_identifiants,
                                                                  monkeypatch):
    """Sans OAuth, l'adaptateur ne renonce plus : il emprunte le flux Atom PUBLIC.

    Auparavant il levait `SourceNonConfiguree`, et l'onglet affichait « Reddit — source non
    configurée » pour TOUTES les vulnérabilités : le consultant lisait un message
    d'administration au lieu des discussions qui existaient bel et bien.

    Ce n'est pas un contournement de l'authentification. L'API JSON exige OAuth et refuse
    l'anonyme ; le flux `search.rss` est une autre interface, publiée par Reddit et ouverte
    par construction. On emprunte la porte prévue pour cela.
    """
    appelé = {"flux": False}

    async def _flux(_cve):
        appelé["flux"] = True
        return [{"source": "Reddit", "title": f"Discussion sur {CVE}",
                 "url": "https://www.reddit.com/r/netsec/comments/x/y/", "community": "r/netsec",
                 "author": None, "published_at": None, "summary": None, "comments": 0}]

    monkeypatch.setattr(dc, "_reddit_flux_public", _flux)
    resultats = asyncio.run(dc.SOURCES["reddit"]["adapter"](CVE))

    assert appelé["flux"] is True
    assert len(resultats) == 1


def test_non_configure_n_est_pas_un_echec_dans_la_recherche(sans_identifiants, monkeypatch):
    """Une source sans identifiants ne prive JAMAIS le consultant des autres communautés.

    Le registre est intégralement remplacé — et non complété source par source. Une entrée
    laissée à sa vraie implémentation partirait sur le réseau pendant les tests : la suite
    deviendrait lente, dépendante d'un tiers, et rouge le jour où ce tiers change de format.
    C'est exactement ce qui s'est produit à l'ajout de Hacker News.
    """
    async def stack_ok(_cve):
        return [{"source": "Stack Exchange", "title": f"Analyse de {CVE}",
                 "summary": "exploit et patch", "url": "https://se.test/1"}]

    # Le statut NON CONFIGURÉ reste atteignable : il décrit désormais une source dont la
    # seule voie d'accès demande des identifiants absents. On le simule explicitement, plutôt
    # que de compter sur Reddit — qui, lui, dispose d'un flux public de repli.
    async def sans_acces(_cve):
        raise dc.SourceNonConfiguree("identifiants requis")

    monkeypatch.setattr(dc, "SOURCES", {
        "reddit": {"adapter": sans_acces, "label": "Reddit", "requires_auth": True},
        "stack_exchange": {"adapter": stack_ok, "label": "Stack Exchange",
                           "requires_auth": False},
    })
    retenues, etats = asyncio.run(dc.rechercher(CVE))
    par_source = {e["source"]: e for e in etats}
    assert par_source["Reddit"]["status"] == dc.UNCONFIGURED
    assert par_source["Stack Exchange"]["status"] == dc.COMPLETED
    assert len(retenues) == 1        # une source non configurée ne prive pas des autres


# ---------------------------------------------------------------------------------------
# 2. Authentification et cache du jeton.
# ---------------------------------------------------------------------------------------

def test_authentification_reussie(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton("jeton-abc"))
    assert asyncio.run(ro.obtenir_jeton()) == "jeton-abc"


def test_jeton_reutilise_tant_qu_il_vaut(identifiants, monkeypatch):
    """Redemander un jeton à chaque recherche gaspillerait des appels et heurterait le débit."""
    appels = {"n": 0}

    async def _post(url, data=None, headers=None, timeout=None):
        appels["n"] += 1
        return FausseReponse(200, {"access_token": f"jeton-{appels['n']}", "expires_in": 3600})

    monkeypatch.setattr(net, "post", _post)
    premier = asyncio.run(ro.obtenir_jeton())
    second = asyncio.run(ro.obtenir_jeton())
    assert premier == second and appels["n"] == 1


def test_jeton_renouvele_apres_expiration(identifiants, monkeypatch):
    appels = {"n": 0}

    async def _post(url, data=None, headers=None, timeout=None):
        appels["n"] += 1
        return FausseReponse(200, {"access_token": f"jeton-{appels['n']}", "expires_in": 3600})

    monkeypatch.setattr(net, "post", _post)
    asyncio.run(ro.obtenir_jeton())
    ro._jeton["expire_a"] = time.monotonic() - 1        # le jeton vient d'expirer
    assert asyncio.run(ro.obtenir_jeton()) == "jeton-2" and appels["n"] == 2


def test_marge_de_securite_avant_echeance(identifiants, monkeypatch):
    """On renouvelle un peu AVANT l'échéance : un jeton ne doit pas expirer en vol."""
    monkeypatch.setattr(net, "post", _post_jeton(duree=3600))
    asyncio.run(ro.obtenir_jeton())
    restant = ro._jeton["expire_a"] - time.monotonic()
    assert restant < 3600 and restant > 3600 - ro.MARGE_EXPIRATION - 5


def test_authentification_refusee_est_une_indisponibilite(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton(status=401))
    with pytest.raises(ro.RedditIndisponible):
        asyncio.run(ro.obtenir_jeton())


def test_service_d_authentification_injoignable(identifiants, monkeypatch):
    async def _post(*a, **k):
        return None
    monkeypatch.setattr(net, "post", _post)
    with pytest.raises(ro.RedditIndisponible):
        asyncio.run(ro.obtenir_jeton())


# ---------------------------------------------------------------------------------------
# 3. Appels à l'API : reprise unique sur 401, refus d'insister sur 429.
# ---------------------------------------------------------------------------------------

def test_401_declenche_un_renouvellement_et_UN_seul_nouvel_essai(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())
    appels = {"n": 0}

    async def _get(url, headers=None, timeout=None, params=None):
        appels["n"] += 1
        return FausseReponse(401 if appels["n"] == 1 else 200, {"data": {"children": []}})

    monkeypatch.setattr(net, "get", _get)
    assert asyncio.run(ro.appeler("/x", {})) == {"data": {"children": []}}
    assert appels["n"] == 2          # une reprise, pas davantage


def test_401_persistant_ne_boucle_pas(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())
    appels = {"n": 0}

    async def _get(url, headers=None, timeout=None, params=None):
        appels["n"] += 1
        return FausseReponse(401)

    monkeypatch.setattr(net, "get", _get)
    with pytest.raises(ro.RedditIndisponible):
        asyncio.run(ro.appeler("/x", {}))
    assert appels["n"] == 2          # borné : jamais de boucle infinie


def test_429_n_est_pas_reessaye(identifiants, monkeypatch):
    """Insister sur une limite de débit l'aggrave et retarde les autres sources."""
    monkeypatch.setattr(net, "post", _post_jeton())
    appels = {"n": 0}

    async def _get(url, headers=None, timeout=None, params=None):
        appels["n"] += 1
        return FausseReponse(429)

    monkeypatch.setattr(net, "get", _get)
    with pytest.raises(ro.RedditIndisponible):
        asyncio.run(ro.appeler("/x", {}))
    assert appels["n"] == 1


def test_reponse_illisible_est_une_indisponibilite(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())

    async def _get(url, headers=None, timeout=None, params=None):
        r = FausseReponse(200)
        r._payload = None
        return r

    monkeypatch.setattr(net, "get", _get)
    with pytest.raises(ro.RedditIndisponible):
        asyncio.run(ro.appeler("/x", {}))


# ---------------------------------------------------------------------------------------
# 4. Recherche : normalisation, appariement exact, résultat vide.
# ---------------------------------------------------------------------------------------

def _reddit_repond(publications):
    async def _get(url, headers=None, timeout=None, params=None):
        return FausseReponse(200, {"data": {"children": [{"data": p} for p in publications]}})
    return _get


def test_recherche_avec_identifiant_exact(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())
    monkeypatch.setattr(net, "get", _reddit_repond([{
        "permalink": "/r/netsec/comments/a/", "subreddit": "netsec",
        "title": f"Deep dive on {CVE}", "author": "chercheur",
        "created_utc": 1755000000, "selftext": "exploit et patch", "num_comments": 12}]))
    res = asyncio.run(dc.SOURCES["reddit"]["adapter"](CVE))
    assert len(res) == 1
    assert res[0]["source"] == "Reddit" and res[0]["community"] == "r/netsec"
    assert res[0]["url"].startswith("https://www.reddit.com/r/netsec/")
    # La pertinence est celle du système COMMUN : Reddit n'a pas sa propre règle.
    assert dc.niveau(dc.score_pertinence(res[0], CVE)) == dc.HIGH


def test_publication_citant_une_autre_cve_est_rejetee(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())
    monkeypatch.setattr(net, "get", _reddit_repond([{
        "permalink": "/r/netsec/comments/b/", "subreddit": "netsec",
        "title": "Exploit for CVE-2026-9999", "created_utc": 1755000000}]))
    monkeypatch.setitem(dc.SOURCES, "stack_exchange",
                        {"adapter": lambda _c: _vide(), "label": "Stack Exchange",
                         "requires_auth": False})
    retenues, etats = asyncio.run(dc.rechercher(CVE))
    assert retenues == []
    assert {e["source"]: e["status"] for e in etats}["Reddit"] == dc.COMPLETED


async def _vide():
    return []


def test_recherche_aboutie_sans_resultat(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())
    monkeypatch.setattr(net, "get", _reddit_repond([]))
    monkeypatch.setitem(dc.SOURCES, "stack_exchange",
                        {"adapter": lambda _c: _vide(), "label": "Stack Exchange",
                         "requires_auth": False})
    _retenues, etats = asyncio.run(dc.rechercher(CVE))
    reddit = {e["source"]: e for e in etats}["Reddit"]
    # « Aucun résultat » est un FAIT sur la communauté, distinct d'une panne.
    assert reddit["status"] == dc.COMPLETED and reddit["results"] == 0


def test_panne_reddit_n_empeche_pas_stack_exchange(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())

    async def _get(url, headers=None, timeout=None, params=None):
        return FausseReponse(500)

    monkeypatch.setattr(net, "get", _get)

    async def stack_ok(_cve):
        return [{"source": "Stack Exchange", "title": f"Analyse de {CVE}",
                 "summary": "patch", "url": "https://se.test/2"}]

    monkeypatch.setitem(dc.SOURCES, "stack_exchange",
                        {"adapter": stack_ok, "label": "Stack Exchange", "requires_auth": False})
    retenues, etats = asyncio.run(dc.rechercher(CVE))
    par_source = {e["source"]: e["status"] for e in etats}
    assert par_source["Reddit"] == dc.UNAVAILABLE
    assert par_source["Stack Exchange"] == dc.COMPLETED and len(retenues) == 1


def test_doublon_reddit_non_duplique(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton())
    pub = {"permalink": "/r/netsec/comments/c/", "subreddit": "netsec",
           "title": f"Analyse de {CVE}", "created_utc": 1755000000, "selftext": "patch"}
    monkeypatch.setattr(net, "get", _reddit_repond([pub, dict(pub)]))
    monkeypatch.setitem(dc.SOURCES, "stack_exchange",
                        {"adapter": lambda _c: _vide(), "label": "Stack Exchange",
                         "requires_auth": False})
    retenues, _ = asyncio.run(dc.rechercher(CVE))
    assert len(retenues) == 1


# ---------------------------------------------------------------------------------------
# 5. Aucun secret ne franchit la frontière du serveur.
# ---------------------------------------------------------------------------------------

def test_aucun_secret_dans_les_discussions_produites(identifiants, monkeypatch):
    monkeypatch.setattr(net, "post", _post_jeton("jeton-secret-abc"))
    monkeypatch.setattr(net, "get", _reddit_repond([{
        "permalink": "/r/netsec/comments/d/", "subreddit": "netsec",
        "title": f"Analyse de {CVE}", "created_utc": 1755000000, "selftext": "patch"}]))
    monkeypatch.setitem(dc.SOURCES, "stack_exchange",
                        {"adapter": lambda _c: _vide(), "label": "Stack Exchange",
                         "requires_auth": False})
    retenues, etats = asyncio.run(dc.rechercher(CVE))
    brut = repr(retenues) + repr(etats)
    for interdit in ("jeton-secret-abc", "secret-test", "identifiant-test", "Authorization",
                     "bearer"):
        assert interdit not in brut


def test_les_discussions_ne_portent_aucun_champ_officiel(identifiants, monkeypatch):
    """La garantie centrale : rien de communautaire ne touche l'information officielle."""
    monkeypatch.setattr(net, "post", _post_jeton())
    monkeypatch.setattr(net, "get", _reddit_repond([{
        "permalink": "/r/netsec/comments/e/", "subreddit": "netsec",
        "title": f"Analyse de {CVE}", "created_utc": 1755000000, "selftext": "patch"}]))
    monkeypatch.setitem(dc.SOURCES, "stack_exchange",
                        {"adapter": lambda _c: _vide(), "label": "Stack Exchange",
                         "requires_auth": False})
    retenues, _ = asyncio.run(dc.rechercher(CVE))
    interdits = {"solution", "references", "cvss_score", "severity", "official_source",
                 "affected_products", "vendor", "product"}
    assert not (interdits & set(retenues[0]))
