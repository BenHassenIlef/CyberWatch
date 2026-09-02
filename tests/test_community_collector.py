"""Tests du collecteur de veille communautaire.

Deux exigences y sont vérifiées en priorité :
  • une publication SANS identifiant CVE est conservée (le collecteur de CVE la jetterait) ;
  • un résultat vide n'est jamais considéré comme un succès s'il peut venir d'une panne.
"""
from datetime import datetime, timedelta

import pytest

from app.backend.services.community import collector as cc


FLUX_RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <item>
    <title>Analyse technique de CVE-2026-12345 dans Apache Tomcat</title>
    <description><![CDATA[<p>Un PoC public circule pour cette faille.</p>]]></description>
    <link>https://blog.example/analyse-tomcat</link>
    <pubDate>Mon, 18 Aug 2026 10:00:00 GMT</pubDate>
  </item>
  <item>
    <title>Rumeur de zero-day sur Microsoft Exchange Server</title>
    <description>Aucun identifiant publie a ce stade, discussion en cours.</description>
    <link>https://forum.example/thread/42</link>
    <pubDate>Mon, 18 Aug 2026 08:00:00 GMT</pubDate>
  </item>
</channel></rss>"""

FLUX_ATOM = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Correctif urgent publie par l editeur</title>
    <summary>Le correctif corrige plusieurs vulnerabilites critiques.</summary>
    <link href="https://vendor.example/advisory/1"/>
    <published>2026-08-18T09:00:00Z</published>
  </entry>
</feed>"""


# --------------------------------------------------------------- analyse de flux

def test_publication_sans_cve_est_conservee():
    """LE point qui distingue ce collecteur de celui des CVE."""
    pubs = cc.parse_feed(FLUX_RSS, "https://blog.example/feed")
    titres = [p["title"] for p in pubs]
    assert len(pubs) == 2
    assert any("zero-day" in t.lower() for t in titres), (
        "une publication sans identifiant CVE doit etre conservee")


def test_champs_extraits():
    p = cc.parse_feed(FLUX_RSS, "https://blog.example/feed")[0]
    assert "CVE-2026-12345" in p["title"]
    assert "PoC" in p["content"]
    assert p["url"] == "https://blog.example/analyse-tomcat"
    assert isinstance(p["published_at"], datetime)


def test_format_atom_supporte():
    pubs = cc.parse_feed(FLUX_ATOM, "https://vendor.example/feed")
    assert len(pubs) == 1
    assert pubs[0]["url"] == "https://vendor.example/advisory/1"


def test_html_retire_du_contenu():
    p = cc.parse_feed(FLUX_RSS, "https://blog.example/feed")[0]
    assert "<p>" not in p["content"]


def test_flux_vide_donne_liste_vide():
    assert cc.parse_feed("<rss><channel></channel></rss>", "https://x/f") == []


def test_titre_trop_court_ignore():
    flux = "<rss><channel><item><title>Bref</title><link>https://x/1</link></item></channel></rss>"
    assert cc.parse_feed(flux, "https://x/f") == []


# --------------------------------------------------------------- statuts de collecte

class _Reponse:
    def __init__(self, code=200, text=""):
        self.status_code = code
        self.text = text


@pytest.mark.asyncio
async def test_source_avec_publications(monkeypatch):
    async def _get(url, **kw):
        return _Reponse(200, FLUX_RSS)
    monkeypatch.setattr(cc.net, "get", _get)
    r = await cc.collect_source({"_id": "1", "name": "blog", "url": "https://blog.example/feed"})
    assert r["status"] == "success" and r["detected"] == 2
    assert all(p["source_name"] == "blog" for p in r["publications"])


@pytest.mark.asyncio
async def test_flux_valide_mais_sans_nouveaute(monkeypatch):
    """Vrai flux, aucun element : c'est un SUCCES vide, pas une panne."""
    async def _get(url, **kw):
        return _Reponse(200, '<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>')
    monkeypatch.setattr(cc.net, "get", _get)
    r = await cc.collect_source({"_id": "1", "name": "blog", "url": "https://x/f"})
    assert r["status"] == "empty"


@pytest.mark.asyncio
async def test_reponse_sans_structure_de_flux_est_suspecte(monkeypatch):
    """Page HTML renvoyee a la place du flux : structure changee, NE PAS valider."""
    async def _get(url, **kw):
        return _Reponse(200, "<html><body>Bienvenue sur notre site</body></html>")
    monkeypatch.setattr(cc.net, "get", _get)
    r = await cc.collect_source({"_id": "1", "name": "blog", "url": "https://x/f"})
    assert r["status"] == "empty_suspect"
    assert r["error"]


@pytest.mark.asyncio
async def test_source_injoignable(monkeypatch):
    async def _get(url, **kw):
        return None
    monkeypatch.setattr(cc.net, "get", _get)
    r = await cc.collect_source({"_id": "1", "name": "blog", "url": "https://x/f"})
    assert r["status"] == "timeout"


@pytest.mark.asyncio
async def test_erreur_http(monkeypatch):
    async def _get(url, **kw):
        return _Reponse(503, "")
    monkeypatch.setattr(cc.net, "get", _get)
    r = await cc.collect_source({"_id": "1", "name": "blog", "url": "https://x/f"})
    assert r["status"] == "failed" and "503" in r["error"]


@pytest.mark.asyncio
async def test_exception_reseau_ne_propage_pas(monkeypatch):
    async def _get(url, **kw):
        raise ConnectionError("reseau coupe")
    monkeypatch.setattr(cc.net, "get", _get)
    r = await cc.collect_source({"_id": "1", "name": "blog", "url": "https://x/f"})
    assert r["status"] == "failed"


# --------------------------------------------------------------- dedup / correlation

def test_dedoublonnage_par_url():
    a = {"url": "https://blog.example/post/1", "title": "A"}
    b = {"url": "https://blog.example/post/1/", "title": "Titre different"}
    assert cc.dedup_key(a) == cc.dedup_key(b), "meme URL = meme publication"


def test_publications_distinctes_non_fusionnees():
    a = {"url": "https://a.example/1", "title": "Sujet"}
    b = {"url": "https://b.example/9", "title": "Sujet"}
    assert cc.dedup_key(a) != cc.dedup_key(b)


def test_correlation_par_cve():
    assert cc.correlation_key({}, ["CVE-2026-2", "CVE-2026-1"]) == "CVE-2026-1"


def test_pas_de_correlation_sans_cve():
    """Rapprocher deux billets sur leur seul titre creerait de faux regroupements."""
    assert cc.correlation_key({"title": "Faille critique"}, []) is None


# --------------------------------------------------------------- fraicheur

def test_publication_posterieure_est_nouvelle():
    ref = datetime(2026, 8, 18, 8, 0)
    assert cc.is_new_publication({"published_at": ref + timedelta(hours=1)}, ref) is True
    assert cc.is_new_publication({"published_at": ref - timedelta(hours=1)}, ref) is False


def test_sans_date_consideree_nouvelle():
    assert cc.is_new_publication({}, datetime(2026, 8, 18)) is True
