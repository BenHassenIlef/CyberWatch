"""HACKER NEWS, NETTOYAGE DU TEXTE et COURRIEL DE VEILLE.

Trois corrections que ces tests verrouillent :

  1. Hacker News rejoint les sources communautaires. Son intérêt tient aux COMMENTAIRES :
     c'est là que se trouvent les retours d'exploitation et les contournements, pas dans les
     titres. Reddit ayant fermé son accès anonyme, c'était la seule communauté réellement
     interrogeable sans identifiants.
  2. Les API renvoient du HTML échappé. Un titre s'affichait « Does Log4Shell
     (&quot;CVE-2021-44228&quot;) affect… », et — plus grave — une entité non décodée pouvait
     masquer l'identifiant CVE et faire REJETER une discussion parfaitement pertinente.
  3. Le courriel de veille confondait une découverte du jour et la mise à jour d'une fiche
     déjà connue. C'est la première question que se pose un consultant en l'ouvrant.

Aucun appel réseau : les réponses des API sont simulées.
"""
import asyncio

import pytest

from app.backend.services.collection import net
from app.backend.services.community import discussions as dc

CVE = "CVE-2021-44228"


# ---------------------------------------------------------------------------------------
# 1. Nettoyage du texte reçu des communautés
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("brut, attendu", [
    ('Does Log4Shell (&quot;CVE-2021-44228&quot;) affect K8S?',
     'Does Log4Shell ("CVE-2021-44228") affect K8S?'),
    ("<p>Analyse de <b>CVE-2021-44228</b></p>", "Analyse de CVE-2021-44228"),
    ("&gt; citation   avec    espaces", "> citation avec espaces"),
    ("", None),
    (None, None),
])
def test_nettoyage_du_texte(brut, attendu):
    assert dc.propre(brut) == attendu


def test_entite_echappee_ne_masque_plus_l_identifiant():
    """Le décodage doit précéder l'évaluation de pertinence.

    Sans lui, l'identifiant reste noyé dans les entités et `cite_la_cve` échoue : une
    discussion valide serait écartée en silence, ce qui est le pire des deux mondes.
    """
    discussion = {"title": dc.propre("Impact de &quot;CVE-2021-44228&quot; en production"),
                  "summary": None}
    assert dc.cite_la_cve(discussion, CVE)


# ---------------------------------------------------------------------------------------
# 2. Adaptateur Hacker News
# ---------------------------------------------------------------------------------------

class _Reponse:
    status_code = 200

    def __init__(self, charge):
        self._charge = charge

    def json(self):
        return self._charge


def _hn_simule(monkeypatch, billets, commentaires):
    """Simule l'API Algolia : deux requêtes distinctes, billets puis commentaires."""
    async def _get(url, **kw):
        if "tags=comment" in url:
            return _Reponse({"hits": commentaires})
        return _Reponse({"hits": billets})
    monkeypatch.setattr(net, "get", _get)


def test_hacker_news_remonte_billets_et_commentaires(monkeypatch):
    _hn_simule(
        monkeypatch,
        billets=[{"objectID": "29", "title": f"Log4Shell ({CVE}) cheat sheet",
                  "created_at_i": 1_639_000_000, "author": "weinzierl", "num_comments": 42}],
        commentaires=[{"objectID": "30", "story_title": f"Log4Shell ({CVE})",
                       "comment_text": f"Nous avons vu des tentatives d&#x27;exploit sur {CVE}",
                       "created_at_i": 1_639_100_000, "author": "praticien"}])

    resultats = asyncio.run(dc._hacker_news(CVE))
    assert len(resultats) == 2

    billet = next(r for r in resultats if not r.get("is_comment"))
    assert billet["url"] == "https://news.ycombinator.com/item?id=29"
    assert billet["community"] == "Billets"

    commentaire = next(r for r in resultats if r.get("is_comment"))
    assert commentaire["community"] == "Commentaires"
    assert commentaire["title"].startswith("Commentaire sur")
    # L'apostrophe encodée doit être rendue lisible.
    assert "d'exploit" in commentaire["summary"]


def test_hacker_news_indisponible_n_est_pas_une_absence(monkeypatch):
    """Une panne ne doit JAMAIS se lire « personne n'en a parlé »."""
    async def _get(url, **kw):
        return None
    monkeypatch.setattr(net, "get", _get)
    with pytest.raises(dc.SourceIndisponible):
        asyncio.run(dc._hacker_news(CVE))


def test_hacker_news_erreur_http_signalee(monkeypatch):
    class _Erreur:
        status_code = 503

        def json(self):
            return {}

    async def _get(url, **kw):
        return _Erreur()
    monkeypatch.setattr(net, "get", _get)
    with pytest.raises(dc.SourceIndisponible):
        asyncio.run(dc._hacker_news(CVE))


# ---------------------------------------------------------------------------------------
# 3. Un commentaire n'hérite pas de l'autorité de son billet
# ---------------------------------------------------------------------------------------

def test_commentaire_ne_recoit_pas_le_bonus_de_titre():
    """Un commentaire porte le titre du billet : lui accorder le bonus le surclasserait.

    Il serait alors présenté comme aussi pertinent que le billet lui-même, alors qu'il peut
    n'être qu'une remarque en passant dans un fil consacré à tout autre chose.
    """
    billet = {"title": f"Analyse de {CVE}", "summary": "exploit et patch"}
    commentaire = {"title": f"Commentaire sur « Analyse de {CVE} »",
                   "summary": "exploit et patch", "is_comment": True}
    assert dc.score_pertinence(billet, CVE) > dc.score_pertinence(commentaire, CVE)
    # Le commentaire reste néanmoins retenu : il cite bien la vulnérabilité.
    assert dc.score_pertinence(commentaire, CVE) >= dc.SEUIL_AFFICHAGE


# ---------------------------------------------------------------------------------------
# 4. Courriel de veille — nouveautés et mises à jour ne se confondent pas
# ---------------------------------------------------------------------------------------

from app.backend.services import notifications as N     # noqa: E402


def _digest_simule():
    fiches = [
        {"cve_id": "CVE-2026-1", "severity": "critical", "cvss_score": 9.8,
         "title": "Faille critique", "is_new": True},
        {"cve_id": "CVE-2026-2", "severity": "high", "cvss_score": 7.5,
         "title": "Faille connue revue", "update_unread": True},
    ]
    return {"total": 2, "nouvelles": 1, "mises_a_jour": 1,
            "produits": [{"nom": "Mozilla Firefox", "total": 2, "critiques": 1,
                          "nouvelles": 1, "mises_a_jour": 1, "fiches": fiches}]}


def test_version_texte_distingue_nouveau_et_mise_a_jour():
    texte = N._bloc_produits(_digest_simule())
    assert "[NOUVEAU]" in texte and "[MIS À JOUR]" in texte
    assert "1 nouvelle(s)" in texte and "1 mise(s) à jour" in texte


def test_version_html_distingue_nouveau_et_mise_a_jour():
    html = N._corps_html(_digest_simule(), "Raed", "23/08/2026", 1, 1)
    assert "NOUVEAU" in html and "MIS À JOUR" in html
    assert "Mozilla Firefox" in html
    assert "CVE-2026-1" in html and "CVE-2026-2" in html


def test_html_echappe_le_contenu_collecte():
    """Le titre vient d'une source externe : il ne doit jamais être injecté brut."""
    digest = _digest_simule()
    digest["produits"][0]["fiches"][0]["title"] = '<script>alert("x")</script>'
    html = N._corps_html(digest, "Raed", "23/08/2026", 1, 1)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_courriel_vide_le_dit_clairement():
    vide = {"total": 0, "produits": [], "nouvelles": 0, "mises_a_jour": 0}
    assert "Aucune vulnérabilité nouvelle" in N._bloc_produits(vide)
    assert "Aucune vulnérabilité nouvelle" in N._corps_html(vide, "Raed", "23/08/2026", 0, 0)


def test_destinataires_supplementaires_dedoublonnes(monkeypatch):
    """Une adresse déjà titulaire d'un compte ne doit pas recevoir deux fois le même courriel."""
    from app.backend.core.config import settings
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS",
                        "supervision@exemple.fr, Supervision@Exemple.fr , ")
    assert settings.extra_recipients == ["supervision@exemple.fr"]

    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "")
    assert settings.extra_recipients == []
