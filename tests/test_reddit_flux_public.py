"""REDDIT SANS IDENTIFIANTS — repli sur le flux Atom public.

L'onglet « Discussions communautaires » affichait « Reddit — source non configurée » pour
toutes les vulnérabilités, sans exception : l'API JSON de Reddit exige OAuth et refuse
l'anonyme (403). Le consultant lisait un message d'administration au lieu des discussions.

Reddit publie EN PARALLÈLE un flux Atom (`search.rss`) ouvert et destiné à la consommation
publique. On emprunte la porte prévue pour cela — ce n'est pas un contournement de
l'authentification, mais l'usage d'une autre interface publiée, non protégée par construction.

OAuth reste la voie PRINCIPALE : le flux ne porte ni commentaires ni corps de billet. Le repli
ne s'active que faute d'identifiants.

Aucun appel réseau : le flux est simulé.
"""
import asyncio

import pytest

from app.backend.services.community import discussions as dc


FLUX = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Technical Information Security Content &amp; Discussion</title>
    <link href="https://www.reddit.com/r/netsec/"/>
    <updated>2007-05-18T00:00:00+00:00</updated>
  </entry>
  <entry>
    <title>VMware Response to CVE-2021-44228: Apache Log4j RCE</title>
    <link href="https://www.reddit.com/r/vmware/comments/rdbwqd/vmware_response/"/>
    <updated>2021-12-10T18:21:00+00:00</updated>
    <author><name>/u/analyste</name></author>
    <category label="r/vmware"/>
    <content type="html">&lt;p&gt;Avis publie par l'editeur.&lt;/p&gt;</content>
  </entry>
  <entry>
    <title>Who else is still up working on log4j - CVE-2021-44228</title>
    <link href="https://www.reddit.com/r/devops/comments/rdvhs0/who_else/"/>
    <updated>2021-12-11T03:04:00+00:00</updated>
    <category label="r/devops"/>
  </entry>
</feed>
"""


class _Reponse:
    def __init__(self, code, contenu=b""):
        self.status_code = code
        self.content = contenu


def _servir(reponses):
    """Renvoie une fonction `net.get` qui débite les réponses fournies, l'une après l'autre."""
    file = list(reponses)

    async def _get(url, headers=None, timeout=None, **_k):
        _get.appels.append({"url": url, "headers": headers or {}})
        return file.pop(0) if file else _Reponse(500)

    _get.appels = []
    return _get


@pytest.fixture(autouse=True)
def _sans_attente(monkeypatch):
    """Neutralise la temporisation entre deux tentatives : les tests ne dorment pas."""
    async def _immediat(_secondes):
        return None
    monkeypatch.setattr(dc.asyncio, "sleep", _immediat)


def test_les_sous_reddits_ne_sont_pas_des_discussions(monkeypatch):
    """Le flux mêle aux billets des COMMUNAUTÉS entières (« r/netsec »).

    Les retenir afficherait « r/cybersecurity » comme s'il s'agissait d'un échange sur la
    vulnérabilité. Seule une publication porte « /comments/ » dans son adresse.
    """
    monkeypatch.setattr(dc.net, "get", _servir([_Reponse(200, FLUX.encode())]))
    resultats = asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))

    assert len(resultats) == 2, "le sous-reddit doit être écarté"
    assert all("/comments/" in d["url"] for d in resultats)
    assert not any("Technical Information Security" in (d["title"] or "") for d in resultats)


def test_la_forme_est_identique_a_celle_des_autres_sources(monkeypatch):
    """La vérification de pertinence est COMMUNE : Reddit n'a pas sa propre règle.

    Une forme divergente obligerait à traiter Reddit à part — et c'est ainsi qu'une source
    finit par échapper aux contrôles que les autres subissent.
    """
    monkeypatch.setattr(dc.net, "get", _servir([_Reponse(200, FLUX.encode())]))
    premier = asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))[0]

    for champ in ("source", "community", "title", "url", "author", "published_at",
                  "summary", "comments"):
        assert champ in premier, f"champ « {champ} » absent : forme incompatible"
    assert premier["source"] == "Reddit"
    assert premier["community"] == "r/vmware"
    assert premier["published_at"].year == 2021
    assert premier["published_at"].tzinfo is None, "les dates sont stockées en UTC naïf"


def test_le_contenu_html_du_flux_est_nettoye(monkeypatch):
    """Le flux porte le HTML de rendu du billet : il ne doit pas atteindre l'interface."""
    monkeypatch.setattr(dc.net, "get", _servir([_Reponse(200, FLUX.encode())]))
    resume = asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))[0]["summary"]
    assert resume and "<p>" not in resume and "&lt;" not in resume


def test_une_limite_de_debit_est_reessayee_une_fois(monkeypatch):
    """Reddit répond « 429 » sans préavis ; une reprise espacée suffit en pratique."""
    servir = _servir([_Reponse(429), _Reponse(200, FLUX.encode())])
    monkeypatch.setattr(dc.net, "get", servir)

    assert len(asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))) == 2
    assert len(servir.appels) == 2


def test_un_refus_persistant_est_signale_comme_indisponible(monkeypatch):
    """« Indisponible » est un incident ; « non configurée » serait un contresens ici.

    Les confondre ferait croire qu'il manque des identifiants alors que la source a
    simplement refusé la requête.
    """
    monkeypatch.setattr(dc.net, "get", _servir([_Reponse(429), _Reponse(429)]))
    with pytest.raises(dc.SourceIndisponible, match="débit"):
        asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))


def test_un_flux_illisible_ne_fait_pas_tomber_la_recherche(monkeypatch):
    monkeypatch.setattr(dc.net, "get", _servir([_Reponse(200, b"<pas du xml")]))
    with pytest.raises(dc.SourceIndisponible):
        asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))


def test_l_agent_utilisateur_est_descriptif(monkeypatch):
    """Reddit refuse les agents génériques ; l'en-tête doit nommer l'application."""
    servir = _servir([_Reponse(200, FLUX.encode())])
    monkeypatch.setattr(dc.net, "get", servir)
    asyncio.run(dc._reddit_flux_public("CVE-2021-44228"))

    agent = servir.appels[0]["headers"].get("User-Agent", "")
    assert "cyberwatch" in agent.lower()
    assert dc._REDDIT_FLUX in servir.appels[0]["url"]


def test_oauth_reste_la_voie_principale(monkeypatch):
    """Le repli ne doit s'activer QUE faute d'identifiants.

    Le flux public ne porte ni commentaires ni corps de billet — c'est là que se trouve
    l'analyse technique. Le préférer à OAuth appauvrirait la veille sans raison.
    """
    from app.backend.services.community import reddit_oauth

    monkeypatch.setattr(reddit_oauth, "est_configure", lambda: True)
    appels = {"flux": 0}

    async def _flux(_cve):
        appels["flux"] += 1
        return []

    async def _appeler(*_a, **_k):
        return {"data": {"children": []}}

    monkeypatch.setattr(dc, "_reddit_flux_public", _flux)
    monkeypatch.setattr(reddit_oauth, "appeler", _appeler)

    asyncio.run(dc._reddit("CVE-2021-44228"))
    assert appels["flux"] == 0, "OAuth configuré : le flux public ne doit pas être sollicité"


def test_le_repli_s_active_sans_identifiants(monkeypatch):
    from app.backend.services.community import reddit_oauth

    monkeypatch.setattr(reddit_oauth, "est_configure", lambda: False)
    monkeypatch.setattr(dc.net, "get", _servir([_Reponse(200, FLUX.encode())]))

    resultats = asyncio.run(dc._reddit("CVE-2021-44228"))
    assert len(resultats) == 2, "sans OAuth, les discussions publiques restent accessibles"
