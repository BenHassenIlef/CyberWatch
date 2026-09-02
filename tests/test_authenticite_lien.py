"""AUTHENTICITÉ DU LIEN — détection d'une adresse contrefaite (niveau 3).

Les niveaux 1 et 2 répondent à « le site répond-il ? » et « son contenu est-il crédible ? ».
Une contrefaçon soigne précisément ces deux points : elle répond en HTTPS et publie des CVE
d'apparence valide. Ces tests verrouillent la question qui précède les deux autres — **cette
adresse est-elle bien celle qu'elle prétend être ?** — et, tout aussi important, le fait que
les sources RÉELLES du projet ne soient jamais accusées à tort.

Aucun appel réseau : l'annuaire RDAP est neutralisé, les contrôles restants sont hors ligne.
"""
import pytest

from app.backend.services.verification import authenticity as auth


@pytest.fixture(autouse=True)
def _sans_rdap(monkeypatch):
    """Neutralise l'appel RDAP : les tests portent sur les contrôles hors ligne."""
    async def _indetermine(host):
        return None
    monkeypatch.setattr(auth, "age_du_domaine", _indetermine)


# --------------------------------------------------------------------------------------
# Ce qui DOIT être détecté
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("url, procede", [
    ("https://micros0ft.com/security",      "chiffre substitué à une lettre"),
    ("https://nvd-nist.com/vuln",           "tiret substitué au point"),
    ("https://nist-gov.net/advisories",     "nom officiel + suffixe en label"),
    ("https://cisa-gov.xyz/kev",            "nom officiel + extension à risque"),
    ("https://xn--ciscoo-9va.com/advisory", "homographe encodé en punycode"),
])
async def test_usurpation_caracterisee(url, procede):
    """Un procédé d'imitation identifié doit produire un verdict d'usurpation, pas une nuance."""
    r = await auth.verifier_authenticite(url)
    assert r["usurpation"] is True, f"{procede} non détecté sur {url}"
    assert r["alertes"], "une usurpation doit être motivée par au moins une alerte"


@pytest.mark.asyncio
@pytest.mark.parametrize("url, attendu", [
    ("https://203.0.113.24/avis",              "IP nue"),
    ("https://bit.ly/3xYz",                    "raccourcisseur"),
    ("https://cert-fr.blogspot.com/",          "hébergement gratuit + autorité"),
    ("http://example.org/avis",                "HTTP en clair"),
    ("https://securite-advisory.tk/",          "extension à risque"),
])
async def test_signaux_faibles_alertent_sans_accuser(url, attendu):
    """Un indice isolé ABAISSE le score et alerte — il n'accuse pas.

    Un domaine récent, une extension inhabituelle ou un lien raccourci peuvent être
    parfaitement légitimes. Conclure à la fraude sur ce seul fondement produirait des refus
    injustifiés, et un outil qui crie au loup finit ignoré.
    """
    r = await auth.verifier_authenticite(url)
    assert r["alertes"], f"{attendu} devrait produire une alerte"
    assert r["usurpation"] is False, f"{attendu} ne suffit pas à caractériser une usurpation"
    assert r["score"] < 100


@pytest.mark.asyncio
async def test_redirection_vers_un_autre_domaine():
    """L'adresse affichée doit mener où elle l'annonce."""
    class _Reponse:
        final_url = "https://collecte-cve.example.net/page"

    r = await auth.verifier_authenticite("https://avis-securite.example.org/", _Reponse())
    assert any("redirige" in a for a in r["alertes"])


@pytest.mark.asyncio
async def test_url_illisible_est_rejetee():
    r = await auth.verifier_authenticite("pas une url")
    assert r["usurpation"] is True and r["score"] == 0


# --------------------------------------------------------------------------------------
# Ce qui NE DOIT JAMAIS être accusé — le risque symétrique
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "https://nvd.nist.gov/vuln",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",   # sous-domaine légitime
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://www.cert.ssi.gouv.fr/avis/",
    "https://www.csa.gov.sg/alerts-and-advisories",       # CSA Singapour, voisin de « cisa »
    "https://dgssi.gov.ma/fr/bulletins/",
    "https://www.ancs.tn/fr/vulnerabilites",
    "https://msrc.microsoft.com/update-guide/vulnerability",
    "https://www.cve.org/",
    "https://app.opencve.io/cve/",
    "https://www.tenable.com/cve",
    "https://secalerts.co/sitemap.xml",
])
async def test_sources_legitimes_jamais_accusees(url):
    """Aucune source réelle du projet ne doit être qualifiée de contrefaçon.

    Le faux positif est ici plus coûteux que le faux négatif : il retire de la veille une
    source officielle valide. Le cas « csa.gov.sg » contre « cisa.gov » est explicite —
    deux agences nationales authentiques dont les acronymes ne diffèrent que d'une lettre.
    """
    r = await auth.verifier_authenticite(url)
    assert r["usurpation"] is False, f"{url} accusé à tort : {r['alertes']}"


def test_extraction_du_nom_ignore_les_etiquettes_structurelles():
    """« gov », « gouv », « com » nomment une structure, pas une organisation.

    Sans cette distinction, « csa.gov.sg » se réduisait à « gov » et « cert.ssi.gouv.fr » à
    « ssi » : la comparaison « gov » / « gouv » ne diffère que d'une lettre, et l'agence
    singapourienne se voyait accusée d'imiter le CERT français.
    """
    assert auth._sans_tld("csa.gov.sg") == "csa"
    assert auth._sans_tld("cert.ssi.gouv.fr") == "ssi"
    assert auth._sans_tld("nvd.nist.gov") == "nist"
    assert auth._sans_tld("www.thehackerwire.com") == "thehackerwire"


def test_domaine_gouvernemental_hors_de_portee_du_typosquattage():
    """On ne dépose pas « .gov.sg » ni « .gouv.fr » : le registre exige une éligibilité."""
    assert auth.detecter_typosquattage("csa.gov.sg") is None
    assert auth.detecter_typosquattage("anssi.gouv.fr") is None
    # Hors suffixe étatique, la même imitation est bien relevée.
    assert auth.detecter_typosquattage("cisa-gov.xyz") is not None


def test_distance_edition():
    assert auth.distance("microsoft", "micros0ft") == 1
    assert auth.distance("nist", "nist") == 0
    assert auth.distance("cve", "nvd") == 2       # le « v » est commun
    assert auth.distance("csa", "cisa") == 1      # insertion : voisinage réel, pas fraude


def test_reduction_au_domaine_enregistrable():
    """RDAP n'indexe que les domaines DÉPOSÉS, jamais les sous-domaines.

    Interroger « www.thehackerwire.com » ne renvoie rien alors que « thehackerwire.com »
    répond : sans cette réduction, le contrôle d'ancienneté restait toujours « indéterminé »
    et ne servait à rien. Les suffixes composés doivent survivre à la réduction — « csa.gov.sg »
    se dépose sous « gov.sg », pas sous « sg ».
    """
    assert auth.domaine_enregistrable("www.thehackerwire.com") == "thehackerwire.com"
    assert auth.domaine_enregistrable("services.nvd.nist.gov") == "nist.gov"
    assert auth.domaine_enregistrable("www.csa.gov.sg") == "csa.gov.sg"
    assert auth.domaine_enregistrable("www.cert.ssi.gouv.fr") == "ssi.gouv.fr"
    assert auth.domaine_enregistrable("nist.gov") == "nist.gov"
