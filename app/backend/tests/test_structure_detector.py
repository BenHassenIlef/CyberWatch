"""Tests du détecteur de structure GÉNÉRIQUE (Phase 1).

Déterministes, sans réseau : on utilise un hôte INVENTÉ (cert.example.org) — jamais ANCS ni
DGSSI — pour prouver que la détection « liste → détail » ne dépend d'aucun site codé en dur.

Exécution :  python -m app.backend.tests.test_structure_detector
"""
import asyncio

from app.backend.services.collection import structure_detector as sd

_fails = []


def _check(label, cond, got=""):
    status = "OK " if cond else "ÉCHEC"
    if not cond:
        _fails.append(label)
    print(f"  [{status}] {label}" + (f"  (obtenu: {got})" if got else ""))


HOST = "cert.example.org"
BASE = "https://cert.example.org/fr/bulletins?page=0"

# Page LISTE d'un CERT fictif : aucun CVE, plusieurs liens de détail + « Lire la suite » + pagination.
LISTING_HTML = """
<html><body>
<nav><a href="/fr/contact">Contact</a><a href="/fr/recherche">Recherche</a></nav>
<ul class="bulletins">
  <li><a href="/fr/bulletins/vulnerabilite-apache-2026">Vulnérabilité critique Apache</a>
      <a href="/fr/bulletins/vulnerabilite-apache-2026">Lire la suite</a></li>
  <li><a href="/fr/bulletins/faille-openssl-2026">Faille OpenSSL</a></li>
  <li><a href="/fr/bulletins/mise-a-jour-mozilla-2026">Mise à jour Mozilla</a></li>
  <li><a href="/fr/bulletins/avis-cisco-2026">Avis Cisco</a></li>
</ul>
<a href="https://twitter.com/cert">Twitter</a>
<div class="pager"><a href="?page=1">Suivant</a><a href="?page=2">2</a></div>
</body></html>
"""

# Page DÉTAIL correspondante : contient des CVE (la « preuve »).
DETAIL_HTML = """
<html><body><article>
<h1>Vulnérabilité critique Apache</h1>
<p>Identifiants externes : CVE-2026-1111 ; CVE-2026-2222 ; CVE-2026-3333</p>
</article></body></html>
"""

# Page LISTE qui expose DÉJÀ les CVE (collecte simple niveau 1, PAS un portail deux niveaux).
FLAT_LIST_HTML = """
<html><body>
<table>
<tr><td>CVE-2026-4444</td><td>Apache</td></tr>
<tr><td>CVE-2026-5555</td><td>Nginx</td></tr>
<tr><td>CVE-2026-6666</td><td>PHP</td></tr>
</table>
</body></html>
"""

# Page ordinaire (blog) : peu de liens de détail, pas de CVE -> pas un portail.
BLOG_HTML = """
<html><body>
<a href="/fr/apropos">À propos</a>
<a href="/fr/article/bonnes-pratiques">Bonnes pratiques de sécurité</a>
</body></html>
"""


def test_candidate_links():
    print("candidate_links (générique, host inventé)")
    links = sd.candidate_links(LISTING_HTML, BASE, HOST)
    _check("4 liens de bulletin détectés", len(links) == 4, str(len(links)))
    _check("lien via motif de chemin", "https://cert.example.org/fr/bulletins/faille-openssl-2026" in links)
    _check("liens externes exclus (twitter)", all("twitter" not in u for u in links))
    _check("navigation exclue (contact/recherche)", all("/contact" not in u and "/recherche" not in u for u in links))
    _check("pagination exclue des liens", all("page=" not in u for u in links))


def test_pagination_and_cve_count():
    print("pagination + count_cves")
    _check("pagination détectée", sd.has_pagination(LISTING_HTML, BASE) is True)
    _check("0 CVE sur la page liste", sd.count_cves(LISTING_HTML) == 0, str(sd.count_cves(LISTING_HTML)))
    _check("3 CVE distinctes sur le détail", sd.count_cves(DETAIL_HTML) == 3, str(sd.count_cves(DETAIL_HTML)))


async def _detect(body, fetch_child):
    return await sd.detect_two_level(body, BASE, HOST, fetch_child)


def test_two_level_confirmed():
    print("detect_two_level : portail confirmé par échantillon enfant")
    async def fetch_child(_url):
        return DETAIL_HTML
    rep = asyncio.run(_detect(LISTING_HTML, fetch_child))
    _check("is_two_level = True", rep["is_two_level"] is True, str(rep["is_two_level"]))
    _check("confiance élevée", rep["confidence"] == "high", rep["confidence"])
    _check("échantillon a vu des CVE", rep["sample_cves"] >= 3, str(rep["sample_cves"]))


def test_flat_list_not_portal():
    print("detect_two_level : liste plate (CVE déjà présentes) -> niveau 1")
    async def fetch_child(_url):
        raise AssertionError("ne doit PAS échantillonner une liste qui contient déjà des CVE")
    rep = asyncio.run(_detect(FLAT_LIST_HTML, fetch_child))
    _check("is_two_level = False", rep["is_two_level"] is False, str(rep["is_two_level"]))
    _check("aucun échantillonnage", rep["sampled"] == 0, str(rep["sampled"]))


def test_blog_not_portal():
    print("detect_two_level : page ordinaire -> pas un portail")
    async def fetch_child(_url):
        return "<html><body>pas de CVE ici</body></html>"
    rep = asyncio.run(_detect(BLOG_HTML, fetch_child))
    _check("is_two_level = False", rep["is_two_level"] is False, str(rep["is_two_level"]))


if __name__ == "__main__":
    for fn in (test_candidate_links, test_pagination_and_cve_count,
               test_two_level_confirmed, test_flat_list_not_portal, test_blog_not_portal):
        fn()
    if _fails:
        print(f"\n{len(_fails)} test(s) en échec ❌ : {_fails}")
        raise SystemExit(1)
    print("\nTous les tests sont passés ✅")
