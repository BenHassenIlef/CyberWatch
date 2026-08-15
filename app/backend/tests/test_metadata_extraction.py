"""Tests de l'extraction des métadonnées (date de publication + organisation).

Trois cas réalistes, sur des échantillons HTML statiques (déterministes, sans réseau) :
  1. CERT-FR  — date en texte visible français + organisation par mapping de domaine
  2. MSRC     — date par métadonnée article:published_time + organisation par mapping
  3. NVD      — date par JSON-LD datePublished + organisation par mapping

Exécution :  python -m app.backend.tests.test_metadata_extraction
(ou via pytest si installé)
"""
from app.backend.services.verification.metadata_extraction import (
    extract_organization,
    extract_publication_date,
    normalize_date,
)

# --------------------------------------------------------------------------------------
# Échantillons HTML
# --------------------------------------------------------------------------------------

CERTFR_HTML = """
<html><head>
<title>CERTFR-2026-ALE-008 : Multiples vulnérabilités dans Microsoft SharePoint</title>
</head><body>
<h1>Multiples vulnérabilités dans Microsoft SharePoint</h1>
<p class="date">Publié le 22 juillet 2026</p>
<p>Le 14 juillet 2026, Microsoft a publié des correctifs pour deux vulnérabilités critiques
identifiées par le CERT-FR (ANSSI).</p>
</body></html>
"""
CERTFR_HOST = "www.cert.ssi.gouv.fr"

MSRC_HTML = """
<html><head>
<meta property="article:published_time" content="2026-07-22T17:00:00Z" />
<meta name="author" content="Microsoft Security Response Center" />
<title>Security Update Guide</title>
</head><body>
<h1>Multiple SharePoint vulnerabilities</h1>
<p>Published on July 22, 2026 by the Microsoft Security Response Center.</p>
</body></html>
"""
MSRC_HOST = "msrc.microsoft.com"

NVD_HTML = """
<html><head>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Report","headline":"CVE-2026-12345 Detail",
 "datePublished":"2026-07-22","publisher":{"@type":"Organization","name":"NIST National Vulnerability Database"}}
</script>
<title>NVD - CVE-2026-12345</title>
</head><body><h1>CVE-2026-12345</h1></body></html>
"""
NVD_HOST = "nvd.nist.gov"


def _check(name: str, condition: bool, detail: str = ""):
    status = "OK  " if condition else "FAIL"
    print(f"  [{status}] {name}{(' — ' + detail) if detail else ''}")
    assert condition, f"{name} a échoué. {detail}"


def test_normalize_date():
    print("normalize_date")
    _check("FR '22 juillet 2026'", normalize_date("22 juillet 2026") == "2026-07-22")
    _check("FR '22/07/2026'", normalize_date("Publication : 22/07/2026") == "2026-07-22")
    _check("EN 'July 22, 2026'", normalize_date("Published on July 22, 2026") == "2026-07-22")
    _check("ISO '2026-07-22'", normalize_date("2026-07-22T17:00:00Z") == "2026-07-22")
    _check("Invalide -> None", normalize_date("pas une date") is None)


def test_certfr():
    print("CERT-FR")
    date = extract_publication_date(CERTFR_HTML)
    _check("date détectée", date is not None and date["value"] == "2026-07-22",
           f"{date}" if date else "None")
    _check("méthode = texte visible", date["source"] == "text_extraction", date["source"])
    org = extract_organization(CERTFR_HTML, CERTFR_HOST)
    _check("organisation détectée", org is not None and org["value"] == "CERT-FR / ANSSI",
           f"{org}" if org else "None")
    _check("méthode = domain_mapping", org["source"] == "domain_mapping", org["source"])
    _check("confiance >= 0.9", org["confidence"] >= 0.9, str(org["confidence"]))


def test_msrc():
    print("Microsoft MSRC")
    date = extract_publication_date(MSRC_HTML)
    _check("date détectée", date is not None and date["value"] == "2026-07-22",
           f"{date}" if date else "None")
    _check("méthode = html_metadata", date["source"] == "html_metadata", date["source"])
    org = extract_organization(MSRC_HTML, MSRC_HOST)
    _check("organisation détectée", org is not None and org["value"] == "Microsoft Security Response Center",
           f"{org}" if org else "None")
    _check("méthode = domain_mapping", org["source"] == "domain_mapping", org["source"])


def test_nvd():
    print("NVD")
    date = extract_publication_date(NVD_HTML)
    _check("date détectée", date is not None and date["value"] == "2026-07-22",
           f"{date}" if date else "None")
    _check("méthode = json_ld", date["source"] == "json_ld", date["source"])
    org = extract_organization(NVD_HTML, NVD_HOST)
    _check("organisation détectée", org is not None and org["value"] == "NIST National Vulnerability Database",
           f"{org}" if org else "None")
    _check("méthode = domain_mapping", org["source"] == "domain_mapping", org["source"])


if __name__ == "__main__":
    for fn in (test_normalize_date, test_certfr, test_msrc, test_nvd):
        fn()
    print("\nTous les tests sont passés ✅")
