"""ASSAINISSEMENT des valeurs extraites — filtre unique, appliqué à TOUS les collecteurs.

Problème résolu : l'extraction mordait sur le gabarit des pages au lieu du contenu de la
vulnérabilité. On trouvait en base des descriptions contenant du CSS
(« @media screen and (max-width:640px) ») et des produits valant le titre de la page
(« CVE-2025-24293 - Overview, Insights & Trends »).

RÈGLE : en cas de doute, on renvoie None. Une valeur absente est toujours préférable à une
valeur fausse — le champ affichera « Non disponible » et l'enrichissement par identifiant
pourra le renseigner correctement.

Ce module est la SOURCE UNIQUE de vérité sur « cette valeur est-elle exploitable ». Tous les
collecteurs et le parser générique l'appellent ; aucune règle n'est dupliquée ailleurs.
"""
import re
from urllib.parse import urlparse

from app.backend.services.collection.schema import CVE_RE

# Marqueurs de CODE (CSS, JavaScript, JSON-LD) : gabarit de page, jamais du contenu d'avis.
# Détection par sous-chaînes littérales : plus lisible et plus sûr qu'une regex à échappements.
_CODE_MARKERS = ("@media", ":root{", "<style", "<script", "NREUM", "<!--",
                 '"@context"', "function(", "function (", "px){", "display:none",
                 "max-width:", "font-family:", "background-color:")

# Page NON RENDUE, erreur HTTP, ou protection anti-robot.
_JUNK_MARKERS = ("you are being redirected", "potential security issue",
                 "enable javascript", "javascript is disabled", "access denied",
                 "just a moment", "checking your browser", "attention required",
                 "activez le javascript", "403 forbidden", "404 not found")

# Habillage de site : navigation, bandeaux, pieds de page.
# NB : les marqueurs doivent etre des EXPRESSIONS, pas des mots isoles. « cookie » seul
# rejetait « does not sign or verify its guest-session cookie » — une description de faille
# parfaitement valable. Un terme technique courant ne peut pas servir de marqueur d habillage.
_BOILERPLATE_MARKERS = ("cookie policy", "cookie consent", "accept cookies",
                        "utilisation des cookies", "politique de cookies",
                        "newsletter", "sign in", "log in", "subscribe",
                        "all rights reserved", "privacy policy", "terms of use",
                        "terms of service", "menu principal", "mentions legales",
                        # Libelles de NAVIGATION releves sur des portails reels. Un bulletin
                        # a presente « BY COMPANY SIZE Enterprises Small and medium teams »
                        # comme la remediation a appliquer : c est le menu du site.
                        "by company size", "small and medium teams", "book a demo",
                        "sign up", "pricing", "skip to content", "skip to main content",
                        "quick links", "suggested searches", "aller au contenu",
                        "back to top", "choose your language", "select region")

# Titre de RUBRIQUE d'un portail de veille, pris à tort pour un produit.
_PORTAL_TITLE_RE = re.compile(
    r"(overview|insights|trends|newest|latest|trending)\b.{0,40}\b(cves?|vulnerabilit)|"
    r"\b(cves?|vulnerabilit)\w*\b.{0,40}\b(overview|insights|trends)", re.I)


def _contient(texte: str, marqueurs) -> bool:
    """Compare EN MINUSCULES des deux côtés.

    Le texte seul était abaissé : un marqueur écrit en capitales (« NREUM », la sonde
    JavaScript de New Relic) ne pouvait donc jamais correspondre. Le garde-fou existait
    mais ne se déclenchait pas, et le script injecté par un portail se retrouvait présenté
    comme la description d'une vulnérabilité.
    """
    bas = texte.lower()
    return any(m.lower() in bas for m in marqueurs)


# Balises HTML d'un texte d'avis. MITRE encadre ses descriptions de « <p>…</p> » : on les
# RETIRE plutôt que de rejeter le texte, sinon on perdrait une description parfaitement
# valable pour un simple défaut de présentation.
# Une VRAIE balise commence par une lettre, une barre oblique ou un point d exclamation.
# Sans cette exigence, « extension < 2.4.1 - The Joomla extension ... » etait pris pour une
# balise et une description parfaitement valable se retrouvait mutilee : dans ces textes,
# « < » est un operateur de comparaison de version, pas du balisage.
_BALISE_RE = re.compile(r"<[a-zA-Z/!][^>]{0,80}>")
# Entites NUMERIQUES de presentation (tiret cadratin, apostrophe typographique...). Les
# codes correspondant a  <  >  &  "  sont exclus : comme leurs equivalents nommes, ils
# peuvent porter un payload documente.
_ENTITE_NUM_RE = re.compile(r"&#(x?[0-9a-fA-F]+);")
_CODES_RESERVES = {34, 38, 60, 62}
# Entités de PRÉSENTATION uniquement. « &lt; », « &gt; » et « &amp; » sont délibérément
# absents : dans une description de faille XSS, ils portent le payload documenté
# (« decode-after-sanitize of &lt;script&gt; »). Les décoder changerait le sens technique du
# texte — et sur une vulnérabilité de double décodage, ce serait un contresens.
_ENTITES = (("&nbsp;", " "), ("&#39;", "'"), ("&apos;", "'"))


def sans_balises(texte: str) -> str:
    """Texte débarrassé de ses balises et entités HTML, espaces normalisés."""
    sortie = _BALISE_RE.sub(" ", texte or "")
    for entite, reel in _ENTITES:
        sortie = sortie.replace(entite, reel)

    def _numerique(m):
        brut = m.group(1)
        try:
            code = int(brut[1:], 16) if brut[:1].lower() == "x" else int(brut)
            if code in _CODES_RESERVES:
                return m.group(0)          # balisage encode : c est du contenu
            return chr(code) if 32 <= code <= 0x10FFFF else " "
        except (ValueError, OverflowError):
            return m.group(0)

    sortie = _ENTITE_NUM_RE.sub(_numerique, sortie)
    return re.sub(r"\s+", " ", sortie).strip()


MIN_DESCRIPTION = 40      # sous ce seuil, un texte ne décrit pas une vulnérabilité
MAX_PRODUCT = 160


def _est_code(brut, propre) -> bool:
    """Marqueurs de code cherches sur le texte BRUT **et** sur le texte nettoye.

    Le retrait des balises efface la preuve : « <script>var x=1;</script> » devient
    « var x=1; », ou le marqueur « <script » ne figure plus. Interroger les deux etats
    garantit qu un gabarit de page ne franchit pas le filtre en perdant ses chevrons.
    """
    return _contient(brut, _CODE_MARKERS) or _contient(propre, _CODE_MARKERS)


def _base(value):
    """Valeur textuelle normalisee : balises HTML retirees, espaces compactes, ou None.

    Le retrait des balises a lieu ICI, au seuil de tous les nettoyages : une description
    encadree de « <p>…</p> » s affichait telle quelle dans la fiche et le bulletin.
    """
    if not isinstance(value, str):
        return None
    nettoye = sans_balises(value) if '<' in value or '&' in value else value.strip()
    return nettoye or None


def clean_description(value):
    """Description EXPLOITABLE, ou None. Rejette code, erreurs HTTP et habillage de site."""
    s = _base(value)
    if s is None or len(s) < MIN_DESCRIPTION:
        return None
    if _est_code(str(value), s) or _contient(s, _JUNK_MARKERS):
        return None
    # Habillage : toléré s'il n'occupe qu'une part marginale d'un texte par ailleurs long.
    if _contient(s, _BOILERPLATE_MARKERS) and len(s) < 200:
        return None
    return s


def clean_product(value):
    """Nom de produit EXPLOITABLE, ou None.

    Un produit ne contient jamais d'identifiant CVE et n'est pas un titre de rubrique.
    """
    s = _base(value)
    if s is None or len(s) > MAX_PRODUCT:
        return None
    if CVE_RE.search(s):
        return None
    if _est_code(str(value), s) or _contient(s, _JUNK_MARKERS):
        return None
    if _PORTAL_TITLE_RE.search(s):
        return None
    return s


def clean_vendor(value):
    """Éditeur EXPLOITABLE, ou None. Mêmes garde-fous que le produit."""
    return clean_product(value)


# Part maximale qu un SEUL mot peut occuper dans un texte avant de trahir un menu.
# « Services Support Back Support Support Home Support Library » : « Support » y pese la
# moitie des mots. Une remediation redigee ne se repete pas ainsi. Le seuil est volontairement
# haut : « Update Windows Update service and Windows Update agent » (37 %) reste accepte.
PART_MOT_REPETE = 0.40
MOTS_MIN_POUR_JUGER = 8


def _semble_menu(texte: str) -> bool:
    """Vrai si un mot revient si souvent que le texte est une liste de liens, pas une phrase."""
    mots = [m for m in re.findall(r"[\w'-]+", texte.lower()) if len(m) > 2]
    if len(mots) < MOTS_MIN_POUR_JUGER:
        return False
    plus_frequent = max(mots.count(m) for m in set(mots))
    return plus_frequent / len(mots) >= PART_MOT_REPETE


def clean_text(value, min_len: int = 12):
    """Texte court (impact, solution, versions) : rejette code et habillage.

    L habillage est controle ICI AUSSI. Il ne l etait que pour les descriptions : un menu de
    navigation pouvait donc s afficher dans « Solution », c est-a-dire a l endroit exact ou
    un consultant lit ce qu il doit appliquer sur un systeme reel.
    """
    s = _base(value)
    if s is None or len(s) < min_len:
        return None
    if _est_code(str(value), s) or _contient(s, _JUNK_MARKERS):
        return None
    if _contient(s, _BOILERPLATE_MARKERS) or _semble_menu(s):
        return None
    return s


def clean_record(rec: dict) -> dict:
    """Assainit EN PLACE les champs textuels d'un enregistrement collecté.

    Appelé par tous les collecteurs : une valeur douteuse devient None plutôt que d'entrer
    en base. Renvoie le compte des champs écartés, par champ (traçabilité).
    """
    ecartes = {}
    for champ, nettoyeur in (("description", clean_description),
                             ("product", clean_product),
                             ("vendor", clean_vendor),
                             ("impact", clean_text),
                             ("solution", clean_text),
                             ("affected_versions", clean_text),
                             ("fixed_version", clean_text)):
        avant = rec.get(champ)
        if avant in (None, "", []):
            continue
        apres = nettoyeur(avant)
        if apres is None:
            rec[champ] = None
            ecartes[champ] = str(avant)[:60]

    # RÉFÉRENCES : l'habillage de page est écarté DÈS LA COLLECTE.
    #
    # Il ne l'était qu'à la construction du bulletin : les liens de polices, de partage et
    # d'abonnement entraient donc en base et devaient être nettoyés après coup, collecte
    # après collecte. Les filtrer ici tarit la source — et tout consommateur des références,
    # présent ou futur, en bénéficie sans le savoir.
    for champ in ("references", "patch_links"):
        liens = rec.get(champ)
        if not isinstance(liens, list) or not liens:
            continue
        propres = [u for u in liens if not est_habillage(u)]
        if len(propres) != len(liens):
            ecartes[champ] = f"{len(liens) - len(propres)} lien(s) d'habillage"
            rec[champ] = propres
    return ecartes


# Liens d'HABILLAGE d'une page web : polices, feuilles de style, réseaux d'affiliation,
# boutons de partage, profils de site. Ils n'ont aucune valeur documentaire et polluaient la
# section « Références » du bulletin dès que la page de collecte était un blog — on y voyait
# « fonts.googleapis.com », « reddit.com/submit?url=… » ou un lien d'affiliation marchand
# au milieu des avis éditeur.
_HABILLAGE_HOTES = (
    "fonts.googleapis.com", "fonts.gstatic.com", "gmpg.org", "w3.org", "schema.org",
    "gravatar.com", "googletagmanager.com", "google-analytics.com", "doubleclick.net",
    "aliexpress.com", "amazon-adsystem.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "bootstrapcdn.com", "polyfill.io",
    # Services d abonnement aux lettres d information des organismes publics : le lien
    # « s inscrire » figure sur chaque page de portail et ne documente aucune faille.
    "govdelivery.com", "list-manage.com", "mailchi.mp",
)
_HABILLAGE_CHEMINS = re.compile(
    r"/(submit|share|sharer|intent/tweet|shareArticle|feed|rss|wp-json|"
    r"wp-content|wp-includes|xmlrpc\.php|tag|category|author)(/|$)", re.I)

# Espaces communautaires ou profils SANS contenu propre : la racine d'un sous-forum, un compte
# de réseau social. Une DISCUSSION précise y reste admise — c'est la matière de la veille
# communautaire — mais la page d'accueil d'une communauté ne documente aucune vulnérabilité.
_SOCIAL_HOTES = ("reddit.com", "twitter.com", "x.com", "facebook.com", "linkedin.com",
                 "t.me", "mastodon.social", "bsky.app", "instagram.com", "youtube.com")
_DISCUSSION_RE = re.compile(r"/(comments|status|posts?|threads?)/", re.I)


def est_habillage(url: str) -> bool:
    """Vrai si l'URL relève de la mise en page du site, non de la documentation de la faille."""
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return True
    try:
        parts = urlparse(url)
    except ValueError:
        return True
    host, chemin = (parts.netloc or "").lower(), parts.path or "/"
    if not host:
        return True
    if any(host == h or host.endswith("." + h) for h in _HABILLAGE_HOTES):
        return True
    if any(host == h or host.endswith("." + h) for h in _SOCIAL_HOTES):
        # Seule une discussion identifiée est conservée ; profils et racines sont écartés.
        return not _DISCUSSION_RE.search(chemin)
    # RACINE D'UN SITE : une page d'accueil ne documente aucune vulnérabilité. Elle
    # apparaissait pourtant parmi les références (« https://www.yootheme.com/ »,
    # « https://www.nist.gov ») et, notée comme domaine éditeur, pouvait même être retenue
    # comme « source officielle » de la faille — un lien vers un site vitrine.
    if chemin.strip("/") == "" and not parts.query:
        return True
    return bool(_HABILLAGE_CHEMINS.search(chemin))
