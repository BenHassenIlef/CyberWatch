"""AUTHENTICITÉ D'UN LIEN — détecte une adresse contrefaite, usurpée ou trompeuse.

Les deux niveaux existants répondent à « le site répond-il ? » et « est-il crédible ? ». Ils
ne répondent pas à la question qui précède les deux autres : **cette adresse est-elle bien
celle qu'elle prétend être ?**

Un flux de veille alimente des décisions de sécurité. Une source contrefaite y injecterait des
vulnérabilités inventées, des correctifs frauduleux, des liens de téléchargement piégés — avec
l'autorité que lui confère sa présence dans l'outil. Les contrôles ci-dessous visent donc les
procédés connus d'usurpation :

  • TYPOSQUATTAGE     « nvd-nist.gov », « micros0ft.com » : une lettre change, l'œil ne voit rien
  • HOMOGRAPHE        caractères non latins encodés en punycode (« xn--… »)
  • REDIRECTION       l'adresse affichée mène ailleurs qu'annoncé
  • ADRESSE IP        un organisme officiel ne publie pas ses avis sur une IP nue
  • DOMAINE RÉCENT    une « autorité de sécurité » créée il y a trois semaines
  • TLS               certificat absent, expiré, ou délivré pour un autre nom
  • HÉBERGEMENT       sous-domaine gratuit se présentant comme un organisme officiel

AUCUN VERDICT AUTOMATIQUE DE FRAUDE. Ces signaux sont des ALERTES : un domaine récent peut
être légitime, un TLD inhabituel aussi. On les expose au consultant, on les pondère, et on
refuse la source seulement lorsque l'usurpation est caractérisée — un typosquattage avéré,
par exemple, qui ne s'explique pas autrement.
"""
import logging
import re
from urllib.parse import urlparse

from app.backend.services.verification.domains import OFFICIAL_DOMAINS, _is_gov_domain

logger = logging.getLogger("cyberwatch.verification.authenticity")

# Extensions surreprésentées dans les campagnes d'usurpation, gratuites ou à bas coût.
TLD_A_RISQUE = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".link",
                ".work", ".loan", ".zip", ".mov", ".rest", ".fit"}

# Hébergements gratuits : légitimes en soi, mais un organisme officiel n'y publie pas ses avis.
HEBERGEMENTS_GRATUITS = ("blogspot.", "wordpress.com", "wixsite.com", "weebly.com",
                         "000webhost", "github.io", "netlify.app", "vercel.app",
                         "herokuapp.com", "glitch.me", "repl.co", "pages.dev")

# Raccourcisseurs : ils masquent la destination réelle, ce qui est disqualifiant pour une
# source de veille — on doit pouvoir vérifier où l'on va AVANT d'y aller.
RACCOURCISSEURS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
                   "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy")

# Mots par lesquels un site se réclame d'une autorité. Combinés à un hébergement gratuit ou
# à un domaine très récent, ils signalent une usurpation d'identité institutionnelle.
MOTS_D_AUTORITE = ("cert", "cve", "nvd", "nist", "cisa", "security-advisory", "advisory",
                   "gov", "official")

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
JOURS_DOMAINE_RECENT = 180


def _hote(url: str | None) -> str:
    return (urlparse(url or "").hostname or "").lower().strip(".")


def distance(a: str, b: str) -> int:
    """Distance d'édition (Levenshtein). Implémentation directe : les noms sont courts."""
    if a == b:
        return 0
    precedente = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        courante = [i]
        for j, cb in enumerate(b, 1):
            courante.append(min(precedente[j] + 1, courante[j - 1] + 1,
                                precedente[j - 1] + (ca != cb)))
        precedente = courante
    return precedente[-1]


# Étiquettes STRUCTURELLES d'un nom de domaine : elles ne désignent pas une organisation.
# Sans cette liste, « csa.gov.sg » se réduisait à « gov » et « cert.ssi.gouv.fr » à « ssi » ;
# la comparaison « gov » / « gouv » ne diffère que d'une lettre, et l'agence nationale de
# cybersécurité de Singapour se voyait accusée d'imiter le CERT français.
_ETIQUETTES_GENERIQUES = {"gov", "gouv", "com", "org", "net", "edu", "ac", "co", "go",
                          "gob", "mil", "int", "info", "biz", "www"}


def _sans_tld(domaine: str) -> str:
    """Étiquette qui NOMME l'organisation, en ignorant les étiquettes structurelles.

    « csa.gov.sg » -> « csa », « cert.ssi.gouv.fr » -> « ssi », « nvd.nist.gov » -> « nist ».
    On remonte depuis la droite jusqu'à trouver un nom propre.
    """
    for morceau in reversed(domaine.split(".")[:-1]):   # on saute l'extension finale
        if morceau and morceau not in _ETIQUETTES_GENERIQUES:
            return morceau
    return domaine


def detecter_typosquattage(host: str) -> dict | None:
    """Domaine ressemblant à s'y méprendre à une source officielle, sans en être une.

    C'est le procédé le plus efficace contre un œil humain : « nvd-nist.gov » ou
    « micros0ft.com » se lisent comme l'original. La comparaison porte sur le nom SANS son
    extension, pour attraper aussi « cisa.gov.co » et « nist-gov.net ».
    """
    if not host or host in OFFICIAL_DOMAINS:
        return None
    for officiel in OFFICIAL_DOMAINS:
        if host == officiel or host.endswith("." + officiel):
            return None            # sous-domaine légitime d'une source officielle

    # DOMAINE GOUVERNEMENTAL : hors de portée du typosquattage. On ne dépose pas « .gov.sg »
    # ni « .gouv.fr » : l'enregistrement suppose une éligibilité étatique vérifiée par le
    # registre. Sans cette exemption, deux agences nationales bien réelles aux acronymes
    # voisins s'accusent mutuellement - « csa.gov.sg » (Singapour) contre « cisa.gov ».
    # L'usurpation réaliste se joue ailleurs : « cisa-gov.xyz », « nvd-nist.com ».
    if _is_gov_domain(host):
        return None

    nom = _sans_tld(host)
    for officiel in OFFICIAL_DOMAINS:
        cible = _sans_tld(officiel)
        if len(cible) < 4:
            continue
        d = distance(nom, cible)
        # 1 caractère d'écart sur un nom court, 2 sur un nom long : au-delà, ce n'est plus
        # une ressemblance mais deux mots différents.
        if d and d <= (1 if len(cible) <= 6 else 2):
            return {"imite": officiel, "distance": d}
        # Le nom officiel INCLUS dans un domaine tiers : « nvd-nist-gov.example.com ».
        if cible in nom and nom != cible:
            return {"imite": officiel, "distance": 0}
    return None


# Suffixes en DEUX étiquettes : « csa.gov.sg » s'enregistre sous « gov.sg », pas sous « sg ».
_SUFFIXES_COMPOSES = (
    "gov.sg", "gov.uk", "co.uk", "org.uk", "ac.uk", "gouv.fr", "com.au", "gov.au",
    "net.au", "org.au", "co.jp", "go.jp", "co.kr", "go.kr", "gov.in", "co.in",
    "com.br", "gov.br", "gov.za", "co.za", "gov.ma", "gov.tn", "com.tr", "gov.tr",
    "gov.it", "gob.es", "com.cn", "gov.cn", "co.nz", "govt.nz", "gc.ca",
)


def domaine_enregistrable(host: str) -> str:
    """Réduit un hôte au domaine réellement déposé auprès d'un registre.

    RDAP n'indexe QUE les domaines enregistrés : interroger « www.thehackerwire.com » ne
    renvoie rien, alors que « thehackerwire.com » répond. Sans cette réduction, le contrôle
    d'ancienneté restait systématiquement « indéterminé » et ne servait à rien.
    """
    etiquettes = [e for e in host.split(".") if e]
    if len(etiquettes) <= 2:
        return host
    if ".".join(etiquettes[-2:]) in _SUFFIXES_COMPOSES:
        return ".".join(etiquettes[-3:])
    return ".".join(etiquettes[-2:])


async def age_du_domaine(host: str) -> int | None:
    """Âge du domaine en jours, via RDAP (annuaire public). None si indéterminable.

    Un organisme de sécurité existant depuis des années a un domaine ancien. Un domaine créé
    il y a trois semaines qui se présente comme un CERT mérite au minimum un examen humain.
    """
    from app.backend.services.collection import net

    try:
        resp = await net.get(f"https://rdap.org/domain/{domaine_enregistrable(host)}", timeout=10)
        if resp is None or resp.status_code != 200:
            return None
        for evenement in resp.json().get("events") or []:
            if evenement.get("eventAction") == "registration":
                from datetime import datetime, timezone
                creation = datetime.fromisoformat(
                    str(evenement["eventDate"]).replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - creation).days
    except Exception as exc:  # noqa: BLE001 - annuaire indisponible : on ne conclut pas
        logger.info("RDAP indisponible pour %s : %s", host, str(exc)[:100])
    return None


async def verifier_authenticite(url: str, fetched=None) -> dict:
    """Contrôles d'authenticité du lien. Renvoie {checks, score, alertes, usurpation}.

    `usurpation` est réservé aux cas CARACTÉRISÉS — typosquattage avéré, punycode. Un simple
    faisceau d'indices ne suffit pas à accuser : il alimente le score et la liste d'alertes.
    """
    host = _hote(url)
    checks: list[dict] = []
    alertes: list[str] = []
    usurpation = False

    def noter(nom: str, ok: bool, detail: str = "", grave: bool = False):
        checks.append({"label": nom, "passed": ok, "detail": detail})
        if not ok:
            alertes.append(detail or nom)
            if grave:
                nonlocal_usurpation()

    def nonlocal_usurpation():
        nonlocal usurpation
        usurpation = True

    if not host:
        return {"checks": [{"label": "Adresse analysable", "passed": False,
                            "detail": "URL illisible."}],
                "score": 0, "alertes": ["URL illisible."], "usurpation": True}

    # 1. HOMOGRAPHE — caractères non latins encodés en punycode.
    punycode = host.startswith("xn--") or ".xn--" in host
    noter("Aucun caractère trompeur dans le domaine", not punycode,
          "Le domaine emploie des caractères non latins (punycode) : procédé caractéristique "
          "d'une imitation visuelle." if punycode else "", grave=punycode)

    # 2. TYPOSQUATTAGE.
    imitation = detecter_typosquattage(host)
    noter("Le domaine n'imite aucune source officielle", imitation is None,
          (f"« {host} » ressemble à « {imitation['imite']} » sans en être un sous-domaine.")
          if imitation else "", grave=bool(imitation))

    # 3. ADRESSE IP NUE.
    est_ip = bool(_IP_RE.match(host))
    noter("Nom de domaine (et non adresse IP)", not est_ip,
          "L'adresse pointe une IP nue : aucune organisation n'y publie ses avis." if est_ip else "")

    # 4. RACCOURCISSEUR — la destination réelle est masquée.
    raccourci = any(host == r or host.endswith("." + r) for r in RACCOURCISSEURS)
    noter("Adresse directe (non raccourcie)", not raccourci,
          "Lien raccourci : la destination réelle ne peut pas être vérifiée." if raccourci else "")

    # 5. EXTENSION à risque.
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    noter("Extension de domaine courante", tld not in TLD_A_RISQUE,
          f"L'extension « {tld} » est surreprésentée dans les usurpations." if tld in TLD_A_RISQUE else "")

    # 6. HÉBERGEMENT GRATUIT + revendication d'autorité.
    gratuit = any(h in host for h in HEBERGEMENTS_GRATUITS)
    revendique = any(m in host for m in MOTS_D_AUTORITE)
    noter("Hébergement propre à l'organisation", not (gratuit and revendique),
          "Le site se réclame d'une autorité tout en étant hébergé sur une plateforme "
          "gratuite." if (gratuit and revendique) else "")

    # 7. REDIRECTION vers un autre domaine que celui annoncé.
    final = _hote(getattr(fetched, "final_url", None) or getattr(fetched, "url", None))
    detourne = bool(final and final != host and not final.endswith("." + host)
                    and not host.endswith("." + final))
    noter("La destination correspond à l'adresse annoncée", not detourne,
          f"L'adresse redirige vers « {final} », différent de « {host} »." if detourne else "")

    # 8. TLS — une source de sécurité en HTTP clair est un signal en soi.
    en_clair = (urlparse(url or "").scheme or "").lower() != "https"
    noter("Connexion chiffrée (HTTPS)", not en_clair,
          "La source est servie en HTTP non chiffré : son contenu peut être altéré en "
          "transit." if en_clair else "")

    # 9. ÂGE DU DOMAINE — vérifié en dernier (appel réseau), et jamais bloquant seul.
    jours = await age_du_domaine(host)
    if jours is not None:
        recent = jours < JOURS_DOMAINE_RECENT
        noter(f"Domaine établi ({jours} jours)", not recent,
              f"Domaine créé il y a {jours} jours : très récent pour une source de "
              "référence." if recent else "")
    else:
        checks.append({"label": "Ancienneté du domaine", "passed": None,
                       "detail": "Annuaire RDAP indisponible : ancienneté non vérifiée."})

    evalues = [c for c in checks if c["passed"] is not None]
    reussis = sum(1 for c in evalues if c["passed"])
    score = round(100 * reussis / len(evalues)) if evalues else 0
    return {"checks": checks, "score": score, "alertes": alertes, "usurpation": usurpation}
