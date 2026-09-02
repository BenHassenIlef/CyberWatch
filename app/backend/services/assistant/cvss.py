"""LECTURE DU VECTEUR CVSS et du statut d'exploitation — décodage, jamais déduction.

Deux sections de la fiche d'assistance étaient structurellement vides :

  • « Impact »       — le champ `impact` n'est renseigné que sur 23 % des fiches ;
  • « Exploitation » — le champ `exploit_status` est vide sur la TOTALITÉ des fiches.

Elles affichaient donc « Information non disponible », y compris quand la donnée était là,
écrite autrement. Un vecteur `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` énonce
exactement l'impact ; une référence vers le catalogue KEV de la CISA atteste exactement d'une
exploitation constatée.

DÉCODER N'EST PAS DÉDUIRE. On ne devine rien : on traduit une notation normalisée (CVSS v3.x
et v4.0, spécification FIRST) et on constate la présence d'une référence. Aucune valeur n'est
inventée, aucune n'est extrapolée ; si le vecteur est absent ou illisible, la fonction renvoie
None et la section redevient honnêtement vide.
"""
import re

# Libellés des métriques de BASE. Volontairement rédigés en langage d'analyste plutôt qu'en
# jargon de spécification : la fiche s'adresse à un consultant, pas à un parseur.
_LIBELLES: dict[str, dict[str, str]] = {
    "AV": {"N": "exploitable à distance depuis le réseau",
           "A": "exploitable depuis le réseau adjacent",
           "L": "exploitable en accès local",
           "P": "nécessite un accès physique à l'équipement"},
    "AC": {"L": "sans condition particulière à réunir",
           "H": "au prix de conditions difficiles à réunir"},
    "PR": {"N": "sans aucun privilège préalable",
           "L": "avec des privilèges limités",
           "H": "avec des privilèges élevés"},
    "UI": {"N": "sans interaction d'un utilisateur",
           "R": "à condition qu'un utilisateur effectue une action",
           "P": "à condition qu'un utilisateur effectue une action",
           "A": "à condition qu'un utilisateur effectue une action"},
    "S": {"C": "l'impact déborde du composant vulnérable",
          "U": "l'impact reste circonscrit au composant vulnérable"},
    "C": {"H": "confidentialité entièrement compromise",
          "L": "confidentialité partiellement exposée",
          "N": "aucune atteinte à la confidentialité"},
    "I": {"H": "intégrité entièrement compromise",
          "L": "intégrité partiellement altérée",
          "N": "aucune atteinte à l'intégrité"},
    "A": {"H": "disponibilité entièrement compromise",
          "L": "disponibilité partiellement dégradée",
          "N": "aucune atteinte à la disponibilité"},
}

# CVSS v4.0 renomme les métriques d'impact (VC/VI/VA pour le système vulnérable) et
# l'interaction utilisateur. On les ramène aux clés v3 pour un rendu unique.
_EQUIVALENCES_V4 = {"VC": "C", "VI": "I", "VA": "A", "AT": "AC"}

_PAIRE_RE = re.compile(r"([A-Z]{1,2}):([A-Z])")


def decoder(vecteur: str | None) -> dict[str, str]:
    """Métriques de base présentes dans le vecteur, ramenées aux clés v3.x."""
    if not vecteur or not isinstance(vecteur, str):
        return {}
    metriques: dict[str, str] = {}
    for cle, valeur in _PAIRE_RE.findall(vecteur.upper()):
        if cle in ("CVSS",):
            continue
        cle = _EQUIVALENCES_V4.get(cle, cle)
        if cle in _LIBELLES and valeur in _LIBELLES[cle]:
            metriques.setdefault(cle, valeur)
    return metriques


def impact_lisible(vecteur: str | None) -> str | None:
    """Phrase française décrivant l'impact ET les conditions d'exploitation. None si illisible.

    Exemple : `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` devient « Vulnérabilité
    exploitable à distance depuis le réseau, sans aucun privilège préalable, sans interaction
    d'un utilisateur et sans condition particulière à réunir. Conséquences : confidentialité
    entièrement compromise, intégrité entièrement compromise, disponibilité entièrement
    compromise ; l'impact déborde du composant vulnérable. »
    """
    m = decoder(vecteur)
    if not m:
        return None

    conditions = [_LIBELLES[c][m[c]] for c in ("AV", "PR", "UI", "AC") if c in m]
    consequences = [_LIBELLES[c][m[c]] for c in ("C", "I", "A") if c in m]
    if not conditions and not consequences:
        return None

    phrases = []
    if conditions:
        phrases.append("Vulnérabilité " + ", ".join(conditions[:-1])
                       + (" et " if len(conditions) > 1 else "") + conditions[-1] + ".")
    if consequences:
        suite = "Conséquences : " + ", ".join(consequences)
        if "S" in m:
            suite += " ; " + _LIBELLES["S"][m["S"]]
        phrases.append(suite + ".")
    return " ".join(phrases)


# --------------------------------------------------------------------------------------
# Exploitation constatée — attestée par une référence, jamais supposée
# --------------------------------------------------------------------------------------

# Catalogue des vulnérabilités ACTIVEMENT EXPLOITÉES de la CISA (KEV). L'inscription d'une
# CVE à ce catalogue est une constatation officielle d'exploitation en conditions réelles.
_KEV_RE = re.compile(r"known-exploited-vulnerabilit", re.I)

# Preuves de faisabilité publiées. Leur existence ne prouve pas une exploitation en cours,
# et le texte produit le dit : confondre les deux conduirait à sur-prioriser à tort.
_POC_RE = re.compile(r"exploit-db\.com|/exploits?/|packetstorm|metasploit|proof.of.concept", re.I)

KEV = "kev"
POC = "poc"


def exploitation(doc: dict) -> tuple[str, str] | None:
    """(nature, phrase) si une exploitation est ATTESTÉE par les données, sinon None.

    Le champ `exploit_status` reste prioritaire quand une source le renseigne. À défaut, on
    ne conclut qu'à partir de ce qui est vérifiable : la présence d'une référence vers le
    catalogue KEV, ou vers une base de preuves de faisabilité.
    """
    statut = (doc.get("exploit_status") or "").strip()
    if statut:
        return (KEV, statut)

    references = " ".join(str(r) for r in (doc.get("references") or []))
    if _KEV_RE.search(references):
        return (KEV, "Cette vulnérabilité figure au catalogue des vulnérabilités activement "
                     "exploitées (KEV) de la CISA : son exploitation en conditions réelles est "
                     "constatée, ce qui en fait une priorité de remédiation.")
    if _POC_RE.search(references):
        return (POC, "Une preuve de faisabilité publique est référencée pour cette "
                     "vulnérabilité. Cela atteste que l'exploitation est réalisable, sans "
                     "établir qu'elle est activement menée.")
    return None
