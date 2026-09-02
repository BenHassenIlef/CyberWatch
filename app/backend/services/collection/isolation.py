"""VALIDATION D'ISOLATION — dernière barrière avant qu'une CVE ne soit publiée.

Une CVE ne doit porter QUE ses propres données. Les modules amont s'y emploient déjà ; ce
module vérifie le résultat, parce qu'un avis collectif trouve toujours de nouvelles façons de
déborder sur les vulnérabilités qu'il cite.

CE QUI EST CONTRÔLÉ

  • l'identifiant est un identifiant CVE bien formé ;
  • aucun champ ne cite un AUTRE identifiant CVE (une remédiation qui nomme CVE-X sur la
    fiche de CVE-Y vient d'ailleurs) ;
  • le produit affecté n'est pas un titre d'avis ;
  • les références portant un identifiant CVE portent CELUI de la fiche ;
  • la date de publication n'est ni absente, ni postérieure à la collecte.

CE QUI N'EST PAS CONTRÔLÉ ICI : la véracité des valeurs. Ce module vérifie leur APPARTENANCE
à cette CVE, pas leur exactitude — l'enrichissement et la provenance s'en chargent.

En cas d'échec, la fiche n'est pas rejetée : elle est MARQUÉE. Supprimer une vulnérabilité
réelle parce qu'un de ses champs est douteux serait un remède pire que le mal.
"""
import re

from app.backend.services.collection.schema import CVE_RE

# Champs textuels susceptibles d'avoir été recopiés depuis un avis collectif.
CHAMPS_TEXTUELS = ("description", "impact", "solution", "product", "vendor")

# Un PRODUIT nomme une chose ; un titre d'avis annonce une action. La distinction se lit à
# l'attaque de la chaîne, dans les deux langues de la veille.
TITRE_D_AVIS_RE = re.compile(
    r"^\s*(mises?\s+[àa]\s+jour|vuln[ée]rabilit|failles?\s|security\s+updates?|"
    r"multiple\s+vulnerabilit|bulletin\s|avis\s+de\s+s[ée]curit)", re.I)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _cve_etrangeres(texte: str, cve_id: str) -> set[str]:
    """Identifiants CVE cités par un texte, autres que celui de la fiche."""
    if not texte:
        return set()
    return {m.group(0).upper() for m in CVE_RE.finditer(str(texte))} - {(cve_id or "").upper()}


def valider(rec: dict) -> list[str]:
    """Renvoie la liste des manquements d'isolation. Liste vide = fiche saine."""
    cve_id = rec.get("cve_id") or ""
    manquements: list[str] = []

    if not CVE_ID_RE.match(cve_id):
        manquements.append("identifiant CVE invalide")
        return manquements          # sans identifiant fiable, le reste n'a pas de sens

    for champ in CHAMPS_TEXTUELS:
        etrangeres = _cve_etrangeres(rec.get(champ), cve_id)
        if etrangeres:
            manquements.append(
                f"{champ} cite une autre vulnerabilite ({sorted(etrangeres)[0]})")

    produit = rec.get("product")
    if produit and TITRE_D_AVIS_RE.search(str(produit)):
        manquements.append("le produit est un titre d'avis, pas un produit")

    for ref in (rec.get("references") or []):
        if isinstance(ref, str):
            cites = {m.group(0).upper() for m in CVE_RE.finditer(ref)}
            if cites and cve_id.upper() not in cites:
                manquements.append(f"reference portant une autre vulnerabilite ({ref[:60]})")
                break

    publication = rec.get("published_at")
    collecte = rec.get("collected_at")
    if publication and collecte:
        try:
            if _naif(publication) > _naif(collecte):
                manquements.append("date de publication posterieure a la collecte")
        except (TypeError, AttributeError):
            pass

    return manquements


def _naif(valeur):
    return valeur.replace(tzinfo=None) if getattr(valeur, "tzinfo", None) else valeur


def appliquer(rec: dict) -> bool:
    """Marque la fiche selon le résultat. Renvoie True si elle est publiable telle quelle.

    Une fiche en défaut reste collectée et consultable — elle porte simplement
    `validation_status = "needs_review"` et le détail des manquements, de sorte qu'un
    analyste sache quoi vérifier au lieu de découvrir l'anomalie dans un bulletin.
    """
    manquements = valider(rec)
    rec["isolation_checked"] = True
    if manquements:
        rec["isolation_issues"] = manquements
        rec["validation_status"] = "needs_review"
        return False
    rec.pop("isolation_issues", None)
    return True
