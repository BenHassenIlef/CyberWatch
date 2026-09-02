"""Export PDF RÉEL du bulletin de sécurité Advancia (aucune boîte d'impression navigateur).

Le bulletin normalisé (même modèle que l'affichage écran) est rendu en HTML autonome puis
converti en PDF A4 par le Chromium headless DÉJÀ présent dans le projet (Playwright, utilisé
par la vérification de sources). Aucune dépendance supplémentaire n'est introduite.

    bulletin (dict)  ->  build_html()  ->  browser_client.render_pdf()  ->  octets PDF

Le document est INTÉGRALEMENT autonome : styles en ligne et logo intégré en data: URI. Le
rendu ne déclenche donc aucune requête réseau (elles sont d'ailleurs bloquées côté navigateur).

Structure imposée (cf. cahier des charges) : Produit/Technologie, Éditeur, CVE, Résumé,
Risque/Impact, Systèmes affectés, Sévérité/Score, Type de vulnérabilité, Solution, Références,
Date de publication, Source officielle. « Vecteur d'attaque » et « Référence de l'avis » sont
volontairement ABSENTS.
"""
import base64
import html as html_mod
import logging
import os
import re
from datetime import datetime

from app.backend.services.collection import remediation
from app.backend.services.verification import browser_client

logger = logging.getLogger("cyberwatch.collection.bulletin_pdf")

# Logo Advancia servi par le frontend ; intégré en data: URI pour un PDF autonome.
_LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))), "frontend", "public", "logo-advancia.png")

_SEVERITY_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}

# Nb max d'identifiants listés en tête d'un bulletin groupé (lisibilité du PDF).
_MAX_IDS_SHOWN = 20

_LABEL_CSS = ("border:1px solid #000;padding:8px 10px;text-align:center;font-weight:bold;"
              "vertical-align:middle;width:26%")
_CONTENT_CSS = "border:1px solid #000;padding:8px 12px;text-align:left;vertical-align:top"
_MUTED = '<span style="color:#999">—</span>'


def _esc(value) -> str:
    return html_mod.escape("" if value is None else str(value), quote=True)


def _logo_data_uri() -> str | None:
    """Logo encodé en base64, ou None s'il est introuvable (le bulletin reste généré)."""
    try:
        with open(_LOGO_PATH, "rb") as fh:
            return "data:image/png;base64," + base64.b64encode(fh.read()).decode("ascii")
    except OSError:
        logger.info("Logo introuvable (%s) : bulletin PDF généré sans logo.", _LOGO_PATH)
        return None


def _fmt_date(value) -> str | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.strftime("%d/%m/%Y")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime("%d/%m/%Y")
    except ValueError:
        return str(value)[:10]


def _bullets(items) -> str:
    values = [i for i in (items if isinstance(items, list) else [items] if items else []) if i]
    if not values:
        return _MUTED
    return ('<ul style="margin:0;padding-left:18px">'
            + "".join(f"<li>{_esc(v)}</li>" for v in values) + "</ul>")


def _links(refs) -> str:
    values = [r for r in (refs or []) if r]
    if not values:
        return _MUTED
    return "".join(
        f'<div style="margin:2px 0;word-break:break-all">&bull;&nbsp;{_esc(r)}</div>'
        for r in values)


def _row(label: str, content: str | None) -> str:
    if content is None:
        return ""
    return (f'<tr><td style="{_LABEL_CSS}">{_esc(label)}</td>'
            f'<td style="{_CONTENT_CSS}">{content}</td></tr>')


def _est_bulletin_produit(bulletin: dict) -> bool:
    """Bulletin GROUPE d un produit (par opposition au bulletin d UNE vulnerabilite).

    Le marqueur existe deja dans le modele : product_bulletin prefixe son identifiant par
    « PROD- ». On s appuie dessus plutot que de deviner d apres le nombre de CVE.
    """
    return str(bulletin.get("bulletin_id") or "").startswith("PROD-")


def _les_plus_graves(bulletin: dict) -> tuple[dict, set]:
    """(score par CVE, identifiants portant le score MAXIMAL du bulletin).

    Le maximum est recalcule sur les vulnerabilites REELLEMENT listees, et non repris de
    l agregat : un bulletin borne a 80 CVE pourrait annoncer un score qui ne figure sur
    aucune ligne, et aucune ne serait alors mise en evidence. Plusieurs CVE peuvent partager
    ce maximum — elles sont toutes signalees.
    """
    scores = {v["cve_id"]: v["cvss_score"] for v in (bulletin.get("vulnerabilities") or [])
              if v.get("cve_id") and isinstance(v.get("cvss_score"), (int, float))}
    if not scores:
        return {}, set()
    maximum = max(scores.values())
    return scores, {c for c, s in scores.items() if s == maximum}


def _identifiant_cell(cve_id: str, scores: dict, plus_graves: set) -> str:
    """Identifiant du bulletin — EN ROUGE s il porte le score le plus eleve du lot.

    Un bulletin produit aligne parfois huit identifiants sans hierarchie : le consultant
    devait ouvrir chaque fiche pour savoir par laquelle commencer.
    """
    if cve_id not in plus_graves:
        return f'<div style="font-weight:bold">{_esc(cve_id)}</div>'
    note = scores.get(cve_id)
    suffixe = (f' <span style="font-size:11px">(CVSS {float(note):.1f})</span>'
               if note is not None else "")
    return f'<div style="font-weight:bold;color:#b91c1c">{_esc(cve_id)}{suffixe}</div>'


def _solution_cell(bulletin: dict) -> str:
    """Solution / Correctif : la remédiation, ou l'état exact de l'information.

    Un PDF est transmis, archivé, opposé. Il ne doit pas laisser croire qu'aucun correctif
    n'existe alors que l'application n'a pas su lire les avis de l'éditeur. Le tiret muet
    employé jusqu'ici était ambigu ; l'état est désormais explicite.
    """
    if bulletin.get("solution"):
        return _esc(bulletin["solution"])
    message = bulletin.get("solution_message") or remediation.MESSAGES[
        remediation.EXTRACTION_INCOMPLETE]
    return f'<span style="color:#666;font-style:italic">{_esc(message)}</span>'


def _official_cell(bulletin: dict) -> str:
    """SITE OFFICIEL : celui de l'éditeur du produit vulnérable, ou son avis de sécurité.

    Jamais la page de collecte, jamais une base de vulnérabilités (NVD, CVE.org, avis
    GitHub) : celles-ci figurent en « Références ». Faute d'éditeur identifiable de façon
    vérifiable, le PDF porte « Non identifié » — un tiret se lirait comme un oubli.
    """
    source = bulletin.get("official_source") or {}
    url = source.get("url") or bulletin.get("official_url")
    if not url:
        return '<span style="color:#999;font-style:italic">Non identifié</span>'
    name = source.get("name")
    head = f'<div style="font-weight:bold">{_esc(name)}</div>' if name else ""
    return head + f'<div style="word-break:break-all">{_esc(url)}</div>'


def build_html(bulletin: dict) -> str:
    """Document HTML autonome du bulletin (A4, styles en ligne, logo intégré)."""
    cves = bulletin.get("cves") or []
    ghsa = (bulletin.get("identifiers") or {}).get("ghsa") or []
    identifiers = [*cves, *ghsa]
    # Un bulletin groupé peut porter des dizaines de CVE : les empiler toutes occuperait une
    # page entière avant le premier contenu utile. On en montre un extrait et on annonce le
    # reste — le détail complet reste disponible dans le tableau des vulnérabilités de l'app.
    scores, plus_graves = _les_plus_graves(bulletin)
    # LES PLUS GRAVES D ABORD. Le bulletin ne montre que les premiers identifiants ; sans ce
    # tri, la vulnerabilite la plus critique du lot pouvait ne PAS figurer dans le document —
    # constate sur un bulletin de 58 CVE ou la seule notee 10.0 etait hors des 20 affichees.
    identifiers.sort(key=lambda c: -(scores.get(c) if scores.get(c) is not None else -1))
    shown, overflow = identifiers[:_MAX_IDS_SHOWN], max(0, len(identifiers) - _MAX_IDS_SHOWN)
    severity = _SEVERITY_FR.get(bulletin.get("severity"), bulletin.get("severity") or "—")
    score = bulletin.get("cvss_score")
    score_txt = f"{float(score):.1f}" if isinstance(score, (int, float)) else "—"
    logo = _logo_data_uri()

    product_cell = (
        f'<div style="font-weight:bold;font-size:15px;margin-bottom:6px">'
        f'{_esc(bulletin.get("title") or (bulletin.get("products") or ["—"])[0])}</div>'
        + (f'<div style="margin-bottom:6px">Éditeur : <b>{_esc(bulletin.get("vendor"))}</b></div>'
           if bulletin.get("vendor") else "")
        + ("".join(_identifiant_cell(c, scores, plus_graves) for c in shown)
           if shown else _MUTED)
        + (f'<div style="margin-top:6px;color:#555">…et {overflow} autre(s) identifiant(s)</div>'
           if overflow else ""))

    rows = "".join([
        _row("Résumé", _esc(bulletin["summary"]) if bulletin.get("summary") else _MUTED),
        _row("Risque / Impact", _bullets(bulletin.get("risk"))),
        _row("Systèmes affectés", _bullets(bulletin.get("affected_systems"))),
        _row("Sévérité / Score", f"<b>{_esc(severity)}</b>&nbsp;&nbsp;/&nbsp;&nbsp;{_esc(score_txt)}"),
        # Ligne TOUJOURS présente (structure imposée) : « — » plutôt qu'une ligne manquante.
        _row("Type de vulnérabilité",
             _esc(bulletin["vulnerability_type"]) if bulletin.get("vulnerability_type") else _MUTED),
        _row("Solution", _solution_cell(bulletin)),
        # RÉFÉRENCES : omises sur un bulletin PRODUIT. Il agrège des dizaines de CVE, donc
        # des centaines de liens qui noient la synthèse sans rien apprendre — le détail par
        # CVE porte, lui, la source officielle de chaque vulnérabilité. Sur le bulletin d'UNE
        # CVE, en revanche, les références restent l'essentiel.
        "" if _est_bulletin_produit(bulletin)
        else _row("Références", _links(bulletin.get("references"))),
        _row("Date de publication",
             _esc(_fmt_date(bulletin.get("publication_date")) or "") or _MUTED),
        # Date de RÉVISION de la fiche, distincte de sa publication. Un PDF est archivé et
        # opposé : sans elle, rien n'indique que le score ou le correctif a changé depuis.
        _row("Dernière mise à jour",
             _esc(_fmt_date(bulletin.get("update_date")) or "")
             or '<span style="color:#999;font-style:italic">Non disponible</span>'),
        _row("Source officielle", _official_cell(bulletin)),
    ])

    summary_block = ""
    if bulletin.get("ai_summary"):
        summary_block = (
            '<div style="border-left:4px solid #1f3c88;background:#f4f6fb;padding:10px 14px;'
            'margin:0 0 12px">'
            '<div style="font-weight:bold;color:#1f3c88;margin-bottom:4px">Résumé (analyste)</div>'
            f'{_esc(bulletin["ai_summary"])}</div>')

    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Bulletin de sécurité</title>
<style>
  /* MARGES DE PAGE : le bulletin était collé aux quatre bords, ce qui le faisait paraître
     décentré et empêchait toute impression sur une imprimante ordinaire — celles-ci
     réservent une zone non imprimable en périphérie. 14 mm laissent le tableau respirer et
     le placent au centre de la feuille. */
  @page {{ size: A4; margin: 14mm; }}
  body {{ margin:0; font-family:'Times New Roman', Georgia, serif; color:#111;
          font-size:12.5px; line-height:1.45; }}
  /* Le tableau occupe la largeur utile et reste CENTRÉ dans la zone imprimable. */
  table {{ width:100%; max-width:180mm; margin:0 auto; border-collapse:collapse;
           border:1px solid #000; }}
  tr, td {{ page-break-inside: avoid; }}
</style></head>
<body>
{summary_block}
<table>
  <tbody>
    <tr>
      <td style="border:1px solid #000;padding:8px;text-align:center;vertical-align:middle;width:26%">
        {f'<img src="{logo}" alt="Advancia IT System" style="max-height:46px;max-width:140px"/>'
         if logo else '<b>Advancia IT System</b>'}
      </td>
      <td style="border:1px solid #000;padding:10px;text-align:center;color:#1f3c88;
                 font-weight:bold;font-size:15px">
        Bulletin de sécurité &ndash; Nouvelles vulnérabilités CVE
      </td>
    </tr>
    <tr>
      <td style="{_LABEL_CSS}">Produit / Technologie</td>
      <td style="border:1px solid #000;padding:10px;text-align:center;vertical-align:middle">
        {product_cell}
      </td>
    </tr>
    {rows}
  </tbody>
</table>
</body></html>"""


_DETAIL_TH = ("border:1px solid #000;padding:6px 8px;background:#f1f4f9;font-weight:bold;"
              "text-align:left;font-size:11px")
_DETAIL_TD = "border:1px solid #000;padding:6px 8px;vertical-align:top;font-size:10.5px"


def _cellule(valeur) -> str:
    """Cellule du tableau de détail. Une valeur absente est ÉCRITE, jamais laissée vide."""
    if isinstance(valeur, list):
        valeur = " · ".join(str(v) for v in valeur if v)
    if valeur in (None, "", []):
        return '<span style="color:#888;font-style:italic">Non disponible</span>'
    return _esc(valeur)


def build_details_html(bulletin: dict) -> str:
    """Document AUTONOME du DÉTAIL DES VULNÉRABILITÉS — une ligne par CVE.

    Séparé du bulletin de synthèse à dessein : le tableau récapitulatif et le détail
    répondent à deux usages distincts (transmettre une alerte / travailler ligne à ligne),
    et un consultant veut souvent l'un sans l'autre. En paysage, le tableau tient dans la
    largeur sans rogner les colonnes.

    Chaque ligne lit SA vulnérabilité : aucune valeur agrégée du bulletin n'y descend.
    """
    vulns = bulletin.get("vulnerabilities") or []
    produit = bulletin.get("vendor") or "—"
    # CVE la plus grave RÉELLEMENT présente dans ce tableau : c'est par elle qu'on commence.
    scores = [v.get("cvss_score") for v in vulns if isinstance(v.get("cvss_score"), (int, float))]
    maximum = max(scores) if scores else None

    entetes = ("CVE", "Publiée", "Dernière mise à jour", "Résumé", "Impact", "CVSS",
               "Sévérité", "Systèmes affectés", "Solution", "Site officiel")
    lignes = []
    for v in vulns:
        grave = maximum is not None and v.get("cvss_score") == maximum
        fond = ' style="background:#fff1f2"' if grave else ""
        identifiant = _esc(v.get("cve_id"))
        if grave:
            identifiant = (f'<b style="color:#b91c1c">{identifiant}</b>'
                           '<div style="color:#b91c1c;font-size:9px">Score le plus élevé</div>')
        source = (v.get("official_source") or {}).get("url")
        solution = v.get("solution") or v.get("solution_message")
        cellules = [
            identifiant,
            _cellule(_fmt_date(v.get("published_at"))),
            _cellule(_fmt_date(v.get("updated_at"))),
            _cellule(v.get("description")),
            _cellule(v.get("impact")),
            _cellule(None if v.get("cvss_score") is None else f'{float(v["cvss_score"]):.1f}'),
            _cellule(_SEVERITY_FR.get(v.get("severity"), v.get("severity"))),
            _cellule(v.get("affected_systems") or v.get("affected_products")
                     or v.get("affected_versions")),
            _cellule(solution),
            _cellule(source),
        ]
        lignes.append(f"<tr{fond}>" + "".join(f'<td style="{_DETAIL_TD}">{c}</td>'
                                              for c in cellules) + "</tr>")

    periode = bulletin.get("periode_libelle") or ""
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"/>
<style>@page {{ size: A4 landscape; margin: 12mm; }}
 body {{ font-family:'Times New Roman',Georgia,serif; color:#111; }}</style>
</head><body>
<h1 style="font-size:16px;color:#1f3c88;margin:0 0 4px">
  Détail des vulnérabilités &ndash; {_esc(produit)}</h1>
<p style="font-size:11px;color:#555;margin:0 0 12px">
  {len(vulns)} vulnérabilité(s){f' &bull; {_esc(periode)}' if periode else ''}
  &bull; une ligne par CVE, chacune avec ses propres données.</p>
<table style="width:100%;border-collapse:collapse;border:1px solid #000">
  <thead><tr>{''.join(f'<th style="{_DETAIL_TH}">{_esc(h)}</th>' for h in entetes)}</tr></thead>
  <tbody>{''.join(lignes) or '<tr><td style="' + _DETAIL_TD + '" colspan="10">Aucune vulnérabilité sur cette période.</td></tr>'}</tbody>
</table>
</body></html>"""


async def build_details_pdf(bulletin: dict) -> bytes | None:
    """Octets du PDF de DÉTAIL, ou None si le moteur de rendu est indisponible."""
    return await browser_client.render_pdf(build_details_html(bulletin))


def details_filename_for(bulletin: dict) -> str:
    """Nom de fichier du détail, distinct de celui du bulletin de synthèse."""
    return filename_for(bulletin).replace("Bulletin_", "Detail_CVE_", 1)


# Un nom de produit est COURT. Au-delà, on tient un intitulé d'avis (« Dell OpenManage
# Enterprise SQL Injection (CVE-…) – TheHackerWire »), qui ferait un nom de fichier illisible.
_LONGUEUR_MAX_PRODUIT = 40


def _ressemble_a_un_produit(valeur: str | None) -> bool:
    """Vrai si la valeur peut servir de nom de produit dans un nom de fichier.

    Trois disqualifications : trop longue (c'est une phrase), portant un identifiant CVE
    (c'est un titre d'avis), ou décrivant des plateformes plutôt qu'un produit — le champ
    `products` vaut parfois « Linux Mac OS Windows ».
    """
    v = (valeur or "").strip()
    if not v or len(v) > _LONGUEUR_MAX_PRODUIT or re.search(r"CVE-\d{4}-\d{4,7}", v, re.I):
        return False
    mots = {m.lower() for m in re.findall(r"[A-Za-z]+", v)}
    plateformes = {"linux", "mac", "os", "windows", "android", "ios", "unix"}
    return not (mots and mots <= plateformes)


def _nom_de_produit(bulletin: dict) -> str:
    """Meilleur nom de produit disponible, du plus précis au plus général.

    Le titre est retenu en premier quand il EST un nom de produit (« Google Chrome ») ;
    sinon on descend vers le produit déclaré, puis l'éditeur. Faute de candidat convenable,
    on renvoie une chaîne vide : le fichier gardera son seul identifiant, ce qui vaut mieux
    qu'un nom de deux lignes.
    """
    for candidat in (bulletin.get("title"), (bulletin.get("products") or [None])[0],
                     bulletin.get("vendor")):
        if _ressemble_a_un_produit(candidat):
            return candidat.strip()
    return ""


def filename_for(bulletin: dict) -> str:
    """Nom de fichier explicite : « Bulletin_CVE-2026-0290.pdf » pour une CVE unique,
    « Bulletin_Securite_Mozilla_2026-08-14.pdf » pour un bulletin groupé."""
    cves = bulletin.get("cves") or []
    # LE PRODUIT D'ABORD.
    #
    # Le nom se réduisait à l'identifiant : « Bulletin_CVE-2026-76020.pdf ». Dans un dossier
    # de téléchargements, rien ne distinguait deux bulletins l'un de l'autre sans les ouvrir.
    # Le produit est ce qu'un consultant cherche des yeux ; l'identifiant reste pour lever
    # toute ambiguïté entre deux vulnérabilités du même produit.
    # Le PRODUIT prime sur l'éditeur : « Google Chrome » identifie le bulletin, « Google »
    # le laisserait confondre avec Android, Workspace ou Cloud. Sur un bulletin PRODUIT, en
    # revanche, c'est `vendor` qui porte déjà le nom du produit surveillé.
    if _est_bulletin_produit(bulletin):
        produit = bulletin.get("vendor") or ""
    else:
        produit = _nom_de_produit(bulletin)
    produit = re.sub(r"\s*\(.*?\)\s*", " ", str(produit)).strip()[:48]

    if len(cves) == 1:
        base = f"Bulletin_{produit}_{cves[0]}" if produit else f"Bulletin_{cves[0]}"
    else:
        day = _fmt_date(bulletin.get("publication_date")) or datetime.now().strftime("%d/%m/%Y")
        iso_day = "-".join(reversed(day.split("/")))
        base = f"Bulletin_Securite_{produit or 'CVE'}_{iso_day}"
    # ASCII strict : un nom de fichier accentué casse l'en-tête Content-Disposition.
    base = (base.replace("é", "e").replace("è", "e").replace("ê", "e").replace("à", "a")
                .replace("ç", "c").replace("û", "u").replace("ô", "o").replace("î", "i"))
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_")
    return f"{base[:120]}.pdf"


async def build_pdf(bulletin: dict) -> bytes | None:
    """Octets du PDF, ou None si le moteur de rendu est indisponible."""
    return await browser_client.render_pdf(build_html(bulletin))
