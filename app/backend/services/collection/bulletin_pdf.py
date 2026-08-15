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


def _official_cell(bulletin: dict) -> str:
    """Source OFFICIELLE : nom de l'autorité + URL. Jamais la source de collecte."""
    source = bulletin.get("official_source") or {}
    url = source.get("url") or bulletin.get("official_url")
    if not url:
        return _MUTED
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
        + ("".join(f'<div style="font-weight:bold">{_esc(c)}</div>' for c in shown)
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
        _row("Solution", _esc(bulletin["solution"]) if bulletin.get("solution") else _MUTED),
        _row("Références", _links(bulletin.get("references"))),
        _row("Date de publication",
             _esc(_fmt_date(bulletin.get("publication_date")) or "") or _MUTED),
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
  @page {{ size: A4; margin: 0; }}
  body {{ margin:0; font-family:'Times New Roman', Georgia, serif; color:#111;
          font-size:12.5px; line-height:1.45; }}
  table {{ width:100%; border-collapse:collapse; border:1px solid #000; }}
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


def filename_for(bulletin: dict) -> str:
    """Nom de fichier explicite : « Bulletin_CVE-2026-0290.pdf » pour une CVE unique,
    « Bulletin_Securite_Mozilla_2026-08-14.pdf » pour un bulletin groupé."""
    cves = bulletin.get("cves") or []
    if len(cves) == 1:
        base = f"Bulletin_{cves[0]}"
    else:
        subject = bulletin.get("vendor") or (bulletin.get("products") or [None])[0] or "CVE"
        day = _fmt_date(bulletin.get("publication_date")) or datetime.now().strftime("%d/%m/%Y")
        iso_day = "-".join(reversed(day.split("/")))
        base = f"Bulletin_Securite_{subject}_{iso_day}"
    # ASCII strict : un nom de fichier accentué casse l'en-tête Content-Disposition.
    base = (base.replace("é", "e").replace("è", "e").replace("ê", "e").replace("à", "a")
                .replace("ç", "c").replace("û", "u").replace("ô", "o").replace("î", "i"))
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_")
    return f"{base[:120]}.pdf"


async def build_pdf(bulletin: dict) -> bytes | None:
    """Octets du PDF, ou None si le moteur de rendu est indisponible."""
    return await browser_client.render_pdf(build_html(bulletin))
