"""Générateur de résumés ANCRÉS de l'assistant RAG.

Architecture : base historique → récupération → informations CVE pertinentes → construction du
contexte → (LLM de reformulation) → générateur de résumé → consultant.

Le résumé est TOUJOURS produit à partir des seuls champs réellement présents en base. Deux
chemins :
  1) LLM configuré  -> reformulation naturelle sous bridage strict (llm.py) à partir du contexte.
  2) Sinon (défaut) -> synthèse déterministe extractive (aucune hallucination possible).
Dans les deux cas : jamais d'invention, valeurs (CVSS, versions, sources…) inchangées, et
« Information non disponible dans la base de connaissances. » pour tout champ manquant.
"""
import json
import re
from datetime import datetime

from app.backend.services.assistant import llm
from app.backend.services.collection.storage import _CHANGE_LABELS

MISSING = "Information non disponible dans la base de connaissances."

_SEV_FR = {"critical": "critique", "high": "élevée", "medium": "moyenne", "low": "faible"}

# Titres de sections par style (l'ordre est respecté par le LLM comme par le fallback).
STYLE_SECTIONS = {
    "executive": ["Résumé exécutif", "Sévérité", "Recommandation", "Sources"],
    "technical": ["Résumé exécutif", "Vulnérabilité", "Impact", "Produits affectés",
                  "Sévérité", "Exploitation", "Recommandation", "Sources"],
    "changes": ["Historique des modifications", "Sources"],
}

VALID_STYLES = set(STYLE_SECTIONS)


# --------------------------------------------------------------------------------------
# Contexte : uniquement les champs réels du document CVE.
# --------------------------------------------------------------------------------------

# Valeurs « fourre-tout » sans information réelle -> traitées comme absentes.
_JUNK = {"n/a", "na", "n.a.", "unknown", "inconnu", "none", "null", "-", "—", "tbd", "non disponible", ""}


def _is_junk(s) -> bool:
    return isinstance(s, str) and s.strip().lower() in _JUNK


def _clean(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = v.strip()
        return None if _is_junk(v) else (v or None)
    if isinstance(v, list):
        v = [x for x in v if x not in (None, "") and not _is_junk(x)]
        return v or None
    return v


def _fmt_date(d):
    return d.strftime("%d/%m/%Y") if isinstance(d, datetime) else (str(d)[:10] if d else None)


def _sources(doc: dict) -> list[str]:
    names = [s.get("name") for s in (doc.get("sources") or []) if s.get("name")]
    return list(dict.fromkeys(names + (doc.get("confirmed_sources") or [])))


def build_context(doc: dict) -> dict:
    """Extrait UNIQUEMENT les données réelles (None si absent) — c'est tout ce que voit le LLM."""
    return {
        "cve_id": doc.get("cve_id"),
        "title": _clean(doc.get("title")),
        "vendor": _clean(doc.get("vendor")),
        "product": _clean(doc.get("product")) or _clean(doc.get("affected_products")),
        "affected_products": _clean(doc.get("affected_products")),
        "affected_versions": _clean(doc.get("affected_versions")),
        "affected_systems": _clean(doc.get("affected_systems")),
        "description": _clean(doc.get("description")),
        "impact": _clean(doc.get("impact")),
        "vuln_type": _clean(doc.get("cwe")) or _clean(doc.get("vuln_type")),
        "severity": doc.get("severity"),
        "cvss_score": doc.get("cvss_score"),
        "cvss_vector": _clean(doc.get("cvss_vector")),
        "exploit_status": _clean(doc.get("exploit_status")),
        "solution": _clean(doc.get("solution")),
        "patch_links": _clean(doc.get("patch_links")),
        "references": _clean(doc.get("references")),
        "sources": _sources(doc),
        "published_at": _fmt_date(doc.get("published_at")),
        "updated_at": _fmt_date(doc.get("updated_at")),
    }


def _result_row(doc: dict) -> dict:
    from app.backend.services.assistant.rag import _result_row as row
    return row(doc)


# --------------------------------------------------------------------------------------
# Sections déterministes (fallback ancré, sans LLM).
# --------------------------------------------------------------------------------------

def _sev_label(ctx: dict) -> str | None:
    return _SEV_FR.get(ctx.get("severity")) if ctx.get("severity") else None


def _as_text(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def _executive_paragraph(ctx: dict) -> str:
    cve = ctx["cve_id"]
    target = ctx.get("product") or ctx.get("vendor")
    typ = ctx.get("vuln_type")
    s1 = f"{cve} est une vulnérabilité"
    if typ:
        s1 += f" de type {_as_text(typ)}"
    if target:
        s1 += f" affectant {_as_text(target)}"
    s1 += "."
    sev, cvss = _sev_label(ctx), ctx.get("cvss_score")
    if sev and cvss is not None:
        s2 = f"Elle est classée de sévérité {sev} (score CVSS {cvss})."
    elif sev:
        s2 = f"Elle est classée de sévérité {sev} ; le score CVSS n'est pas renseigné dans la base."
    elif cvss is not None:
        s2 = f"Son score CVSS est de {cvss}."
    else:
        s2 = "Sa sévérité et son score CVSS ne sont pas renseignés dans la base."
    if ctx.get("exploit_status"):
        s3 = f"Statut d'exploitation : {ctx['exploit_status']}."
    elif ctx.get("solution"):
        s3 = "Une remédiation est disponible dans la base (voir la section Recommandation)."
    else:
        s3 = "Aucune information d'exploitation ni de remédiation n'est renseignée dans la base."
    return " ".join([s1, s2, s3])


def _affected_body(ctx: dict) -> str:
    lines = []
    if ctx.get("product"):
        lines.append(f"Produit / éditeur : {_as_text(ctx['product'])}"
                     + (f" ({ctx['vendor']})" if ctx.get("vendor") and ctx.get("vendor") not in _as_text(ctx["product"]) else ""))
    if ctx.get("affected_versions"):
        lines.append(f"Versions affectées : {_as_text(ctx['affected_versions'])}")
    if ctx.get("affected_systems"):
        lines.append(f"Systèmes affectés : {_as_text(ctx['affected_systems'])}")
    return "\n".join(lines) if lines else MISSING


def _severity_body(ctx: dict) -> str:
    lines = []
    lines.append(f"Score CVSS : {ctx['cvss_score']}" if ctx.get("cvss_score") is not None else f"Score CVSS : {MISSING}")
    sev = _sev_label(ctx)
    lines.append(f"Niveau de sévérité : {sev}" if sev else f"Niveau de sévérité : {MISSING}")
    if ctx.get("cvss_vector"):
        lines.append(f"Vecteur CVSS : {ctx['cvss_vector']}")
    return "\n".join(lines)


def _recommendation_body(ctx: dict) -> str:
    if ctx.get("solution"):
        body = ctx["solution"]
        if ctx.get("patch_links"):
            body += "\n\nCorrectifs :\n" + "\n".join(f"• {u}" for u in ctx["patch_links"])
        return body
    if ctx.get("patch_links"):
        return "Correctifs disponibles :\n" + "\n".join(f"• {u}" for u in ctx["patch_links"])
    return MISSING


def _sources_body(ctx: dict) -> str:
    lines = []
    if ctx.get("sources"):
        lines.append("Sources : " + ", ".join(ctx["sources"]))
    if ctx.get("references"):
        lines.append("Références :\n" + "\n".join(f"• {u}" for u in ctx["references"][:8]))
    if ctx.get("published_at"):
        lines.append(f"Publiée le : {ctx['published_at']}")
    if ctx.get("updated_at"):
        lines.append(f"Mise à jour le : {ctx['updated_at']}")
    return "\n".join(lines) if lines else MISSING


def _section_body(title: str, ctx: dict) -> str:
    if title == "Résumé exécutif":
        return _executive_paragraph(ctx)
    if title == "Vulnérabilité":
        return ctx.get("description") or MISSING
    if title == "Impact":
        return ctx.get("impact") or MISSING
    if title == "Produits affectés":
        return _affected_body(ctx)
    if title == "Sévérité":
        return _severity_body(ctx)
    if title == "Exploitation":
        return ctx.get("exploit_status") or MISSING
    if title == "Recommandation":
        return _recommendation_body(ctx)
    if title == "Sources":
        return _sources_body(ctx)
    return MISSING


def _deterministic_sections(ctx: dict, style: str) -> list[dict]:
    return [{"title": t, "body": _section_body(t, ctx)} for t in STYLE_SECTIONS[style]]


# --------------------------------------------------------------------------------------
# Narratif « ce qui a changé » (historique permanent des versions de la CVE).
# --------------------------------------------------------------------------------------

def _val(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "—"
    return str(v)


def _changes_facts(doc: dict) -> list[str]:
    """Faits d'évolution, dérivés de l'historique réel (ts + changes {old/new | ajout})."""
    facts = []
    hist = doc.get("history") or []
    for h in hist:
        ts = _fmt_date(h.get("ts")) or "date inconnue"
        for field, delta in (h.get("changes") or {}).items():
            label = _CHANGE_LABELS.get(field, field)
            if isinstance(delta, dict) and "ajout" in delta:
                facts.append(f"{ts} : {label} enrichi(e)s (+{delta['ajout']} élément(s)).")
            elif isinstance(delta, dict):
                old, new = delta.get("old"), delta.get("new")
                if old in (None, "", []):
                    facts.append(f"{ts} : {label} ajouté(e) → {_val(new)}.")
                else:
                    facts.append(f"{ts} : {label} modifié(e) de « {_val(old)} » à « {_val(new)} ».")
            else:
                facts.append(f"{ts} : {label} modifié(e).")
    return facts


def _changes_sections(doc: dict, ctx: dict) -> list[dict]:
    facts = _changes_facts(doc)
    if not facts:
        pub = ctx.get("published_at")
        body = (f"Aucune modification n'a été enregistrée pour {ctx['cve_id']} depuis sa collecte"
                + (f" (publiée le {pub})." if pub else ".")
                + " La fiche reflète l'état initial des données collectées.")
    else:
        body = ("Cette vulnérabilité a évolué dans la base de connaissances CyberWatch AI :\n\n"
                + "\n".join(f"• {f}" for f in facts))
    return [{"title": "Historique des modifications", "body": body},
            {"title": "Sources", "body": _sources_body(ctx)}]


# --------------------------------------------------------------------------------------
# Reformulation LLM (optionnelle) — sous bridage strict.
# --------------------------------------------------------------------------------------

def _llm_prompt(ctx: dict, titles: list[str], facts: list[str] | None) -> str:
    template = "\n".join(f"### {t}\n<contenu>" for t in titles)
    payload = {"contexte_cve": ctx}
    if facts is not None:
        payload["historique_des_modifications"] = facts
    return (
        "Voici les données JSON RÉELLES issues de la base interne (n'utilise QUE celles-ci) :\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        + "\n\nRédige une synthèse professionnelle en français en respectant EXACTEMENT ce plan "
        "de sections Markdown (mêmes titres, même ordre) :\n\n"
        + template
        + "\n\nRappels : ne mets aucune information absente des données ; pour tout champ vide, "
        "écris « " + MISSING + " » ; ne modifie aucune valeur (CVSS, versions, sources, dates)."
    )


_SECTION_RE = re.compile(r"^#{2,4}\s*(.+?)\s*$", re.MULTILINE)


def _parse_sections(text: str) -> list[dict]:
    """Découpe la réponse LLM « ### Titre \\n corps » en sections structurées."""
    matches = list(_SECTION_RE.finditer(text))
    if not matches:
        return []
    out = []
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        if title:
            out.append({"title": title, "body": body or MISSING})
    return out


# --------------------------------------------------------------------------------------
# Point d'entrée : résumé d'UNE CVE.
# --------------------------------------------------------------------------------------

def _sections_to_text(sections: list[dict]) -> str:
    return "\n\n".join(f"### {s['title']}\n{s['body']}" for s in sections)


async def summarize_cve(db, doc: dict, style: str = "technical") -> dict:
    style = style if style in VALID_STYLES else "technical"
    ctx = build_context(doc)

    if style == "changes":
        sections = _changes_sections(doc, ctx)
        facts = _changes_facts(doc)
        titles = STYLE_SECTIONS["changes"]
    else:
        sections = _deterministic_sections(ctx, style)
        facts = None
        titles = STYLE_SECTIONS[style]

    generated_by = "grounded"
    llm_text = await llm.generate(_llm_prompt(ctx, titles, facts))
    if llm_text:
        parsed = _parse_sections(llm_text)
        if parsed:
            sections = parsed
            generated_by = "llm"

    return {
        "answer": _sections_to_text(sections),
        "sections": sections,
        "results": [_result_row(doc)],
        "sources": ctx["sources"],
        "confidence": "high",
        "count": 1,
        "style": style,
        "generated_by": generated_by,
    }


# --------------------------------------------------------------------------------------
# Résumé de GROUPE (bulletin produit / éditeur) — synthèse exécutive multi-CVE ancrée.
# --------------------------------------------------------------------------------------

async def summarize_group(db, docs: list[dict], label: str, total: int | None = None) -> dict:
    if not docs:
        from app.backend.services.assistant.rag import NOT_FOUND
        return {"answer": NOT_FOUND, "sections": [], "results": [], "sources": [],
                "confidence": "none", "count": 0, "style": "executive", "generated_by": "grounded"}

    n = total if total is not None else len(docs)
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in docs:
        if d.get("severity") in by_sev:
            by_sev[d["severity"]] += 1
    dist = " · ".join(f"{_SEV_FR[k]} : {v}" for k, v in by_sev.items() if v)
    top = sorted(docs, key=lambda d: (d.get("cvss_score") or 0), reverse=True)[:8]
    sources = []
    for d in docs:
        for s in _sources(d):
            if s not in sources:
                sources.append(s)

    scope = "" if n == len(docs) else f" (sur les {len(docs)} plus critiques analysées)"
    exec_body = (f"{n} vulnérabilité(s) concernant {label} sont référencées dans la base "
                 f"CyberWatch AI." + (f" Répartition par sévérité{scope} — {dist}." if dist else ""))
    top_lines = "\n".join(
        f"• {d.get('cve_id')} — CVSS {d.get('cvss_score') if d.get('cvss_score') is not None else '—'}"
        f" ({_SEV_FR.get(d.get('severity'), 'sévérité non renseignée')})"
        + (f" — {d.get('product') or d.get('vendor')}" if (d.get('product') or d.get('vendor')) else "")
        for d in top)
    sections = [
        {"title": "Résumé exécutif", "body": exec_body},
        {"title": "Vulnérabilités les plus critiques", "body": top_lines or MISSING},
        {"title": "Sources", "body": "Sources : " + (", ".join(sources) if sources else MISSING)},
    ]

    generated_by = "grounded"
    facts = [f"{d.get('cve_id')} | CVSS={d.get('cvss_score')} | sévérité={d.get('severity')} | "
             f"produit={d.get('product') or d.get('vendor')}" for d in top]
    prompt = (
        "Données RÉELLES (n'utilise QUE celles-ci) pour un bulletin de sécurité concernant "
        f"« {label} » :\n\n"
        + json.dumps({"nombre_total": len(docs), "repartition_severite": by_sev,
                      "cve_les_plus_critiques": facts, "sources": sources},
                     ensure_ascii=False, indent=2, default=str)
        + "\n\nRédige une synthèse exécutive professionnelle en français avec EXACTEMENT ces "
        "sections Markdown : \n### Résumé exécutif\n### Vulnérabilités les plus critiques\n### Sources"
        "\n\nN'invente rien ; ne modifie aucune valeur ; « " + MISSING + " » si une donnée manque."
    )
    llm_text = await llm.generate(prompt)
    if llm_text:
        parsed = _parse_sections(llm_text)
        if parsed:
            sections = parsed
            generated_by = "llm"

    return {
        "answer": _sections_to_text(sections),
        "sections": sections,
        "results": [_result_row(d) for d in top],
        "sources": sources[:12],
        "confidence": "high",
        "count": n,
        "style": "executive",
        "generated_by": generated_by,
    }
