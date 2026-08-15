"""Moteur RAG (Retrieval-Augmented Generation) de l'assistant cyber.

DEUX PORTÉES de réponse, toujours distinguées et étiquetées (champ `scope`) :

  • scope = "internal" — la réponse est 100 % ANCRÉE sur la base CyberWatch AI (CVE,
    historiques, bulletins, sources). Elle ne fait que restituer les documents RÉELLEMENT
    récupérés ; un LLM peut la reformuler, jamais la compléter.
  • scope = "external" — la question ne porte pas sur le contenu de la base (définition,
    méthodologie, CVE non collectée…). La réponse vient alors des connaissances propres du
    modèle configuré (Grok / xAI par défaut) et est explicitement signalée comme hors base.
    Voir `services/assistant/external.py`.

Pipeline : question → compréhension (filtres/intention/portée) → RÉCUPÉRATION en base →
construction du contexte → SYNTHÈSE ancrée (reformulée par le LLM si configuré) → sources
utilisées + niveau de confiance ; à défaut de document pertinent, bascule externe.

Extensible : `retrieve()` est le seul point d'accès aux données ; on peut le remplacer plus tard
par une recherche vectorielle (ChromaDB/Qdrant/pgvector…) SANS toucher au reste.
"""
import json
import re
from datetime import datetime, timedelta

from app.backend.services.assistant import llm
from app.backend.services.collection.advisory_bulletin import _KNOWN_VENDORS, _VENDOR_DISPLAY
from app.backend.services.collection.schema import CVE_RE

NOT_FOUND = "Cette information n'est pas disponible dans la base de connaissances actuelle de CyberWatch AI."

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SEV_FR = {
    "critique": "critical", "critiques": "critical", "élevé": "high", "élevée": "high", "eleve": "high",
    "elevee": "high", "haute": "high", "haut": "high", "moyen": "medium", "moyenne": "medium",
    "faible": "low", "critical": "critical", "high": "high", "medium": "medium", "low": "low",
}
_MONTHS = {
    "janvier": 1, "january": 1, "février": 2, "fevrier": 2, "february": 2, "mars": 3, "march": 3,
    "avril": 4, "april": 4, "mai": 5, "may": 5, "juin": 6, "june": 6, "juillet": 7, "july": 7,
    "août": 8, "aout": 8, "august": 8, "septembre": 9, "september": 9, "octobre": 10, "october": 10,
    "novembre": 11, "november": 11, "décembre": 12, "decembre": 12, "december": 12,
}
# Mots vides à ignorer pour l'extraction de mots-clés produit.
# Sans ce filtrage, une question naturelle (« quelles CVE avons-nous en base ? ») produirait
# des pseudo-produits (« avons », « nous », « base ») qui videraient la requête Mongo.
_STOP = {"the", "les", "des", "vulnerabilities", "vulnérabilités", "vulnerabilite", "cve", "cves",
         "show", "list", "affiche", "afficher", "liste", "montre", "montrer", "which", "quel",
         "quelle", "quelles", "quels", "with", "avec", "greater", "than", "supérieur", "superieur",
         "score", "published", "publié", "publiées", "publiees", "this", "ce", "cette", "de", "du",
         "and", "et", "for", "pour", "all", "tous", "toutes", "que", "qui", "how", "many", "combien",
         "vulnerability", "affecting", "affectant", "product", "produit", "vendor", "éditeur",
         "compare", "comparer", "changed", "changé", "summarize", "résume", "resume", "today",
         "aujourd", "hui", "month", "mois", "year", "année", "annee", "critical", "critiques",
         # Verbes, pronoms et déterminants courants (français / anglais).
         "avons", "avez", "avait", "avaient", "sont", "sommes", "êtes", "etes", "était", "etait",
         "étaient", "etaient", "nous", "vous", "elle", "elles", "ils", "leur", "leurs", "notre",
         "nos", "votre", "vos", "mes", "ton", "tes", "dans", "chez", "base", "bases", "données",
         "donnees", "connaissances", "plus", "moins", "très", "tres", "aussi", "encore", "déjà",
         "deja", "peux", "peut", "peuvent", "dois", "doit", "faire", "sais", "savoir", "voir",
         "donne", "donner", "dire", "quoi", "quand", "où", "existe", "existent", "trouve",
         "trouver", "cherche", "chercher", "recherche", "sur", "par", "être", "etre", "avoir",
         "have", "has", "are", "was", "were", "our", "your", "their", "there", "them", "these",
         "those", "what", "when", "where", "does", "did", "can", "could", "should", "would",
         "please", "give", "find", "about", "from", "into", "over", "been", "being", "some", "any",
         # Synonymes génériques de « vulnérabilité » (jamais des noms de produit).
         "est", "ont", "faille", "failles", "faiblesse", "faiblesses", "problème", "probleme",
         "problèmes", "problemes", "menace", "menaces", "risque", "risques", "correctif",
         "correctifs", "flaw", "flaws", "issue", "issues", "weakness", "threat", "threats"}


def _utcnow() -> datetime:
    return datetime.utcnow()


def _is_stopword(token: str) -> bool:
    """Mot vide, y compris sous forme composée (« avons-nous », « est-ce »).

    Un nom de produit composé (« log4j-core », « x-force ») conserve au moins un segment
    signifiant : il n'est donc jamais filtré.
    """
    parts = [p for p in re.split(r"[-'’_]", token.lower()) if p]
    return all(p in _STOP or p.isdigit() or len(p) <= 2 for p in parts)


# --------------------------------------------------------------------------------------
# 1) Compréhension de la question (filtres + intention)
# --------------------------------------------------------------------------------------

def parse_query(question: str) -> dict:
    q = question.strip()
    low = q.lower()
    parsed: dict = {"raw": q, "cve_ids": [], "vendor": None, "severity": None, "cvss_min": None,
                    "date_field": "published_at", "date_from": None, "date_to": None,
                    "keywords": [], "exploit": False, "intent": "list", "summary_style": None}

    parsed["cve_ids"] = list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(q)))

    # Intention
    if re.search(r"\b(how many|combien|number of|nombre de)\b", low):
        parsed["intent"] = "count"
    if re.search(r"\b(most|highest|le plus|la plus|top)\b", low) and re.search(r"vendor|éditeur|editeur|product|produit", low):
        parsed["intent"] = "top_vendor"
    if re.search(r"\bchang|évolu|evolu|history|historique|what changed|qu.est.ce qui a changé\b", low) and parsed["cve_ids"]:
        parsed["intent"] = "changes"
    if re.search(r"\bcompare|comparer\b", low) and parsed["cve_ids"]:
        parsed["intent"] = "compare"
    if re.search(r"\bsummar|résume|resume|synthèse\b", low):
        parsed["intent"] = "summarize"
    if parsed["cve_ids"] and re.search(r"expli|explain|détaill|detaill|impact|remédiation|remediation", low):
        parsed["intent"] = "explain"
    elif parsed["cve_ids"] and parsed["intent"] == "list" and len(parsed["cve_ids"]) == 1 and len(low.split()) <= 6:
        parsed["intent"] = "explain"

    # Style de résumé demandé (boutons « Résumé exécutif / technique / Expliquer les changements »).
    if re.search(r"exécutif|executif|executive", low):
        parsed["summary_style"] = "executive"
    elif re.search(r"technique|technical", low):
        parsed["summary_style"] = "technical"
    if parsed["intent"] == "changes":
        parsed["summary_style"] = "changes"

    # Sévérité
    for word, canon in _SEV_FR.items():
        if re.search(rf"\b{re.escape(word)}\b", low):
            parsed["severity"] = canon
            break

    # Seuil CVSS
    m = re.search(r"cvss[^0-9]{0,12}(\d+(?:\.\d+)?)|(?:score|>=|>|supérieur[e]?\s*à|greater than|above)\s*(\d+(?:\.\d+)?)", low)
    if m:
        parsed["cvss_min"] = float(m.group(1) or m.group(2))

    # Exploit
    if re.search(r"exploit|activement exploité|actively exploited|kev|poc", low):
        parsed["exploit"] = True

    # Éditeur / produit connus
    for v in sorted(_KNOWN_VENDORS, key=len, reverse=True):
        if re.search(rf"\b{re.escape(v)}\b", low):
            parsed["vendor"] = _VENDOR_DISPLAY.get(v, v.title())
            break

    # Dates : today / this month / this year / <mois> <année> / updated
    now = _utcnow()
    if re.search(r"updated|mise? à jour|enrichi|enriched", low):
        parsed["date_field"] = "updated_at"
    if re.search(r"today|aujourd", low):
        start = datetime(now.year, now.month, now.day)
        parsed["date_from"], parsed["date_to"] = start, now
    elif re.search(r"this month|ce mois|du mois", low):
        parsed["date_from"] = datetime(now.year, now.month, 1)
        parsed["date_to"] = now
    elif re.search(r"this year|cette année|de l.année|de l.annee", low):
        parsed["date_from"] = datetime(now.year, 1, 1)
        parsed["date_to"] = now
    else:
        mm = re.search(r"(" + "|".join(_MONTHS) + r")\s+(\d{4})", low)
        if mm:
            mo, yr = _MONTHS[mm.group(1)], int(mm.group(2))
            parsed["date_from"] = datetime(yr, mo, 1)
            parsed["date_to"] = datetime(yr + (mo == 12), (mo % 12) + 1, 1)

    # Mots-clés produit (ce qui reste, hors mots vides / nombres). PAS d'extraction quand la
    # question cible une CVE précise (sinon un mot comme « changed » pollue la requête).
    if not parsed["vendor"] and not parsed["cve_ids"]:
        for tok in re.findall(r"[A-Za-zÀ-ÿ][\w.+-]{3,}", q):  # ≥ 4 caractères
            if _is_stopword(tok) or CVE_RE.match(tok):
                continue
            parsed["keywords"].append(tok)
        parsed["keywords"] = parsed["keywords"][:4]

    return parsed


# --------------------------------------------------------------------------------------
# 1 bis) Portée de la question : contenu de la base (interne) ou question générale (externe) ?
# --------------------------------------------------------------------------------------

# Référence NON AMBIGUË au corpus collecté (« dans la base », « aujourd'hui », « liste »…).
# Sa présence tranche en faveur de la base, même dans une tournure interrogative générale.
_CORPUS_RE = re.compile(
    r"en base|dans la base|de la base|base de connaissances|database|catalogue|collect[ée]|"
    r"aujourd|ce mois|cette ann[ée]e|\bliste[rz]?\b|affiche|combien|nos sources|mes sources|"
    r"nos (?:cve|vuln)|mes (?:cve|vuln)", re.I)

# Tournure DÉFINITIONNELLE : question sur un concept, pas sur le contenu du corpus.
# Prioritaire sur `_TOPIC_RE` (« différence entre CVE, CWE et CVSS » = concept, pas catalogue).
_DEFINITION_RE = re.compile(
    r"qu.est.ce que|qu.est.ce qu|c.est quoi|que signifie|d[ée]finition|diff[ée]rence entre|"
    r"[àa] quoi sert|what\s+is\s|what.s the difference", re.I)

# Sujet AMBIGU : peut désigner le corpus (« vulnérabilités Apache ») aussi bien qu'un concept.
# En l'absence de tournure définitionnelle, on privilégie la base — c'est le cœur du produit.
_TOPIC_RE = re.compile(r"\bcve\b|vuln[ée]rabilit|bulletin|\b[ée]diteur\b", re.I)

# Tournures de question générale plus faibles (méthode, conseil, pédagogie). Elles ne
# court-circuitent PAS la base : elles autorisent seulement le repli externe quand la
# recherche n'a rien donné (« comment corriger… ? » mérite mieux qu'un « non disponible »).
_GENERAL_RE = re.compile(
    r"bonnes?\s+pratiques?|comment\s|pourquoi\s|peux-tu m.expliquer|explique-moi|"
    r"how\s+(do|to|does|can)|why\s|best\s+practices?|donne-moi des conseils|"
    r"recommandations?\s+g[ée]n[ée]rales?|exemple\s+de|what\s+are", re.I)

# Filtres structurés : leur présence prouve que la question interroge le catalogue de CVE.
_DB_FILTER_KEYS = ("severity", "cvss_min", "date_from", "exploit")


def _has_db_filters(p: dict) -> bool:
    return any(p.get(k) for k in _DB_FILTER_KEYS) or p["intent"] in ("count", "top_vendor")


def _mentions_database(question: str) -> bool:
    """La question évoque-t-elle le corpus CyberWatch AI (référence explicite ou sujet CVE) ?"""
    return bool(_CORPUS_RE.search(question) or _TOPIC_RE.search(question))


def classify_scope(question: str, p: dict) -> str:
    """« internal » (interroger la base) | « external » (connaissance générale) | « auto ».

    Seul « external » court-circuite la base ; « internal » et « auto » l'interrogent toutes
    deux, et c'est l'absence de résultat qui déclenche ensuite un éventuel repli externe
    (voir `answer_question`). L'ordre des tests est significatif :

      1. filtres structurés / identifiant CVE   -> la base, sans discussion ;
      2. référence explicite au corpus          -> la base, même en tournure interrogative ;
      3. tournure définitionnelle SANS éditeur  -> question de concept, on part en externe ;
      4. sujet CVE ou éditeur identifié         -> la base ;
      5. tournure générale faible (« comment… ») -> la base d'abord, externe si elle est vide.

    L'étape 5 est volontairement prudente : « Comment corriger la faille Fortinet ? » doit
    profiter des CVE collectées avant de retomber sur une réponse générique.
    """
    if p["cve_ids"] or _has_db_filters(p):
        return "internal"
    if _CORPUS_RE.search(question):
        return "internal"
    if _DEFINITION_RE.search(question) and not p["vendor"]:
        return "external"
    if _TOPIC_RE.search(question) or p["vendor"]:
        return "internal"
    return "auto"


# --------------------------------------------------------------------------------------
# 2) Récupération en base (point d'extension vers une recherche vectorielle)
# --------------------------------------------------------------------------------------

def _build_query(p: dict) -> dict:
    q: dict = {}
    if p["cve_ids"]:
        q["cve_id"] = {"$in": p["cve_ids"]}
    if p["severity"]:
        q["severity"] = p["severity"]
    if p["cvss_min"] is not None:
        q["cvss_score"] = {"$gte": p["cvss_min"]}
    if p["exploit"]:
        q["exploit_status"] = {"$regex": "exploit|poc|kev|actively", "$options": "i"}
    if p["date_from"] or p["date_to"]:
        rng = {}
        if p["date_from"]:
            rng["$gte"] = p["date_from"]
        if p["date_to"]:
            rng["$lte"] = p["date_to"]
        q[p["date_field"]] = rng
    terms = ([p["vendor"]] if p["vendor"] else []) + p["keywords"]
    for t in terms:
        # Mot ENTIER (word-boundary) -> « est » ne matche pas « request », précision accrue.
        rx = {"$regex": r"\b" + re.escape(t) + r"\b", "$options": "i"}
        q.setdefault("$and", []).append(
            {"$or": [{"vendor": rx}, {"product": rx}, {"affected_products": rx},
                     {"title": rx}, {"description": rx}]})
    return q


async def retrieve(db, parsed: dict, limit: int = 40) -> tuple[list[dict], int]:
    """Récupère les documents CVE pertinents (structurés + texte). Renvoie (docs, total)."""
    query = _build_query(parsed)
    total = await db.cves.count_documents(query)
    proj = {"cve_id": 1, "title": 1, "description": 1, "product": 1, "vendor": 1, "affected_products": 1,
            "severity": 1, "cvss_score": 1, "cwe": 1, "vuln_type": 1, "exploit_status": 1,
            "published_at": 1, "updated_at": 1, "references": 1, "solution": 1, "sources": 1,
            "confirmed_sources": 1, "history": 1, "detail_url": 1}
    docs = await db.cves.find(query, proj).sort([("cvss_score", -1), ("published_at", -1)]).to_list(limit)
    return docs, total


# --------------------------------------------------------------------------------------
# 3) Synthèse ANCRÉE (jamais d'invention) + sources + confiance
# --------------------------------------------------------------------------------------

_SEV_FR_LABEL = {"critical": "critique", "high": "élevée", "medium": "moyenne", "low": "faible"}


def _fmt_date(d):
    return d.strftime("%d/%m/%Y") if isinstance(d, datetime) else (str(d)[:10] if d else "—")


def _doc_sources(doc: dict) -> list[str]:
    names = [s.get("name") for s in (doc.get("sources") or []) if s.get("name")]
    return list(dict.fromkeys(names + (doc.get("confirmed_sources") or [])))


def _result_row(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")) if doc.get("_id") else None,
        "cve_id": doc.get("cve_id"), "title": doc.get("title"),
        "product": doc.get("product") or ", ".join(doc.get("affected_products") or [])[:80] or None,
        "vendor": doc.get("vendor"), "severity": doc.get("severity"), "cvss_score": doc.get("cvss_score"),
        "cwe": doc.get("cwe") or doc.get("vuln_type"), "exploit_status": doc.get("exploit_status"),
        "published_at": doc.get("published_at"), "updated_at": doc.get("updated_at"),
        "references": (doc.get("references") or [])[:4], "sources": _doc_sources(doc),
        "detail_url": doc.get("detail_url"),
    }


async def synthesize(db, question: str, parsed: dict, docs: list[dict], total: int) -> dict:
    intent = parsed["intent"]

    # Rien trouvé -> réponse « non disponible » (jamais d'invention).
    if not docs and intent not in ("count",):
        return {"answer": NOT_FOUND, "results": [], "sources": [], "confidence": "none", "count": 0}

    # Intention : compter
    if intent == "count":
        crit = _describe_filters(parsed)
        return {"answer": f"{total} vulnérabilité(s) correspondent à votre demande{crit}.",
                "results": [_result_row(d) for d in docs[:10]],
                "sources": _union_sources(docs), "confidence": "high", "count": total}

    # Intention : éditeur avec le plus de vulnérabilités (agrégation)
    if intent == "top_vendor":
        pipe = [{"$match": _build_query(parsed)},
                {"$match": {"vendor": {"$nin": [None, "", "n/a", "Unknown"]}}},
                {"$group": {"_id": "$vendor", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 8}]
        rows = [r async for r in db.cves.aggregate(pipe)]
        if not rows:
            return {"answer": NOT_FOUND, "results": [], "sources": [], "confidence": "none", "count": 0}
        top = rows[0]
        lst = " · ".join(f"{r['_id']} ({r['n']})" for r in rows)
        return {"answer": f"L'éditeur le plus touché est {top['_id']} avec {top['n']} vulnérabilité(s). "
                          f"Classement : {lst}.",
                "results": [_result_row(d) for d in docs[:8]], "sources": _union_sources(docs),
                "confidence": "high", "count": total}

    # Intention : ce qui a changé pour une CVE (historique)
    if intent == "changes" and docs:
        d = docs[0]
        hist = d.get("history") or []
        if not hist:
            return {"answer": f"Aucune modification enregistrée pour {d['cve_id']} depuis sa collecte "
                              f"(complétude actuelle disponible sur sa fiche).",
                    "results": [_result_row(d)], "sources": _doc_sources(d), "confidence": "medium", "count": 1}
        lines = []
        for h in hist[-8:]:
            fields = ", ".join((h.get("changes") or {}).keys())
            lines.append(f"• {_fmt_date(h.get('ts'))} : {fields or 'modifiée'}")
        return {"answer": f"Évolution de {d['cve_id']} ({len(hist)} modification(s) enregistrée(s)) :\n"
                          + "\n".join(lines),
                "results": [_result_row(d)], "sources": _doc_sources(d), "confidence": "high", "count": 1}

    # Intention : comparer les sources d'une CVE (ex. DGSSI vs CISA)
    if intent == "compare" and docs:
        d = docs[0]
        srcs = _doc_sources(d)
        return {"answer": f"{d['cve_id']} est présente dans {len(srcs)} source(s) : {', '.join(srcs) or '—'}. "
                          f"Sévérité {_SEV_FR_LABEL.get(d.get('severity'), '—')}, CVSS {d.get('cvss_score') or '—'}. "
                          f"Toutes les références collectées sont consolidées ci-dessous.",
                "results": [_result_row(d)], "sources": srcs, "confidence": "high", "count": 1}

    # Intention : expliquer UNE CVE
    if intent == "explain" and docs:
        d = docs[0]
        row = _result_row(d)
        title = (d.get("title") or d.get("product") or "").strip()
        head = title if title.upper().startswith(d["cve_id"]) else f"{d['cve_id']} — {title}".strip(" —")
        parts = [head, (d.get("description") or "")[:400]]
        parts.append(f"Sévérité : {_SEV_FR_LABEL.get(d.get('severity'), '—')} · CVSS : {d.get('cvss_score') or '—'} · "
                     f"Type : {d.get('cwe') or d.get('vuln_type') or '—'}.")
        if d.get("solution"):
            parts.append(f"Remédiation : {d['solution'][:300]}")
        return {"answer": "\n\n".join(p for p in parts if p), "results": [row],
                "sources": _doc_sources(d), "confidence": "high", "count": 1}

    # Défaut : liste/synthèse de vulnérabilités
    crit = _describe_filters(parsed)
    head = f"{total} vulnérabilité(s) trouvée(s){crit}."
    if total > len(docs):
        head += f" Voici les {len(docs)} plus pertinentes (triées par CVSS)."
    return {"answer": head, "results": [_result_row(d) for d in docs],
            "sources": _union_sources(docs), "confidence": "high" if total else "none", "count": total}


def _describe_filters(p: dict) -> str:
    bits = []
    if p["vendor"]:
        bits.append(f"éditeur {p['vendor']}")
    if p["keywords"]:
        bits.append("produit « " + " ".join(p["keywords"]) + " »")
    if p["severity"]:
        bits.append(f"sévérité {_SEV_FR_LABEL.get(p['severity'], p['severity'])}")
    if p["cvss_min"] is not None:
        bits.append(f"CVSS ≥ {p['cvss_min']}")
    if p["exploit"]:
        bits.append("exploit connu")
    if p["date_from"]:
        field = "mise à jour" if p["date_field"] == "updated_at" else "publiées"
        bits.append(f"{field} entre {_fmt_date(p['date_from'])} et {_fmt_date(p['date_to'])}")
    return (" (" + ", ".join(bits) + ")") if bits else ""


def _union_sources(docs: list[dict]) -> list[str]:
    out: list[str] = []
    for d in docs:
        for s in _doc_sources(d):
            if s not in out:
                out.append(s)
    return out[:12]


# --------------------------------------------------------------------------------------
# 4) Narration LLM d'une réponse ANCRÉE — reformulation seulement, jamais d'ajout
# --------------------------------------------------------------------------------------

# Intentions dont la réponse déterministe gagne à être reformulée en langage naturel.
_NARRATE_INTENTS = {"list", "summarize", "count", "top_vendor", "compare"}


def _narration_facts(docs: list[dict], limit: int = 15) -> list[dict]:
    """Faits bruts transmis au LLM : uniquement des champs réellement présents en base."""
    facts = []
    for d in docs[:limit]:
        facts.append({
            "cve_id": d.get("cve_id"),
            "produit": d.get("product") or d.get("vendor"),
            "severite": d.get("severity"),
            "cvss": d.get("cvss_score"),
            "type": d.get("cwe") or d.get("vuln_type"),
            "exploitation": d.get("exploit_status"),
            "publiee_le": _fmt_date(d.get("published_at")),
            "sources": _doc_sources(d)[:4],
        })
    return facts


async def narrate(question: str, parsed: dict, result: dict, docs: list[dict],
                  total: int) -> dict:
    """Réécrit la réponse ancrée en français naturel à partir des SEULS faits récupérés.

    En cas d'indisponibilité du LLM, la réponse déterministe est conservée telle quelle.
    """
    if not llm.available() or not docs or parsed["intent"] not in _NARRATE_INTENTS:
        return result
    payload = {
        "question_du_consultant": question,
        "nombre_total_de_cve_correspondantes": total,
        "filtres_appliques": _describe_filters(parsed).strip(" ()") or None,
        "cve_recuperees_en_base": _narration_facts(docs),
        "synthese_deterministe": result["answer"],
    }
    prompt = (
        "Voici le résultat RÉEL d'une recherche dans la base interne CyberWatch AI :\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        + "\n\nRédige une réponse courte (3 à 6 phrases, sans titre de section) qui répond "
        "directement à la question du consultant et met en avant ce qui compte : volume, "
        "sévérités dominantes, CVE les plus critiques, exploitation active éventuelle. "
        "Les identifiants, scores CVSS et dates doivent être repris EXACTEMENT tels quels. "
        "N'ajoute aucune CVE, aucun produit et aucun chiffre absent des données ci-dessus. "
        "Ne répète pas la liste complète : elle est déjà affichée sous ta réponse."
    )
    text = await llm.generate(prompt, max_tokens=600)
    if text:
        result["answer"] = text.strip()
        result["generated_by"] = "llm"
    return result


# --------------------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------------------

def _echo_filters(parsed: dict) -> dict:
    return {k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in parsed.items() if k not in ("raw",) and v not in (None, [], False)}


def _finalize(result: dict, parsed: dict) -> dict:
    """Complète la réponse avec les métadonnées communes (portée, filtres, origine)."""
    result.setdefault("scope", "internal")
    result.setdefault("generated_by", "grounded")
    result["filters"] = _echo_filters(parsed)
    return result


async def answer_question(db, question: str, mode: str | None = None) -> dict:
    """Point d'entrée de l'assistant.

    `mode` (executive/technical/changes) force un résumé structuré ; sinon l'intention et la
    PORTÉE sont déduites de la question :
      • question sur la base  -> récupération MongoDB + synthèse ancrée (reformulée par le LLM) ;
      • question générale     -> réponse externe explicitement étiquetée (external.py) ;
      • CVE inconnue en base  -> réponse externe qui commence par le dire.
    """
    # Imports tardifs (évitent un cycle avec summary/external qui référencent ce module).
    from app.backend.services.assistant import external, summary

    parsed = parse_query(question)
    style = mode if mode in summary.VALID_STYLES else parsed.get("summary_style")
    wants_summary = style is not None or parsed["intent"] in ("summarize", "explain", "changes")

    # Portée : question de connaissance générale -> on ne fouille même pas la base
    # (un mode de résumé explicite reste, lui, toujours une demande sur la base).
    if mode is None and classify_scope(question, parsed) == "external" and external.enabled():
        return _finalize(await external.answer_general(question), parsed)

    if wants_summary:
        # Résumé d'UNE CVE ciblée (fiche CVE, bulletin CVE, ou question en langage naturel).
        if parsed["cve_ids"]:
            cve_id = parsed["cve_ids"][0]
            doc = await db.cves.find_one({"cve_id": cve_id})
            if doc is None:
                # CVE absente de la base : on le dit, puis le LLM peut documenter la CVE.
                if external.enabled():
                    return _finalize(await external.answer_unknown_cve(cve_id, question), parsed)
                return _finalize({"answer": NOT_FOUND, "results": [], "sources": [],
                                  "confidence": "none", "count": 0}, parsed)
            st = style or ("changes" if parsed["intent"] == "changes" else "technical")
            return _finalize(await summary.summarize_cve(db, doc, st), parsed)
        # Résumé de GROUPE (bulletin produit/éditeur) : déclenché par un mode explicite + cible.
        if style in ("executive", "technical") and (parsed["vendor"] or parsed["keywords"]):
            docs, total = await retrieve(db, parsed, limit=200)
            label = parsed["vendor"] or " ".join(parsed["keywords"])
            return _finalize(await summary.summarize_group(db, docs, label, total=total), parsed)

    limit = 60 if parsed["intent"] in ("summarize", "list") else 40
    docs, total = await retrieve(db, parsed, limit=limit)

    # Rien en base : bascule externe SAUF si la question interroge explicitement le catalogue
    # de CVE — dans ce cas « aucun résultat » EST la bonne réponse, et elle reste ancrée.
    # Une tournure de conseil (« comment corriger… ? ») autorise malgré tout le repli externe.
    if not docs and external.enabled() and not _has_db_filters(parsed):
        if parsed["cve_ids"]:
            return _finalize(await external.answer_unknown_cve(parsed["cve_ids"][0], question),
                             parsed)
        if not _mentions_database(question) or _GENERAL_RE.search(question):
            return _finalize(await external.answer_general(question), parsed)

    result = await synthesize(db, question, parsed, docs, total)
    result = await narrate(question, parsed, result, docs, total)
    return _finalize(result, parsed)
