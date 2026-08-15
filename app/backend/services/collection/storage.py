"""Sauvegarde en base : insère les nouvelles CVE, met à jour les CVE existantes modifiées
(uniquement les champs changés), conserve un historique, et signale les mises à jour
importantes pour la notification du consultant.

RÈGLE DE NOTIFICATION : une notification n'est créée que si la VRAIE date de publication de
la CVE (published_at) est dans la fenêtre configurée (CVE_NOTIFY_WINDOW_DAYS). Une ancienne
CVE simplement redécouverte aujourd'hui est enregistrée mais NE génère PAS de notification.
On ne se base JAMAIS sur collected_at / detected_at pour cette décision."""
from app.backend.core.config import settings
from app.backend.services.collection.schema import (
    CANONICAL_KEYS, IMPORTANT_FIELDS, LIST_FIELDS, completeness, content_hash, is_recent)
from app.backend.utils import utcnow

# Champs comparables (on ne touche ni à l'identifiant ni à l'URL d'origine).
_COMPARABLE = tuple(k for k in CANONICAL_KEYS if k not in ("cve_id", "detail_url"))
# Champs texte « riches » : on ne remplace JAMAIS une valeur détaillée par une plus courte.
_RICH_TEXT = ("description", "solution", "impact")

_CHANGE_LABELS = {
    "cvss_score": "Score CVSS", "cvss_vector": "Vecteur CVSS", "severity": "Sévérité", "cwe": "CWE",
    "vuln_type": "Type", "solution": "Solution", "references": "Références", "vendor": "Éditeur",
    "product": "Produit", "affected_products": "Produits affectés", "affected_systems": "Systèmes affectés",
    "affected_versions": "Versions affectées", "description": "Description", "patch_links": "Correctifs",
}


def _classify_sync(changes: dict, content_changed: bool) -> str:
    """État de synchro : ENRICHED (uniquement des champs vides désormais remplis) vs UPDATED
    (une valeur existante a changé) vs UNCHANGED."""
    if not changes:
        return "updated" if content_changed else "unchanged"
    only_fills = all(("ajout" in v) or (isinstance(v, dict) and v.get("old") in (None, "", []))
                     for v in changes.values())
    return "enriched" if only_fills else "updated"


def _change_summary(changes: dict) -> list[str]:
    """Libellés lisibles des modifications (« Score CVSS ajouté », « Références enrichies »…)."""
    out = []
    for k, v in changes.items():
        label = _CHANGE_LABELS.get(k, k)
        if isinstance(v, dict) and "ajout" in v:
            out.append(f"{label} enrichi(e)s")
        elif isinstance(v, dict) and v.get("old") in (None, "", []):
            out.append(f"{label} ajouté(e)")
        else:
            out.append(f"{label} mis(e) à jour")
    return out


def _diff(existing: dict, rec: dict) -> tuple[dict, dict, bool]:
    """Calcule les champs à mettre à jour et les changements importants.

    Renvoie (set_fields, changes, important).
    - Listes : union (on n'enlève jamais une donnée déjà confirmée).
    - Scalaires : on complète si vide, on met à jour si la valeur diffère.
    """
    set_fields: dict = {}
    changes: dict = {}
    important = False
    for key in _COMPARABLE:
        newv, oldv = rec.get(key), existing.get(key)
        if key in LIST_FIELDS:
            union = list(dict.fromkeys((oldv or []) + (newv or [])))
            if len(union) != len(oldv or []):
                set_fields[key] = union
                if key in IMPORTANT_FIELDS:
                    changes[key] = {"ajout": len(union) - len(oldv or [])}
                    important = True
        else:
            if newv in (None, "", []):
                continue
            if not oldv:
                set_fields[key] = newv
                if key in IMPORTANT_FIELDS:
                    changes[key] = {"old": None, "new": newv}
                    important = True
            elif newv != oldv:
                # Ne JAMAIS remplacer un texte riche par un plus court/pauvre (garder le meilleur).
                if key in _RICH_TEXT and len(str(newv)) < len(str(oldv)):
                    continue
                set_fields[key] = newv
                if key in IMPORTANT_FIELDS:
                    changes[key] = {"old": oldv, "new": newv}
                    important = True
    return set_fields, changes, important


async def save_records(db, records: list[dict]) -> dict:
    """Insère les nouvelles CVE ; met à jour les existantes (champs modifiés + historique).

    Renvoie {inserted, notified_new, updated, notified_updates, already_known, sources_added,
    important_updates}.
    """
    window = settings.CVE_NOTIFY_WINDOW_DAYS
    inserted = notified_new = updated = notified_updates = already = sources_added = important_updates = 0
    for rec in records:
        existing = await db.cves.find_one({"cve_id": rec["cve_id"]})
        if not existing:
            # Notification UNIQUEMENT si la CVE a été réellement PUBLIÉE récemment.
            recent = is_recent(rec.get("published_at"), window)
            now = utcnow()
            rec["collected_at"] = now
            rec["is_new"] = recent          # ancienne CVE redécouverte -> pas de notification
            rec["is_updated"] = False
            rec["history"] = []
            # Métadonnées de synchronisation incrémentale (moteur type OpenCVE).
            rec["first_published"] = rec.get("published_at")
            rec["last_updated"] = rec.get("updated_at") or rec.get("published_at")
            rec["last_collected"] = now
            rec["last_sync"] = now
            rec["last_hash"] = content_hash(rec)
            rec["sync_status"] = "new"
            rec["information_completeness"] = completeness(rec)
            rec["change_summary"] = []
            rec["title"] = rec.get("title") or f"{rec['cve_id']} — {rec.get('product') or rec.get('vuln_type') or 'CVE'}"
            await db.cves.insert_one(rec)
            inserted += 1
            if recent:
                notified_new += 1
            continue

        already += 1
        set_fields, changes, important = _diff(existing, rec)

        # PÉRIMÈTRE DE SURVEILLANCE — une CVE peut affecter plusieurs produits (découverts au fil des
        # collectes, à mesure que l'enrichissement précise l'éditeur/le produit) : on UNIONNE
        # `monitored_products` / `domains` et on renseigne le produit primaire s'il manquait.
        for arr_key in ("monitored_products", "domains"):
            new_arr = rec.get(arr_key) or []
            if new_arr:
                union = list(dict.fromkeys((existing.get(arr_key) or []) + new_arr))
                if union != (existing.get(arr_key) or []):
                    set_fields[arr_key] = union
        if rec.get("monitored_product") and not existing.get("monitored_product"):
            set_fields["monitored_product"] = rec["monitored_product"]
        if rec.get("domain") and not existing.get("domain"):
            set_fields["domain"] = rec["domain"]

        # TRADUCTION — les champs français produits par l'agent voyagent avec l'enregistrement
        # mais ne font pas partie des champs canoniques comparés par `_diff` : on les persiste
        # explicitement. Une traduction déjà réussie n'est jamais écrasée par un échec ultérieur.
        for key in ("title_fr", "description_fr", "impact_fr", "solution_fr"):
            if rec.get(key) and rec[key] != existing.get(key):
                set_fields[key] = rec[key]
        new_status = rec.get("translation_status")
        if new_status and not (new_status == "failed" and existing.get("translation_status") == "completed"):
            set_fields["translation_status"] = new_status
            for meta in ("translated_fields", "translation_error", "translation_warning"):
                if rec.get(meta) is not None:
                    set_fields[meta] = rec[meta]

        # Sources admin (liste) + sources officielles confirmées : union.
        known = {str(s.get("source_id")) for s in (existing.get("sources") or [])}
        new_sources = [s for s in rec.get("sources", []) if str(s.get("source_id")) not in known]
        conf = list(dict.fromkeys((existing.get("confirmed_sources") or []) + (rec.get("confirmed_sources") or [])))
        if conf != (existing.get("confirmed_sources") or []):
            set_fields["confirmed_sources"] = conf

        # Synchronisation : la CVE est revue à chaque cycle (jamais ignorée car « déjà connue »).
        now = utcnow()
        merged_view = {**existing, **set_fields}
        new_hash = content_hash(merged_view)
        new_completeness = completeness(merged_view)
        base_set: dict = {"last_collected": now, "last_sync": now,
                          "information_completeness": new_completeness, "last_hash": new_hash}
        content_changed = new_hash != existing.get("last_hash")
        base_set["sync_status"] = _classify_sync(changes, content_changed)

        if not set_fields and not new_sources and not content_changed:
            # Rien de neuf : on note juste le passage de synchronisation (last_sync / last_collected).
            await db.cves.update_one({"_id": existing["_id"]}, {"$set": base_set})
            continue

        update_doc: dict = {"$set": {**base_set, **set_fields}}
        if new_sources:
            update_doc["$push"] = {"sources": {"$each": new_sources}}
        if changes:
            important_updates += 1
            # Notification de mise à jour UNIQUEMENT si la modification est RÉCENTE (la source
            # a modifié la CVE dans la fenêtre), et jamais pour une simple complétion de données
            # sur une CVE ancienne.
            recent_mod = is_recent(rec.get("updated_at") or existing.get("updated_at"), window)
            hist = {"ts": now, "changes": changes}
            update_doc.setdefault("$push", {})["history"] = hist
            update_doc["$set"].update({
                "last_important_update": now, "is_updated": True,
                "change_summary": _change_summary(changes),
            })
            if recent_mod:
                update_doc["$set"]["update_unread"] = True  # déclenche une notification
                notified_updates += 1
        if set_fields:
            update_doc["$set"]["updated_at"] = rec.get("updated_at") or existing.get("updated_at")

        await db.cves.update_one({"_id": existing["_id"]}, update_doc)
        if set_fields:
            updated += 1
        sources_added += len(new_sources)

    return {"inserted": inserted, "notified_new": notified_new, "updated": updated,
            "notified_updates": notified_updates, "already_known": already,
            "sources_added": sources_added, "important_updates": important_updates}
