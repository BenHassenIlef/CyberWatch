"""Sauvegarde en base : insère les nouvelles CVE, met à jour les CVE existantes modifiées
(uniquement les champs changés), conserve un historique, et signale les mises à jour
importantes pour la notification du consultant.

RÈGLE DE NOTIFICATION : une notification n'est créée que si la VRAIE date de publication de
la CVE (published_at) est dans la fenêtre configurée (CVE_NOTIFY_WINDOW_DAYS). Une ancienne
CVE simplement redécouverte aujourd'hui est enregistrée mais NE génère PAS de notification.
On ne se base JAMAIS sur collected_at / detected_at pour cette décision."""
from datetime import datetime, timedelta

from app.backend.core.config import settings
from app.backend.services.collection import provenance
from app.backend.services.collection.schema import (
    CANONICAL_KEYS, IMPORTANT_FIELDS, LIST_FIELDS, completeness, content_hash, is_recent)
from app.backend.utils import utcnow

# Champs comparables (on ne touche ni à l'identifiant ni à l'URL d'origine).
_COMPARABLE = tuple(k for k in CANONICAL_KEYS if k not in ("cve_id", "detail_url"))
# Champs texte « riches » : on ne remplace JAMAIS une valeur détaillée par une plus courte.
_RICH_TEXT = ("description", "solution", "impact")

# --------------------------------------------------------------------------------------
# DATE DE PUBLICATION — règle de monotonie
#
# La date de publication d'une CVE est un FAIT figé : elle ne peut pas avancer dans le temps.
# Or un avis (ANCS, DGSSI, SecAlerts…) republié aujourd'hui et citant une CVE de mai fournit
# la date de L'AVIS, pas celle de la CVE. Sans garde-fou, chaque nouvelle collecte repoussait
# `published_at` vers aujourd'hui — une CVE de 2008 s'est ainsi retrouvée datée de 2026.
#
# Règle : on n'accepte une nouvelle valeur que si elle est ANTÉRIEURE et crédible (correction
# légitime, ex. NVD révèle la vraie date). Toute valeur postérieure est ignorée.
# --------------------------------------------------------------------------------------

_CVE_ERA_START = datetime(1999, 1, 1)   # le programme CVE débute en 1999


def _naive(d):
    """Ramène en UTC naïf : les dates stockées le sont, `utcnow()` est « aware »."""
    return d.replace(tzinfo=None) if isinstance(d, datetime) and d.tzinfo else d


def accept_publication_date(new, old, collected_at=None, verifiee: bool = False) -> bool:
    """Faut-il remplacer la date de publication connue par la nouvelle ?

    Trois garde-fous, du plus evident au plus subtil :

    1. DATE ABERRANTE — anterieure au programme CVE (1999) ou dans le futur : refusee.

    2. POSTERIEURE A LA COLLECTE — on ne peut pas avoir decouvert une CVE AVANT qu'elle soit
       publiee. Une date plus recente que `collected_at` trahit donc une date de PAGE ou
       d'AVIS, pas celle de la vulnerabilite. Exception : une source d'AUTORITE peut
       legitimement publier apres coup une CVE d'abord reservee, d'ou le drapeau `verifiee`.

    3. MONOTONIE — une date de publication ne recule jamais vers le futur. Seule une
       correction vers le PASSE est acceptee.
    """
    new = _naive(new)
    if not isinstance(new, datetime):
        return False
    if new < _CVE_ERA_START or new > _naive(utcnow()) + timedelta(days=2):
        return False                      # date aberrante (trop ancienne ou dans le futur)

    # Impossible d'avoir collecte une CVE avant sa publication — sauf autorite explicite.
    coll = _naive(collected_at)
    if not verifiee and isinstance(coll, datetime) and new > coll + timedelta(days=1):
        return False

    old = _naive(old)
    if not isinstance(old, datetime):
        return True                       # rien de connu : on prend
    return new < old                      # UNIQUEMENT une correction vers le passé


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


def _valeur_lisible(v) -> str:
    """Valeur affichable dans un libellé de changement, bornée en longueur."""
    if v in (None, "", []):
        return "non renseigné"
    if isinstance(v, list):
        return f"{len(v)} élément(s)"
    return str(v)[:60]


def decrire_changements(changes: dict) -> list[str]:
    """Libellés DÉTAILLÉS d'un ensemble de modifications, avec les valeurs avant/après.

    « Mise à jour de CVE » ne dit rien à un consultant : il doit savoir si c'est le score qui
    a été réévalué, un correctif qui vient de paraître, ou l'exploitation qui est confirmée —
    trois situations qui n'appellent pas la même réaction. Les valeurs sont donc restituées
    telles qu'elles ont changé (« Score CVSS : 7.1 → 9.8 »), et jamais interprétées.
    """
    out = []
    for champ, v in (changes or {}).items():
        label = _CHANGE_LABELS.get(champ, champ)
        if isinstance(v, dict) and "ajout" in v:
            out.append(f"{label} : {v['ajout']} ajout(s)")
        elif isinstance(v, dict) and ("old" in v or "new" in v):
            avant, apres = _valeur_lisible(v.get("old")), _valeur_lisible(v.get("new"))
            out.append(f"{label} : {avant} → {apres}" if v.get("old") not in (None, "", [])
                       else f"{label} : {apres} (ajouté)")
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
                # Le champ est VIDE : c'est justement le cas de toutes les CVE issues d'un
                # avis depuis que le collecteur ne renseigne plus `published_at`. Sans ce
                # controle, la premiere date venue — souvent celle de la page — s'installerait.
                if key == "published_at" and not accept_publication_date(
                        newv, None, existing.get("collected_at"),
                        verifiee=((rec.get("provenance") or {}).get("cve_published_at")
                                  or {}).get("confidence") == "verified"):
                    continue
                set_fields[key] = newv
                if key in IMPORTANT_FIELDS:
                    changes[key] = {"old": None, "new": newv}
                    important = True
            elif newv != oldv:
                # Ne JAMAIS remplacer un texte riche par un plus court/pauvre (garder le meilleur).
                if key in _RICH_TEXT and len(str(newv)) < len(str(oldv)):
                    continue
                # La date de publication ne recule jamais vers le futur (voir plus haut).
                if key == "published_at" and not accept_publication_date(
                        newv, oldv, existing.get("collected_at"),
                        verifiee=((rec.get("provenance") or {}).get("cve_published_at")
                                  or {}).get("confidence") == "verified"):
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

        # Si la publication a été CORRIGÉE vers une date antérieure, la borne basse observée
        # (`first_published`) doit suivre : elle sert de référence de réparation.
        if "published_at" in set_fields:
            fp = existing.get("first_published")
            if not isinstance(fp, datetime) or set_fields["published_at"] < fp:
                set_fields["first_published"] = set_fields["published_at"]

        # PROVENANCE — fusionnée champ par champ : une valeur vérifiée ne peut jamais être
        # remplacée par une valeur d'avis, quel que soit l'ordre des collectes.
        prov_new = rec.get("provenance") or {}
        if prov_new:
            prov_old = existing.get("provenance") or {}
            fusion = dict(prov_old)
            for champ, entree in prov_new.items():
                if provenance.should_replace(champ, prov_old.get(champ), entree):
                    fusion[champ] = entree
                    if entree.get("value") not in (None, "", []):
                        set_fields[champ] = entree["value"]
            if fusion != prov_old:
                set_fields["provenance"] = fusion
                set_fields["validation_status"] = provenance.validation_status(
                    {**existing, **set_fields, "provenance": fusion})

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
