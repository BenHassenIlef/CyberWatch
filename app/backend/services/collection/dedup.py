"""Déduplication : une seule entrée par identifiant CVE, en fusionnant les champs et en
conservant la liste de TOUTES les sources où la CVE a été trouvée (points 7 et 8)."""
from app.backend.services.collection.schema import merge_records


def deduplicate(records: list[dict]) -> list[dict]:
    """Fusionne les enregistrements portant le même cve_id. Renvoie la liste unique."""
    by_id: dict[str, dict] = {}
    for rec in records:
        cid = rec.get("cve_id")
        if not cid:
            continue
        if cid in by_id:
            merge_records(by_id[cid], rec)
        else:
            by_id[cid] = rec
    return list(by_id.values())
