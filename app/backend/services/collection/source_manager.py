"""Gestionnaire des sources : fournit les sources à collecter depuis la base de données.

Aucune source n'est codée en dur : seules les sources ajoutées et VALIDÉES par l'admin
sont utilisées. Une nouvelle source validée est automatiquement prise en compte.
"""

# Statuts considérés comme « actifs » pour la collecte.
ACTIVE_STATUSES = ("validated",)


async def get_active_sources(db) -> list[dict]:
    """Toutes les sources validées et actives (non désactivées), telles qu'enregistrées."""
    cursor = db.sources.find({"status": {"$in": list(ACTIVE_STATUSES)}})
    return await cursor.to_list(1000)
