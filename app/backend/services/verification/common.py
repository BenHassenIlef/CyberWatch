"""Structures et utilitaires partagés par les modules de vérification.

Un « check » est un dict :
    {"label": str, "passed": bool | None, "weight": float, "detail": str | None}

`passed` :
    True  -> critère satisfait
    False -> critère non satisfait
    None  -> indéterminé (ex. API externe injoignable) — n'est jamais pénalisant.
"""


def make_check(label: str, passed: bool | None, weight: float = 1.0, detail: str | None = None) -> dict:
    return {"label": label, "passed": passed, "weight": weight, "detail": detail}


def weighted_score(checks: list[dict], neutral: int = 50) -> int:
    """Score 0–100 = somme des poids des checks réussis / somme des poids déterminés.

    Les checks indéterminés (`passed is None`) sont exclus du calcul afin de ne pas pénaliser.
    Si aucun check n'est déterminable, renvoie la valeur neutre.
    """
    determined = [c for c in checks if c["passed"] is not None]
    if not determined:
        return neutral
    total = sum(c["weight"] for c in determined)
    if total == 0:
        return neutral
    gained = sum(c["weight"] for c in determined if c["passed"])
    return round(100 * gained / total)


def simple_score(checks: list[dict]) -> int:
    """Score 0–100 basé uniquement sur le ratio de checks booléens réussis."""
    boolean = [c for c in checks if c["passed"] is not None]
    if not boolean:
        return 0
    return round(100 * sum(1 for c in boolean if c["passed"]) / len(boolean))
