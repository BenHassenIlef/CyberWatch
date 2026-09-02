"""CHIFFRES RENDUS PAR L'ASSISTANT — deux défauts constatés sur la base réelle.

Les deux produisaient un nombre FAUX annoncé avec une confiance « élevée ». C'est la pire
forme d'erreur pour un travail de société : un chiffre assuré n'appelle aucune vérification,
il est recopié tel quel dans un rapport.

  1. PÉRIODE IGNORÉE. « Combien de CVE critiques collectées cette semaine ? » répondait
     1 499 — le total de la base depuis toujours — au lieu de 25. Ni « cette semaine », ni
     « les 7 derniers jours », ni « hier » n'étaient reconnus, et « collectée » n'orientait
     pas la recherche vers la date d'entrée en base.

  2. EXTRAIT PRIS POUR LA POPULATION. Les documents sont triés par CVSS décroissant puis
     coupés à 40. Sur 2 043 vulnérabilités Microsoft, le modèle ne recevait que les 40 plus
     graves — toutes critiques — et en concluait que « la quasi-totalité » l'était, quand
     10 % le sont. Le modèle ne fabulait pas : il décrivait ce qu'on lui montrait.

Aucun appel réseau : l'analyse est pure, la base est un double.
"""
from datetime import datetime, timedelta

import pytest

from app.backend.services.assistant import rag


# ---------------------------------------------------------------------------------------
# 1. Périodes
# ---------------------------------------------------------------------------------------

def test_cette_semaine_part_du_lundi():
    """« Cette semaine » désigne la semaine EN COURS, comme « ce mois » part du 1er."""
    p = rag.parse_query("Combien de CVE critiques cette semaine ?")
    assert p["date_from"] is not None, "la période n'était pas reconnue : la base entière était comptée"
    assert p["date_from"].weekday() == 0
    assert p["date_from"] <= rag._utcnow()


def test_les_derniers_jours_sont_une_fenetre_glissante():
    """« Derniers » ne désigne pas une période calendaire mais une fenêtre qui glisse."""
    p = rag.parse_query("Les CVE des 7 derniers jours")
    ecart = rag._utcnow() - p["date_from"]
    assert timedelta(days=6, hours=23) < ecart < timedelta(days=7, hours=1)


@pytest.mark.parametrize("question, jours", [
    ("CVE des 30 derniers jours", 30),
    ("vulnerabilites des 3 derniers jours", 3),
    ("last 14 days", 14),
])
def test_le_nombre_de_jours_demande_est_respecte(question, jours):
    p = rag.parse_query(question)
    ecart = rag._utcnow() - p["date_from"]
    assert abs(ecart - timedelta(days=jours)) < timedelta(hours=1)


def test_hier_ne_couvre_que_la_veille():
    """Une question sur hier ne doit pas ramener celles d'aujourd'hui."""
    p = rag.parse_query("Quelles vulnerabilites ont ete publiees hier ?")
    veille = rag._utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    assert p["date_from"] == veille
    assert p["date_to"] == veille + timedelta(days=1)


def test_aucune_periode_ne_pose_aucun_filtre():
    """Sans mention de temps, la recherche porte sur toute la base : c'est voulu."""
    assert rag.parse_query("Les vulnerabilites Fortinet")["date_from"] is None


# ---------------------------------------------------------------------------------------
# 2. Champ de date : publiée, collectée, mise à jour
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("question, champ", [
    ("Combien de CVE collectees cette semaine ?", "collected_at"),
    ("Les CVE collectées aujourd'hui", "collected_at"),
    # Sans accent ET au pluriel : « mise? à jour » ne couvrait ni l'un ni l'autre, et la
    # question interrogeait alors la date de PUBLICATION — un compte exact pour une autre
    # question, l'erreur la plus difficile à repérer.
    ("Les CVE mises a jour cette semaine", "updated_at"),
    ("Les CVE mise à jour ce mois", "updated_at"),
    ("Les CVE publiees cette semaine", "published_at"),
])
def test_le_champ_de_date_suit_le_verbe_employe(question, champ):
    assert rag.parse_query(question)["date_field"] == champ


def test_le_libelle_nomme_le_champ_reellement_filtre():
    """Annoncer « publiées » sur un filtre de collecte ferait relire un chiffre juste sous
    une étiquette fausse."""
    p = {**rag.parse_query("CVE collectees cette semaine"), "date_to": rag._utcnow()}
    assert "collectées" in rag._describe_filters(p)
    assert "publiées" not in rag._describe_filters(p)


# ---------------------------------------------------------------------------------------
# 3. L'extrait n'est pas la population
# ---------------------------------------------------------------------------------------

class _CollectionFactice:
    """Base minimale : un total, un extrait, et une répartition par sévérité."""

    def __init__(self, total: int, extrait: list[dict], severites: dict | None = None,
                 agregation_cassee: bool = False):
        self._total, self._extrait = total, extrait
        self._severites = severites or {}
        self._cassee = agregation_cassee
        self.agregations = 0

    async def count_documents(self, _requete):
        return self._total

    def find(self, _requete, _projection=None):
        return self

    def sort(self, *_a, **_k):
        return self

    async def to_list(self, limite):
        return self._extrait[:limite]

    def aggregate(self, _pipeline):
        self.agregations += 1
        if self._cassee:
            raise RuntimeError("agrégation indisponible")

        async def _flux():
            for cle, n in self._severites.items():
                yield {"_id": cle, "n": n}

        return _flux()


class _BaseFactice:
    def __init__(self, collection):
        self.cves = collection


async def test_la_repartition_reelle_accompagne_un_extrait_partiel():
    """40 documents montrés sur 2 043 : la répartition doit venir de la requête ENTIÈRE."""
    extrait = [{"cve_id": f"CVE-2026-{i:05d}", "severity": "critical"} for i in range(40)]
    base = _BaseFactice(_CollectionFactice(
        2043, extrait, {"high": 839, "medium": 537, None: 449, "critical": 199, "low": 19}))
    analyse = rag.parse_query("Les vulnerabilites Microsoft")

    _, total = await rag.retrieve(base, analyse, limit=40)

    assert total == 2043
    repartition = analyse["repartition_severites"]
    assert repartition["critical"] == 199, "l'extrait est 100 % critique, la population 10 %"
    assert repartition["non renseignée"] == 449, "une sévérité absente doit être nommée, pas tue"


async def test_aucune_agregation_quand_l_extrait_est_la_population():
    """Tout est montré : la répartition n'apprendrait rien et coûterait une requête."""
    extrait = [{"cve_id": "CVE-2026-00001", "severity": "critical"}]
    collection = _CollectionFactice(1, extrait, {"critical": 1})
    analyse = rag.parse_query("Les vulnerabilites Fortinet")

    await rag.retrieve(_BaseFactice(collection), analyse, limit=40)

    assert collection.agregations == 0
    assert "repartition_severites" not in analyse


async def test_une_agregation_en_echec_ne_prive_pas_de_reponse():
    """La répartition enrichit la réponse ; elle ne la conditionne pas."""
    extrait = [{"cve_id": f"CVE-2026-{i:05d}", "severity": "high"} for i in range(40)]
    base = _BaseFactice(_CollectionFactice(500, extrait, agregation_cassee=True))
    analyse = rag.parse_query("Les vulnerabilites Microsoft")

    docs, total = await rag.retrieve(base, analyse, limit=40)

    assert total == 500 and len(docs) == 40
    assert analyse["repartition_severites"] == {}


def test_la_repartition_n_apparait_pas_parmi_les_filtres():
    """Elle transite par l'analyse sans être un critère : l'afficher laisserait croire que
    le consultant l'a demandée."""
    analyse = {**rag.parse_query("Les vulnerabilites Microsoft"),
               "repartition_severites": {"critical": 199}}
    assert "repartition_severites" not in rag._echo_filters(analyse)
