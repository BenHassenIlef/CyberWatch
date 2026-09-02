"""FENÊTRE DE VEILLE — depuis la collecte précédente, non depuis minuit.

L'ANGLE MORT CORRIGÉ ICI
Une collecte du matin ne voyait que ce qui avait paru depuis minuit. Or la collecte
précédente pouvait dater de la veille à 10 h : tout ce qui était publié entre 10 h et minuit
tombait dans un intervalle que personne ne couvrait — ni « publié aujourd'hui » au passage
suivant, ni déjà collecté au passage précédent. Ces vulnérabilités étaient écartées en
silence, sous le motif « ancienne et inconnue ».

Mesuré sur l'installation avant correction : **13 heures** d'angle mort entre la collecte du
26/08 à 10 h 02 et minuit.

Partir de la collecte précédente ferme ce trou par construction : deux passages successifs
couvrent toujours l'intervalle qui les sépare, à quelque heure qu'ils tombent.
"""
import asyncio
from datetime import datetime, timedelta

import pytest

from app.backend.services.collection import pipeline as P


class _Executions:
    """Historique des collectes, en lecture seule."""

    def __init__(self, derniere: datetime | None = None, illisible: bool = False):
        self._derniere = derniere
        self._illisible = illisible

    async def find_one(self, _requete, sort=None):
        if self._illisible:
            raise RuntimeError("base indisponible")
        return {"started_at": self._derniere} if self._derniere else None


class _Base:
    def __init__(self, derniere=None, illisible=False):
        self.collection_runs = _Executions(derniere, illisible)


def _fenetre(derniere=None, illisible=False):
    return asyncio.run(P._bornes_de_la_veille(_Base(derniere, illisible)))


# ---------------------------------------------------------------------------------------
# 1. Le trou entre deux collectes
# ---------------------------------------------------------------------------------------

def test_la_fenetre_remonte_a_la_collecte_precedente():
    """LE DÉFAUT CORRIGÉ. Une CVE publiée hier à 18 h n'était couverte par personne.

    La collecte de la veille (10 h) était passée avant elle ; celle d'aujourd'hui ne
    regardait que depuis minuit. Huit heures de publications disparaissaient sans trace.
    """
    minuit, _fin = P._bornes_du_jour()
    hier_matin = minuit - timedelta(hours=13)          # veille, 10 h du matin

    debut, fin, motif = _fenetre(derniere=hier_matin)

    assert debut == hier_matin, "la fenêtre doit repartir de la collecte précédente"
    assert debut < minuit, "elle doit couvrir la soirée de la veille"
    assert fin > minuit
    assert "collecte du" in motif, "le motif doit expliquer d'où part la fenêtre"


def test_une_collecte_du_jour_ne_retrecit_pas_la_fenetre():
    """Une relance dix minutes après la précédente doit toujours montrer la veille du jour.

    Sans ce plancher, relancer la collecte à 11 h ne montrerait que ce qui a paru depuis
    10 h 50 — et la page « Collectées aujourd'hui » se viderait à chaque relance.

    Le plancher couvre en outre les 24 heures précédentes (voir
    `test_le_filtre_couvre_toujours_les_24_dernieres_heures`) : la fenêtre ne peut donc que
    S'ÉLARGIR au-delà de minuit, jamais se refermer en deçà.
    """
    minuit, _fin = P._bornes_du_jour()
    ce_matin = minuit + timedelta(hours=7)

    debut, _fin2, motif = _fenetre(derniere=ce_matin)

    assert debut <= minuit, "la fenêtre ne se referme jamais en deçà de la journée"
    assert "journée en cours" in motif


# ---------------------------------------------------------------------------------------
# 2. Bornes de sécurité
# ---------------------------------------------------------------------------------------

def test_le_rattrapage_est_plafonne():
    """Une application arrêtée trois semaines ne doit pas déverser trois semaines de CVE.

    Le consultant se retrouverait devant des centaines de fiches sans distinguer ce qui
    relève d'aujourd'hui — la veille deviendrait illisible au moment précis où elle redevient
    disponible.
    """
    minuit, fin = P._bornes_du_jour()
    tres_ancienne = minuit - timedelta(days=30)

    debut, _fin, motif = _fenetre(derniere=tres_ancienne)

    assert debut > tres_ancienne
    assert debut == fin - P.RATTRAPAGE_MAX
    assert "plafonné" in motif
    assert P.RATTRAPAGE_MAX <= timedelta(days=14), "un rattrapage trop long noie la veille"


def test_sans_historique_la_fenetre_vaut_la_journee():
    """Première collecte d'une installation : rien à rattraper."""
    minuit, _fin = P._bornes_du_jour()
    debut, _f, motif = _fenetre(derniere=None)

    assert debut == minuit
    assert "aucune collecte précédente" in motif


def test_un_historique_illisible_ne_bloque_pas_la_collecte():
    """Une base indisponible ne doit pas empêcher la veille de tourner.

    On retombe sur la journée en cours — moins large, mais sûr — et on le dit.
    """
    minuit, _fin = P._bornes_du_jour()
    debut, _f, motif = _fenetre(illisible=True)

    assert debut == minuit
    assert "historique indisponible" in motif


def test_une_date_invalide_est_ignoree():
    """Un enregistrement corrompu ne doit pas produire une fenêtre absurde."""
    minuit, _fin = P._bornes_du_jour()
    debut, _f, motif = _fenetre(derniere="pas une date")

    assert debut == minuit
    assert "aucune collecte précédente" in motif


# ---------------------------------------------------------------------------------------
# 3. Le filtre rend bien le motif à l'appelant
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_le_filtre_rend_le_motif_de_la_fenetre(monkeypatch):
    """Le motif s'inscrit dans le journal de collecte que le consultant lit.

    « depuis la collecte du 26/08 à 10h02 » explique un volume inhabituel ; une ligne muette
    laisserait croire à un dysfonctionnement.
    """
    from app.backend.core.config import settings

    monkeypatch.setattr(settings, "DAILY_COLLECTION_TODAY_ONLY", True, raising=False)
    minuit, _fin = P._bornes_du_jour()

    class _Cves:
        def find(self, *_a, **_k):
            class _C:
                def __aiter__(self):
                    async def _g():
                        return
                        yield
                    return _g()
            return _C()

    base = _Base(derniere=minuit - timedelta(hours=13))
    base.cves = _Cves()

    publiee_hier_soir = minuit - timedelta(hours=5)
    records = [{"cve_id": "CVE-2026-1", "published_at": publiee_hier_soir}]

    gardees, ecartees, _sans_date, motif = await P.filtrer_veille_du_jour(base, records)

    assert len(gardees) == 1, (
        "une CVE publiée hier soir, après la dernière collecte, doit être retenue")
    assert ecartees == 0
    assert "collecte du" in motif


@pytest.mark.asyncio
async def test_le_filtre_desactive_rend_aussi_quatre_valeurs(monkeypatch):
    """Le contrat de retour doit être le même dans les deux branches.

    Une branche rendant trois valeurs et l'autre quatre casserait l'appelant au moment
    précis où l'on désactive le filtre — c'est-à-dire quand on cherche à diagnostiquer.
    """
    from app.backend.core.config import settings

    monkeypatch.setattr(settings, "DAILY_COLLECTION_TODAY_ONLY", False, raising=False)
    resultat = await P.filtrer_veille_du_jour(_Base(), [{"cve_id": "CVE-2026-1"}])

    assert len(resultat) == 4
    assert resultat[0] == [{"cve_id": "CVE-2026-1"}]


# ---------------------------------------------------------------------------------------
# 4. La REQUÊTE à la source doit couvrir la même période que le filtre
# ---------------------------------------------------------------------------------------
#
# Ce qui n'est pas DEMANDÉ ne peut pas être filtré ensuite. La fenêtre du filtre était
# corrigée, mais le collecteur NVD demandait toujours « depuis minuit » : 105 vulnérabilités
# publiées après la dernière collecte de la veille n'étaient jamais rapatriées. Trente et une
# concernaient des produits surveillés — Red Hat Enterprise Linux, MongoDB — et manquaient
# purement et simplement à la veille.

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _debut_demande(since, monkeypatch):
    from app.backend.core.config import settings
    from app.backend.services.collection.collectors import api_json

    monkeypatch.setattr(settings, "DAILY_COLLECTION_TODAY_ONLY", True, raising=False)
    monkeypatch.setattr(settings, "DAILY_COLLECTION_WINDOW_DAYS", 1, raising=False)
    url = api_json._nvd_recency_window(NVD, since)
    return datetime.fromisoformat(url.split("pubStartDate=")[1].split("&")[0])


def test_la_requete_remonte_a_la_derniere_synchronisation(monkeypatch):
    """Le cas mesuré : dernière collecte la veille à 17 h 52.

    Ancrée sur minuit, la requête ignorait tout ce qui avait paru entre 17 h 52 et minuit.
    """
    maintenant = datetime.utcnow()
    minuit = maintenant.replace(hour=0, minute=0, second=0, microsecond=0)
    hier_soir = minuit - timedelta(hours=6, minutes=8)          # veille, 17 h 52

    debut = _debut_demande(hier_soir, monkeypatch)

    assert debut < minuit, "la requête doit couvrir la soirée de la veille"
    assert debut <= hier_soir, "elle doit inclure l'instant de la dernière synchronisation"


def test_une_synchronisation_du_jour_ne_retrecit_pas_la_requete(monkeypatch):
    """Le plancher reste minuit : une relance ne doit pas amputer la veille du jour."""
    maintenant = datetime.utcnow()
    minuit = maintenant.replace(hour=0, minute=0, second=0, microsecond=0)

    assert _debut_demande(minuit + timedelta(hours=7), monkeypatch) == minuit
    assert _debut_demande(None, monkeypatch) == minuit


def test_le_rattrapage_de_la_requete_est_plafonne(monkeypatch):
    """Une source muette un mois ne doit pas demander un mois de publications d'un coup."""
    from app.backend.services.collection.collectors import api_json

    maintenant = datetime.utcnow()
    debut = _debut_demande(maintenant - timedelta(days=30), monkeypatch)

    assert debut > maintenant - timedelta(days=api_json.RATTRAPAGE_JOURS + 1)


def test_les_deux_plafonds_sont_alignes():
    """Filtre et requête doivent rattraper la MÊME durée.

    Un collecteur qui remonterait plus loin que le filtre rapporterait des vulnérabilités
    aussitôt rejetées : du travail réseau pour rien. L'inverse — un filtre plus large que la
    requête — rouvrirait exactement le trou que l'on vient de fermer.
    """
    from app.backend.services.collection.collectors import api_json

    assert timedelta(days=api_json.RATTRAPAGE_JOURS) == P.RATTRAPAGE_MAX


def test_le_filtre_couvre_toujours_les_24_dernieres_heures():
    """DEUX notions de « dernier passage » coexistent, et elles divergent.

    Celle du pipeline (dernière exécution) et celle de chaque source (`last_sync_at`, qui
    n'avance qu'en cas de réussite). Une source en échec deux jours re-demandera deux jours
    de publications — que le filtre rejetterait si sa fenêtre s'était refermée sur la seule
    dernière exécution. Le plancher de 24 h aligne les deux sans les coupler.
    """
    minuit, fin = P._bornes_du_jour()
    ce_matin = minuit + timedelta(hours=7)

    debut, _f, motif = _fenetre(derniere=ce_matin)

    assert debut <= fin - timedelta(days=2), "la fenêtre doit couvrir les 24 h précédentes"
    assert "24 h" in motif
