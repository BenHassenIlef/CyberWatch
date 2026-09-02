"""Discussions communautaires : pertinence, isolement des sources, séparation de l'officiel.

Une discussion de forum peut être juste, fausse ou spéculative. Elle enrichit l'analyse ;
elle ne fait autorité sur aucun champ de la fiche. Ces tests verrouillent les trois garanties
qui rendent cette couche utilisable sans danger :

  1. une discussion n'est associée qu'à la CVE qu'elle cite EXPLICITEMENT ;
  2. une source fermée ou en panne n'empêche jamais les autres d'aboutir, et n'est jamais
     présentée comme « aucune discussion » ;
  3. rien de ce qui vient d'ici ne touche la solution, les références ou les produits.
"""
import asyncio

import pytest

from app.backend.services.community import discussions as dc

CVE = "CVE-2026-0290"
AUTRE = "CVE-2026-9999"


def _d(titre, resume="", **extra):
    return {"title": titre, "summary": resume, "url": "https://exemple.test/x",
            "source": "Stack Exchange", **extra}


# ---------------------------------------------------------------------------------------
# 1. Appariement EXACT — la condition sans laquelle tout le reste est faux.
# ---------------------------------------------------------------------------------------

def test_discussion_citant_la_cve_est_retenue():
    assert dc.cite_la_cve(_d(f"Analyse de {CVE}"), CVE)


def test_discussion_citant_une_autre_cve_est_rejetee():
    assert not dc.cite_la_cve(_d(f"Exploit pour {AUTRE}"), CVE)
    assert dc.score_pertinence(_d(f"Exploit pour {AUTRE}"), CVE) == 0.0


def test_mention_du_produit_seul_ne_suffit_pas():
    """Le rapprochement par sujet fabriquerait des liens que personne n'a établis."""
    d = _d("Prisma Browser hardening", "conseils généraux de durcissement")
    assert dc.score_pertinence(d, CVE) == 0.0


def test_casse_indifferente():
    assert dc.cite_la_cve(_d(f"about {CVE.lower()}"), CVE)


# ---------------------------------------------------------------------------------------
# 2. Niveaux de pertinence — seul ce qui éclaire est montré.
# ---------------------------------------------------------------------------------------

def test_titre_portant_la_cve_et_technique_est_eleve():
    d = _d(f"Exploit for {CVE}", "proof of concept and patch", answers=3)
    assert dc.niveau(dc.score_pertinence(d, CVE)) == dc.HIGH


def test_simple_mention_dans_le_corps_reste_moyenne():
    d = _d("Revue hebdomadaire", f"cite {CVE} parmi d'autres sujets")
    assert dc.niveau(dc.score_pertinence(d, CVE)) == dc.MEDIUM


def test_revue_d_actualite_est_declassee():
    """Un billet citant dix CVE n'analyse aucune d'elles en particulier."""
    beaucoup = " ".join(f"CVE-2026-10{i:02d}" for i in range(8))
    dilue = dc.score_pertinence(_d(f"{CVE} et autres", beaucoup), CVE)
    concentre = dc.score_pertinence(_d(f"{CVE} et autres", "analyse"), CVE)
    assert dilue < concentre


def test_seuil_ecarte_les_liens_faibles():
    assert dc.niveau(dc.SEUIL_AFFICHAGE - 0.01) == dc.LOW


# ---------------------------------------------------------------------------------------
# 3. Doublons — rejouer la recherche ne doit rien dupliquer.
# ---------------------------------------------------------------------------------------

def test_cle_stable_malgre_la_casse_et_la_barre_finale():
    a = dc.cle_unique(CVE, {"source": "Reddit", "url": "https://r.test/x/"})
    b = dc.cle_unique(CVE, {"source": "reddit", "url": "https://r.test/x"})
    assert a == b


def test_meme_discussion_sur_deux_cve_reste_distincte():
    """Une discussion peut légitimement citer deux CVE : ce ne sont pas des doublons."""
    d = {"source": "Reddit", "url": "https://r.test/x"}
    assert dc.cle_unique(CVE, d) != dc.cle_unique(AUTRE, d)


# ---------------------------------------------------------------------------------------
# 4. Isolement des sources — une panne n'est pas un silence de la communauté.
# ---------------------------------------------------------------------------------------

def _recherche(sources):
    """Recherche sur un registre de test. `sources` : {nom: coroutine}.

    Le registre porte desormais, pour chaque source, son adaptateur et son libelle affiche :
    on l habille ici pour que ces tests restent centres sur le COMPORTEMENT, pas sur la forme
    de la configuration.
    """
    original = dc.SOURCES
    dc.SOURCES = {nom: {"adapter": fn, "label": nom, "requires_auth": False}
                  for nom, fn in sources.items()}
    try:
        return asyncio.run(dc.rechercher(CVE))
    finally:
        dc.SOURCES = original


def test_une_source_en_panne_n_empeche_pas_les_autres():
    async def ko(_cve):
        raise dc.SourceIndisponible("accès fermé")

    async def ok(_cve):
        return [_d(f"Analyse de {CVE}", "exploit et patch", url="https://ok.test/1")]

    retenues, etats = _recherche({"ko": ko, "ok": ok})
    par_source = {e["source"]: e["status"] for e in etats}
    assert len(retenues) == 1
    assert par_source["ko"] == dc.UNAVAILABLE and par_source["ok"] == dc.COMPLETED


def test_toutes_les_sources_en_panne_sont_signalees():
    async def ko(_cve):
        raise dc.SourceIndisponible("indisponible")

    retenues, etats = _recherche({"a": ko, "b": ko})
    assert retenues == []
    assert {e["status"] for e in etats} == {dc.UNAVAILABLE}


def test_source_vide_n_est_pas_un_echec():
    """Aucun résultat est un FAIT ; une panne est une limite technique. À ne pas confondre."""
    async def vide(_cve):
        return []

    retenues, etats = _recherche({"vide": vide})
    # Recherche ABOUTIE sans resultat : un fait sur la communaute, pas une panne.
    assert retenues == [] and etats == [{"source": "vide", "status": dc.COMPLETED,
                                         "results": 0}]


def test_resultat_hors_sujet_est_ecarte_sans_erreur():
    async def hors_sujet(_cve):
        return [_d(f"Exploit pour {AUTRE}", url="https://hs.test/1")]

    retenues, etats = _recherche({"s": hors_sujet})
    assert retenues == [] and etats[0]["status"] == dc.COMPLETED


# ---------------------------------------------------------------------------------------
# 5. Résumé — rapporter, jamais recommander.
# ---------------------------------------------------------------------------------------

def test_absence_de_discussion_donne_le_message_prevu():
    texte, origine = asyncio.run(dc.resume_communautaire([]))
    assert texte == dc.AUCUNE_DISCUSSION and origine == "deterministe"


def test_resume_deterministe_rappelle_le_caractere_non_officiel():
    # Discussion SANS matiere exploitable : le modele n aurait rien a synthetiser et
    # repondrait par une remarque sur sa propre tache. Le decompte deterministe, lui,
    # reste exact — c est donc lui qui doit sortir.
    d = {"source": "Stack Exchange", "community": "Information Security",
         "relevance_level": dc.HIGH, "title": "t"}
    texte, origine = asyncio.run(dc.resume_communautaire([d]))
    assert origine == "deterministe"
    assert "ne remplacent pas" in texte and "Stack Exchange" in texte


def test_reponse_meta_du_modele_est_refusee():
    """Un modele qui commente sa tache au lieu de la faire ne doit pas etre publie."""
    from app.backend.services.assistant import llm

    d = {"source": "Reddit", "community": "r/netsec", "relevance_level": dc.HIGH,
         "title": f"Analyse technique de {CVE} et de son exploitation",
         "summary": "x" * 200}
    original_dispo, original_gen = llm.available, llm.generate
    llm.available = lambda: True
    async def meta(*a, **k):
        return "Aucun extrait de discussion n a ete fourni ; il n est donc pas possible de rediger."
    llm.generate = meta
    try:
        texte, origine = asyncio.run(dc.resume_communautaire([d]))
    finally:
        llm.available, llm.generate = original_dispo, original_gen
    assert origine == "deterministe" and "ne remplacent pas" in texte


def test_consigne_interdit_la_recommandation_en_nom_propre():
    assert "aucune recommandation en ton nom" in dc._RESUME_SYSTEM
    assert "n'inventes" in dc._RESUME_SYSTEM


# ---------------------------------------------------------------------------------------
# 6. SÉPARATION de l'officiel — la garantie centrale.
# ---------------------------------------------------------------------------------------

def test_les_discussions_ne_portent_aucun_champ_officiel():
    """Une discussion retenue ne doit contenir ni solution, ni référence, ni score CVSS."""
    async def ok(_cve):
        return [_d(f"Analyse de {CVE}", "exploit", url="https://ok.test/1")]

    retenues, _ = _recherche({"ok": ok})
    interdits = {"solution", "references", "cvss_score", "severity", "affected_products",
                 "official_source", "vendor", "product"}
    assert not (interdits & set(retenues[0]))


def test_la_discussion_est_marquee_comme_communautaire():
    from app.backend.services.community import agent

    async def ok(_cve):
        return [_d(f"Analyse de {CVE}", url="https://ok.test/1")]

    retenues, _ = _recherche({"ok": ok})
    assert retenues[0]["source_type"] == agent.COMMUNITY


@pytest.mark.parametrize("champ", ["cve_id", "relevance_score", "relevance_level",
                                   "verification_status"])
def test_chaque_discussion_porte_sa_tracabilite(champ):
    async def ok(_cve):
        return [_d(f"Analyse de {CVE}", url="https://ok.test/1")]

    retenues, _ = _recherche({"ok": ok})
    assert champ in retenues[0]
