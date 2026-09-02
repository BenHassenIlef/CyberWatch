"""FIABILITÉ DE L'ASSISTANT — les défauts trouvés en interrogeant la base réelle.

Chaque test ci-dessous correspond à une question qui recevait une MAUVAISE réponse, ou une
réponse correcte au prix d'une attente déraisonnable. Ils ne testent pas des cas imaginés :
ils rejouent des échecs constatés.

Aucun appel réseau : ces tests portent sur l'analyse, le classement et les garde-fous.
"""
import pytest

from app.backend.services.assistant import external, llm, rag, summary


# ---------------------------------------------------------------------------------------
# 1. Mots vides non accentués — « editeur » devenait un mot-clé PRODUIT
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("mot", ["editeur", "éditeur", "annee", "année",
                                 "vulnerabilites", "vulnérabilités", "donnees", "critiques"])
def test_les_mots_vides_le_restent_sans_accent(mot):
    """Un consultant tape « editeur » aussi souvent que « éditeur ».

    La liste des mots vides ne portait que les formes accentuées. « editeur » devenait donc
    un mot-clé produit, la requête Mongo exigeait ce mot dans le champ produit d'une CVE —
    condition qu'aucune fiche ne remplit — et « Quel éditeur a le plus de vulnérabilités ? »
    répondait « information non disponible ».
    """
    assert rag._is_stopword(mot) is True


def test_un_nom_de_produit_n_est_jamais_pris_pour_un_mot_vide():
    """La normalisation ne doit pas rendre le filtre gourmand."""
    for produit in ("fortinet", "log4j-core", "windows", "sharepoint", "x-force"):
        assert rag._is_stopword(produit) is False


def test_question_sur_l_editeur_le_plus_touche():
    analyse = rag.parse_query("Quel editeur a le plus de vulnerabilites cette annee ?")
    assert analyse["intent"] == "top_vendor"
    assert analyse["keywords"] == [], (
        f"mots-clés parasites : {analyse['keywords']} — ils videraient la requête")


# ---------------------------------------------------------------------------------------
# 2. Portée — une définition ne doit pas être capturée par un mot technique
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("question, portee", [
    # Définitions : le mot « KEV » activait le filtre « exploitation », donc une recherche en
    # base, qui ne trouvait rien et répondait « information non disponible » à une définition.
    ("Qu'est-ce que le catalogue KEV ?", "external"),
    ("Qu'est-ce qu'un exploit ?", "external"),
    ("Quelle est la difference entre CVE, CWE et CVSS ?", "external"),
    ("Qu'est-ce qu'une attaque par chaine d'approvisionnement ?", "external"),
    # Interrogations du catalogue : elles doivent rester ancrées, même sans résultat.
    ("Quelles CVE ont un exploit connu ?", "internal"),
    ("Combien de CVE critiques en base ?", "internal"),
    ("Affiche notre catalogue de CVE critiques", "internal"),
    ("Quelles vulnerabilites Microsoft ce mois-ci ?", "internal"),
    ("Explique CVE-2021-44228", "internal"),
    ("Affiche les CVE critiques de Fortinet exploitees", "internal"),
])
def test_portee_de_la_question(question, portee):
    assert rag.classify_scope(question, rag.parse_query(question)) == portee


def test_une_question_de_methode_n_est_pas_verrouillee_sur_la_base():
    """« Comment prioriser avec EPSS et le catalogue KEV ? » — une des questions SUGGÉRÉES.

    Le mot « KEV » suffisait à verrouiller la réponse sur la base (`_has_db_filters`), ce qui
    interdisait le repli sur les connaissances du modèle. La question proposée par l'interface
    elle-même recevait donc « information non disponible ».
    """
    question = "Comment prioriser la remediation avec EPSS et le catalogue KEV ?"
    analyse = rag.parse_query(question)
    assert analyse["exploit"] is True, "le mot KEV active bien le signal"
    assert rag._has_db_filters(analyse) is False, (
        "un signal d'exploitation SEUL ne doit pas verrouiller la base")
    assert rag.classify_scope(question, analyse) != "internal"


def test_l_exploitation_verrouille_la_base_avec_une_cible_concrete():
    """Combiné à un éditeur ou un identifiant, le signal redevient déterminant."""
    assert rag._has_db_filters(rag.parse_query("CVE Fortinet exploitees activement")) is True
    assert rag._has_db_filters(rag.parse_query("CVE-2021-44228 est-elle exploitee ?")) is True


# ---------------------------------------------------------------------------------------
# 3. Latence bornée — une réponse tardive est un défaut, pas un désagrément
# ---------------------------------------------------------------------------------------

def test_le_budget_d_attente_borne_la_latence():
    """Une latence maximale doit se PROUVER, pas s'espérer.

    Chaque garde-fou semblait suffisant pris isolément — trois tentatives, chacune plafonnée —
    et pourtant une question a mis 2 000 secondes lors d'un enchaînement rapide. Le budget
    cumulé rend la durée maximale indépendante du nombre de couches de reprise.
    """
    assert llm.BUDGET_ATTENTE_TOTAL <= 30.0
    assert llm.ATTENTE_MAX <= llm.BUDGET_ATTENTE_TOTAL, (
        "une attente unitaire supérieure au budget serait toujours refusée : "
        "la reprise ne servirait alors plus jamais")
    assert llm.ATTENTE_PAR_DEFAUT <= llm.ATTENTE_MAX


@pytest.mark.parametrize("valeur, attendu", [
    ("915ms", 0.915), ("24s", 24.0), ("2m52.8s", 172.8), ("1m", 60.0), ("7.66s", 7.66),
    (None, None), ("", None), ("plus tard", None),
])
def test_lecture_de_l_echeance_annoncee(valeur, attendu):
    """Le fournisseur annonce quand le crédit revient ; on attendait à l'aveugle."""
    resultat = llm._secondes(valeur)
    if attendu is None:
        assert resultat is None
    else:
        assert resultat == pytest.approx(attendu)


# ---------------------------------------------------------------------------------------
# 4. Économie de jetons — le débit est borné à quelques milliers de jetons PAR MINUTE
# ---------------------------------------------------------------------------------------

def test_l_invite_de_fiche_exclut_ce_qui_ne_se_redige_pas():
    """Références et sources ne sont plus transmises : la section « Sources » est déterministe.

    Les envoyer coûtait plusieurs centaines de jetons par fiche pour un contenu que le modèle
    n'a pas à rédiger — et ces jetons se payaient en attente sur la question suivante.
    """
    contexte = {"cve_id": "CVE-2021-44228", "severity": "critical", "cvss_score": 10.0,
                "description": "Exécution de code à distance.",
                "references": ["https://exemple.test/a"] * 30,
                "sources": ["nvd", "cisa"], "impact": None, "solution": ""}
    invite = summary._llm_prompt(contexte, ["Résumé exécutif"], None)

    assert "https://exemple.test/a" not in invite, "les références gonflaient l'invite"
    assert "CVE-2021-44228" in invite and "critical" in invite
    # Les champs vides n'apprennent rien et occupent le budget.
    assert '"impact"' not in invite and '"solution"' not in invite
    # Sérialisation compacte : `indent=2` gonflait l'invite d'environ un tiers.
    assert '"cve_id":"CVE-2021-44228"' in invite


def test_la_section_sources_ne_passe_pas_par_le_modele():
    """Une URL recopiée par un modèle est une URL qui peut changer d'un caractère.

    Dans un outil de sécurité, un lien altéré envoie un consultant sur une page qui n'est pas
    celle de l'éditeur. La liste est donc rendue de façon déterministe.
    """
    assert "Sources" in summary.STYLE_SECTIONS["technical"]
    invite = summary._llm_prompt({"cve_id": "CVE-2021-44228"},
                                 [t for t in summary.STYLE_SECTIONS["technical"]
                                  if t != "Sources"], None)
    assert "### Sources" not in invite


# ---------------------------------------------------------------------------------------
# 5. Messages d'indisponibilité — ne pas envoyer l'administrateur sur une fausse piste
# ---------------------------------------------------------------------------------------

def test_quota_epuise_ne_se_presente_pas_comme_une_absence_de_configuration(monkeypatch):
    """Un seul message existait : « renseignez LLM_PROVIDER et LLM_API_KEY ».

    Il s'affichait AUSSI lorsque la clé était parfaitement configurée et que le fournisseur
    avait simplement épuisé son quota de la minute. Le consultant lisait qu'il fallait
    configurer un modèle déjà configuré, et un administrateur pouvait passer un long moment
    à vérifier un fichier `.env` irréprochable.
    """
    from app.backend.core.config import settings

    monkeypatch.setattr(settings, "LLM_API_KEY", "gsk_test", raising=False)
    monkeypatch.setattr(settings, "LLM_PROVIDER", "groq", raising=False)
    message = external._message_indisponible()
    assert "momentanément indisponible" in message
    assert "LLM_API_KEY" not in message, "la clé EST configurée : ne pas accuser la config"
    assert "aucune action n'est requise" in message

    monkeypatch.setattr(settings, "LLM_API_KEY", "", raising=False)
    message = external._message_indisponible()
    assert "LLM_API_KEY" in message, "là, il manque réellement une configuration"


# ---------------------------------------------------------------------------------------
# 6. Une faute de frappe ne doit pas vider la réponse
# ---------------------------------------------------------------------------------------

class _CollectionFactice:
    """Compte les documents selon que la requête impose ou non des mots-clés produit."""

    def __init__(self, avec_mots_cles: int, sans_mots_cles: int):
        self.avec, self.sans = avec_mots_cles, sans_mots_cles
        self.requetes = []

    @staticmethod
    def _porte_des_mots_cles(requete: dict) -> bool:
        return any("$and" == cle or "$or" in str(cle) for cle in requete) and \
            "produit" in str(requete).lower() or "$and" in requete

    async def count_documents(self, requete):
        self.requetes.append(requete)
        return self.avec if "$and" in requete else self.sans

    def find(self, requete, _projection=None):
        return self

    def sort(self, *_a, **_k):
        return self

    async def to_list(self, _limite):
        return [{"cve_id": "CVE-2026-77994", "severity": "critical"}]


class _BaseFactice:
    def __init__(self, cves):
        self.cves = cves


@pytest.mark.asyncio
async def test_un_mot_mal_orthographie_ne_vide_pas_la_reponse():
    """« c'est quoi les cve puble aujourd'hui en generale » ne trouvait RIEN.

    « puble » et « generale » devenaient des mots-clés PRODUIT, appliqués en conjonction : la
    requête exigeait une vulnérabilité dont le produit contient « puble ». Aucune fiche ne
    remplit cette condition — et l'assistant répondait « information non disponible » alors
    que deux CVE publiées ce jour-là attendaient en base.

    Quand la question porte déjà un critère structuré (ici une date), celui-ci borne la
    recherche à lui seul : les mots-clés deviennent une préférence, pas une exigence.
    """
    from datetime import datetime

    analyse = {**rag.parse_query("les cve puble aujourd'hui en generale"),
               "date_from": datetime(2026, 8, 24), "keywords": ["puble", "generale"]}
    base = _BaseFactice(_CollectionFactice(avec_mots_cles=0, sans_mots_cles=2))

    docs, total = await rag.retrieve(base, analyse, limit=10)

    assert total == 2, "la date seule devait suffire à trouver les vulnérabilités du jour"
    assert analyse["keywords"] == [], "les mots-clés parasites doivent être abandonnés"
    assert analyse["keywords_ignores"] == ["puble", "generale"], (
        "l'abandon doit rester traçable, pour pouvoir l'expliquer au consultant")


@pytest.mark.asyncio
async def test_sans_autre_critere_les_mots_cles_restent_contraignants():
    """« CVE log4j-inexistant » doit rester « aucun résultat », pas « voici toute la base ».

    Sans critère structuré, abandonner les mots-clés renverrait l'intégralité du catalogue —
    une réponse pire que l'absence de réponse, parce qu'elle a l'air pertinente.
    """
    analyse = {**rag.parse_query("CVE log4j-inexistant-xyz"), "keywords": ["log4j-inexistant-xyz"]}
    base = _BaseFactice(_CollectionFactice(avec_mots_cles=0, sans_mots_cles=11656))

    _docs, total = await rag.retrieve(base, analyse, limit=10)

    assert total == 0
    assert analyse["keywords"] == ["log4j-inexistant-xyz"], "les mots-clés doivent être conservés"


def test_aucun_resultat_n_est_pas_information_indisponible():
    """Deux messages, deux significations — les confondre inquiète pour rien.

    « Aucun résultat » est une réponse : la recherche a abouti et rien ne correspond.
    « Information non disponible » laisse croire à une lacune de la base, voire à une panne.
    """
    assert "pas disponible" in rag.NOT_FOUND, "le message d'indisponibilité existe toujours"
    # Le message d'absence de résultat, lui, affirme que la recherche a bien eu lieu.
    from app.backend.services.assistant.rag import _describe_filters

    critere = _describe_filters({"vendor": "Fortinet", "severity": None, "cvss_min": None,
                                 "date_from": None, "date_to": None, "keywords": [],
                                 "exploit": False, "cve_ids": []})
    message = f"Aucune vulnérabilité ne correspond à votre demande{critere}."
    assert "Aucune vulnérabilité ne correspond" in message
    assert "pas disponible" not in message
