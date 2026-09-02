"""NOYAU DU HARNESS — le contrôleur d'exécution placé autour de l'assistant existant.

    Consultant
        ↓
    API  /consultant/assistant/ask                (inchangée)
        ↓
    HARNESS  ← ce module
        ↓  planifie, autorise, exécute, réessaie, valide
    Outils / agents spécialisés  (deep_synthesis, community, verification)
        ↓
    Validation
        ↓
    ASSISTANT EXISTANT  rag.answer_question()     ← rédige TOUJOURS la réponse finale
        ↓
    Assainissement de la sortie
        ↓
    Consultant

CE QUE LE HARNESS NE FAIT PAS
Il ne rédige pas. Il ne reformule pas. Il ne décide pas du contenu d'une réponse. Ces
responsabilités restent à `rag.py`, qui les assumait déjà et continue de le faire avec son
prompt, son modèle et sa mémoire. Le harness apporte ce qui manquait autour : le choix des
capacités, la permission, le délai, la reprise, la validation et la trace.

POURQUOI UN OUTIL N'EST PAS TOUJOURS APPELÉ
L'assistant interroge déjà la base et rédige seul. Un outil n'est planifié que lorsqu'il
apporte une capacité qu'il n'a pas — lire les pages référencées, interroger les communautés,
vérifier une adresse. Le chemin sans outil n'est donc pas un cas dégradé : c'est le cas normal.

RÈGLE ABSOLUE SUR L'ÉCHEC
Un outil qui échoue ne disparaît pas du récit. Le harness transmet l'échec à l'assistant sous
forme de fait — « la lecture des pages sources n'a pas abouti » — pour qu'il le DISE. Un
silence laisserait croire que l'information n'existe pas, ce qui, dans un outil de sécurité,
est plus grave que l'échec lui-même. Aucun résultat n'est jamais fabriqué.
"""
import asyncio
import logging

from app.backend.services.assistant.harness import agents as profils
from app.backend.services.assistant.harness import outils as registre
from app.backend.services.assistant.harness import securite
from app.backend.services.assistant.harness.trace import (ECHEC, EXPIRE, INVALIDE, OK, REFUSE,
                                                          VIDE, AppelOutil, Trace)

logger = logging.getLogger("cyberwatch.assistant.harness")

# Reprises. Deux tentatives supplémentaires au plus : une panne réseau passagère se dissipe
# dès la première reprise ; au-delà, on répète une erreur durable en faisant patienter le
# consultant. La borne existe pour empêcher toute boucle d'exécution.
MAX_REPRISES = 2
ATTENTE_ENTRE_REPRISES = 1.5

# Budget total des outils pour une requête. Le consultant attend une réponse : mieux vaut une
# réponse ancrée sur la base sans enrichissement qu'un écran figé.
BUDGET_OUTILS_S = 120.0


class HarnessIndisponible(RuntimeError):
    """Le harness ne peut pas traiter la demande (entrée refusée)."""


# =======================================================================================
# Exécution d'UN outil : permission -> délai -> reprises -> validation
# =======================================================================================

async def executer_outil(nom: str, arguments: dict, agent: str, contexte: dict,
                         trace: Trace) -> tuple[bool, object, str]:
    """Exécute un outil sous contrôle. Renvoie (réussi, résultat, motif).

    Le motif est rédigé pour être LU par l'assistant : c'est lui qui expliquera au consultant
    ce qui n'a pas pu être obtenu.
    """
    outil = registre.obtenir(nom)
    if outil is None:
        trace.ajouter(AppelOutil(nom, REFUSE, 0, erreur="outil inconnu"))
        return False, None, "outil inconnu"

    # PERMISSION — refus par défaut. Un outil absent du profil de l'agent n'est pas exécuté,
    # même s'il existe et fonctionnerait : c'est la limite qui donne son sens au harness.
    if nom not in profils.outils_autorises(agent):
        trace.ajouter(AppelOutil(nom, REFUSE, 0, arguments=sorted(arguments),
                                 erreur=f"non autorisé pour « {agent} »"))
        logger.warning("[harness %s] outil « %s » refusé à l'agent « %s ».",
                       trace.requete_id, nom, agent)
        return False, None, f"l'outil « {nom} » n'est pas autorisé pour cet agent"

    tentatives_max = 1 + (MAX_REPRISES if outil.reessayable else 0)
    dernier_motif = "échec inconnu"
    import time

    for tentative in range(1, tentatives_max + 1):
        depart = time.monotonic()
        try:
            resultat = await asyncio.wait_for(
                outil.executer(contexte, **arguments), timeout=outil.delai_s)
        except asyncio.TimeoutError:
            duree = int((time.monotonic() - depart) * 1000)
            dernier_motif = f"délai de {outil.delai_s:.0f} s dépassé"
            if tentative == tentatives_max:
                trace.ajouter(AppelOutil(nom, EXPIRE, duree, tentative,
                                         erreur=dernier_motif, arguments=sorted(arguments)))
                return False, None, dernier_motif
            await asyncio.sleep(ATTENTE_ENTRE_REPRISES)
            continue
        except Exception as exc:  # noqa: BLE001 - un outil défaillant n'interrompt pas la réponse
            duree = int((time.monotonic() - depart) * 1000)
            dernier_motif = f"{type(exc).__name__}"
            if tentative == tentatives_max:
                trace.ajouter(AppelOutil(nom, ECHEC, duree, tentative,
                                         erreur=str(exc)[:200], arguments=sorted(arguments)))
                logger.warning("[harness %s] outil « %s » en échec : %s",
                               trace.requete_id, nom, str(exc)[:200])
                return False, None, dernier_motif
            await asyncio.sleep(ATTENTE_ENTRE_REPRISES)
            continue

        duree = int((time.monotonic() - depart) * 1000)

        # VALIDATION — un outil qui répond n'a pas forcément répondu quelque chose d'utilisable.
        try:
            valide, detail = outil.valider(resultat)
        except Exception as exc:  # noqa: BLE001 - un validateur ne doit jamais faire tomber le tour
            valide, detail = False, f"validateur en erreur ({type(exc).__name__})"

        if not valide:
            dernier_motif = detail
            # Une sortie MALFORMÉE se rejoue (l'appel a pu être tronqué) ; on ne s'acharne pas.
            if tentative < tentatives_max:
                await asyncio.sleep(ATTENTE_ENTRE_REPRISES)
                continue
            trace.ajouter(AppelOutil(nom, INVALIDE, duree, tentative, erreur=detail,
                                     validation=detail, arguments=sorted(arguments)))
            return False, None, detail

        statut = VIDE if _est_vide(resultat) else OK
        trace.ajouter(AppelOutil(nom, statut, duree, tentative, validation=detail,
                                 arguments=sorted(arguments)))
        return True, resultat, detail

    trace.ajouter(AppelOutil(nom, ECHEC, 0, tentatives_max, erreur=dernier_motif))
    return False, None, dernier_motif


def _est_vide(resultat) -> bool:
    """« Rien trouvé » est un résultat valide, distinct d'un échec — et rapporté comme tel."""
    if resultat is None:
        return True
    if isinstance(resultat, tuple) and resultat:
        return not resultat[0]
    if isinstance(resultat, (list, dict, str)):
        return not resultat
    return False


# =======================================================================================
# Mise en forme des résultats pour l'assistant existant
# =======================================================================================

def _faits_pour_assistant(nom: str, resultat, motif: str) -> dict:
    """Transforme la sortie d'un outil en FAITS que l'assistant peut intégrer à sa rédaction.

    Le contenu de provenance externe est encadré par `securite` AVANT d'entrer dans un prompt :
    c'est le point unique où une page web ou un commentaire de forum devient une donnée inerte.
    """
    outil = registre.obtenir(nom)
    externe = outil is not None and outil.fiabilite == registre.EXTERNE

    if nom == "discussions_communautaires":
        discussions, etats = resultat
        extraits = [f"[{d.get('source')}] {d.get('title')} — {(d.get('summary') or '')}"
                    for d in discussions[:6]]
        # NE CITER QUE LES COMMUNAUTÉS RÉELLEMENT INTERROGÉES. Transmettre la liste complète
        # amenait le modèle à écrire « 21 mentions sur Reddit, Stack Exchange et Hacker News »
        # alors que Reddit n'est pas configuré et n'a rien rapporté : une source citée à tort
        # dans un outil de veille est une erreur de fond, pas une approximation de style.
        abouties = [e.get("source") for e in etats if e.get("status") == "completed"]
        indisponibles = [e.get("source") for e in etats if e.get("status") != "completed"]
        return {
            "outil": nom,
            "nature": "discussions publiques (rapportées, jamais validées)",
            "nombre": len(discussions),
            "communautes_interrogees": abouties,
            "communautes_non_interrogees": indisponibles,
            "consigne": ("Ne cite QUE les communautés listées dans « communautes_interrogees ». "
                         "Les autres n'ont pas pu être consultées : ne les nomme pas comme "
                         "source, et ne conclus rien de leur silence."),
            "contenu_externe": securite.encadrer_contenu_externe(extraits),
        }

    if nom == "synthese_approfondie":
        return {
            "outil": nom,
            "nature": "lecture des pages référencées par la vulnérabilité",
            "statut": resultat.get("status"),
            "contenu_externe": securite.encadrer_contenu_externe(
                [resultat.get("summary") or "", resultat.get("solution") or ""]),
            "source_de_la_solution": resultat.get("solution_source"),
        }

    if nom == "verification_source":
        return {
            "outil": nom,
            "nature": "vérification d'une adresse de veille",
            "score_global": resultat.get("overall_score"),
            "decision": resultat.get("decision"),
            "authenticite": (resultat.get("authenticity") or {}).get("score"),
            "usurpation": (resultat.get("authenticity") or {}).get("usurpation"),
            "alertes": (resultat.get("authenticity") or {}).get("alertes", [])[:5],
        }

    # Cas général : on ne devine pas la forme, on encadre si la provenance l'exige.
    brut = resultat if isinstance(resultat, (str, int, float)) else str(resultat)[:MAX_BRUT]
    return {"outil": nom, "nature": motif,
            ("contenu_externe" if externe else "contenu"): (
                securite.encadrer_contenu_externe([brut]) if externe else brut)}


MAX_BRUT = 2000


def _echec_pour_assistant(nom: str, motif: str) -> dict:
    """Un échec est un FAIT à énoncer, pas une donnée à taire."""
    outil = registre.obtenir(nom)
    return {
        "outil": nom,
        "echec": True,
        "nature": (outil.but if outil else nom),
        "motif": motif,
        "consigne": ("Dis clairement au consultant que cette information n'a pas pu être "
                     "obtenue, et pourquoi. N'invente aucun résultat de remplacement, et ne "
                     "laisse pas croire que l'information n'existe pas."),
    }


# =======================================================================================
# Point d'entrée du harness
# =======================================================================================

async def repondre(db, question: str, historique: list[dict] | None = None,
                   mode: str | None = None) -> dict:
    """Traite une demande de bout en bout et renvoie la réponse de l'ASSISTANT EXISTANT.

    Le dictionnaire retourné est celui de `rag.answer_question`, enrichi d'une clé `harness`
    portant la trace d'exécution. Les appelants existants continuent donc de fonctionner sans
    modification : rien n'est retiré du contrat, seul un champ s'ajoute.
    """
    from app.backend.services.assistant import rag

    trace = Trace()
    try:
        propre = securite.valider_question(question)
    except securite.EntreeRefusee as exc:
        trace.incident(f"entrée refusée : {exc}")
        trace.validation_sortie = "entree_refusee"
        trace.journaliser()
        raise HarnessIndisponible(str(exc)) from exc

    # 1) ANALYSE — celle de l'assistant existant, réutilisée telle quelle. Aucun second
    #    analyseur : deux analyses divergentes produiraient deux compréhensions de la question.
    parsed = rag.parse_query(propre)

    # 2) PLANIFICATION — quel agent, quels outils complémentaires.
    plan = profils.planifier(propre, parsed)
    trace.agent = plan.agent

    # 3) EXÉCUTION DES OUTILS — sous permission, délai, reprises bornées et validation.
    faits: list[dict] = []
    if plan.appels:
        try:
            faits = await asyncio.wait_for(
                _executer_le_plan(plan, {"db": db}, trace), timeout=BUDGET_OUTILS_S)
        except asyncio.TimeoutError:
            trace.incident("budget d'outils épuisé : réponse produite sans enrichissement")
            faits = [_echec_pour_assistant(nom, "délai global dépassé") for nom, _ in plan.appels]

    # 4) ASSISTANT EXISTANT — c'est LUI qui rédige, avec son prompt, son modèle, sa mémoire.
    resultat = await rag.answer_question(db, propre, mode=mode, historique=historique,
                                         outils=faits or None)

    # 5) ASSAINISSEMENT DE LA SORTIE — ni clé, ni prompt système, ni raisonnement interne.
    texte, expurge = securite.assainir_sortie(resultat.get("answer"))
    resultat["answer"] = texte
    for section in resultat.get("sections") or []:
        section["body"], retires = securite.assainir_sortie(section.get("body"))
        expurge += retires
    trace.expurge = sorted(set(expurge))
    trace.validation_sortie = "expurgee" if trace.expurge else "conforme"

    trace.journaliser()
    resultat["harness"] = trace.rapport()
    return resultat


async def _executer_le_plan(plan, contexte: dict, trace: Trace) -> list[dict]:
    """Déroule les appels du plan, avec repli sur l'outil alternatif quand il en existe un."""
    faits: list[dict] = []
    for nom, arguments in plan.appels:
        reussi, resultat, motif = await executer_outil(nom, arguments, plan.agent,
                                                       contexte, trace)
        if reussi:
            faits.append(_faits_pour_assistant(nom, resultat, motif))
            continue

        # OUTIL DE REPLI — une capacité voisine vaut mieux qu'une absence, à condition d'être
        # elle aussi autorisée pour l'agent : un repli ne contourne jamais les permissions.
        outil = registre.obtenir(nom)
        secours = outil.alternative if outil else None
        if secours and secours in profils.outils_autorises(plan.agent):
            trace.incident(f"repli de « {nom} » vers « {secours} » ({motif})")
            reussi2, resultat2, motif2 = await executer_outil(secours, arguments, plan.agent,
                                                              contexte, trace)
            if reussi2:
                faits.append(_faits_pour_assistant(secours, resultat2, motif2))
                continue
            motif = f"{motif} ; le repli « {secours} » a également échoué"

        faits.append(_echec_pour_assistant(nom, motif))
    return faits
