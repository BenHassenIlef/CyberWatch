"""AI AGENT HARNESS — couche d'orchestration placée AUTOUR de l'assistant existant.

L'assistant de CyberWatch AI (`services/assistant/rag.py`) reste l'unique interlocuteur du
consultant : c'est lui qui comprend la question, interroge la base, et rédige la réponse avec
son prompt, son modèle et sa mémoire. Le harness ne le remplace pas et n'en crée pas un second.

Il apporte ce qui lui manquait autour :

    planification   quel agent traite la demande, et quelle capacité complémentaire mobiliser
    permission      quel outil un agent a le droit d'appeler — refus par défaut
    exécution       délai maximal, reprises bornées, outil de repli
    validation      la sortie d'un outil est-elle exploitable avant d'atteindre le modèle
    sécurité        contenu externe traité comme hostile, sortie expurgée
    trace           agent, outils, statuts, reprises, durée — sans aucune donnée sensible

Point d'entrée unique : `noyau.repondre(db, question, historique, mode)`.
"""
from app.backend.services.assistant.harness import agents, outils, securite, trace
from app.backend.services.assistant.harness.noyau import (BUDGET_OUTILS_S, MAX_REPRISES,
                                                          HarnessIndisponible, executer_outil,
                                                          repondre)

__all__ = ["repondre", "executer_outil", "HarnessIndisponible", "MAX_REPRISES",
           "BUDGET_OUTILS_S", "agents", "outils", "securite", "trace"]
