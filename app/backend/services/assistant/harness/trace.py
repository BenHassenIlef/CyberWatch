"""TRACE D'EXÉCUTION du harness — ce qui s'est passé pour une requête, et à quel prix.

Un orchestrateur qui décide seul quel agent répond, quels outils tourner et combien de fois
réessayer devient indébogable s'il n'énonce pas ses décisions. La trace répond, pour chaque
requête, aux questions qu'on se pose quand une réponse déçoit : quel agent a répondu, quels
outils ont tourné, lesquels ont échoué, combien de reprises, combien de temps.

CE QUI N'Y ENTRE JAMAIS
Ni question, ni réponse, ni adresse, ni identifiant de consultant, ni clé, ni jeton. La trace
porte des NOMS D'OUTILS, des STATUTS et des DURÉES — de quoi diagnostiquer une panne, rien de
quoi reconstituer une conversation. Les arguments d'outils sont réduits à leurs clés : savoir
qu'une recherche portait sur `cve_id` suffit au diagnostic, connaître laquelle ne sert à rien.
"""
import logging
import time
import uuid
from dataclasses import dataclass, field

logger = logging.getLogger("cyberwatch.assistant.harness")

# Statuts d'une exécution d'outil. Volontairement distincts : « rien trouvé » est un RÉSULTAT,
# « en échec » est un incident, « refusé » est une décision de sécurité. Les confondre ferait
# passer un refus de permission pour une panne, et une absence de résultat pour une erreur.
OK, VIDE, ECHEC, REFUSE, INVALIDE, EXPIRE = (
    "ok", "vide", "echec", "refuse", "invalide", "expire")


@dataclass
class AppelOutil:
    """Une exécution d'outil : ce qui a été tenté, ce qui en est sorti, en combien de temps."""
    outil: str
    statut: str
    duree_ms: int
    tentatives: int = 1
    erreur: str | None = None
    validation: str | None = None
    arguments: list[str] = field(default_factory=list)   # NOMS des paramètres, jamais valeurs

    def resume(self) -> dict:
        return {"outil": self.outil, "statut": self.statut, "duree_ms": self.duree_ms,
                "tentatives": self.tentatives, "validation": self.validation,
                "erreur": (self.erreur or None), "arguments": self.arguments}


@dataclass
class Trace:
    """Trace complète d'une requête traversant le harness."""
    requete_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent: str = "assistant_general"
    debut: float = field(default_factory=time.monotonic)
    appels: list[AppelOutil] = field(default_factory=list)
    validation_sortie: str = "non_evaluee"
    expurge: list[str] = field(default_factory=list)
    incidents: list[str] = field(default_factory=list)

    # ---- alimentation -----------------------------------------------------------------

    def ajouter(self, appel: AppelOutil) -> None:
        self.appels.append(appel)

    def incident(self, message: str) -> None:
        """Anomalie non bloquante. Le message est écrit par le code, jamais par l'utilisateur."""
        self.incidents.append(message[:200])

    # ---- lecture ----------------------------------------------------------------------

    @property
    def duree_ms(self) -> int:
        return int((time.monotonic() - self.debut) * 1000)

    @property
    def outils_utilises(self) -> list[str]:
        return [a.outil for a in self.appels]

    @property
    def reprises(self) -> int:
        """Nombre total de RE-tentatives — la première n'en est pas une."""
        return sum(max(0, a.tentatives - 1) for a in self.appels)

    @property
    def statut(self) -> str:
        """« ok » si aucun outil n'a échoué ; « degrade » sinon — la réponse existe quand même."""
        if any(a.statut in (ECHEC, EXPIRE, INVALIDE) for a in self.appels):
            return "degrade"
        return "ok"

    def rapport(self) -> dict:
        """Vue exposable : ce que l'API peut renvoyer et ce que le journal enregistre."""
        return {
            "request_id": self.requete_id,
            "agent": self.agent,
            "tools": [a.resume() for a in self.appels],
            "status": self.statut,
            "retries": self.reprises,
            "duration_ms": self.duree_ms,
            "output_validation": self.validation_sortie,
            "redacted": self.expurge,
            "incidents": self.incidents,
        }

    def journaliser(self) -> None:
        """Une ligne par requête, lisible dans un journal — et rien de confidentiel dedans."""
        details = " ".join(
            f"{a.outil}={a.statut}" + (f"(x{a.tentatives})" if a.tentatives > 1 else "")
            for a in self.appels) or "aucun-outil"
        niveau = logger.warning if self.statut == "degrade" else logger.info
        niveau("[harness %s] agent=%s statut=%s outils=[%s] reprises=%d duree=%dms validation=%s%s",
               self.requete_id, self.agent, self.statut, details, self.reprises,
               self.duree_ms, self.validation_sortie,
               f" expurge={','.join(self.expurge)}" if self.expurge else "")
        for incident in self.incidents:
            logger.warning("[harness %s] incident : %s", self.requete_id, incident)
