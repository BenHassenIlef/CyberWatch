import base64
import hashlib
import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("cyberwatch.config")

# RACINE DU PROJET, déduite de l'emplacement de CE fichier :
#   app/backend/core/config.py  ->  parents[3]
#
# Le chemin du fichier de configuration était écrit « .env », donc RELATIF au répertoire
# COURANT. Lancée depuis la racine, l'application chargeait tout ; lancée depuis n'importe
# quel autre répertoire — un service Windows, une tâche planifiée, un `cd` malheureux — elle
# ne chargeait RIEN et démarrait quand même : SMTP_HOST vide, donc courriels muets, et
# LLM_API_KEY vide, donc assistant dégradé. Le tout sans le moindre message.
#
# Ancré ici sur un chemin absolu, le comportement ne dépend plus de la façon dont on démarre.
RACINE_PROJET = Path(__file__).resolve().parents[3]
FICHIER_ENV = RACINE_PROJET / ".env"

# Copie locale historique, JAMAIS chargée (elle ne l'a jamais été, malgré les apparences).
# On la signale plutôt que de la supprimer : quelqu'un y a saisi des valeurs, et découvrir
# qu'elles n'ont aucun effet vaut mieux que de les voir disparaître.
_ENV_IGNORE = RACINE_PROJET / "app" / "backend" / ".env"

# Alias de fournisseurs LLM saisis dans .env -> nom canonique interne.
# ATTENTION : « Groq » (groq.com, clés « gsk_… ») et « Grok » (xAI, clés « xai-… ») sont DEUX
# fournisseurs différents malgré leurs noms quasi identiques. Les deux sont supportés ici.
LLM_ALIASES = {"groq": "groq", "groqcloud": "groq",
               "grok": "xai", "xai": "xai", "x.ai": "xai", "grok-ai": "xai",
               "anthropic": "anthropic", "claude": "anthropic",
               "openai": "openai", "gpt": "openai"}

# Modèle utilisé si LLM_MODEL n'est pas renseigné.
LLM_DEFAULT_MODELS = {"groq": "openai/gpt-oss-120b", "xai": "grok-4",
                      "anthropic": "claude-sonnet-4-5", "openai": "gpt-4o-mini"}


def tracer_chargement() -> None:
    """Annonce QUEL fichier de configuration a été lu, et lesquels ne le sont pas.

    Appelé au démarrage. Une valeur saisie dans un fichier que personne ne charge est
    indétectable autrement : on constate seulement que le réglage « ne marche pas ».
    Aucune valeur n'est journalisée — seulement des chemins et des présences.
    """
    if FICHIER_ENV.exists():
        logger.info("Configuration lue depuis %s", FICHIER_ENV)
    else:
        logger.warning(
            "Aucun fichier %s : l'application démarre sur ses valeurs par défaut. "
            "Les courriels et l'assistant IA resteront inactifs.", FICHIER_ENV)
    if _ENV_IGNORE.exists():
        logger.warning(
            "Le fichier %s existe mais N'EST PAS LU : seule la configuration de la racine "
            "est chargée. Toute valeur saisie ici reste sans effet.", _ENV_IGNORE)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=FICHIER_ENV, extra="ignore")

    MONGO_URI: str = "mongodb://localhost:27017"
    DB_NAME: str = "cyberwatch"

    JWT_SECRET: str = "change-this-to-a-long-random-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    CORS_ORIGINS: str = "http://localhost:5173"

    # Clé API NVD (optionnelle) : augmente fortement la limite de débit de la collecte.
    # https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY: str = ""

    # ENRICHISSEMENT pendant la COLLECTE.
    #
    # true  : chaque CVE collectée est complétée en interrogeant, PAR IDENTIFIANT, les bases
    #         officielles (NVD, MITRE, OSV, Red Hat, GitHub, MSRC). Meilleure complétude
    #         (score CVSS, CWE, références), mais ~6 requêtes réseau par CVE — c'est de très
    #         loin l'étape la plus lente de la collecte.
    # false : la collecte se limite STRICTEMENT aux sources configurées par l'administrateur.
    #         Beaucoup plus rapide, mais les CVE ne portent que ce que leur source publie.
    #
    # L'enrichissement À LA DEMANDE (ouverture d'une fiche CVE) n'est PAS concerné : il reste
    # actif et complète la fiche au moment où un consultant la consulte réellement.
    ENRICHMENT_ENABLED: bool = True

    # TRADUCTION pendant la COLLECTE.
    #
    # false (défaut) : la collecte n'appelle PAS le modèle de traduction. Les CVE sont
    #         enregistrées telles quelles ; la traduction se fait à part, via
    #         `python translate_existing.py`, à son propre rythme.
    # true  : chaque CVE collectée est traduite avant d'être stockée.
    #
    # Le défaut est « false » à dessein : traduire pendant la collecte fait dépendre la DURÉE
    # de la collecte du quota du fournisseur LLM (Groq renvoie HTTP 429 en rafale). Une
    # limitation de débit chez un tiers ne doit pas retarder la veille en vulnérabilités.
    TRANSLATION_IN_COLLECTION: bool = False

    # Ordre de priorité des sources pour la fusion des champs en cas de conflit (configurable).
    # La première source l'emporte sur les suivantes.
    # NVD > éditeur officiel (Microsoft/Red Hat…) > CNA (MITRE) > CERT > GitHub/OSV > OpenCVE.
    CVE_SOURCE_PRIORITY: str = "nvd,msrc,redhat,mitre,cert-fr,github,osv,opencve,source"

    # Fenêtre de notification (en jours) : une CVE ne génère une notification QUE si sa VRAIE
    # date de publication est dans cette fenêtre. Au-delà, la CVE est enregistrée sans notifier.
    CVE_NOTIFY_WINDOW_DAYS: int = 2

    # Fuseau horaire du scheduler (nom IANA, ex. « Africa/Tunis », « Europe/Paris »).
    # L'heure de planification (ex. 08:00) est interprétée dans CE fuseau.
    # Vide = fuseau LOCAL du serveur (recommandé si le serveur est à l'heure locale).
    SCHEDULER_TIMEZONE: str = ""

    # Déclencheur de la collecte QUOTIDIENNE :
    #   "external" (défaut, RECOMMANDÉ) -> la Tâche planifiée Windows lance collect_once.py ;
    #        FastAPI/Uvicorn NE lance PAS de collecte automatique (il ne sert que l'API/UI).
    #        La collecte ne dépend donc plus d'une fenêtre Uvicorn ouverte.
    #   "internal" -> l'ancien comportement : le scheduler interne (dans FastAPI) déclenche la
    #        collecte tant que le process Uvicorn tourne.
    # Un VERROU en base empêche de toute façon une double collecte simultanée (ceinture + bretelles).
    COLLECTION_TRIGGER: str = "external"

    # Nombre maximum de rendus Chromium SIMULTANÉS (toutes sources confondues). Empêche le
    # « thrash » : sans plafond, N sources HTML en parallèle lançaient N navigateurs -> timeouts.
    RENDER_CONCURRENCY: int = 3

    @property
    def internal_scheduler_enabled(self) -> bool:
        return (self.COLLECTION_TRIGGER or "external").strip().lower() == "internal"

    # ---- LLM de l'assistant IA (OPTIONNEL mais recommandé) -----------------------------
    # Deux usages, strictement séparés :
    #   1) ANCRÉ (base interne) : reformulation/résumé des CVE réellement récupérées en base.
    #      Prompt de bridage strict -> aucune invention, aucune valeur modifiée.
    #   2) EXTERNE (hors base) : questions générales de cybersécurité (définitions, méthodo,
    #      bonnes pratiques, CVE absente de la base). Réponse explicitement étiquetée
    #      « hors base de connaissances » côté API et côté interface.
    # Si aucune clé n'est fournie, l'assistant retombe sur la synthèse déterministe ancrée
    # et refuse les questions externes — aucune régression.
    #   LLM_PROVIDER : "groq" | "grok" (alias "xai") | "anthropic" | "openai" (vide = désactivé)
    #      -> « groq »  = groq.com, clés « gsk_… »  (Llama, GPT-OSS, Qwen… en inférence rapide)
    #      -> « grok »  = xAI,      clés « xai-… »  (modèles Grok)
    #   LLM_API_KEY  : clé API du fournisseur (Groq : https://console.groq.com/keys)
    #   LLM_MODEL    : identifiant de modèle (défaut adapté au fournisseur si vide)
    #   LLM_BASE_URL : override de l'URL de base (proxy/gateway) — optionnel
    LLM_PROVIDER: str = ""
    LLM_API_KEY: str = ""
    LLM_MODEL: str = ""
    LLM_BASE_URL: str = ""
    # Délai maximal (secondes) d'un appel LLM avant retour au mode déterministe.
    LLM_TIMEOUT: int = 45

    # Autorise l'assistant à répondre AUX QUESTIONS EXTERNES (hors base CyberWatch AI).
    # Mettre à false pour un mode « base interne uniquement » (comportement historique).
    ASSISTANT_EXTERNAL_ANSWERS: bool = True

    @property
    def llm_provider(self) -> str:
        """Nom canonique du fournisseur ('xai' | 'anthropic' | 'openai'), ou '' si désactivé."""
        return LLM_ALIASES.get((self.LLM_PROVIDER or "").strip().lower(), "")

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_provider and self.LLM_API_KEY.strip())

    @property
    def external_answers_enabled(self) -> bool:
        """Les questions hors base ne sont possibles que si un LLM est réellement configuré."""
        return self.ASSISTANT_EXTERNAL_ANSWERS and self.llm_enabled

    @property
    def llm_model(self) -> str:
        if self.LLM_MODEL:
            return self.LLM_MODEL
        return LLM_DEFAULT_MODELS.get(self.llm_provider, "grok-4")

    @property
    def source_priority(self) -> list[str]:
        return [s.strip().lower() for s in self.CVE_SOURCE_PRIORITY.split(",") if s.strip()]

    # Notifications par email (désactivées par défaut ; activées si SMTP configuré).
    EMAIL_NOTIFICATIONS_ENABLED: bool = False
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "cyberwatch@localhost"
    # CHIFFREMENT DE LA LIAISON. Le code n'appelait `starttls()` que si un identifiant était
    # renseigné : un relais exigeant TLS sans authentification recevait donc le message EN
    # CLAIR — et un identifiant Gmail traversait le réseau sans protection si la configuration
    # était incomplète. Le chiffrement ne doit dépendre que du serveur, jamais de la présence
    # d'un mot de passe.
    #
    #   587 -> STARTTLS (la liaison démarre en clair puis bascule) — cas de Gmail ;
    #   465 -> TLS implicite (la liaison est chiffrée dès l'ouverture).
    SMTP_USE_TLS: bool = True
    # Fenetre d activite des consultants destinataires, en jours. 0 = tout consultant s etant
    # connecte au moins une fois. Au-dela, seuls ceux qui se sont connectes recemment sont
    # prevenus : un compte de demonstration cesse ainsi de recevoir la veille quotidienne.
    NOTIFY_ACTIVE_CONSULTANT_DAYS: int = 0

    # Adresses AJOUTEES a chaque envoi, en plus des consultants (separees par des virgules).
    # Destinees a une boite de supervision qui doit tout recevoir, y compris lorsqu aucun
    # consultant ne remplit le critere d activite. Ces adresses ne dependent d aucun compte.
    NOTIFY_EXTRA_RECIPIENTS: str = ""

    # LISTE EXCLUSIVE de destinataires (separees par des virgules). Renseignee, elle REMPLACE
    # entierement la selection automatique : seules ces adresses recoivent la veille, et
    # aucun compte consultant n y est ajoute.
    #
    # NOTIFY_EXTRA_RECIPIENTS ajoute ; celle-ci restreint. La distinction compte : une
    # entreprise qui dirige la veille vers une boite de service unique ne veut pas qu une
    # connexion d un consultant, ou la creation d un compte de demonstration, remette
    # discretement des adresses dans la liste. Laissee vide, le comportement est inchange.
    NOTIFY_ONLY_RECIPIENTS: str = ""

    @staticmethod
    def _adresses(valeur: str) -> list[str]:
        """Adresses d une liste separee par des virgules, sans doublon (casse ignoree)."""
        vus: list[str] = []
        for adresse in (valeur or "").split(","):
            adresse = adresse.strip()
            if adresse and adresse.lower() not in [v.lower() for v in vus]:
                vus.append(adresse)
        return vus

    @property
    def extra_recipients(self) -> list[str]:
        return self._adresses(self.NOTIFY_EXTRA_RECIPIENTS)

    @property
    def only_recipients(self) -> list[str]:
        return self._adresses(self.NOTIFY_ONLY_RECIPIENTS)

    # VEILLE DU JOUR : la collecte quotidienne ne retient que les vulnérabilités PUBLIÉES
    # aujourd'hui.
    #
    # Sans cette borne, la fenêtre interrogée couvrait jusqu'à 120 jours et le plafond par
    # source tronquait le résultat depuis le PLUS ANCIEN : on rapatriait des centaines de
    # CVE de 2018 à 2022 sans jamais atteindre celles du jour. Un rattrapage sur plusieurs
    # jours reste possible en élargissant `DAILY_COLLECTION_WINDOW_DAYS`.
    DAILY_COLLECTION_TODAY_ONLY: bool = True
    # Nombre de jours couverts quand la borne ci-dessus est active. 1 = aujourd'hui seul.
    # Au-delà, on rattrape les publications tardives des jours précédents.
    DAILY_COLLECTION_WINDOW_DAYS: int = 1

    # --- Reddit (discussions communautaires) -------------------------------------------
    # Accès SERVEUR À SERVEUR à l'API officielle. L'accès anonyme est fermé (HTTP 403) et
    # ne doit pas être contourné : sans ces identifiants, la source se déclare simplement
    # NON CONFIGURÉE. Aucune valeur par défaut ne doit être écrite ici.
    #   1. https://www.reddit.com/prefs/apps → « create app » → type « script »
    #   2. reporter l'identifiant et le secret dans le fichier .env
    REDDIT_CLIENT_ID: str = ""
    REDDIT_CLIENT_SECRET: str = ""
    # Reddit EXIGE un agent utilisateur descriptif et unique ; un agent générique est rejeté.
    REDDIT_USER_AGENT: str = "CyberWatchAI/1.0 (veille de vulnerabilites)"

    @property
    def email_enabled(self) -> bool:
        return self.EMAIL_NOTIFICATIONS_ENABLED and bool(self.SMTP_HOST)

    # Clé maître de chiffrement des secrets de sources (API Key, Bearer, OAuth...).
    # Fournir une clé Fernet dédiée en production ; sinon dérivée de JWT_SECRET.
    CREDENTIALS_ENCRYPTION_KEY: str = ""

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def credentials_key(self) -> bytes:
        """Clé Fernet (urlsafe base64, 32 octets). Dérivée de JWT_SECRET si non fournie."""
        if self.CREDENTIALS_ENCRYPTION_KEY:
            return self.CREDENTIALS_ENCRYPTION_KEY.encode()
        digest = hashlib.sha256(self.JWT_SECRET.encode()).digest()
        return base64.urlsafe_b64encode(digest)


settings = Settings()
