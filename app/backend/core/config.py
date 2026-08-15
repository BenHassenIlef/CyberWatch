import base64
import hashlib

from pydantic_settings import BaseSettings, SettingsConfigDict

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


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

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
