"""Domaines officiels et réputation (whitelist / blacklist).

Architecture pensée pour être étendue facilement :
- `OFFICIAL_DOMAINS` : autorités et éditeurs reconnus en cybersécurité.
- `ReputationStore`  : listes blanche/noire éditables (en mémoire ici, remplaçables par une
  base de données ou un service externe — VirusTotal, MISP, etc. — plus tard).
"""

# Autorités et éditeurs officiels reconnus (le sous-domaine est accepté : *.nist.gov, etc.).
# Le préfixe « www. » est géré automatiquement par `_host_matches` (www.ancs.tn ≈ ancs.tn).
OFFICIAL_DOMAINS: set[str] = {
    "cisa.gov",
    "nist.gov",
    "nvd.nist.gov",
    "cve.org",
    "mitre.org",
    "microsoft.com",
    "microsoftsecurity.com",
    "cisco.com",
    "talosintelligence.com",
    "paloaltonetworks.com",
    "crowdstrike.com",
    "sentinelone.com",
    "fortinet.com",
    "rapid7.com",
    "tenable.com",
    # --- CERT nationaux / organismes gouvernementaux de cybersécurité ---
    "ancs.tn",          # ANCS — Agence Nationale de la Cybersécurité (Tunisie)
    "tuncert.tn",       # TunCERT (opéré par l'ANCS)
    "cert.ssi.gouv.fr", # CERT-FR / ANSSI (France)
    "ssi.gouv.fr",      # ANSSI (France)
    "cert.europa.eu",   # CERT-EU
    "us-cert.gov",      # US-CERT
    "dgssi.gov.ma",     # DGSSI / maCERT (Maroc)
}

# Suffixes de domaines gouvernementaux reconnus comme officiels (CERT/autorités nationales).
GOV_TLD_SUFFIXES: tuple[str, ...] = (".gov", ".gouv.fr", ".gov.uk", ".gc.ca", ".govt.nz", ".gov.ma")


def _host_matches(host: str, domain: str) -> bool:
    """Vrai si `host` est `domain` ou un de ses sous-domaines."""
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def _is_gov_domain(host: str) -> bool:
    """Domaine gouvernemental reconnu (CERT / autorité nationale)."""
    host = host.lower().strip(".")
    return any(host == suf.strip(".") or host.endswith(suf) for suf in GOV_TLD_SUFFIXES)


def is_official_domain(host: str | None) -> bool:
    if not host:
        return False
    return any(_host_matches(host, d) for d in OFFICIAL_DOMAINS) or _is_gov_domain(host)


class ReputationStore:
    """Réputation par domaine, éditable et extensible.

    Aujourd'hui : deux ensembles en mémoire. Demain : remplacer `is_whitelisted` /
    `is_blacklisted` par un appel à une base ou un service de threat-intel externe, sans
    changer le reste de l'agent.
    """

    def __init__(self, whitelist: set[str] | None = None, blacklist: set[str] | None = None):
        # La whitelist par défaut reprend les domaines officiels (réputation forte connue).
        self.whitelist: set[str] = whitelist if whitelist is not None else set(OFFICIAL_DOMAINS)
        # Exemples de domaines à bannir (fournisseurs de fausses informations, typosquatting…).
        self.blacklist: set[str] = blacklist if blacklist is not None else set()

    def is_whitelisted(self, host: str | None) -> bool:
        if not host:
            return False
        # Domaines explicitement en liste blanche OU domaines gouvernementaux officiels.
        return any(_host_matches(host, d) for d in self.whitelist) or _is_gov_domain(host)

    def is_blacklisted(self, host: str | None) -> bool:
        return bool(host) and any(_host_matches(host, d) for d in self.blacklist)

    def classify(self, host: str | None) -> str:
        """Retourne 'blacklisted' | 'whitelisted' | 'unknown'."""
        if self.is_blacklisted(host):
            return "blacklisted"
        if self.is_whitelisted(host):
            return "whitelisted"
        return "unknown"


# Instance partagée par défaut (peut être remplacée par injection dans l'orchestrateur).
default_reputation_store = ReputationStore()
