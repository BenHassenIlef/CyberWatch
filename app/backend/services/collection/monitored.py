"""Périmètre de surveillance PILOTÉ PAR LES DONNÉES : domaines + produits suivis (alias, mots-clés,
CPE) sont stockés en base (`domains`, `monitored_products`) et gérés par l'administrateur. La collecte
charge dynamiquement la liste ACTIVE à chaque exécution — aucun changement de code n'est requis pour
ajouter un produit.

Deux rôles :
  1. CATALOGUE PAR DÉFAUT (`_CATALOG`) = graine d'amorçage (produits « par défaut ») + REPLI hors-ligne
     (tests / base vide). Les produits par défaut sont marqués `is_default: True`.
  2. CATALOGUE ACTIF (`_active`) = compilé depuis la base via `refresh_catalog(db)` ; retombe sur le
     catalogue par défaut si la base est vide.

Réconciliation IDEMPOTENTE (`seed_catalog`) : à chaque démarrage/collecte, les produits/domaines PAR
DÉFAUT manquants sont créés (jamais dupliqués grâce à `default_key`), les modifications de l'admin sont
préservées (`$setOnInsert`), et les produits PERSONNALISÉS (`is_default: False`) ne sont JAMAIS supprimés.

Règle anti-faux-positifs (voir `classify_all`) :
  - On regarde d'ABORD les champs STRUCTURÉS (vendor / product / affected_products / affected_systems)
    + les CPE. S'ils existent mais ne correspondent à aucun produit suivi -> on REJETTE, même si la
    description cite un produit suivi.
  - On ne se rabat sur la DESCRIPTION (alias STRICTS, plus spécifiques) que lorsqu'AUCUNE information
    produit structurée n'est disponible.

Un produit peut appartenir à PLUSIEURS domaines (ex. « Windows Server » ∈ Systèmes d'exploitation ET
Microsoft) ; une CVE peut affecter PLUSIEURS produits. `classify_all` renvoie toutes les correspondances.
"""
import logging
import re

logger = logging.getLogger("cyberwatch.collection.monitored")

# Alias curatés par produit : nom -> (vendor, alias STRUCTURÉS [larges], alias DESCRIPTION [stricts]).
# Ces valeurs techniques sont GÉRÉES EN INTERNE — l'admin ne saisit que nom / éditeur / domaine.
_A: dict[str, tuple[str, list[str], list[str] | None]] = {
    # Systèmes d'exploitation
    "Windows 10": ("Microsoft", ["windows 10", "windows_10"], ["windows 10"]),
    "Windows 11": ("Microsoft", ["windows 11", "windows_11"], ["windows 11"]),
    "Windows Server": ("Microsoft", ["microsoft windows server", "windows server", "windows_server"], ["windows server"]),
    "Linux Kernel": ("Linux", ["linux kernel", "linux_kernel"], ["linux kernel"]),
    "Ubuntu": ("Canonical", ["ubuntu"], None),
    "Debian": ("Debian", ["debian"], None),
    "Red Hat Enterprise Linux": ("Red Hat", ["red hat enterprise linux", "rhel", "red hat"], ["red hat enterprise linux", "rhel"]),
    # Microsoft
    "Microsoft Windows": ("Microsoft", ["microsoft windows", "windows"], ["microsoft windows"]),
    "Microsoft Office": ("Microsoft", ["microsoft office", "ms office", "office"], ["microsoft office"]),
    "Microsoft 365": ("Microsoft", ["microsoft 365", "office 365", "m365"], ["microsoft 365", "office 365"]),
    "Microsoft Exchange Server": ("Microsoft", ["microsoft exchange server", "exchange server", "microsoft exchange", "exchange"], ["microsoft exchange server", "exchange server"]),
    "Microsoft SharePoint": ("Microsoft", ["microsoft sharepoint", "sharepoint server", "sharepoint"], ["microsoft sharepoint", "sharepoint server"]),
    "Microsoft Teams": ("Microsoft", ["microsoft teams"], None),
    "Microsoft SQL Server": ("Microsoft", ["microsoft sql server", "sql server", "mssql"], ["microsoft sql server", "sql server"]),
    "Microsoft IIS": ("Microsoft", ["internet information services", "microsoft iis", "iis"], ["internet information services", "microsoft iis"]),
    "Active Directory": ("Microsoft", ["active directory", "microsoft active directory", "ad ds", "ad cs", "active directory certificate services"], ["active directory"]),
    "Microsoft Entra ID": ("Microsoft", ["microsoft entra", "entra id", "azure active directory", "azure ad"], ["microsoft entra", "entra id", "azure active directory"]),
    "Microsoft Defender": ("Microsoft", ["microsoft defender", "windows defender", "defender for endpoint", "defender for identity"], ["microsoft defender", "windows defender"]),
    "Microsoft Azure": ("Microsoft", ["microsoft azure", "azure"], ["microsoft azure"]),
    "Hyper-V": ("Microsoft", ["hyper-v", "hyperv", "hyper v"], ["hyper-v"]),
    # Réseaux
    "Cisco IOS": ("Cisco", ["cisco ios"], ["cisco ios"]),
    "Cisco IOS XE": ("Cisco", ["cisco ios xe", "ios xe", "ios-xe", "ios_xe"], ["cisco ios xe", "ios xe"]),
    "Cisco NX-OS": ("Cisco", ["cisco nx-os", "nx-os", "nxos"], ["cisco nx-os"]),
    "Cisco ASA": ("Cisco", ["cisco asa", "adaptive security appliance", "cisco secure firewall"], ["cisco asa", "adaptive security appliance"]),
    "Juniper": ("Juniper", ["juniper", "junos"], None),
    "Aruba": ("HPE", ["aruba networks", "arubaos", "aruba"], ["aruba networks", "arubaos"]),
    "Fortinet FortiOS": ("Fortinet", ["fortinet fortios", "fortios", "fortigate"], ["fortinet fortios", "fortios"]),
    "Palo Alto PAN-OS": ("Palo Alto Networks", ["palo alto pan-os", "pan-os", "panos"], ["pan-os"]),
    # Switchs et équipements HP / HPE
    "HP Switch": ("HP", ["hp switch", "hp procurve", "procurve"], ["hp switch", "hp procurve"]),
    "HPE Switch": ("HPE", ["hpe switch", "hpe procurve", "hpe flexnetwork", "hpe flexfabric"], ["hpe switch", "hpe procurve"]),
    "HPE Aruba Switch": ("HPE", ["hpe aruba switch", "aruba switch", "aruba cx switch"], ["hpe aruba switch", "aruba switch"]),
    "ArubaOS-Switch": ("HPE", ["arubaos-switch", "arubaos switch"], ["arubaos-switch"]),
    "Aruba AOS-CX": ("HPE", ["aruba aos-cx", "aos-cx"], ["aruba aos-cx", "aos-cx"]),
    "HPE Aruba Networking": ("HPE", ["hpe aruba networking", "aruba networking"], ["hpe aruba networking"]),
    # Matériel / Hardware
    "HPE ProLiant": ("Hewlett Packard Enterprise", ["hpe proliant", "hp proliant", "proliant"], ["hpe proliant", "hp proliant"]),
    "HPE iLO": ("Hewlett Packard Enterprise", ["hpe ilo", "hp ilo", "integrated lights-out", "ilo"], ["hpe ilo", "hp ilo", "integrated lights-out"]),
    "HPE OneView": ("Hewlett Packard Enterprise", ["hpe oneview", "hp oneview", "oneview"], ["hpe oneview", "hp oneview"]),
    "Dell PowerEdge": ("Dell", ["dell poweredge", "poweredge"], ["dell poweredge"]),
    "Dell iDRAC": ("Dell", ["dell idrac", "idrac", "integrated dell remote access"], ["dell idrac", "idrac"]),
    "Dell OpenManage": ("Dell", ["dell openmanage", "openmanage"], ["dell openmanage"]),
    "Dell EMC": ("Dell", ["dell emc", "dell unity", "dell powerstore"], ["dell emc"]),
    "Dell Networking": ("Dell", ["dell networking", "dell os10", "powerswitch"], ["dell networking"]),
    # Serveurs Web
    "Apache HTTP Server": ("Apache", ["apache http server", "apache httpd", "httpd"], ["apache http server", "apache httpd"]),
    "Nginx": ("F5", ["nginx"], None),
    "Apache Tomcat": ("Apache", ["apache tomcat", "tomcat"], ["apache tomcat"]),
    # Applications et Frameworks
    "WordPress": ("WordPress", ["wordpress"], None),
    "Drupal": ("Drupal", ["drupal"], None),
    "Joomla": ("Joomla", ["joomla"], None),
    "Laravel": ("Laravel", ["laravel"], None),
    "Spring Framework": ("VMware", ["spring framework", "spring boot", "spring security", "spring cloud"], ["spring framework", "spring boot"]),
    # Bases de données
    "Oracle Database": ("Oracle", ["oracle database", "oracle db", "oracle rdbms"], ["oracle database"]),
    "MySQL": ("Oracle", ["mysql"], None),
    "PostgreSQL": ("PostgreSQL", ["postgresql", "postgres"], None),
    "MongoDB": ("MongoDB", ["mongodb"], None),
    # Cloud et Conteneurs
    "Docker": ("Docker", ["docker"], None),
    "Kubernetes": ("CNCF", ["kubernetes", "k8s"], None),
    "OpenShift": ("Red Hat", ["openshift"], None),
    "containerd": ("CNCF", ["containerd"], None),
    "VMware": ("VMware", ["vmware esxi", "vmware vcenter", "vmware", "esxi", "vcenter"], ["vmware esxi", "vmware vcenter", "vmware"]),
    # Solutions de sécurité
    "Fortinet": ("Fortinet", ["fortinet"], None),
    "Palo Alto Networks": ("Palo Alto Networks", ["palo alto networks", "palo alto"], ["palo alto networks", "palo alto"]),
    "Check Point": ("Check Point", ["check point", "checkpoint"], None),
    "Sophos": ("Sophos", ["sophos"], None),
    "CrowdStrike": ("CrowdStrike", ["crowdstrike"], None),
    # Messagerie
    "Microsoft Exchange": ("Microsoft", ["microsoft exchange", "exchange server", "exchange"], ["microsoft exchange", "exchange server"]),
    "Zimbra": ("Synacor", ["zimbra"], None),
    "Postfix": ("Postfix", ["postfix"], None),
    # Navigateurs
    "Google Chrome": ("Google", ["google chrome", "chromium", "chrome"], ["google chrome", "chromium"]),
    "Mozilla Firefox": ("Mozilla", ["mozilla firefox", "firefox"], ["mozilla firefox", "firefox"]),
    "Microsoft Edge": ("Microsoft", ["microsoft edge", "edge"], ["microsoft edge"]),
    "Safari": ("Apple", ["apple safari", "safari"], ["apple safari"]),
    # Bibliothèques critiques
    "OpenSSL": ("OpenSSL", ["openssl"], None),
    "OpenSSH": ("OpenBSD", ["openssh"], None),
    "Log4j": ("Apache", ["apache log4j", "log4j2", "log4j"], ["log4j"]),
}

# Organisation par défaut : (domaine, [noms de produits]). Un même produit PEUT apparaître dans
# plusieurs domaines (multi-domaines) — c'est voulu et supporté (clé unique = nom + domaine).
_DEFAULT_LAYOUT: list[tuple[str, list[str]]] = [
    ("Systèmes d'exploitation", ["Windows 10", "Windows 11", "Windows Server", "Linux Kernel",
                                 "Ubuntu", "Debian", "Red Hat Enterprise Linux"]),
    ("Microsoft", ["Microsoft Windows", "Windows Server", "Microsoft Office", "Microsoft 365",
                   "Microsoft Exchange Server", "Microsoft SharePoint", "Microsoft Teams",
                   "Microsoft SQL Server", "Microsoft IIS", "Active Directory", "Microsoft Entra ID",
                   "Microsoft Defender", "Microsoft Azure", "Hyper-V"]),
    ("Réseaux et équipements réseau", ["Cisco IOS", "Cisco IOS XE", "Cisco NX-OS", "Cisco ASA",
                                       "Juniper", "Aruba", "Fortinet FortiOS", "Palo Alto PAN-OS"]),
    ("Switchs et équipements HP / HPE", ["HP Switch", "HPE Switch", "HPE Aruba Switch",
                                         "ArubaOS-Switch", "Aruba AOS-CX", "HPE Aruba Networking"]),
    ("Matériel / Hardware", ["HPE ProLiant", "HPE iLO", "HPE OneView", "Dell PowerEdge",
                             "Dell iDRAC", "Dell OpenManage", "Dell EMC", "Dell Networking"]),
    ("Serveurs Web", ["Apache HTTP Server", "Nginx", "Microsoft IIS", "Apache Tomcat"]),
    ("Applications et Frameworks", ["WordPress", "Drupal", "Joomla", "Laravel", "Spring Framework"]),
    ("Bases de données", ["Oracle Database", "Microsoft SQL Server", "MySQL", "PostgreSQL", "MongoDB"]),
    ("Cloud et Conteneurs", ["Docker", "Kubernetes", "OpenShift", "containerd", "VMware"]),
    ("Solutions de sécurité", ["Fortinet", "Palo Alto Networks", "Check Point", "Sophos",
                               "CrowdStrike", "Microsoft Defender"]),
    ("Messagerie", ["Microsoft Exchange", "Zimbra", "Postfix"]),
    ("Navigateurs", ["Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Safari"]),
    ("Bibliothèques critiques", ["OpenSSL", "OpenSSH", "Log4j", "Spring Framework"]),
]


def _auto_aliases(name: str, vendor: str | None) -> tuple[list[str], list[str]]:
    """Génère des alias RAISONNABLES à partir du nom + éditeur (pour les produits PERSONNALISÉS —
    l'admin ne saisit pas d'alias). `broad` (structuré) inclut l'éditeur seul ; `strict` (description)
    reste spécifique (nom + « éditeur nom ») pour éviter les faux positifs."""
    n = (name or "").strip().lower()
    v = (vendor or "").strip().lower()
    broad = [n]
    if v:
        if v not in n:
            broad.append(f"{v} {n}")
        broad.append(v)          # correspondance ÉDITEUR (structuré) — priorité vendor+produit
    strict = [n]
    if v and v not in n:
        strict.append(f"{v} {n}")   # description : reste spécifique (jamais l'éditeur seul)
    return list(dict.fromkeys(a for a in broad if a)), list(dict.fromkeys(s for s in strict if s))


def _catalog_entry(name: str) -> tuple[str, list[str], list[str] | None]:
    """(vendor, broad, strict) d'un produit par défaut — alias curatés si connus, sinon auto."""
    if name in _A:
        return _A[name]
    b, s = _auto_aliases(name, "")
    return "", b, s


# (Domaine, [ (Produit, vendor, broad, strict) ]) — construit à partir de la disposition + alias curatés.
_CATALOG: list[tuple[str, list[tuple[str, str, list[str], list[str] | None]]]] = [
    (domain, [(name, *_catalog_entry(name)) for name in names])
    for domain, names in _DEFAULT_LAYOUT
]


def slug(name: str) -> str:
    """Identifiant URL-safe (ex. « FortiGate / FortiOS » -> « fortigate-fortios »)."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")


def _default_key(name: str, domain: str) -> str:
    """Clé STABLE d'un produit par défaut (nom + domaine) — garantit l'idempotence du seed."""
    return f"{slug(name)}__{slug(domain)}"


def _boundary(alias: str) -> re.Pattern:
    """Regex « mot entier » (bornes non-alphanumériques) — évite les correspondances partielles."""
    return re.compile(r"(?<![a-z0-9])" + re.escape(alias.lower()) + r"(?![a-z0-9])")


class _Product:
    """Produit surveillé COMPILÉ (regex prêtes). `broad` sert au texte STRUCTURÉ, `strict` à la
    DESCRIPTION (plus spécifique), `cpes` au préfixe CPE. `enabled` filtre l'activation."""
    __slots__ = ("name", "vendor", "domain", "broad", "strict", "cpes", "enabled",
                 "specifiques", "editeur_seul")

    def __init__(self, name, vendor, domain, broad, strict, cpes=None, enabled=True):
        self.name = name
        self.vendor = vendor or ""
        self.domain = domain
        self.broad = [_boundary(a) for a in broad if a]
        self.strict = [_boundary(a) for a in (strict if strict is not None else broad) if a]
        self.cpes = [c.lower() for c in (cpes or []) if c]
        self.enabled = enabled

        # ALIAS SPÉCIFIQUES vs ALIAS RÉDUIT À L'ÉDITEUR.
        #
        # Un produit créé depuis l'interface reçoit l'éditeur nu parmi ses alias. « Windows
        # Server 2022 » captait alors TOUTE vulnérabilité Microsoft — Excel, Xbox — et le
        # consultant recevait des alertes sans rapport avec le produit qu'il surveille.
        # L'alias éditeur reste utile pour SITUER une CVE, mais il ne suffit jamais à
        # l'attribuer : il faut au moins un alias qui désigne le PRODUIT.
        marque = (vendor or "").strip().lower()
        # Quand le produit PORTE le nom de son éditeur (« Docker » édité par « Docker »),
        # l'alias est à la fois la marque et le produit : le déclasser reviendrait à ne plus
        # jamais reconnaître ce produit. Une vulnérabilité Docker se retrouvait ainsi
        # attribuée à « Microsoft Windows » et pas à Docker.
        homonyme = marque and (name or "").strip().lower() == marque
        vendeur_seul = (lambda a: not homonyme and a.strip().lower() == marque)
        self.specifiques = [_boundary(a) for a in broad if a and not vendeur_seul(a)]
        self.editeur_seul = [_boundary(a) for a in broad if a and vendeur_seul(a)]


def _build_static() -> list[_Product]:
    out: list[_Product] = []
    for domain, prods in _CATALOG:
        for (name, vendor, broad, strict) in prods:
            out.append(_Product(name, vendor, domain, broad, strict))
    return out


# ---------------------------------------------------------------------------------------------
# ÉTAT ACTIF (remplacé par refresh_catalog ; retombe sur le catalogue par défaut si base vide)
# ---------------------------------------------------------------------------------------------
_active: list[_Product] = _build_static()
_from_db: bool = False

PRODUCTS: list[_Product] = _active
DOMAINS: list[str] = [d for d, _ in _CATALOG]
PRODUCT_BY_SLUG: dict[str, str] = {slug(p.name): p.name for p in _active}
DOMAIN_OF: dict[str, str] = {p.name: p.domain for p in _active}


def _rebuild_derived() -> None:
    global PRODUCTS, DOMAINS, PRODUCT_BY_SLUG, DOMAIN_OF
    PRODUCTS = _active
    PRODUCT_BY_SLUG = {slug(p.name): p.name for p in _active}
    DOMAIN_OF = {p.name: p.domain for p in _active}
    seen: list[str] = []
    for p in _active:
        if p.domain and p.domain not in seen:
            seen.append(p.domain)
    DOMAINS = seen


def _compile_db_product(doc: dict) -> _Product:
    """Compile un document `monitored_products` en _Product. Les alias servent au texte structuré ;
    les mots-clés (plus spécifiques) servent AUSSI à la description ; le nom canonique complète."""
    name = doc.get("name") or ""
    vendor = doc.get("vendor") or ""
    aliases = [a for a in (doc.get("aliases") or []) if a]
    keywords = [k for k in (doc.get("keywords") or []) if k]
    broad = list(dict.fromkeys([name.lower()] + ([f"{vendor} {name}".lower()] if vendor else [])
                               + [a.lower() for a in aliases] + [k.lower() for k in keywords]))
    strict = keywords or aliases or [name]
    return _Product(name, vendor, doc.get("domain") or "", broad, strict,
                    cpes=doc.get("cpes"), enabled=doc.get("enabled", True))


async def refresh_catalog(db) -> int:
    """Recharge le catalogue ACTIF depuis la base (produits ACTIVÉS, domaines ACTIVÉS). À appeler au
    début de chaque collecte et après toute modification admin. Retombe sur le catalogue par défaut
    si vide. Renvoie le nombre de produits actifs."""
    global _active, _from_db
    try:
        dom_docs = [d async for d in db.domains.find({}, {"name": 1, "enabled": 1})]
        disabled_domains = {d["name"] for d in dom_docs if d.get("enabled") is False}
        prod_docs = [d async for d in db.monitored_products.find({"enabled": {"$ne": False}})]
    except Exception as exc:  # noqa: BLE001 - base indisponible -> on garde le catalogue en mémoire
        logger.warning("refresh_catalog: base indisponible (%s) — catalogue conservé.", exc)
        return len(_active)

    active = [_compile_db_product(d) for d in prod_docs
              if (d.get("domain") or "") not in disabled_domains and d.get("name")]
    if active:
        _active, _from_db = active, True
    elif await db.monitored_products.count_documents({}) > 0:
        # LA BASE FAIT AUTORITÉ DÈS QU'ELLE CONTIENT DES PRODUITS.
        #
        # Sans ce cas, désactiver le dernier produit surveillé faisait retomber la collecte
        # sur le catalogue codé en dur : le produit que l'administrateur venait d'écarter
        # revenait aussitôt, et tout le catalogue par défaut avec lui. Un périmètre vide est
        # un choix légitime — il doit être respecté.
        _active, _from_db = [], True
        logger.info("Catalogue de surveillance : aucun produit actif (choix de l'administrateur).")
    else:
        # Base réellement VIERGE (première installation) : le catalogue par défaut sert d'amorce.
        _active, _from_db = _build_static(), False
    _rebuild_derived()
    logger.info("Catalogue de surveillance : %d produit(s) actif(s) (source=%s).",
                len(_active), "base" if _from_db else "défaut")
    return len(_active)


async def seed_catalog(db) -> dict:
    """RÉCONCILIE le catalogue par défaut avec la base — IDEMPOTENT et NON DESTRUCTIF.

    - Migre les documents hérités (sans `is_default`) vers le nouveau modèle (clé stable).
    - Crée les domaines/produits par DÉFAUT manquants (jamais de doublon : upsert par `default_key`).
    - Préserve les modifications de l'admin (`$setOnInsert` n'écrase rien d'existant).
    - Ne supprime JAMAIS un produit PERSONNALISÉ (`is_default: False`).
    - Élague uniquement les produits PAR DÉFAUT obsolètes (plus dans le catalogue) et les domaines
      par défaut devenus vides.
    Renvoie {domains, products, created, pruned}."""
    from app.backend.utils import utcnow
    now = utcnow()

    # 0) Migration des documents hérités (ancienne graine sans marqueur) -> is_default + default_key.
    async for d in db.monitored_products.find({"is_default": {"$exists": False}}):
        await db.monitored_products.update_one(
            {"_id": d["_id"]},
            {"$set": {"is_default": True, "default_key": _default_key(d.get("name", ""), d.get("domain", ""))}})

    # 1) Domaines par défaut (création si absent, préservation sinon).
    default_domains = [d for d, _ in _CATALOG]
    for name in default_domains:
        await db.domains.update_one(
            {"name": name},
            {"$setOnInsert": {"name": name, "description": "", "enabled": True, "deletable": True,
                              "is_default": True, "created_at": now, "updated_at": now}},
            upsert=True)

    # 2) Produits par défaut (upsert par clé stable -> jamais de doublon). Le catalogue fait AUTORITÉ
    #    sur les champs canoniques (nom/domaine/alias : corrige la casse & les évolutions), tandis que
    #    l'ACTIVATION (`enabled`, réglée par l'admin) et les statistiques sont PRÉSERVÉES.
    keys: list[str] = []
    created = 0
    for domain, prods in _CATALOG:
        for (name, vendor, broad, strict) in prods:
            key = _default_key(name, domain)
            keys.append(key)
            res = await db.monitored_products.update_one(
                {"default_key": key},
                {"$set": {"name": name, "vendor": vendor, "domain": domain,
                          "aliases": broad, "keywords": (strict if strict is not None else broad),
                          "is_default": True, "default_key": key, "updated_at": now},
                 "$setOnInsert": {"cpes": [], "enabled": True, "created_at": now,
                                  "last_collection_at": None, "cve_count": 0, "new_count": 0}},
                upsert=True)
            created += 1 if res.upserted_id else 0

    # 3) Élagage des produits PAR DÉFAUT obsolètes (personnalisés jamais touchés).
    pruned = (await db.monitored_products.delete_many(
        {"is_default": True, "default_key": {"$nin": keys}})).deleted_count

    # 4) Élagage des domaines devenus VIDES et non par défaut (nettoyage des anciens domaines).
    used = set(await db.monitored_products.distinct("domain"))
    await db.domains.delete_many({"name": {"$nin": list(set(default_domains) | used)}})

    total_p = await db.monitored_products.count_documents({})
    total_d = await db.domains.count_documents({})
    if created or pruned:
        logger.info("Réconciliation catalogue : %d domaine(s), %d produit(s) (créés=%d, élagués=%d).",
                    total_d, total_p, created, pruned)
    return {"domains": total_d, "products": total_p, "created": created, "pruned": pruned}


# ---------------------------------------------------------------------------------------------
# CLASSIFICATION
# ---------------------------------------------------------------------------------------------
# Qualificatif entre parenthèses dans un nom de produit : plateforme de déploiement, édition,
# variante. Ce n'est PAS l'identité du produit.
_QUALIFICATIF_RE = re.compile(r"\([^)]*\)")


def _sans_qualificatif(nom: str) -> str:
    """Tête d'un nom de produit : ce qui précède tout qualificatif entre parenthèses.

    « Endpoint Privilege Management (Windows deployment) » désigne un produit BeyondTrust
    DÉPLOYÉ sur Windows — pas un produit Microsoft. En cherchant les alias dans la chaîne
    entière, le jeton « windows » du qualificatif attribuait la vulnérabilité à « Microsoft
    Windows », et l'éditeur réel disparaissait du périmètre.

    La convention est générale : un nom de produit commence par sa marque, et la parenthèse
    précise un contexte. « Docker Desktop », « Microsoft Edge (Chromium-based) »,
    « Windows 10 Version 1607 » gardent donc leur identité, tandis que le contexte de
    déploiement cesse de désigner un produit.
    """
    tete = _QUALIFICATIF_RE.sub(" ", nom or "").strip()
    return tete or (nom or "")


def _structured_haystack(rec: dict) -> str:
    parts: list[str] = []
    # L'ÉDITEUR est repris tel quel : il n'a pas de qualificatif de plateforme.
    if rec.get("vendor"):
        parts.append(str(rec["vendor"]))
    if rec.get("product"):
        parts.append(_sans_qualificatif(str(rec["product"])))
    for v in (rec.get("affected_products") or []):
        if v:
            parts.append(_sans_qualificatif(str(v)))
    if rec.get("vendor") and rec.get("product"):
        parts.append(f"{rec['vendor']} {_sans_qualificatif(str(rec['product']))}")

    # « Systèmes affectés » énumère des PLATEFORMES D'EXÉCUTION, pas des produits vulnérables :
    # « Docker Desktop sur Windows versions antérieures à 4.86.0 ». S'en servir pour attribuer
    # un produit revenait à ranger une faille Docker sous « Microsoft Windows » — le système
    # d'exploitation n'est pas l'éditeur.
    #
    # Ce champ ne sert donc qu'en DERNIER RECOURS : quand la CVE n'identifie son produit ni par
    # son éditeur, ni par sa liste de produits affectés. C'est le cas des avis d'autorité qui
    # ne renseignent que cette rubrique, et où elle reste le seul indice disponible.
    if not parts:
        for v in (rec.get("affected_systems") or []):
            if v:
                parts.append(_sans_qualificatif(str(v)))
    return " ; ".join(parts).lower()


def _cpe_list(rec: dict) -> list[str]:
    out: list[str] = []
    for key in ("cpes", "cpe_list", "cpe"):
        v = rec.get(key)
        if isinstance(v, str):
            out.append(v.lower())
        elif isinstance(v, (list, tuple)):
            out += [str(x).lower() for x in v if x]
    return out


def has_structured(rec: dict) -> bool:
    return bool(rec.get("vendor") or rec.get("product") or rec.get("affected_products")
                or rec.get("affected_systems") or _cpe_list(rec))


def _dedupe(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for name, dom in pairs:
        if (name, dom) not in seen:
            seen.add((name, dom))
            out.append((name, dom))
    return out


# Niveaux de confiance d'un appariement CVE <-> produit surveillé, du plus sûr au plus faible.
CONFIRMED = "confirmed"              # identifiant CPE : correspondance structurée, sans ambiguïté
HIGH_CONFIDENCE = "high_confidence"  # alias PRODUIT trouvé dans les champs structurés
POSSIBLE = "possible"                # alias PRODUIT trouvé seulement dans le texte libre
REJECTED = "rejected"                # seul l'éditeur correspond : insuffisant pour attribuer

_ORDRE_CONFIANCE = {CONFIRMED: 0, HIGH_CONFIDENCE: 1, POSSIBLE: 2, REJECTED: 3}


def classify_detailed(rec: dict) -> list[dict]:
    """Appariements du record, chacun avec son NIVEAU DE CONFIANCE et sa PREUVE.

    Renvoie [{product, domain, confidence, evidence}], les plus sûrs d'abord. Les
    appariements `rejected` — ceux qui ne reposent que sur le nom de l'éditeur — figurent
    dans la liste pour rester traçables, mais l'appelant ne doit pas les retenir.
    """
    cpes = _cpe_list(rec)
    struct = _structured_haystack(rec)
    texte = ((rec.get("title") or "") + " " + (rec.get("description") or "")).lower()
    trouves: dict[str, dict] = {}

    def _noter(p, confiance, preuve):
        ancien = trouves.get(p.name)
        if ancien and _ORDRE_CONFIANCE[ancien["confidence"]] <= _ORDRE_CONFIANCE[confiance]:
            return
        trouves[p.name] = {"product": p.name, "domain": p.domain,
                           "confidence": confiance, "evidence": preuve}

    for p in _active:
        if cpes and p.cpes:
            correspondance = next((c for c in cpes
                                   if any(c.startswith(pc) or pc in c for pc in p.cpes)), None)
            if correspondance:
                _noter(p, CONFIRMED, f"CPE {correspondance[:60]}")
                continue

        if struct.strip():
            motif = next((rx for rx in p.specifiques if rx.search(struct)), None)
            if motif:
                _noter(p, HIGH_CONFIDENCE, f"alias produit dans les champs structures")
                continue
            # L'éditeur correspond, le produit non : on trace le rejet et on s'arrête là.
            # Les champs structurés sont renseignés, le texte libre n'a rien à ajouter.
            if any(rx.search(struct) for rx in p.editeur_seul):
                _noter(p, REJECTED, f"seul l'editeur « {p.vendor} » correspond")
            continue

        if texte.strip() and any(rx.search(texte) for rx in p.strict):
            _noter(p, POSSIBLE, "alias produit dans le texte libre")

    return sorted(trouves.values(), key=lambda h: _ORDRE_CONFIANCE[h["confidence"]])


def classify_all(rec: dict) -> list[tuple[str, str]]:
    """TOUTES les correspondances (produit, domaine) — un produit peut appartenir à plusieurs domaines,
    et une CVE peut affecter plusieurs produits.

    1) CPE (si présents) -> 2/3/4) vendor+product / alias / mots-clés sur le texte STRUCTURÉ ->
    5) repli DESCRIPTION (alias stricts) UNIQUEMENT si aucune info produit structurée. Info structurée
    présente mais hors périmètre -> [] (rejet, pas de repli texte)."""
    cpes = _cpe_list(rec)
    hits: list[tuple[str, str]] = []
    if cpes:
        for p in _active:
            if p.cpes and any(any(c.startswith(pc) or pc in c for pc in p.cpes) for c in cpes):
                hits.append((p.name, p.domain))

    struct = _structured_haystack(rec)
    if struct.strip():
        for p in _active:
            if any(rx.search(struct) for rx in p.broad):
                hits.append((p.name, p.domain))
        return _dedupe(hits)

    if hits:
        return _dedupe(hits)

    text = ((rec.get("title") or "") + " " + (rec.get("description") or "")).lower()
    if text.strip():
        for p in _active:
            if any(rx.search(text) for rx in p.strict):
                hits.append((p.name, p.domain))
    return _dedupe(hits)


def classify(rec: dict) -> tuple[str, str] | None:
    """Première correspondance (produit primaire, domaine primaire) ou None. Compat. ascendante."""
    hits = classify_all(rec)
    return hits[0] if hits else None


def candidate(rec: dict) -> bool:
    """Pré-filtre (avant enrichissement) : garde une CVE qui correspond DÉJÀ, ou dont le produit est
    encore INCONNU (aucune info structurée) — l'enrichissement (NVD/CPE…) tranchera. Élimine tout de
    suite les CVE dont le produit structuré est connu et hors périmètre (économise NVD)."""
    return bool(classify_all(rec)) or not has_structured(rec)
