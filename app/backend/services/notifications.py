"""Notifications des consultants.

- Notification « in-app » : gérée par le flag `is_new` / `update_unread` sur chaque CVE
  (voir routers/consultant.py). Chaque nouvelle CVE = une notification affichée immédiatement.
- Notification par email : OPTIONNELLE, envoyée uniquement si activée et si un serveur SMTP
  est configuré (settings.EMAIL_NOTIFICATIONS_ENABLED + SMTP_HOST). Best-effort, jamais bloquant.
"""
import asyncio
import logging
from datetime import timedelta

from app.backend.core.config import settings
from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.notifications")


def _serveur_local(hote: str) -> bool:
    """Vrai pour un relais sur la machine meme, qui accepte une remise sans authentification."""
    return (hote or "").strip().lower() in ("127.0.0.1", "localhost", "::1", "")


class DestinataireNonAutorise(RuntimeError):
    """Une adresse hors de la liste exclusive a atteint la porte d'envoi."""


def _autorises(destinataires: list[str]) -> list[str]:
    """Filtre ULTIME des destinataires, appliqué juste avant la remise.

    POURQUOI ICI, ALORS QUE LA LISTE EST DÉJÀ RESTREINTE EN AMONT.

    `_liste_de_diffusion` décide QUI recevra la veille, et applique déjà
    `NOTIFY_ONLY_RECIPIENTS`. Mais ce n'est qu'un des chemins qui mènent à l'envoi : l'essai
    de remise en emprunte un autre, et rien n'empêche qu'un troisième apparaisse un jour. Une
    règle appliquée à l'endroit où l'on CHOISIT laisse passer tout ce qui n'est pas passé par
    ce choix.

    Cette fonction est la dernière porte, et toute remise la franchit. Une adresse écartée ne
    peut plus réapparaître par un chemin oublié, ni par un compte recréé, ni par un appel
    écrit plus tard par quelqu'un qui ignorait la règle.

    Le refus est BRUYANT : si le filtrage ne laisse plus personne, on lève plutôt que d'ouvrir
    silencieusement une connexion sans destinataire. Une consigne de confidentialité qui
    échoue en silence est une consigne qu'on croit appliquée.
    """
    permis = settings.only_recipients
    if not permis:
        return destinataires
    autorises = {a.lower() for a in permis}
    retenus = [d for d in destinataires if d.lower() in autorises]
    ecartes = [d for d in destinataires if d.lower() not in autorises]
    if ecartes:
        logger.warning(
            "Destinataire(s) écarté(s) par NOTIFY_ONLY_RECIPIENTS avant remise : %s.",
            ", ".join(ecartes))
    if not retenus:
        raise DestinataireNonAutorise(
            "Aucun destinataire autorisé : « %s » ne figure pas dans NOTIFY_ONLY_RECIPIENTS."
            % ", ".join(destinataires))
    return retenus


def _send_email(recipients: list[str], subject: str, body: str, html: str | None = None) -> None:
    """Envoi SMTP synchrone (exécuté dans un thread pour ne pas bloquer l'event loop).

    Message ALTERNATIF quand `html` est fourni : le client de messagerie affiche la version
    riche s'il le peut, la version texte sinon. Les deux portent la même information — la
    version texte n'est pas un résidu, c'est le repli lisible partout (client en mode texte,
    notification de montre, lecteur d'écran).
    """
    recipients = _autorises(recipients)
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
    else:
        msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(recipients)

    # PORT 465 : la liaison est chiffrée DÈS SON OUVERTURE (TLS implicite). Y envoyer un
    # `STARTTLS` échoue, puisque la négociation a déjà eu lieu — le port dicte le protocole.
    tls_implicite = settings.SMTP_USE_TLS and int(settings.SMTP_PORT) == 465
    classe = smtplib.SMTP_SSL if tls_implicite else smtplib.SMTP

    with classe(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as server:
        # CHIFFREMENT D'ABORD, ET INDÉPENDAMMENT DE L'AUTHENTIFICATION.
        #
        # `starttls()` n'était appelé que si un identifiant était renseigné. Deux conséquences :
        # un relais exigeant TLS sans authentification recevait le message en clair, et une
        # configuration incomplète pouvait faire transiter des identifiants sur une liaison
        # non chiffrée. Le chiffrement dépend du SERVEUR, jamais de la présence d'un secret.
        if settings.SMTP_USE_TLS and not tls_implicite:
            server.starttls()
        # L'authentification n'a lieu QUE si les deux éléments sont présents. Appeler `login`
        # avec un mot de passe vide produit un refus serveur illisible (« 535 »), là où
        # l'absence de configuration doit se dire clairement, en amont.
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            # JAMAIS D'IDENTIFIANTS SUR UNE LIAISON EN CLAIR. `AUTH PLAIN` transmet le mot de
            # passe encodé en base64 — c'est-à-dire lisible par quiconque observe le réseau.
            # Un mot de passe d'application Gmail donne accès à la boîte : le laisser fuir
            # pour envoyer une notification serait un échange absurde. On refuse, et le
            # message dit quoi corriger plutôt que de laisser croire à une panne.
            if not settings.SMTP_USE_TLS and not _serveur_local(settings.SMTP_HOST):
                raise RuntimeError(
                    f"Envoi refusé : SMTP_USE_TLS=false enverrait le mot de passe en clair "
                    f"vers « {settings.SMTP_HOST} ». Activez SMTP_USE_TLS=true (port 587 pour "
                    f"STARTTLS, 465 pour TLS implicite).")
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM, recipients, msg.as_string())


# --------------------------------------------------------------------------------------
# Essai de remise — vérifier la configuration SANS attendre la prochaine collecte
# --------------------------------------------------------------------------------------

# Traduction des refus SMTP courants. Un serveur de messagerie répond par des codes et des
# formules brutes (« 535-5.7.8 Username and Password not accepted ») qui n'indiquent pas quoi
# corriger. Sans cette table, un administrateur qui vient de coller un mot de passe ne sait
# pas s'il s'est trompé de valeur, si la validation en deux étapes manque, ou si le compte est
# bloqué — trois causes, trois gestes différents.
_REFUS_CONNUS = (
    ("username and password not accepted",
     "Identifiants refusés par le serveur. Pour Gmail, il faut un MOT DE PASSE "
     "D'APPLICATION (16 caractères), pas le mot de passe du compte — et la validation en "
     "deux étapes doit être activée au préalable."),
    # Microsoft 365 desactive l'authentification simple par defaut depuis 2023. Le message
    # brut ne dit pas qui peut la reactiver : c'est l'administrateur du tenant, pas
    # l'utilisateur de la boite. Sans cette precision, on cherche du cote du mot de passe.
    ("basic authentication is disabled",
     "Ce compte Microsoft 365 refuse l'authentification simple (SMTP AUTH), desactivee "
     "par defaut. Votre administrateur doit l'autoriser pour cette boite — ou fournir un "
     "compte d'envoi dedie. Le mot de passe n'est pas en cause."),
    ("smtpclientauthentication",
     "L'authentification SMTP est desactivee pour cette boite Microsoft 365. "
     "Votre administrateur doit l'activer."),
    ("application-specific password required",
     "Ce compte exige un mot de passe d'application : le mot de passe habituel est refusé."),
    ("please log in via your web browser",
     "Le fournisseur demande une connexion par navigateur : le compte est probablement "
     "bloqué pour activité inhabituelle. Connectez-vous une fois sur le webmail, puis "
     "réessayez."),
    ("authentication required",
     "Le serveur exige une authentification, mais aucun identifiant n'a été accepté."),
    ("sender address rejected",
     "L'adresse d'expédition est refusée. Elle doit en général être identique à "
     "l'identifiant de connexion (SMTP_FROM = SMTP_USER)."),
    ("connection refused",
     "Connexion refusée : vérifiez l'adresse du serveur et le port."),
    ("timed out",
     "Le serveur n'a pas répondu dans le délai imparti : port filtré, ou serveur injoignable "
     "depuis cette machine."),
    ("name or service not known",
     "Le nom du serveur d'envoi est introuvable : vérifiez SMTP_HOST."),
    # Forme renvoyée par Windows quand le nom ne se résout pas — le message brut
    # (« [Errno 11001] getaddrinfo failed ») ne dit rien à qui n'écrit pas de code réseau.
    ("getaddrinfo failed",
     "Le nom du serveur d'envoi n'a pas pu être résolu : vérifiez SMTP_HOST, ou la "
     "connexion réseau de cette machine."),
)


def expliquer_echec(exc: Exception) -> str:
    """Message ACTIONNABLE à partir d'un refus SMTP. Ne contient jamais le mot de passe."""
    brut = str(exc)
    minuscule = brut.lower()
    for motif, explication in _REFUS_CONNUS:
        if motif in minuscule:
            return explication
    # Refus inconnu : on rend le message d'origine, tronqué et débarrassé de tout secret.
    nettoye = brut.replace(settings.SMTP_PASSWORD or "\x00", "[masqué]")
    return f"Le serveur d'envoi a refusé le message : {nettoye[:200]}"


async def essai_de_remise(adresse: str) -> dict:
    """Envoie UN message d'essai à `adresse` et rapporte précisément ce qui s'est passé.

    Sert à valider une configuration à l'instant où on la saisit. Sans cela, un administrateur
    colle un mot de passe puis attend la collecte du lendemain pour savoir s'il a fonctionné —
    et si rien n'arrive, il ignore si la faute est au mot de passe, au compte ou au réseau.
    """
    if not settings.SMTP_HOST:
        return {"envoye": False, "detail": "Aucun serveur d'envoi (SMTP_HOST) n'est renseigné."}
    if not _serveur_local(settings.SMTP_HOST) and not (settings.SMTP_USER and settings.SMTP_PASSWORD):
        manquant = "SMTP_USER" if not settings.SMTP_USER else "SMTP_PASSWORD"
        return {"envoye": False,
                "detail": f"{manquant} n'est pas renseigné : le serveur refusera la remise."}

    corps = (
        "Ceci est un message d'essai envoyé depuis CyberWatch AI.\n\n"
        "Si vous le lisez, la remise par courriel fonctionne : vous recevrez la veille "
        "quotidienne à cette adresse dès la prochaine collecte.\n\n"
        "— CyberWatch AI"
    )
    try:
        await asyncio.to_thread(_send_email, [adresse],
                                "CyberWatch AI — essai de remise", corps)
    except Exception as exc:  # noqa: BLE001 - l'essai sert précisément à révéler l'échec
        logger.warning("Essai de remise vers %s : échec (%s)", adresse, type(exc).__name__)
        return {"envoye": False, "detail": expliquer_echec(exc)}

    logger.info("Essai de remise vers %s : message accepté par %s", adresse, settings.SMTP_HOST)
    return {"envoye": True,
            "detail": f"Message accepté par « {settings.SMTP_HOST} » et remis à {adresse}."}


_MAX_CVES_IN_EMAIL = 10       # au-delà, l'e-mail renvoie vers l'interface

_SEVERITY_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}


_MAX_PRODUITS = 12            # au-delà, l'e-mail renvoie vers l'interface
_MAX_CVES_PAR_PRODUIT = 5     # un aperçu par produit ; le détail est dans l'application
_ORDRE_SEVERITE = {"critical": 0, "high": 1, "medium": 2, "low": 3}


async def digest_du_jour(db) -> dict:
    """Vulnérabilités collectées AUJOURD'HUI, regroupées PAR PRODUIT SURVEILLÉ.

    Un consultant ne lit pas une liste de cent identifiants : il veut savoir quels PRODUITS
    de son parc sont touchés aujourd'hui, et à quel point. Le regroupement rend le courriel
    exploitable en quelques secondes.

    LE CRITÈRE EST « NON LU », PAS « COLLECTÉ AUJOURD'HUI ».

    Le filtre exigeait auparavant que la fiche ait été RE-collectée le jour même. Une
    vulnérabilité détectée hier, jamais recollectée depuis — le cas ordinaire — disparaissait
    donc de tous les digests suivants : si le courriel de la veille n'était pas parti, elle
    n'était plus jamais signalée. Cinquante-cinq fiches non lues dormaient ainsi en base
    pendant que la synthèse du jour n'en annonçait qu'une seule.

    Ce qui compte pour un consultant n'est pas la date de la dernière requête réseau, mais ce
    qu'il n'a pas encore vu. Une fiche cesse d'apparaître lorsqu'il la lit, jamais parce que
    le temps a passé. La date de publication n'entre pas non plus dans ce filtre : une
    vulnérabilité publiée la semaine dernière et découverte aujourd'hui reste une nouvelle.
    """
    filtre = {"$or": [{"is_new": True}, {"update_unread": True}]}
    projection = {"cve_id": 1, "title": 1, "title_fr": 1, "severity": 1, "cvss_score": 1,
                  "monitored_products": 1, "vendor": 1, "product": 1,
                  # NOUVEAUTÉ ou MISE À JOUR : les deux appellent une lecture différente.
                  # Une CVE déjà connue dont le score vient de changer n'est pas une
                  # découverte, et l'annoncer comme telle brouille la lecture du courriel.
                  "is_new": 1, "update_unread": 1}

    try:
        docs = await db.cves.find(filtre, projection).to_list(2000)
    except Exception as exc:  # noqa: BLE001 - l'e-mail ne doit jamais échouer pour ça
        logger.warning("Synthèse du jour indisponible : %s", exc)
        return {"total": 0, "produits": [], "nouvelles": 0, "mises_a_jour": 0}

    par_produit: dict[str, list] = {}
    for d in docs:
        # Une CVE peut concerner PLUSIEURS produits surveillés : elle apparaît sous chacun,
        # car chacun demande une action distincte de la part du consultant.
        for nom in (d.get("monitored_products") or ["Autres produits"]):
            par_produit.setdefault(nom, []).append(d)

    produits = []
    for nom, fiches in par_produit.items():
        fiches.sort(key=lambda x: (_ORDRE_SEVERITE.get(x.get("severity"), 9),
                                   -(x.get("cvss_score") or 0)))
        critiques = sum(1 for f in fiches if f.get("severity") == "critical")
        produits.append({"nom": nom, "total": len(fiches), "critiques": critiques,
                         "nouvelles": sum(1 for f in fiches if f.get("is_new")),
                         "mises_a_jour": sum(1 for f in fiches
                                             if not f.get("is_new") and f.get("update_unread")),
                         "fiches": fiches})
    # Les produits les plus touchés d'abord, critiques en tête.
    produits.sort(key=lambda p: (-p["critiques"], -p["total"]))
    return {"total": len(docs), "produits": produits,
            "nouvelles": sum(1 for d in docs if d.get("is_new")),
            "mises_a_jour": sum(1 for d in docs
                                if not d.get("is_new") and d.get("update_unread"))}


def _bloc_produits(digest: dict) -> str:
    """Rend la synthèse par produit en texte lisible dans n'importe quel client de messagerie."""
    from app.backend.services.collection.translation import localized

    if not digest["produits"]:
        return "Aucune vulnérabilité nouvelle sur vos produits surveillés aujourd'hui.\n\n"

    lignes = [f"Collecte du jour — {digest['total']} vulnérabilité(s) sur "
              f"{len(digest['produits'])} produit(s) surveillé(s).", ""]
    for p in digest["produits"][:_MAX_PRODUITS]:
        entete = f"▸ {p['nom']} — {p['total']} vulnérabilité(s)"
        detail = []
        if p.get("nouvelles"):
            detail.append(f"{p['nouvelles']} nouvelle(s)")
        if p.get("mises_a_jour"):
            detail.append(f"{p['mises_a_jour']} mise(s) à jour")
        if p["critiques"]:
            detail.append(f"{p['critiques']} critique(s)")
        if detail:
            entete += " (" + ", ".join(detail) + ")"
        lignes.append(entete)
        for f in p["fiches"][:_MAX_CVES_PAR_PRODUIT]:
            sev = _SEVERITY_FR.get(f.get("severity"), f.get("severity") or "—")
            score = f.get("cvss_score")
            score_txt = f" (CVSS {float(score):.1f})" if isinstance(score, (int, float)) else ""
            titre = (localized(f, "title") or "").strip()
            # Marqueur explicite : une fiche déjà vue hier et modifiée depuis ne doit pas se
            # confondre avec une découverte du jour.
            marque = "[NOUVEAU]   " if f.get("is_new") else (
                "[MIS À JOUR] " if f.get("update_unread") else "")
            lignes.append(f"    • {marque}{f.get('cve_id')} — {sev}{score_txt}"
                          + (f" — {titre[:90]}" if titre else ""))
        reste = p["total"] - _MAX_CVES_PAR_PRODUIT
        if reste > 0:
            lignes.append(f"    … et {reste} autre(s) sur ce produit.")
        lignes.append("")

    autres = len(digest["produits"]) - _MAX_PRODUITS
    if autres > 0:
        lignes.append(f"… et {autres} autre(s) produit(s) concerné(s).")
        lignes.append("")
    return "\n".join(lignes)


# ---------------------------------------------------------------------------------------
# Version HTML — même information, rendue lisible en un coup d'œil
# ---------------------------------------------------------------------------------------

# Couleurs de sévérité, alignées sur celles de l'interface pour que le courriel et
# l'application se lisent de la même façon.
_COULEUR_SEVERITE = {"critical": "#b91c1c", "high": "#c2410c",
                     "medium": "#a16207", "low": "#4d7c0f"}


def _echapper(valeur) -> str:
    """Échappement HTML. Le contenu vient de sources externes : il n'est jamais inséré brut."""
    return (str(valeur if valeur is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _ligne_cve_html(fiche: dict) -> str:
    from app.backend.services.collection.translation import localized

    severite = fiche.get("severity")
    couleur = _COULEUR_SEVERITE.get(severite, "#475569")
    score = fiche.get("cvss_score")
    score_txt = f"{float(score):.1f}" if isinstance(score, (int, float)) else "—"
    titre = (localized(fiche, "title") or "").strip()

    # NOUVEAU ou MIS À JOUR : la pastille répond à la question que se pose le consultant en
    # ouvrant le message — « qu'est-ce que je n'ai pas déjà vu hier ? »
    if fiche.get("is_new"):
        pastille = ('<span style="background:#1f3c88;color:#fff;font-size:11px;padding:2px 6px;'
                    'border-radius:3px;white-space:nowrap">NOUVEAU</span>')
    elif fiche.get("update_unread"):
        pastille = ('<span style="background:#b45309;color:#fff;font-size:11px;padding:2px 6px;'
                    'border-radius:3px;white-space:nowrap">MIS À JOUR</span>')
    else:
        pastille = ""

    return (
        '<tr>'
        f'<td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap">'
        f'<b>{_echapper(fiche.get("cve_id"))}</b></td>'
        f'<td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;color:{couleur};'
        f'white-space:nowrap"><b>{_echapper(_SEVERITY_FR.get(severite, severite or "—"))}</b> '
        f'{score_txt}</td>'
        f'<td style="padding:6px 10px;border-bottom:1px solid #e2e8f0">{pastille}</td>'
        f'<td style="padding:6px 10px;border-bottom:1px solid #e2e8f0">'
        f'{_echapper(titre[:110])}</td>'
        '</tr>'
    )


def _corps_html(digest: dict, prenom: str, jour: str, new_count: int, updated_count: int,
                published_today: int | None = None) -> str:
    """Courriel HTML : synthèse chiffrée, puis un tableau par produit surveillé."""
    entete = (
        '<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#0f172a;'
        'max-width:760px;margin:0 auto">'
        '<div style="background:#1f3c88;color:#fff;padding:16px 20px;border-radius:6px 6px 0 0">'
        '<div style="font-size:18px;font-weight:bold">CyberWatch AI — veille du ' + _echapper(jour) + '</div>'
        '<div style="font-size:13px;opacity:.85;margin-top:2px">Vulnérabilités détectées sur '
        'vos produits surveillés</div></div>'
        '<div style="border:1px solid #e2e8f0;border-top:none;padding:20px;'
        'border-radius:0 0 6px 6px">'
        f'<p style="margin:0 0 14px">Bonjour {_echapper(prenom)},</p>'
        '<p style="margin:0 0 16px">La collecte du ' + _echapper(jour) + ' a détecté '
        f'<b>{new_count}</b> nouvelle(s) vulnérabilité(s) et '
        f'<b>{updated_count}</b> mise(s) à jour importante(s).</p>'
    )

    if not digest["produits"]:
        return entete + _bloc_rien_de_neuf_html(published_today) + "</div></div>"

    blocs = []
    for p in digest["produits"][:_MAX_PRODUITS]:
        detail = []
        if p.get("nouvelles"):
            detail.append(f'{p["nouvelles"]} nouvelle(s)')
        if p.get("mises_a_jour"):
            detail.append(f'{p["mises_a_jour"]} mise(s) à jour')
        if p["critiques"]:
            detail.append(f'<span style="color:#b91c1c"><b>{p["critiques"]} critique(s)</b></span>')
        blocs.append(
            '<div style="margin:0 0 18px">'
            f'<div style="font-weight:bold;font-size:15px;margin-bottom:6px">'
            f'{_echapper(p["nom"])} '
            f'<span style="font-weight:normal;color:#64748b;font-size:13px">'
            f'— {p["total"]} vulnérabilité(s)'
            + (' · ' + ' · '.join(detail) if detail else '') + '</span></div>'
            '<table style="width:100%;border-collapse:collapse;font-size:13px">'
            + "".join(_ligne_cve_html(f) for f in p["fiches"][:_MAX_CVES_PAR_PRODUIT])
            + '</table>'
            + (f'<div style="color:#64748b;font-size:12px;margin-top:4px">… et '
               f'{p["total"] - _MAX_CVES_PAR_PRODUIT} autre(s) sur ce produit.</div>'
               if p["total"] > _MAX_CVES_PAR_PRODUIT else '')
            + '</div>')

    autres = len(digest["produits"]) - _MAX_PRODUITS
    reste = (f'<p style="color:#64748b;font-size:13px">… et {autres} autre(s) produit(s) '
             'concerné(s).</p>') if autres > 0 else ''

    pied = ('<p style="margin:18px 0 0;padding-top:14px;border-top:1px solid #e2e8f0;'
            'color:#475569;font-size:13px">Connectez-vous à l’espace Consultant, menu '
            '<b>Notifications</b>, pour le détail complet et les bulletins.</p>'
            '<p style="margin:6px 0 0;color:#94a3b8;font-size:12px">— CyberWatch AI</p>'
            '</div></div>')
    return entete + "".join(blocs) + reste + pied


def _bloc_rien_de_neuf(published_today: int | None) -> str:
    """Message d'une journée sans vulnérabilité sur le parc — en texte simple.

    Un « rien à signaler » n'est utile que s'il PROUVE que la veille a tourné. Le nombre de
    vulnérabilités parues dans le monde le prouve : « 159 parues, aucune sur vos produits »
    est un constat ; « rien » est une ambiguïté que le lecteur résout en soupçonnant la panne.
    """
    if published_today:
        return (f"{published_today} vulnérabilité(s) ont été publiées aujourd'hui, toutes "
                "sources et tous éditeurs confondus. Aucune ne concerne les produits que "
                "vous surveillez.\n\n"
                "La collecte a donc bien fonctionné : votre parc n'est pas touché "
                "aujourd'hui.\n\n")
    return ("Aucune vulnérabilité nouvelle n'a été publiée aujourd'hui par les sources "
            "consultées, et aucune ne concerne vos produits surveillés.\n\n")


def _bloc_rien_de_neuf_html(published_today: int | None) -> str:
    if published_today:
        return (
            '<div style="border-left:4px solid #16a34a;background:#f0fdf4;padding:12px 16px">'
            f'<p style="margin:0 0 6px"><b>{published_today}</b> vulnérabilité(s) ont été '
            'publiées aujourd’hui, toutes sources et tous éditeurs confondus. '
            '<b>Aucune ne concerne les produits que vous surveillez.</b></p>'
            '<p style="margin:0;color:#166534">La collecte a bien fonctionné : votre parc '
            'n’est pas touché aujourd’hui.</p></div>')
    return ('<div style="border-left:4px solid #16a34a;background:#f0fdf4;padding:12px 16px">'
            '<p style="margin:0">Aucune vulnérabilité nouvelle n’a été publiée aujourd’hui '
            'par les sources consultées.</p></div>')


async def _recent_cves_block(db) -> str:
    """Liste des CVE non lues, en FRANÇAIS quand la traduction existe.

    Les valeurs TECHNIQUES (identifiant CVE, score CVSS, produit, éditeur) sont restituées
    telles quelles : seul le texte en langage naturel est localisé.
    """
    from app.backend.services.collection import isolation
    from app.backend.services.collection.translation import localized

    try:
        # CE QUI EST NOUVEAU **POUR LE CONSULTANT** : les fiches non lues, qu'elles viennent
        # d'être publiées ou de recevoir une mise à jour importante.
        #
        # Le filtre « publiées aujourd'hui » s'appliquait ici : il convient à l'écran du même
        # nom, mais pas à un courriel de synthèse. Un jour sans publication nouvelle — le cas
        # ordinaire — produisait un message annonçant « 94 mises à jour » sans en citer une
        # seule. Les compteurs venaient de la collecte, la liste d'un tout autre critère.
        #
        # Aucune date n'est modifiée : `published_at` reste la date officielle de la source
        # et continue d'être affichée telle quelle.
        docs = await db.cves.find(
            {"$or": [{"is_new": True}, {"update_unread": True}]},
            {"cve_id": 1, "title": 1, "title_fr": 1, "description": 1, "description_fr": 1,
             "severity": 1, "cvss_score": 1, "product": 1, "vendor": 1},
        ).sort("cvss_score", -1).to_list(_MAX_CVES_IN_EMAIL)
    except Exception as exc:  # noqa: BLE001 - l'e-mail ne doit jamais échouer pour ça
        logger.warning("Détail des CVE indisponible pour l'e-mail : %s", exc)
        return ""
    if not docs:
        return ""

    lignes = []
    for d in docs:
        sev = _SEVERITY_FR.get(d.get("severity"), d.get("severity") or "—")
        score = d.get("cvss_score")
        score_txt = f"{float(score):.1f}" if isinstance(score, (int, float)) else "—"
        # Un « produit » qui est en réalité le TITRE de l'avis dont la CVE a été extraite
        # (« Vulnérabilités affectant le navigateur… ») n'est pas un produit : l'annoncer
        # comme tel dans un courriel désinforme le consultant. On préfère alors l'éditeur,
        # et à défaut on n'affiche rien. Le champ en base n'est pas modifié ici.
        produit = d.get("product") or ""
        if produit and isolation.TITRE_D_AVIS_RE.search(produit):
            produit = ""
        cible = produit or d.get("vendor") or ""
        titre = (localized(d, "title") or d.get("cve_id") or "").strip()
        lignes.append(f"• {d.get('cve_id')} — {titre}")
        lignes.append(f"    Sévérité : {sev} (CVSS {score_txt})"
                      + (f" · Produit : {cible}" if cible else ""))
        resume = (localized(d, "description") or "").strip()
        if resume:
            lignes.append(f"    {resume[:220]}{'…' if len(resume) > 220 else ''}")
    return "Vulnérabilités concernées :\n" + "\n".join(lignes) + "\n\n"


async def destinataires(db) -> list[dict]:
    """Consultants à prévenir : ceux qui SE CONNECTENT réellement à l'application.

    Un compte de démonstration créé pour une présentation et jamais rouvert n'a pas à
    recevoir la veille quotidienne. Le critère est la connexion — `last_login_at`, renseigné
    à chaque authentification — et non la simple existence du compte.

    `NOTIFY_ACTIVE_CONSULTANT_DAYS` restreint en outre aux connexions RÉCENTES ; à 0, tout
    consultant s'étant connecté au moins une fois reste destinataire.

    REPLI DÉLIBÉRÉ : si aucun consultant ne remplit le critère, on retombe sur l'ensemble des
    consultants. Une notification envoyée trop largement se corrige ; une veille qui cesse
    silencieusement d'être distribuée ne se voit pas.
    """
    tous = await db.users.find({"role": "consultant"}).to_list(1000)
    connectes = [u for u in tous if u.get("last_login_at")]

    fenetre = getattr(settings, "NOTIFY_ACTIVE_CONSULTANT_DAYS", 0) or 0
    if fenetre > 0 and connectes:
        limite = utcnow().replace(tzinfo=None) - timedelta(days=fenetre)
        recents = [u for u in connectes
                   if _naif(u["last_login_at"]) and _naif(u["last_login_at"]) >= limite]
        if recents:
            connectes = recents

    if not connectes:
        logger.info("Aucun consultant ne s'est encore connecté : notification adressée aux "
                    "%s compte(s) consultant existants.", len(tous))
        return tous
    return sorted(connectes, key=lambda u: _naif(u["last_login_at"]), reverse=True)


def _naif(valeur):
    return valeur.replace(tzinfo=None) if getattr(valeur, "tzinfo", None) else valeur


async def _liste_de_diffusion(db) -> list[dict]:
    """Destinataires effectifs de la veille, dans l'ordre où l'envoi les traitera.

    DEUX RÉGIMES, ET LE PREMIER EXCLUT LE SECOND.

    `NOTIFY_ONLY_RECIPIENTS` renseignée, la liste est EXACTEMENT celle-là : aucun compte
    consultant n'y est ajouté. C'est le régime d'une entreprise qui dirige sa veille vers une
    boîte de service unique — et qui ne veut pas qu'une simple connexion, ou la création d'un
    compte de démonstration, y réintroduise discrètement une adresse personnelle.

    Sinon, comportement historique : les consultants actifs, plus les adresses de supervision
    de `NOTIFY_EXTRA_RECIPIENTS`. Celles-ci AJOUTENT là où les premières RESTREIGNENT.

    Les adresses configurées empruntent le même chemin d'envoi que les comptes, sous la même
    forme : un canal parallèle finirait par diverger de celui qu'il double.
    """
    exclusifs = settings.only_recipients
    if exclusifs:
        logger.info("Diffusion restreinte par NOTIFY_ONLY_RECIPIENTS : %s destinataire(s), "
                    "les comptes consultants ne sont pas ajoutés.", len(exclusifs))
        return [{"email": adresse, "full_name": "", "_supervision": True}
                for adresse in exclusifs]

    consultants = await destinataires(db)
    connues = {(u.get("email") or "").lower() for u in consultants}
    for adresse in settings.extra_recipients:
        if adresse.lower() not in connues:
            consultants.append({"email": adresse, "full_name": "", "_supervision": True})
            connues.add(adresse.lower())
    return consultants


async def _deja_envoye_aujourd_hui(db, empreinte: str) -> bool:
    """Un courriel identique est-il déjà parti aujourd'hui ?

    Plusieurs collectes ont lieu chaque jour. Sans cette mémoire, le consultant recevait
    autant de messages que de passages — et une veille qui écrit quatre fois la même chose
    finit en dossier « indésirables », ce qui la rend moins utile qu'une veille silencieuse.

    L'empreinte décrit CE QUI EST NOUVEAU. Si de nouvelles vulnérabilités apparaissent en
    cours de journée, l'empreinte change et un second courriel part : la borne empêche la
    répétition, jamais l'information.
    """
    debut = utcnow().replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
    try:
        deja = await db.email_digests.find_one({"empreinte": empreinte,
                                                "envoye_le": {"$gte": debut}})
        return deja is not None
    except Exception as exc:  # noqa: BLE001 - en cas de doute on ENVOIE : mieux vaut un
        logger.warning("Mémoire des envois indisponible (%s) : envoi maintenu.", exc)
        return False          # doublon qu'une veille manquante


async def _memoriser_envoi(db, empreinte: str, destinataires_count: int) -> None:
    try:
        await db.email_digests.insert_one(
            {"empreinte": empreinte, "envoye_le": utcnow(), "destinataires": destinataires_count})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Envoi non mémorisé (%s) : un doublon reste possible aujourd'hui.", exc)


async def notify_new_cves(db, new_count: int, updated_count: int,
                          published_today: int | None = None) -> None:
    """Envoie la veille du jour aux consultants, si les notifications email sont activées.

    APPELÉE APRÈS CHAQUE COLLECTE, y compris quand ce passage n'a rien détecté. Le critère
    d'envoi n'est PAS ce que la collecte vient de trouver, mais ce que le consultant n'a pas
    encore vu : des fiches non lues peuvent dater d'un passage précédent, et rester
    indéfiniment silencieuses si l'on s'en tient au dernier lot.

    `published_today` — nombre de vulnérabilités parues aujourd'hui, tous produits confondus.
    Il permet d'écrire « 159 parues, aucune sur vos produits » plutôt qu'un silence que rien
    ne distingue d'une panne.
    """
    new_count = max(0, new_count or 0)
    updated_count = max(0, updated_count or 0)
    # Les destinataires sont déterminés AVANT de tester l'activation : le journal indique
    # alors précisément QUI aurait été prévenu et POURQUOI l'envoi n'a pas eu lieu. Sans
    # cela, « notifications désactivées » laissait croire à une absence de destinataires,
    # alors que la seule pièce manquante est le serveur d'envoi.
    consultants = await _liste_de_diffusion(db)
    recipients = [u["email"] for u in consultants if u.get("email")]

    if not settings.email_enabled:
        raison = ("SMTP_HOST non renseigné" if not settings.SMTP_HOST
                  else "EMAIL_NOTIFICATIONS_ENABLED=false")
        logger.info(
            "Email non envoyé (%s) — %s nouvelle(s), %s mise(s) à jour. "
            "%s consultant(s) seraient destinataires : %s. Notification in-app conservée.",
            raison, new_count, updated_count, len(recipients),
            ", ".join(recipients) or "aucun")
        return

    if not recipients:
        logger.warning("Envoi email actif mais AUCUN consultant ne porte d'adresse : "
                       "%s nouvelle(s) CVE ne seront signalées qu'en application.", new_count)
        return

    # IDENTIFIANTS MANQUANTS : un relais public (Gmail, Microsoft 365, relais d'entreprise)
    # refuse toute remise anonyme. Sans cette vérification, chaque collecte tentait une
    # connexion vouée à l'échec et la journalisait comme une erreur technique, alors qu'il
    # manque simplement un mot de passe. Un serveur LOCAL, lui, accepte sans authentification :
    # c'est le cas d'un relais interne ou d'un banc d'essai, qu'il ne faut pas bloquer.
    if not _serveur_local(settings.SMTP_HOST) and not (settings.SMTP_USER and settings.SMTP_PASSWORD):
        # Le MOT DE PASSE compte autant que l'identifiant. Renseigner l'un sans l'autre menait
        # à une tentative d'authentification vouée à l'échec, journalisée comme une erreur
        # technique : le message ci-dessous nomme précisément la pièce qui manque.
        manquant = ("SMTP_USER" if not settings.SMTP_USER else
                    "SMTP_PASSWORD (mot de passe d'application, 16 caractères)")
        logger.warning(
            "Envoi email impossible : %s n'est pas renseigné pour « %s ». "
            "%s destinataire(s) en attente : %s. Notification in-app conservée.",
            manquant, settings.SMTP_HOST, len(recipients), ", ".join(recipients))
        return

    digest = await digest_du_jour(db)
    jour = utcnow().strftime("%d/%m/%Y")

    # NE PAS RÉPÉTER LE MÊME MESSAGE. L'empreinte décrit ce qui est nouveau POUR LE
    # CONSULTANT ; tant qu'elle ne change pas, le courriel du jour a déjà été écrit. Elle
    # change dès qu'une vulnérabilité s'ajoute, et un second message part alors.
    empreinte = (f"{jour}|{digest['total']}|{digest.get('nouvelles', 0)}"
                 f"|{digest.get('mises_a_jour', 0)}")
    if await _deja_envoye_aujourd_hui(db, empreinte):
        logger.info("Veille du %s déjà envoyée (%s vulnérabilité(s)) : pas de doublon.",
                    jour, digest["total"])
        return

    # RIEN DE NOUVEAU : on écrit quand même, UNE FOIS PAR JOUR. Un silence ne se distingue
    # pas d'une panne, et c'est précisément ce doute qui fait perdre confiance dans une
    # veille. Le message dit alors ce qui a paru dans le monde et ce qui vous concerne.
    rien_de_neuf = digest["total"] == 0
    bloc = _bloc_produits(digest)
    if rien_de_neuf:
        bloc = _bloc_rien_de_neuf(published_today)
        subject = f"CyberWatch AI — veille du {jour} : aucune vulnérabilité sur vos produits"
    else:
        subject = (f"CyberWatch AI — veille du {jour} : {digest['total']} vulnérabilité(s) "
                   f"sur {len(digest['produits'])} produit(s)")

    # UN COURRIEL PAR CONSULTANT, à SON adresse de connexion.
    #
    # Un envoi groupé plaçait toutes les adresses en « À : », si bien que chaque consultant
    # voyait celles des autres et recevait un message impersonnel. Un destinataire par envoi
    # permet de le nommer, et isole les échecs : une adresse invalide ne prive plus les
    # autres de leur veille.
    envoyes = echecs = 0
    for consultant in consultants:
        adresse = consultant.get("email")
        if not adresse:
            continue
        prenom = (consultant.get("full_name") or "").split(" ")[0] or "bonjour"
        entete = (
            f"Bonjour {prenom},\n\n"
            + (f"La veille du {jour} n'a relevé aucune vulnérabilité nouvelle sur vos "
               "produits surveillés.\n\n" if rien_de_neuf else
               f"La veille du {jour} signale {digest['nouvelles']} nouvelle(s) "
               f"vulnérabilité(s) et {digest['mises_a_jour']} mise(s) à jour "
               "sur vos produits surveillés.\n\n"))
        corps = (entete + bloc +
                 "Connectez-vous à l'espace Consultant pour le détail :\n"
                 "  Menu « Notifications »\n\n"
                 "— CyberWatch AI")
        html = _corps_html(digest, prenom, jour, digest["nouvelles"], digest["mises_a_jour"],
                           published_today=published_today)
        try:
            await asyncio.to_thread(_send_email, [adresse], subject, corps, html)
            envoyes += 1
        except Exception as exc:  # noqa: BLE001 - un destinataire ne bloque pas les autres
            echecs += 1
            logger.error("Échec de l'envoi à %s : %s", adresse, exc)

    if envoyes:
        await _memoriser_envoi(db, empreinte, envoyes)
    logger.info("Veille du jour envoyée à %s destinataire(s)%s — %s vulnérabilité(s) "
                "réparties sur %s produit(s).", envoyes,
                f" ({echecs} échec(s))" if echecs else "",
                digest["total"], len(digest["produits"]))
