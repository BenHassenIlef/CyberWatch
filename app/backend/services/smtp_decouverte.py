"""DÉCOUVERTE DU SERVEUR D'ENVOI à partir d'une adresse de courriel.

Personne ne connaît par cœur l'adresse du serveur SMTP de son entreprise : elle ne figure
nulle part dans une boîte de réception, et chaque hébergeur la nomme autrement. On donne donc
l'adresse de courriel, et ce module cherche.

DEUX VOIES, DANS CET ORDRE

  1. LES HÉBERGEURS CONNUS. Gmail, Microsoft 365, OVH, Orange, Free : leurs réglages sont
     publics et stables. Une correspondance sur le domaine — ou sur l'enregistrement MX,
     qui trahit l'hébergeur derrière un domaine d'entreprise — donne la réponse exacte.

  2. LES CONVENTIONS. À défaut, on essaie « smtp.<domaine> » et « mail.<domaine> ». C'est une
     supposition, donc chaque candidat est VÉRIFIÉ : on ouvre réellement la connexion.

RIEN N'EST PROPOSÉ SANS AVOIR ÉTÉ VÉRIFIÉ. Un serveur plausible mais injoignable entrerait
dans la configuration et échouerait à chaque envoi, en faisant croire à un mot de passe
erroné — le pire des diagnostics, car il envoie chercher au mauvais endroit.

AUCUN IDENTIFIANT N'EST TRANSMIS ICI. La découverte n'ouvre qu'une connexion, sans jamais
s'authentifier : elle établit QUE le serveur existe et parle SMTP, pas qu'un compte y est
valide. La vérification du mot de passe vient après, à l'essai de remise.
"""
import logging
import smtplib
import socket

logger = logging.getLogger("cyberwatch.smtp.decouverte")

# Hébergeurs dont les réglages sont publics et stables.
#   domaine ou fragment d'enregistrement MX -> (serveur, port, chiffrement, note)
HEBERGEURS_CONNUS = {
    "gmail.com": ("smtp.gmail.com", 587, True,
                  "Gmail exige un MOT DE PASSE D'APPLICATION (16 caractères), "
                  "à créer après avoir activé la validation en deux étapes."),
    "google.com": ("smtp.gmail.com", 587, True,
                   "Google Workspace exige un mot de passe d'application."),
    "outlook.com": ("smtp-mail.outlook.com", 587, True, None),
    "hotmail.com": ("smtp-mail.outlook.com", 587, True, None),
    "live.com": ("smtp-mail.outlook.com", 587, True, None),
    "office365.com": ("smtp.office365.com", 587, True,
                      "Microsoft 365 : l'authentification SMTP doit être activée pour la "
                      "boîte concernée par l'administrateur du tenant."),
    "outlook.office365.com": ("smtp.office365.com", 587, True,
                              "Microsoft 365 : l'authentification SMTP doit être activée "
                              "pour cette boîte."),
    "protection.outlook.com": ("smtp.office365.com", 587, True,
                               "Microsoft 365 : l'authentification SMTP doit être activée "
                               "pour cette boîte."),
    "ovh.net": ("ssl0.ovh.net", 587, True, None),
    "ovh.com": ("ssl0.ovh.net", 587, True, None),
    "orange.fr": ("smtp.orange.fr", 587, True, None),
    "wanadoo.fr": ("smtp.orange.fr", 587, True, None),
    "free.fr": ("smtp.free.fr", 587, True, None),
    "sfr.fr": ("smtp.sfr.fr", 587, True, None),
    "laposte.net": ("smtp.laposte.net", 587, True, None),
    "yahoo.com": ("smtp.mail.yahoo.com", 587, True,
                  "Yahoo exige un mot de passe d'application."),
    "zoho.com": ("smtp.zoho.com", 587, True, None),
    "ionos.fr": ("smtp.ionos.fr", 587, True, None),
    "1and1.fr": ("smtp.ionos.fr", 587, True, None),
    "gandi.net": ("mail.gandi.net", 587, True, None),
    "infomaniak.com": ("mail.infomaniak.com", 587, True, None),
}

# Conventions essayées à défaut, par ordre de fréquence.
CONVENTIONS = ("smtp.{domaine}", "mail.{domaine}", "smtp.mail.{domaine}", "{domaine}")

DELAI = 8.0          # secondes ; un serveur qui ne répond pas en 8 s ne répondra pas


def domaine_de(adresse: str) -> str:
    return (adresse or "").strip().rsplit("@", 1)[-1].lower()


def _enregistrements_mx(domaine: str) -> list[str]:
    """Serveurs de RÉCEPTION du domaine. Ils trahissent l'hébergeur réel.

    « societe.fr » hébergé chez Microsoft 365 publie un MX en « …protection.outlook.com » :
    le domaine ne dit rien, l'enregistrement MX dit tout.

    Sans bibliothèque DNS dans le projet, on interroge le résolveur du système. Une absence
    de réponse n'est pas une erreur : on passera simplement aux conventions.
    """
    try:
        import subprocess
        sortie = subprocess.run(["nslookup", "-type=MX", domaine],
                                capture_output=True, text=True, timeout=10).stdout.lower()
        return [ligne.strip() for ligne in sortie.splitlines() if "mail exchanger" in ligne]
    except Exception as exc:  # noqa: BLE001 - la découverte continue sans MX
        logger.info("Enregistrements MX de « %s » indisponibles : %s", domaine, str(exc)[:80])
        return []


def _repond_en_smtp(serveur: str, port: int, chiffrement: bool) -> bool:
    """Le serveur existe-t-il et parle-t-il SMTP ? AUCUN identifiant n'est transmis.

    On établit la connexion, on salue, on repart. C'est tout ce qu'il faut pour écarter une
    adresse inventée — et c'est tout ce qu'on a le droit de faire sans compte.
    """
    try:
        with smtplib.SMTP(serveur, port, timeout=DELAI) as connexion:
            connexion.ehlo()
            if chiffrement:
                connexion.starttls()
                connexion.ehlo()
        return True
    except (smtplib.SMTPException, socket.error, OSError):
        return False


def decouvrir(adresse: str) -> dict:
    """Réglages d'envoi pour une adresse de courriel.

    Renvoie `{trouve, host, port, tls, methode, note, essais}`. `note` porte l'exigence
    propre à l'hébergeur quand il y en a une — mot de passe d'application, autorisation à
    demander à l'administrateur : c'est ce qui fait échouer une configuration pourtant exacte.
    """
    domaine = domaine_de(adresse)
    if not domaine:
        return {"trouve": False, "essais": [],
                "message": "Adresse de courriel illisible."}

    # 1 — hébergeur reconnu par le domaine lui-même
    if domaine in HEBERGEURS_CONNUS:
        serveur, port, tls, note = HEBERGEURS_CONNUS[domaine]
        return {"trouve": True, "host": serveur, "port": port, "tls": tls, "note": note,
                "methode": "hébergeur connu", "essais": [serveur],
                "message": f"Hébergeur reconnu : {serveur}."}

    # 1 bis — hébergeur reconnu par l'enregistrement MX du domaine d'entreprise
    #
    # LES INDICES LES PLUS LONGS D'ABORD. « outlook.com » est contenu dans
    # « actelia-fr.mail.protection.outlook.com » : parcourue dans l'ordre de déclaration, la
    # table renvoyait « smtp-mail.outlook.com » — le serveur d'Outlook GRAND PUBLIC — pour un
    # domaine hébergé sur un locataire Microsoft 365, dont le serveur est
    # « smtp.office365.com ». L'authentification aurait échoué sans que rien ne l'explique.
    mx = _enregistrements_mx(domaine)
    for indice in sorted(HEBERGEURS_CONNUS, key=len, reverse=True):
        serveur, port, tls, note = HEBERGEURS_CONNUS[indice]
        if any(indice in ligne for ligne in mx):
            return {"trouve": True, "host": serveur, "port": port, "tls": tls, "note": note,
                    "methode": "hébergeur déduit des enregistrements MX",
                    "essais": [serveur],
                    "message": (f"Le domaine « {domaine} » est hébergé par un service "
                                f"reconnu : {serveur}.")}

    # 2 — conventions, chacune VÉRIFIÉE
    essais = []
    for modele in CONVENTIONS:
        serveur = modele.format(domaine=domaine)
        if serveur in essais:
            continue
        essais.append(serveur)
        if _repond_en_smtp(serveur, 587, True):
            return {"trouve": True, "host": serveur, "port": 587, "tls": True, "note": None,
                    "methode": "convention vérifiée", "essais": essais,
                    "message": f"Serveur trouvé et joignable : {serveur}."}

    return {
        "trouve": False, "essais": essais, "methode": None,
        "message": (f"Aucun serveur d'envoi trouvé pour « {domaine} » après "
                    f"{len(essais)} essai(s). Demandez son adresse à votre service "
                    "informatique : elle ressemble à « smtp.votre-entreprise.fr » et "
                    "figure dans les réglages du client de messagerie que vous utilisez "
                    "déjà (Outlook, Thunderbird)."),
    }
