"""Configure et VÉRIFIE l'envoi de courriels, quel que soit le fournisseur.

    python configurer_smtp.py

Écrire les réglages à la main dans `.env` marche, mais quatre détails les font échouer
silencieusement : les espaces que certains fournisseurs insèrent dans le mot de passe
affiché, des guillemets ajoutés par réflexe, une adresse de serveur saisie de mémoire, ou
l'édition de `app/backend/.env` — un fichier que l'application ne lit jamais. Ce script
écarte les quatre, puis envoie un vrai message pour confirmer que cela fonctionne.

Le serveur d'envoi est CHERCHÉ à partir du domaine de l'adresse : personne ne connaît par
cœur l'adresse SMTP de son entreprise, et la saisir de mémoire produit une erreur
d'authentification trompeuse — qui fait chercher un mot de passe erroné là où c'est le
serveur qui est faux.

Le mot de passe n'est jamais affiché, jamais journalisé, et n'est écrit que dans le fichier
`.env` de la racine, exclu du dépôt.
"""
import asyncio
import getpass
import io
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
FICHIER_ENV = RACINE / ".env"
sys.path.insert(0, str(RACINE))


def _lire_env() -> str:
    return io.open(FICHIER_ENV, encoding="utf-8").read() if FICHIER_ENV.exists() else ""


def _ecrire_valeur(contenu: str, cle: str, valeur: str) -> str:
    """Remplace la ligne `CLE=…`, ou l'ajoute si elle est absente."""
    ligne = f"{cle}={valeur}"
    if re.search(rf"^{cle}=.*$", contenu, re.M):
        return re.sub(rf"^{cle}=.*$", ligne, contenu, count=1, flags=re.M)
    return contenu.rstrip("\n") + "\n" + ligne + "\n"


def _demander(question: str, defaut: str) -> str:
    saisi = input(f"  {question} [{defaut}] : ").strip()
    return saisi or defaut


def _demander_secret(invite: str) -> str:
    """Saisie masquée quand c'est possible, saisie ordinaire sinon.

    Sous Windows, `getpass` lit la CONSOLE directement et ignore une entrée redirigée : dans
    un terminal intégré, un tube ou un script d'automatisation, il attendait indéfiniment une
    frappe qui ne venait pas. Le script semblait figé sans rien afficher.

    Hors terminal, l'écho n'a de toute façon aucun sens : personne ne regarde. On lit donc
    normalement, en le disant.
    """
    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass(invite)
    print("  (entrée non interactive : la saisie ne sera pas masquée)")
    return input(invite)


def principal() -> int:
    print()
    print("  CONFIGURATION DE L'ENVOI DE COURRIELS — CyberWatch AI")
    print("  " + "-" * 58)
    print(f"  Fichier : {FICHIER_ENV}")
    if not FICHIER_ENV.exists():
        print("  ATTENTION : ce fichier n'existe pas encore, il va être créé.")
    print()

    contenu = _lire_env()
    actuel = dict(re.findall(r"^([A-Z_]+)=(.*)$", contenu, re.M))

    adresse = _demander("Adresse d'expédition (le compte qui ENVOIE)",
                        actuel.get("SMTP_USER") or "")
    if not adresse:
        print()
        print("  Aucune adresse saisie : abandon.")
        return 1

    # SERVEUR D'ENVOI — cherché à partir du domaine de l'adresse.
    from app.backend.services import smtp_decouverte

    print()
    print("  Recherche du serveur d'envoi…")
    trouve = smtp_decouverte.decouvrir(adresse)
    if trouve["trouve"]:
        print(f"  {trouve['message']}  ({trouve['methode']})")
        serveur = _demander("Serveur d'envoi", trouve["host"])
        port = int(_demander("Port", str(trouve["port"])) or trouve["port"])
        chiffrement = trouve["tls"]
    else:
        print(f"  {trouve['message']}")
        print()
        serveur = _demander("Serveur d'envoi (ex. smtp.entreprise.fr)",
                            actuel.get("SMTP_HOST") or "")
        if not serveur:
            print()
            print("  Aucun serveur indiqué : abandon.")
            return 1
        port = int(_demander("Port", "587") or 587)
        chiffrement = True

    # EXIGENCE PROPRE À L'HÉBERGEUR — c'est elle qui fait échouer une configuration pourtant
    # exacte : mot de passe d'application chez Gmail, autorisation SMTP à demander à
    # l'administrateur chez Microsoft 365. La taire laisserait chercher longtemps.
    if trouve.get("note"):
        print()
        print(f"  À SAVOIR : {trouve['note']}")

    print()
    print("  Mot de passe du compte d'envoi.")
    print("  La saisie reste invisible ; collez-la puis validez.")
    brut = _demander_secret("  Mot de passe : ")

    # Les espaces que certains fournisseurs insèrent dans le mot de passe affiché sont
    # décoratifs et font échouer l'authentification si on les recopie. Les guillemets
    # viennent d'un réflexe d'édition ; l'espace insécable, d'un copier-coller web.
    mot_de_passe = brut.strip().strip("\"'").replace(" ", "").replace(" ", "")
    if not mot_de_passe:
        print()
        print("  Aucun mot de passe saisi : abandon.")
        return 1

    # L'avertissement sur les 16 caractères ne vaut QUE pour les hébergeurs qui exigent un
    # mot de passe d'application. Le brandir devant un serveur d'entreprise, où le mot de
    # passe du compte est le bon, ferait douter d'une saisie correcte.
    if trouve.get("note") and "application" in trouve["note"] and len(mot_de_passe) != 16:
        print()
        print(f"  Attention : {len(mot_de_passe)} caractères au lieu de 16 attendus.")
        print("  Ce fournisseur exige un mot de passe d'application, pas celui du compte.")
        if input("  Continuer quand même ? [o/N] : ").strip().lower() not in ("o", "oui"):
            return 1

    print()
    destinataires = _demander(
        "Adresses qui RECEVRONT la veille (séparées par des virgules)",
        actuel.get("NOTIFY_EXTRA_RECIPIENTS") or adresse)

    for cle, valeur in (("SMTP_HOST", serveur),
                        ("SMTP_PORT", str(port)),
                        ("SMTP_USE_TLS", "true" if chiffrement else "false"),
                        ("SMTP_USER", adresse),
                        ("SMTP_PASSWORD", mot_de_passe),
                        # Beaucoup de serveurs refusent d'expédier au nom d'une autre adresse
                        # que l'identifiant : on les aligne par défaut.
                        ("SMTP_FROM", adresse),
                        ("NOTIFY_EXTRA_RECIPIENTS", destinataires),
                        ("EMAIL_NOTIFICATIONS_ENABLED", "true")):
        contenu = _ecrire_valeur(contenu, cle, valeur)
    io.open(FICHIER_ENV, "w", encoding="utf-8").write(contenu)

    print()
    print(f"  Configuration écrite ({len(mot_de_passe)} caractères enregistrés, non affichés).")
    print(f"  Serveur : {serveur}:{port}   Destinataires : {destinataires}")
    print("  Essai de remise en cours…")
    print()

    # Import APRÈS écriture : la configuration est lue au chargement du module.
    from app.backend.services import notifications

    premier = destinataires.split(",")[0].strip() or adresse
    resultat = asyncio.run(notifications.essai_de_remise(premier))
    if resultat["envoye"]:
        print("  RÉUSSI —", resultat["detail"])
        print(f"  Vérifiez la boîte de réception de {premier}.")
        print()
        print("  Redémarrez le backend pour que la veille quotidienne parte à la")
        print("  prochaine collecte.")
        return 0

    print("  ÉCHEC —", resultat["detail"])
    print()
    print("  La configuration est enregistrée ; corrigez le point ci-dessus puis")
    print("  relancez cette commande.")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(principal())
    except KeyboardInterrupt:
        print()
        print("  Interrompu ; aucune modification n'a été enregistrée.")
        raise SystemExit(1)
