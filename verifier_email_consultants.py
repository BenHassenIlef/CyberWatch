"""VÉRIFICATION DE L'ENVOI AUX CONSULTANTS — sans lancer de collecte.

Contrôle la chaîne complète : configuration SMTP, liste des consultants, contenu du message,
puis envoi réel. À lancer après avoir renseigné `SMTP_USER` et `SMTP_PASSWORD` dans
`app/backend/.env`.

    python verifier_email_consultants.py             # diagnostic SEUL, aucun envoi
    python verifier_email_consultants.py --envoyer   # envoi reel aux consultants

Le mode diagnostic affiche exactement ce qui partirait, et à qui. Rien n'est émis tant que
`--envoyer` n'est pas passé : on ne déclenche pas un courriel vers de vraies adresses par
simple curiosité.
"""
import argparse
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


async def run(envoyer: bool) -> int:
    from app.backend.core.config import settings
    from app.backend.db.mongodb import get_database
    from app.backend.services import notifications

    db = get_database()

    print("CONFIGURATION")
    print(f"  EMAIL_NOTIFICATIONS_ENABLED : {settings.EMAIL_NOTIFICATIONS_ENABLED}")
    print(f"  SMTP_HOST                   : {settings.SMTP_HOST or '(vide)'}")
    print(f"  SMTP_PORT                   : {settings.SMTP_PORT}")
    print(f"  SMTP_USER                   : {settings.SMTP_USER or '(vide)'}")
    print(f"  SMTP_PASSWORD               : {'renseigne' if settings.SMTP_PASSWORD else '(vide)'}")
    print(f"  SMTP_FROM                   : {settings.SMTP_FROM}")
    print()

    tous = await db.users.find({"role": "consultant"}).to_list(1000)
    consultants = await notifications.destinataires(db)
    adresses = [u["email"] for u in consultants if u.get("email")]
    retenus = {str(u["_id"]) for u in consultants}
    fenetre = getattr(settings, "NOTIFY_ACTIVE_CONSULTANT_DAYS", 0) or 0
    print(f"DESTINATAIRES — {len(adresses)} sur {len(tous)} compte(s) consultant")
    print("  critere : s est connecte" + (f" depuis moins de {fenetre} jours" if fenetre else " au moins une fois"))
    for u in sorted(tous, key=lambda x: str(x.get("last_login_at") or ""), reverse=True):
        marque = "->" if str(u["_id"]) in retenus else "  "
        derniere = str(u.get("last_login_at") or "jamais connecte")[:19]
        print(f"  {marque} {u.get('email') or '(AUCUNE ADRESSE)':<34} "
              f"{u.get('login_count', 0):>3} connexion(s)  dernier={derniere}")
    print()

    digest = await notifications.digest_du_jour(db)
    print("CONTENU QUI SERAIT ENVOYE — un courriel NOMINATIF par consultant")
    print(notifications._bloc_produits(digest)[:1500])
    print()

    if settings.extra_recipients:
        print("DESTINATAIRES SUPPLEMENTAIRES (supervision, hors comptes consultants)")
        for adresse in settings.extra_recipients:
            deja = " (deja consultant : un seul envoi)" if adresse.lower() in {
                a.lower() for a in adresses} else ""
            print(f"  -> {adresse}{deja}")
        print()

    manque = []
    if not settings.SMTP_HOST:
        manque.append("SMTP_HOST")
    # L'IDENTIFIANT ET LE MOT DE PASSE sont testes separement : n'en signaler qu'un seul
    # laissait croire que l'autre suffisait, et l'envoi echouait ensuite sans explication.
    if not notifications._serveur_local(settings.SMTP_HOST):
        if not settings.SMTP_USER:
            manque.append("SMTP_USER")
        if not settings.SMTP_PASSWORD:
            manque.append("SMTP_PASSWORD (mot de passe D'APPLICATION Gmail, 16 caracteres, "
                          "genere sur https://myaccount.google.com/apppasswords apres "
                          "activation de la validation en deux etapes)")
    if not settings.EMAIL_NOTIFICATIONS_ENABLED:
        manque.append("EMAIL_NOTIFICATIONS_ENABLED=true")
    if not adresses:
        manque.append("au moins un destinataire avec une adresse")

    if manque:
        print("ENVOI IMPOSSIBLE — a renseigner dans .env :")
        for m in manque:
            print("  - " + m)
        return 1

    if not envoyer:
        print("Diagnostic OK : l'envoi fonctionnerait. Relancez avec --envoyer pour l'effectuer.")
        return 0

    print(f"ENVOI REEL vers {len(adresses)} consultant(s)...")
    await notifications.notify_new_cves(db, new_count=0, updated_count=len(adresses))
    print("Termine. Verifiez la boite de reception (et les indesirables).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Verifie l'envoi des notifications aux consultants.")
    ap.add_argument("--envoyer", action="store_true",
                    help="Effectuer un envoi REEL (sinon : diagnostic seul).")
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.envoyer))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
