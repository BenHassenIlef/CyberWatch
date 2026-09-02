r"""SUPPRESSION DE COMPTES NOMMÉMENT DÉSIGNÉS.

    .\app\backend\.venv\Scripts\python.exe supprimer_comptes.py

Supprime les comptes listés dans A_SUPPRIMER, avec les conversations d'assistant qui leur
sont rattachées. Tout compte absent de cette liste est laissé intact.

POURQUOI CE SCRIPT EXISTE. L'application sait créer et modifier un compte, pas le supprimer :
aucun écran ni aucune route ne le permet. L'opération passe donc par la base — et parce
qu'elle est IRRÉVERSIBLE, elle est isolée ici, avec une confirmation à saisir, plutôt que
noyée dans une commande d'administration ordinaire.

UNE LISTE DE SUPPRESSION, PAS UNE LISTE DE CONSERVATION. Énumérer ce qu'on garde fait
disparaître tout ce qu'on a oublié d'y écrire — une faute de frappe dans une adresse, un
compte créé la veille, et il n'en reste rien. Énumérer ce qu'on supprime borne le dégât à ce
qu'on a explicitement nommé : une adresse mal orthographiée n'efface alors rien du tout.

TROIS GARDE-FOUS :

  1. Une sauvegarde JSON de TOUS les comptes est écrite avant toute suppression. Elle porte
     les empreintes de mots de passe : une restauration rend les comptes utilisables tels
     quels, sans réinitialisation.
  2. Le script REFUSE de s'exécuter s'il ne resterait aucun administrateur, ou aucun
     consultant. L'espace d'administration commande les sources et les collectes ; l'espace
     consultant porte la veille elle-même. Perdre l'accès à l'un des deux ne se répare pas
     depuis l'application.
  3. Rien n'est supprimé avant que « SUPPRIMER » ait été saisi.

Les conversations partent AVEC leur compte. Conservées, elles resteraient rattachées à un
identifiant qui ne désigne plus personne : invisibles dans l'interface, et impossibles à
retrouver pour les effacer plus tard.
"""
import asyncio
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bson import json_util  # noqa: E402

from app.backend.db.mongodb import get_database  # noqa: E402

# ---------------------------------------------------------------------------------------
# LES COMPTES À SUPPRIMER. Tout le reste est conservé.
# ---------------------------------------------------------------------------------------
# Vide par defaut, et c'est deliberé : ce fichier reste dans le projet, il finira sur une
# autre machine ou dans une archive. Y laisser des adresses c'est y laisser des noms de
# personnes, longtemps apres que l'operation a eu lieu.
#
# Renseignez-le au moment de vous en servir, videz-le ensuite.
A_SUPPRIMER: set[str] = set()

def _dossier_de_sauvegarde() -> Path:
    """Où déposer la sauvegarde, selon l'endroit d'où l'on exécute.

    Sur Windows, le Bureau : c'est là qu'on la retrouve sans la chercher. Dans un conteneur,
    ce dossier n'existe pas — le script s'y arrêtait sur une erreur de fichier introuvable,
    AVANT d'avoir rien sauvegardé, et pour une opération qui n'est justement pas rattrapable.

    On se rabat alors sur « logs/ », monté depuis l'hôte par docker-compose : la sauvegarde
    survit ainsi au conteneur, ce qui est tout l'intérêt d'une sauvegarde.
    """
    bureau = Path.home() / "Desktop"
    if bureau.is_dir():
        return bureau
    journaux = Path(__file__).resolve().parent / "logs"
    if journaux.is_dir():
        return journaux
    return Path(__file__).resolve().parent


DOSSIER_SAUVEGARDE = _dossier_de_sauvegarde()


def _titre(texte: str) -> None:
    print()
    print(f"  {texte}")
    print("  " + "-" * 68)


async def principal() -> int:
    db = get_database()
    tous = await db.users.find({}).to_list(1000)
    if not tous:
        print("Aucun compte en base.")
        return 1

    partants = [u for u in tous if (u.get("email") or "").lower() in A_SUPPRIMER]
    restants = [u for u in tous if (u.get("email") or "").lower() not in A_SUPPRIMER]

    # ----------------------------------------------------------------------------------
    _titre("1. Sauvegarde")
    # ----------------------------------------------------------------------------------
    horodatage = datetime.now().strftime("%Y%m%d-%H%M%S")
    fichier = DOSSIER_SAUVEGARDE / f"sauvegarde-comptes-{horodatage}.json"
    fichier.write_text(json_util.dumps(tous, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  {len(tous)} compte(s) enregistrés dans :")
    print(f"    {fichier}")

    # ----------------------------------------------------------------------------------
    _titre("2. Vérifications")
    # ----------------------------------------------------------------------------------
    introuvables = A_SUPPRIMER - {(u.get("email") or "").lower() for u in partants}
    if introuvables:
        # Ce n'est pas bloquant : un compte déjà supprimé n'a plus à l'être. Mais une
        # adresse mal orthographiée se signale ici, et non par une suppression silencieuse
        # qui n'aurait rien fait.
        print("  Absent(s) de la base, donc ignoré(s) :", ", ".join(sorted(introuvables)))

    if not partants:
        print("  Aucun des comptes désignés n'existe. Rien à faire.")
        return 0

    for role, libelle in (("admin", "administrateur"), ("consultant", "consultant")):
        if not any(u.get("role") == role for u in restants):
            print()
            print(f"  ARRÊT : aucun compte {libelle} ne subsisterait.")
            print("  L'accès correspondant deviendrait impossible, sans moyen de le rouvrir")
            print("  depuis l'application. Retirez une adresse de A_SUPPRIMER.")
            return 1

    print(f"  Après suppression, il restera {len(restants)} compte(s) : "
          f"{sum(u.get('role') == 'admin' for u in restants)} administrateur(s), "
          f"{sum(u.get('role') == 'consultant' for u in restants)} consultant(s).")

    # ----------------------------------------------------------------------------------
    _titre(f"3. Ce qui sera supprimé ({len(partants)} compte(s))")
    # ----------------------------------------------------------------------------------
    identifiants = [u["_id"] for u in partants]
    conversations = await db.assistant_conversations.count_documents(
        {"consultant_id": {"$in": identifiants}})
    messages = await db.assistant_messages.count_documents(
        {"consultant_id": {"$in": identifiants}})
    discussions = await db.chat_conversations.count_documents(
        {"consultant_id": {"$in": identifiants}})

    for u in sorted(partants, key=lambda x: (x.get("role", ""), x.get("email", ""))):
        nom = (u.get("full_name") or "")[:18]
        print(f"    {u['email']:<32}{u.get('role'):<14}{nom}")
    print()
    print(f"    et leurs échanges : {conversations} conversation(s), {messages} message(s), "
          f"{discussions} discussion(s)")

    # ----------------------------------------------------------------------------------
    _titre("4. Confirmation")
    # ----------------------------------------------------------------------------------
    print("  Cette suppression est DÉFINITIVE. La sauvegarde ci-dessus est le seul retour")
    print("  en arrière possible.")
    print()
    reponse = input("  Tapez SUPPRIMER pour confirmer (ou Entrée pour annuler) : ").strip()
    if reponse != "SUPPRIMER":
        print()
        print("  Annulé. Rien n'a été supprimé.")
        return 0

    # ----------------------------------------------------------------------------------
    _titre("5. Suppression")
    # ----------------------------------------------------------------------------------
    r_msg = await db.assistant_messages.delete_many({"consultant_id": {"$in": identifiants}})
    r_conv = await db.assistant_conversations.delete_many(
        {"consultant_id": {"$in": identifiants}})
    r_chat = await db.chat_conversations.delete_many({"consultant_id": {"$in": identifiants}})
    r_users = await db.users.delete_many({"_id": {"$in": identifiants}})

    print(f"    comptes supprimés        : {r_users.deleted_count}")
    print(f"    messages supprimés       : {r_msg.deleted_count}")
    print(f"    conversations supprimées : {r_conv.deleted_count}")
    print(f"    discussions supprimées   : {r_chat.deleted_count}")

    _titre("6. Comptes restants")
    async for u in db.users.find({}, {"email": 1, "role": 1}).sort("role", 1):
        print(f"    {u['email']:<34}{u.get('role')}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(principal()))
