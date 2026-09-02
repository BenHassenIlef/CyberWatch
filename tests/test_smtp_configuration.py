"""CHARGEMENT DE LA CONFIGURATION ET FLUX SMTP — les causes réelles d'un envoi muet.

Le symptôme observé était « le consultant ne reçoit aucun courriel ». Derrière, trois défauts
distincts, dont deux invisibles :

  1. le fichier `.env` était désigné par un chemin RELATIF : lancée hors de la racine,
     l'application perdait toute sa configuration et démarrait quand même ;
  2. `starttls()` n'était appelé que si un identifiant était renseigné, si bien que le
     chiffrement dépendait de la présence d'un mot de passe au lieu du serveur ;
  3. le port 465 (TLS implicite) n'était pas géré du tout.

Aucun réseau : le transport est simulé.
"""
import smtplib
from pathlib import Path

import pytest

from app.backend.core import config
from app.backend.services import notifications


@pytest.fixture(autouse=True)
def _sans_liste_exclusive(monkeypatch):
    """Neutralise « NOTIFY_ONLY_RECIPIENTS » du poste qui exécute les tests.

    Ces tests portent sur le TRANSPORT — chiffrement, port, authentification — et appellent
    `_send_email` avec des adresses fictives. Le filtre exclusif, lui, s'applique juste avant
    la remise : renseigné dans le `.env` de la machine, il rejetait ces adresses et faisait
    échouer des tests qui n'ont rien à voir avec la liste de diffusion.

    Un test qui dépend du `.env` local n'atteste de rien : il passe ou échoue selon le poste.
    """
    monkeypatch.setattr(notifications.settings, "NOTIFY_ONLY_RECIPIENTS", "", raising=False)


# ---------------------------------------------------------------------------------------
# 1. Chargement de la configuration
# ---------------------------------------------------------------------------------------

def test_le_fichier_env_est_designe_par_un_chemin_absolu():
    """Un chemin relatif dépend du répertoire de lancement — donc du hasard.

    Lancée depuis la racine, l'application chargeait tout ; lancée depuis n'importe où
    ailleurs (service Windows, tâche planifiée, `cd` malheureux), elle ne chargeait RIEN et
    démarrait quand même : SMTP_HOST vide donc courriels muets, LLM_API_KEY vide donc
    assistant dégradé, et pas le moindre message pour l'expliquer.
    """
    assert config.FICHIER_ENV.is_absolute(), (
        "le fichier de configuration doit être ancré, pas relatif au répertoire courant")
    assert config.FICHIER_ENV.name == ".env"
    assert config.RACINE_PROJET.is_absolute()


def test_la_racine_du_projet_est_correctement_deduite():
    """`app/backend/core/config.py` -> la racine est trois niveaux au-dessus."""
    assert (config.RACINE_PROJET / "app" / "backend" / "core" / "config.py").exists()


def test_le_fichier_effectivement_lu_est_celui_declare():
    declare = config.Settings.model_config["env_file"]
    assert Path(declare) == config.FICHIER_ENV


def test_le_reglage_de_chiffrement_existe_et_est_actif_par_defaut():
    """Un défaut prudent : on chiffre sauf mention contraire explicite."""
    assert config.settings.SMTP_USE_TLS is True


# ---------------------------------------------------------------------------------------
# 2. Flux SMTP réellement exécuté
# ---------------------------------------------------------------------------------------

class _ServeurFactice:
    """Enregistre les appels au lieu de parler à un vrai serveur."""

    dernier: "_ServeurFactice | None" = None

    def __init__(self, hote, port, timeout=None):
        self.hote, self.port = hote, port
        self.appels: list[str] = []
        self.identifiants: tuple | None = None
        _ServeurFactice.dernier = self

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def starttls(self):
        self.appels.append("starttls")

    def login(self, utilisateur, mot_de_passe):
        self.appels.append("login")
        self.identifiants = (utilisateur, mot_de_passe)

    def sendmail(self, expediteur, destinataires, message):
        self.appels.append("sendmail")


@pytest.fixture
def serveur(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP", _ServeurFactice)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _ServeurFactice)
    _ServeurFactice.dernier = None
    return _ServeurFactice


def _configurer(monkeypatch, **valeurs):
    from app.backend.core.config import settings

    defauts = {"SMTP_HOST": "smtp.gmail.com", "SMTP_PORT": 587, "SMTP_USE_TLS": True,
               "SMTP_USER": "expediteur@exemple.fr", "SMTP_PASSWORD": "secret-application",
               "SMTP_FROM": "expediteur@exemple.fr"}
    for nom, valeur in {**defauts, **valeurs}.items():
        monkeypatch.setattr(settings, nom, valeur, raising=False)


def test_le_chiffrement_ne_depend_pas_de_la_presence_d_un_mot_de_passe(monkeypatch, serveur):
    """C'est LE défaut : `starttls()` n'était appelé que si un identifiant existait.

    Un relais exigeant TLS sans authentification recevait donc le message en clair.
    """
    _configurer(monkeypatch, SMTP_USER="", SMTP_PASSWORD="")
    notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")

    assert "starttls" in serveur.dernier.appels
    assert "login" not in serveur.dernier.appels, "aucun identifiant : pas d'authentification"
    assert "sendmail" in serveur.dernier.appels


def test_authentification_seulement_si_les_deux_elements_sont_presents(monkeypatch, serveur):
    """`login()` avec un mot de passe vide produit un « 535 » illisible.

    L'absence de configuration doit se dire clairement en amont, pas se traduire par un refus
    serveur que personne ne sait interpréter.
    """
    _configurer(monkeypatch, SMTP_PASSWORD="")
    notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")
    assert "login" not in serveur.dernier.appels

    _configurer(monkeypatch)
    notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")
    assert "login" in serveur.dernier.appels
    assert serveur.dernier.identifiants == ("expediteur@exemple.fr", "secret-application"), (
        "le mot de passe doit bien atteindre l'authentification")


def test_le_port_465_ouvre_une_liaison_deja_chiffree(monkeypatch, serveur):
    """Sur 465, la liaison est chiffrée dès son ouverture : `STARTTLS` y échouerait."""
    _configurer(monkeypatch, SMTP_PORT=465)
    notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")

    assert "starttls" not in serveur.dernier.appels
    assert "login" in serveur.dernier.appels and "sendmail" in serveur.dernier.appels


def test_le_port_587_bascule_en_starttls(monkeypatch, serveur):
    _configurer(monkeypatch, SMTP_PORT=587)
    notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")
    assert serveur.dernier.appels.index("starttls") < serveur.dernier.appels.index("login"), (
        "le chiffrement doit précéder l'envoi des identifiants")


def test_jamais_d_identifiants_sur_une_liaison_en_clair(monkeypatch, serveur):
    """`AUTH PLAIN` transmet le mot de passe en base64 — lisible sur le réseau.

    Un mot de passe d'application Gmail donne accès à la boîte : le laisser fuir pour
    envoyer une notification serait un échange absurde.
    """
    _configurer(monkeypatch, SMTP_USE_TLS=False)
    with pytest.raises(RuntimeError, match="en clair"):
        notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")
    assert serveur.dernier.identifiants is None, "le mot de passe ne doit pas avoir été transmis"


def test_un_relais_local_reste_utilisable_sans_chiffrement(monkeypatch, serveur):
    """Un relais interne sur la machine même ne traverse aucun réseau : la règle ne s'y applique pas."""
    _configurer(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=25, SMTP_USE_TLS=False)
    notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")
    assert "sendmail" in serveur.dernier.appels


def test_le_message_d_erreur_ne_contient_jamais_le_mot_de_passe(monkeypatch, serveur):
    _configurer(monkeypatch, SMTP_USE_TLS=False, SMTP_PASSWORD="mot-de-passe-secret")
    with pytest.raises(RuntimeError) as echec:
        notifications._send_email(["dest@exemple.fr"], "Objet", "Corps")
    assert "mot-de-passe-secret" not in str(echec.value)
