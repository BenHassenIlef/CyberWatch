"""Destinataires des notifications : les consultants qui SE CONNECTENT.

Un compte de démonstration créé pour une présentation et jamais rouvert recevait la veille
quotidienne au même titre qu'un consultant en activité. Le critère retenu est la connexion
(`last_login_at`), renseignée à chaque authentification — pas la simple existence du compte.

Le repli est délibéré : si personne ne satisfait le critère, tous les consultants sont
prévenus. Une notification envoyée trop largement se corrige ; une veille qui cesse
silencieusement d'être distribuée ne se voit pas.
"""
from datetime import datetime, timedelta

import pytest

from app.backend.services import notifications


class _FausseCollection:
    def __init__(self, docs):
        self._docs = docs

    def find(self, _filtre):
        return self

    async def to_list(self, _limite):
        return list(self._docs)


class _FausseBase:
    def __init__(self, docs):
        self.users = _FausseCollection(docs)


def _consultant(email, jours_depuis=None, identifiant=None):
    doc = {"_id": identifiant or email, "email": email, "role": "consultant"}
    if jours_depuis is not None:
        doc["last_login_at"] = datetime.now() - timedelta(days=jours_depuis)
    return doc


@pytest.fixture
def fenetre(monkeypatch):
    def _regler(jours):
        monkeypatch.setattr(notifications.settings,
                            "NOTIFY_ACTIVE_CONSULTANT_DAYS", jours, raising=False)
    return _regler


async def _emails(docs):
    return [u["email"] for u in await notifications.destinataires(_FausseBase(docs))]


# ---------------------------------------------------------------------------------------
# Sans fenêtre : toute connexion compte.
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_compte_jamais_connecte_ecarte(fenetre):
    fenetre(0)
    retenus = await _emails([_consultant("actif@test", jours_depuis=1),
                             _consultant("jamais@test")])
    assert retenus == ["actif@test"]


@pytest.mark.asyncio
async def test_ordre_par_connexion_la_plus_recente(fenetre):
    fenetre(0)
    retenus = await _emails([_consultant("ancien@test", jours_depuis=30),
                             _consultant("recent@test", jours_depuis=1),
                             _consultant("median@test", jours_depuis=10)])
    assert retenus == ["recent@test", "median@test", "ancien@test"]


@pytest.mark.asyncio
async def test_toute_connexion_meme_ancienne_est_retenue(fenetre):
    fenetre(0)
    assert await _emails([_consultant("vieux@test", jours_depuis=400)]) == ["vieux@test"]


# ---------------------------------------------------------------------------------------
# Avec fenêtre : seuls les comptes récemment utilisés.
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fenetre_ecarte_les_comptes_dormants(fenetre):
    fenetre(7)
    retenus = await _emails([_consultant("actif@test", jours_depuis=2),
                             _consultant("demo@test", jours_depuis=45)])
    assert retenus == ["actif@test"]


@pytest.mark.asyncio
async def test_fenetre_large_conserve_tout_le_monde(fenetre):
    fenetre(90)
    retenus = await _emails([_consultant("a@test", jours_depuis=2),
                             _consultant("b@test", jours_depuis=45)])
    assert set(retenus) == {"a@test", "b@test"}


@pytest.mark.asyncio
async def test_fenetre_vidant_tout_retombe_sur_les_connectes(fenetre):
    """Aucun compte récent : on prévient ceux qui se sont connectés, plutôt que personne."""
    fenetre(1)
    retenus = await _emails([_consultant("a@test", jours_depuis=40),
                             _consultant("b@test", jours_depuis=60)])
    assert set(retenus) == {"a@test", "b@test"}


# ---------------------------------------------------------------------------------------
# Repli : ne jamais cesser silencieusement de distribuer la veille.
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aucune_connexion_connue_previent_tout_le_monde(fenetre):
    fenetre(0)
    retenus = await _emails([_consultant("a@test"), _consultant("b@test")])
    assert set(retenus) == {"a@test", "b@test"}


@pytest.mark.asyncio
async def test_aucun_consultant_donne_une_liste_vide(fenetre):
    fenetre(0)
    assert await _emails([]) == []


@pytest.mark.asyncio
async def test_date_avec_fuseau_supportee(fenetre):
    """Selon la source, l'horodatage porte ou non un fuseau : les deux doivent marcher."""
    from datetime import timezone
    fenetre(30)
    doc = _consultant("a@test")
    doc["last_login_at"] = datetime.now(timezone.utc) - timedelta(days=2)
    assert await _emails([doc]) == ["a@test"]


# ---------------------------------------------------------------------------------------
# Relais SMTP : un serveur local n'exige pas d'authentification, un relais public si.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("hote", ["127.0.0.1", "localhost", "::1", ""])
def test_relais_local_reconnu(hote):
    assert notifications._serveur_local(hote)


@pytest.mark.parametrize("hote", ["smtp.gmail.com", "smtp.office365.com", "mail.advancia.tn"])
def test_relais_public_exige_des_identifiants(hote):
    assert not notifications._serveur_local(hote)


# ---------------------------------------------------------------------------------------
# ÉTAT DE LA REMISE — pourquoi le consultant ne reçoit rien
# ---------------------------------------------------------------------------------------

class _UtilisateursFactices:
    def __init__(self, consultants):
        self._consultants = consultants

    def find(self, *_a, **_k):
        return self

    async def to_list(self, *_a, **_k):
        return list(self._consultants)


class _BaseFactice:
    def __init__(self, consultants):
        self.users = _UtilisateursFactices(consultants)


@pytest.mark.asyncio
@pytest.mark.parametrize("hote, identifiant, mot_de_passe, actif, cause", [
    ("smtp.gmail.com", "a@b.fr", "",     True,  "mot_de_passe_manquant"),
    ("smtp.gmail.com", "",       "abc",  True,  "identifiant_manquant"),
    ("",               "a@b.fr", "abc",  True,  "non_configure"),
    ("smtp.gmail.com", "a@b.fr", "abc",  False, "desactive"),
    ("smtp.gmail.com", "a@b.fr", "abc",  True,  None),
    ("localhost",      "",       "",     True,  None),   # relais local : pas d'authentification
])
async def test_la_cause_de_non_remise_est_nommee(monkeypatch, hote, identifiant,
                                                 mot_de_passe, actif, cause):
    """Le consultant doit pouvoir LIRE pourquoi il ne reçoit rien.

    Le diagnostic n'existait que dans les journaux du serveur, qu'un consultant ne consulte
    pas. Il en concluait que l'application était en panne, alors qu'il manquait le plus
    souvent une seule ligne de configuration — et personne ne s'en apercevait tant que rien
    ne l'affichait.
    """
    from app.backend.core.config import settings
    from app.backend.db import mongodb
    from app.backend.routers import consultant as routeur

    consultant = {"_id": "1", "email": "moi@exemple.fr", "role": "consultant",
                  "last_login_at": datetime.utcnow()}
    monkeypatch.setattr(mongodb, "get_database", lambda: _BaseFactice([consultant]))
    monkeypatch.setattr(routeur, "get_database", lambda: _BaseFactice([consultant]))
    monkeypatch.setattr(settings, "SMTP_HOST", hote, raising=False)
    monkeypatch.setattr(settings, "SMTP_USER", identifiant, raising=False)
    monkeypatch.setattr(settings, "SMTP_PASSWORD", mot_de_passe, raising=False)
    monkeypatch.setattr(settings, "EMAIL_NOTIFICATIONS_ENABLED", actif, raising=False)
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "", raising=False)

    etat = await routeur.email_status(user=consultant)
    assert etat["cause"] == cause
    assert etat["operationnel"] is (cause is None)
    if cause is not None:
        assert etat["detail"], "une cause sans explication n'aide personne"


@pytest.mark.asyncio
async def test_l_etat_ne_divulgue_jamais_de_secret(monkeypatch):
    """On dit qu'un mot de passe manque — jamais sa valeur."""
    from app.backend.core.config import settings
    from app.backend.db import mongodb
    from app.backend.routers import consultant as routeur

    secret = "mot-de-passe-tres-secret"
    consultant = {"_id": "1", "email": "moi@exemple.fr", "role": "consultant",
                  "last_login_at": datetime.utcnow()}
    monkeypatch.setattr(mongodb, "get_database", lambda: _BaseFactice([consultant]))
    monkeypatch.setattr(routeur, "get_database", lambda: _BaseFactice([consultant]))
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.gmail.com", raising=False)
    monkeypatch.setattr(settings, "SMTP_USER", "a@b.fr", raising=False)
    monkeypatch.setattr(settings, "SMTP_PASSWORD", secret, raising=False)
    monkeypatch.setattr(settings, "EMAIL_NOTIFICATIONS_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "", raising=False)

    assert secret not in str(await routeur.email_status(user=consultant))


# ---------------------------------------------------------------------------------------
# ESSAI DE REMISE — valider la configuration sans attendre la collecte du lendemain
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("refus, attendu", [
    ("535-5.7.8 Username and Password not accepted", "MOT DE PASSE D'APPLICATION"),
    ("534-5.7.9 Application-specific password required", "mot de passe d'application"),
    ("534-5.7.14 Please log in via your web browser", "bloqué pour activité inhabituelle"),
    ("[Errno 11001] getaddrinfo failed", "n'a pas pu être résolu"),
    ("[Errno 111] Connection refused", "Connexion refusée"),
    ("timed out", "n'a pas répondu dans le délai"),
])
def test_les_refus_smtp_sont_traduits_en_geste_a_faire(refus, attendu):
    """Un code SMTP brut n'indique pas quoi corriger.

    « 535-5.7.8 Username and Password not accepted » peut signifier trois choses : mauvais
    mot de passe, mot de passe de compte au lieu d'un mot de passe d'application, ou
    validation en deux étapes absente. Trois causes, trois gestes différents — et un
    administrateur qui vient de coller une valeur doit savoir laquelle.
    """
    assert attendu in notifications.expliquer_echec(Exception(refus))


def test_un_refus_ne_divulgue_jamais_le_mot_de_passe(monkeypatch):
    """Certains serveurs renvoient la commande fautive, mot de passe compris."""
    from app.backend.core.config import settings

    secret = "abcd efgh ijkl mnop"
    monkeypatch.setattr(settings, "SMTP_PASSWORD", secret, raising=False)
    message = notifications.expliquer_echec(
        Exception(f"503 unexpected command: AUTH PLAIN {secret}"))
    assert secret not in message


@pytest.mark.asyncio
async def test_l_essai_refuse_de_partir_sans_identifiants(monkeypatch):
    """Inutile d'ouvrir une connexion vouée au refus : on nomme la pièce manquante."""
    from app.backend.core.config import settings

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.gmail.com", raising=False)
    monkeypatch.setattr(settings, "SMTP_USER", "a@b.fr", raising=False)
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "", raising=False)

    resultat = await notifications.essai_de_remise("a@b.fr")
    assert resultat["envoye"] is False
    assert "SMTP_PASSWORD" in resultat["detail"]


@pytest.mark.asyncio
async def test_l_essai_reussi_le_dit_clairement(monkeypatch):
    """Le succès doit être aussi explicite que l'échec."""
    from app.backend.core.config import settings

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.exemple.fr", raising=False)
    monkeypatch.setattr(settings, "SMTP_USER", "a@b.fr", raising=False)
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "secret", raising=False)
    monkeypatch.setattr(notifications, "_send_email", lambda *a, **k: None)

    resultat = await notifications.essai_de_remise("moi@exemple.fr")
    assert resultat["envoye"] is True
    assert "moi@exemple.fr" in resultat["detail"]


# ---------------------------------------------------------------------------------------
# LISTE EXCLUSIVE — la veille dirigée vers une boîte de service unique
# ---------------------------------------------------------------------------------------
#
# L'entreprise veut que la veille parte à « serviceenfidha@actelia.fr » et à personne d'autre.
# Cinq comptes consultants existaient, tous connectés au moins une fois : la veille partait
# donc aussi vers deux adresses personnelles et deux comptes de démonstration.
#
# NOTIFY_EXTRA_RECIPIENTS ne pouvait pas répondre à ce besoin : elle AJOUTE. Il fallait une
# liste qui RESTREIGNE — et qui résiste au temps, car tout se défait autrement dès qu'un
# consultant se reconnecte ou qu'un compte est créé.

@pytest.fixture
def diffusion(monkeypatch):
    """Règle les deux listes de configuration pour la durée d'un test."""
    def _regler(exclusifs="", supplementaires=""):
        monkeypatch.setattr(notifications.settings,
                            "NOTIFY_ONLY_RECIPIENTS", exclusifs, raising=False)
        monkeypatch.setattr(notifications.settings,
                            "NOTIFY_EXTRA_RECIPIENTS", supplementaires, raising=False)
    return _regler


async def _diffusion(docs):
    liste = await notifications._liste_de_diffusion(_FausseBase(docs))
    return [u["email"] for u in liste]


@pytest.mark.asyncio
async def test_la_liste_exclusive_ecarte_tous_les_comptes(fenetre, diffusion):
    fenetre(0)
    diffusion(exclusifs="service@entreprise.fr")
    retenus = await _diffusion([_consultant("ilef@perso.fr", jours_depuis=1),
                                _consultant("demo@test", jours_depuis=3)])
    assert retenus == ["service@entreprise.fr"]


@pytest.mark.asyncio
async def test_la_liste_exclusive_prime_sur_les_adresses_ajoutees(fenetre, diffusion):
    """Une liste qui restreint ne peut pas être contournée par une liste qui ajoute."""
    fenetre(0)
    diffusion(exclusifs="service@entreprise.fr", supplementaires="supervision@ailleurs.fr")
    assert await _diffusion([_consultant("ilef@perso.fr", jours_depuis=1)]) \
        == ["service@entreprise.fr"]


@pytest.mark.asyncio
async def test_plusieurs_adresses_exclusives_sont_acceptees(fenetre, diffusion):
    fenetre(0)
    diffusion(exclusifs="service@entreprise.fr, rssi@entreprise.fr")
    assert await _diffusion([_consultant("ilef@perso.fr", jours_depuis=1)]) \
        == ["service@entreprise.fr", "rssi@entreprise.fr"]


@pytest.mark.asyncio
async def test_sans_liste_exclusive_le_comportement_est_inchange(fenetre, diffusion):
    """Le réglage est facultatif : vide, la sélection historique s'applique telle quelle."""
    fenetre(0)
    diffusion(exclusifs="", supplementaires="supervision@ailleurs.fr")
    retenus = await _diffusion([_consultant("actif@test", jours_depuis=1)])
    assert retenus == ["actif@test", "supervision@ailleurs.fr"]


@pytest.mark.asyncio
async def test_une_reconnexion_ne_reintroduit_pas_une_adresse_ecartee(fenetre, diffusion):
    """Le point même du réglage : il tient dans le temps, sans surveillance."""
    fenetre(0)
    diffusion(exclusifs="service@entreprise.fr")
    # Le consultant écarté se reconnecte à l'instant : il ne doit pas revenir dans la liste.
    assert await _diffusion([_consultant("ilef@perso.fr", jours_depuis=0)]) \
        == ["service@entreprise.fr"]


# ---------------------------------------------------------------------------------------
# LE VERROU DE REMISE — dernière porte avant l'envoi
# ---------------------------------------------------------------------------------------
#
# `_liste_de_diffusion` décide QUI recevra la veille. Mais ce n'est qu'un des chemins qui
# mènent à un envoi : l'essai de remise en emprunte un autre, et rien n'interdit qu'un
# troisième soit écrit demain par quelqu'un qui ignore la règle.
#
# Une consigne appliquée à l'endroit où l'on CHOISIT laisse passer tout ce qui n'est pas
# passé par ce choix. `_autorises` est donc appliqué dans `_send_email`, que TOUTE remise
# franchit — y compris celles qui n'existent pas encore.

@pytest.fixture
def exclusifs(monkeypatch):
    def _regler(valeur):
        monkeypatch.setattr(notifications.settings,
                            "NOTIFY_ONLY_RECIPIENTS", valeur, raising=False)
    return _regler


def test_sans_liste_exclusive_les_destinataires_passent(exclusifs):
    exclusifs("")
    assert notifications._autorises(["a@x.fr", "b@y.fr"]) == ["a@x.fr", "b@y.fr"]


def test_une_adresse_hors_liste_est_retiree(exclusifs):
    exclusifs("service@entreprise.fr")
    assert notifications._autorises(
        ["service@entreprise.fr", "perso@gmail.com"]) == ["service@entreprise.fr"]


def test_la_comparaison_ignore_la_casse(exclusifs):
    """« Service@Entreprise.fr » et « service@entreprise.fr » sont la même boîte."""
    exclusifs("service@entreprise.fr")
    assert notifications._autorises(["Service@Entreprise.FR"]) == ["Service@Entreprise.FR"]


def test_un_envoi_sans_destinataire_autorise_echoue_bruyamment(exclusifs):
    """Le refus ne doit pas être silencieux.

    Ouvrir une connexion SMTP sans destinataire ne remettrait rien, sans rien signaler : la
    consigne de confidentialité passerait pour appliquée alors qu'elle aurait été contournée
    en amont. On préfère l'erreur, qui se voit.
    """
    exclusifs("service@entreprise.fr")
    with pytest.raises(notifications.DestinataireNonAutorise):
        notifications._autorises(["perso@gmail.com", "autre@gmail.com"])


def test_le_verrou_s_applique_a_tout_envoi(exclusifs, monkeypatch):
    """Vérification sur `_send_email` lui-même, et non sur le filtre isolé."""
    exclusifs("service@entreprise.fr")
    monkeypatch.setattr(notifications.settings, "SMTP_HOST", "127.0.0.1", raising=False)
    monkeypatch.setattr(notifications.settings, "SMTP_PORT", 25, raising=False)
    monkeypatch.setattr(notifications.settings, "SMTP_USE_TLS", False, raising=False)
    monkeypatch.setattr(notifications.settings, "SMTP_USER", "", raising=False)
    monkeypatch.setattr(notifications.settings, "SMTP_FROM",
                        "service@entreprise.fr", raising=False)

    remis = {}

    class _FauxSMTP:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def ehlo(self):
            pass

        def sendmail(self, expediteur, destinataires, _message):
            remis["de"] = expediteur
            remis["a"] = destinataires

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", _FauxSMTP)

    notifications._send_email(["service@entreprise.fr", "perso@gmail.com"], "sujet", "corps")

    assert remis["a"] == ["service@entreprise.fr"], "l'adresse écartée a atteint la remise"
    assert remis["de"] == "service@entreprise.fr"
