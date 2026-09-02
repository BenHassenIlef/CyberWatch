"""VEILLE PAR COURRIEL — pourquoi aucun message n'arrivait, et ce qui l'empêche de revenir.

Trois défauts se cumulaient, chacun suffisant à produire un silence complet :

  1. Le pipeline n'appelait la fonction d'envoi QUE si le passage venait de créer des
     notifications. Une collecte sans nouveauté n'appelait donc même pas l'envoi, alors que
     des fiches non lues attendaient depuis les passages précédents.
  2. La synthèse ne retenait que les fiches RE-collectées le jour même. Une vulnérabilité
     détectée hier et non recollectée depuis disparaissait de tous les digests suivants :
     cinquante-cinq fiches non lues dormaient en base pendant que la synthèse en annonçait une.
  3. Rien n'était écrit les jours sans nouveauté. Or un silence ne se distingue pas d'une
     panne — c'est exactement le doute qui fait perdre confiance dans une veille.

S'y ajoute la contrainte inverse : plusieurs collectes ont lieu chaque jour, et un message
répété quatre fois finit en indésirables. D'où la mémoire d'envoi.

Aucun envoi réel : la remise SMTP est simulée.
"""
import asyncio

import pytest

from app.backend.core.config import settings
from app.backend.services import notifications as N


# ---------------------------------------------------------------------------------------
# Banc d'essai
# ---------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _diffusion_neutre(monkeypatch):
    """Neutralise la configuration de diffusion du poste qui exécute les tests.

    Ces tests portent sur la sélection ORDINAIRE des destinataires. Ils lisaient pourtant
    l'objet `settings` réel : le jour où « NOTIFY_ONLY_RECIPIENTS » a été renseignée dans le
    `.env` du développeur, deux d'entre eux se sont mis à échouer — non parce que le code
    avait régressé, mais parce que la machine avait changé.

    Un test qui dépend du `.env` local n'atteste de rien : il passe ou échoue selon le poste.
    On fixe donc ici les deux listes, et chaque test qui en dépend les redéfinit ensuite.
    """
    monkeypatch.setattr(settings, "NOTIFY_ONLY_RECIPIENTS", "", raising=False)
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "", raising=False)


class _Collection:
    def __init__(self, docs=None):
        self.docs = list(docs or [])
        self.inseres = []

    def find(self, filtre=None, projection=None):
        self._filtre = filtre or {}
        return self

    async def to_list(self, n=None):
        return list(self.docs)

    async def find_one(self, filtre=None, **k):
        """Honore l'égalité simple des filtres — la mémoire d'envoi cherche par EMPREINTE.

        Un double qui renverrait le premier document venu ferait passer le test de
        dédoublonnage pour toute empreinte, y compris une nouvelle : le mécanisme paraîtrait
        correct alors qu'il bloquerait toute information nouvelle de la journée.
        """
        for doc in self.docs:
            if all(doc.get(cle) == valeur for cle, valeur in (filtre or {}).items()
                   if not isinstance(valeur, dict)):
                return doc
        return None

    async def insert_one(self, doc):
        self.inseres.append(doc)
        self.docs.append(doc)


class _Base:
    def __init__(self, cves=None, users=None, envois=None):
        self.cves = _Collection(cves)
        self.users = _Collection(users)
        self.email_digests = _Collection(envois)


def _fiche(cve_id, produit="Mozilla Firefox", nouvelle=True, severite="critical"):
    return {"cve_id": cve_id, "title": f"Faille {cve_id}", "severity": severite,
            "cvss_score": 9.8, "monitored_products": [produit],
            "is_new": nouvelle, "update_unread": not nouvelle}


@pytest.fixture
def smtp(monkeypatch):
    """Capture ce qui PARTIRAIT, sans rien envoyer."""
    envoyes = []

    def _envoyer(destinataires, sujet, corps, html=None):
        envoyes.append({"a": destinataires, "sujet": sujet, "corps": corps, "html": html})

    monkeypatch.setattr(N, "_send_email", _envoyer)
    monkeypatch.setattr(settings, "EMAIL_NOTIFICATIONS_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "127.0.0.1")     # relais local : sans identifiants
    monkeypatch.setattr(settings, "SMTP_USER", "")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "")
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "")
    return envoyes


# ---------------------------------------------------------------------------------------
# 1. Le critère est « non lu », pas « recollecté aujourd'hui »
# ---------------------------------------------------------------------------------------

def test_le_digest_retient_toutes_les_fiches_non_lues():
    """Une fiche détectée hier et non recollectée doit RESTER signalée.

    C'est le défaut le plus coûteux des trois : il ne provoque aucune erreur, il fait
    simplement disparaître des vulnérabilités du courriel, définitivement.
    """
    base = _Base(cves=[_fiche("CVE-2026-1"), _fiche("CVE-2026-2", nouvelle=False)])
    digest = asyncio.run(N.digest_du_jour(base))
    assert digest["total"] == 2
    assert digest["nouvelles"] == 1 and digest["mises_a_jour"] == 1


def test_le_digest_groupe_par_produit_surveille():
    base = _Base(cves=[_fiche("CVE-2026-1", "Mozilla Firefox"),
                       _fiche("CVE-2026-2", "Mozilla Firefox", nouvelle=False),
                       _fiche("CVE-2026-3", "Google Chrome")])
    digest = asyncio.run(N.digest_du_jour(base))
    assert len(digest["produits"]) == 2
    firefox = next(p for p in digest["produits"] if p["nom"] == "Mozilla Firefox")
    assert firefox["total"] == 2 and firefox["nouvelles"] == 1 and firefox["mises_a_jour"] == 1


# ---------------------------------------------------------------------------------------
# 2. Un courriel part même quand la collecte n'a rien trouvé
# ---------------------------------------------------------------------------------------

def test_envoi_meme_sans_nouveaute_de_ce_passage(smtp):
    """L'envoi ne dépend PAS de ce que le dernier passage vient de trouver.

    Les compteurs transmis valent zéro — c'est le cas réel qui produisait le silence — mais
    des fiches non lues existent : le consultant doit les recevoir.
    """
    base = _Base(cves=[_fiche("CVE-2026-1")],
                 users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "Camille",
                         "role": "consultant", "last_login_at": None}])
    asyncio.run(N.notify_new_cves(base, 0, 0))
    assert len(smtp) == 1
    assert "CVE-2026-1" in smtp[0]["corps"]


def test_journee_sans_rien_produit_un_message_explicite(smtp):
    """Un silence ne se distingue pas d'une panne : on écrit, et on dit ce qui a paru."""
    base = _Base(cves=[], users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "Camille",
                                  "role": "consultant", "last_login_at": None}])
    asyncio.run(N.notify_new_cves(base, 0, 0, published_today=159))

    assert len(smtp) == 1
    message = smtp[0]
    assert "aucune vulnérabilité" in message["sujet"].lower()
    assert "159" in message["corps"], "le message doit prouver que la collecte a tourné"
    assert "n'est pas touché" in message["corps"] or "n’est pas touché" in message["corps"]
    assert "159" in message["html"]


def test_journee_sans_rien_et_sans_chiffre_reste_honnete(smtp):
    """Sans le compte des publications, on n'invente pas de chiffre — on reste factuel."""
    base = _Base(cves=[], users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "",
                                  "role": "consultant", "last_login_at": None}])
    asyncio.run(N.notify_new_cves(base, 0, 0, published_today=None))
    assert len(smtp) == 1
    assert "Aucune vulnérabilité nouvelle" in smtp[0]["corps"]


# ---------------------------------------------------------------------------------------
# 3. Mémoire d'envoi — informer sans harceler
# ---------------------------------------------------------------------------------------

def test_pas_de_doublon_dans_la_meme_journee(smtp):
    """Quatre collectes par jour ne doivent pas produire quatre fois le même message."""
    base = _Base(cves=[_fiche("CVE-2026-1")],
                 users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "Camille",
                         "role": "consultant", "last_login_at": None}])
    asyncio.run(N.notify_new_cves(base, 0, 0))
    asyncio.run(N.notify_new_cves(base, 0, 0))
    asyncio.run(N.notify_new_cves(base, 0, 0))
    assert len(smtp) == 1, "le même digest est parti plusieurs fois"


def test_une_nouveaute_en_cours_de_journee_relance_l_envoi(smtp):
    """La borne empêche la répétition, jamais l'information."""
    base = _Base(cves=[_fiche("CVE-2026-1")],
                 users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "Camille",
                         "role": "consultant", "last_login_at": None}])
    asyncio.run(N.notify_new_cves(base, 0, 0))
    base.cves.docs.append(_fiche("CVE-2026-2"))          # une vulnérabilité s'ajoute
    asyncio.run(N.notify_new_cves(base, 0, 0))
    assert len(smtp) == 2
    assert "CVE-2026-2" in smtp[1]["corps"]


def test_memoire_indisponible_ne_bloque_pas_la_veille(smtp, monkeypatch):
    """En cas de doute, on ENVOIE : un doublon se supprime, une veille manquante ne se voit pas."""
    async def _casse(*a, **k):
        raise RuntimeError("base indisponible")

    base = _Base(cves=[_fiche("CVE-2026-1")],
                 users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "Camille",
                         "role": "consultant", "last_login_at": None}])
    monkeypatch.setattr(base.email_digests, "find_one", _casse)
    asyncio.run(N.notify_new_cves(base, 0, 0))
    assert len(smtp) == 1


# ---------------------------------------------------------------------------------------
# 4. Configuration manquante — le diagnostic doit NOMMER la pièce absente
# ---------------------------------------------------------------------------------------

def test_mot_de_passe_absent_bloque_et_le_journal_le_nomme(smtp, monkeypatch, caplog):
    """Renseigner l'identifiant sans le mot de passe est le cas réel : il doit être nommé."""
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setattr(settings, "SMTP_USER", "veille@exemple.fr")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "")

    base = _Base(cves=[_fiche("CVE-2026-1")],
                 users=[{"_id": 1, "email": "c@exemple.fr", "full_name": "Camille",
                         "role": "consultant", "last_login_at": None}])
    with caplog.at_level("WARNING"):
        asyncio.run(N.notify_new_cves(base, 0, 0))

    assert smtp == [], "aucun message ne doit partir sans authentification possible"
    assert "SMTP_PASSWORD" in caplog.text


def test_un_destinataire_en_echec_ne_prive_pas_les_autres(monkeypatch):
    """Une adresse invalide isole son échec : les autres consultants reçoivent leur veille."""
    envoyes = []

    def _envoyer(destinataires, sujet, corps, html=None):
        if destinataires[0].startswith("invalide"):
            raise RuntimeError("adresse rejetée")
        envoyes.append(destinataires[0])

    monkeypatch.setattr(N, "_send_email", _envoyer)
    monkeypatch.setattr(settings, "EMAIL_NOTIFICATIONS_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "SMTP_USER", "")
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "")

    base = _Base(cves=[_fiche("CVE-2026-1")], users=[
        {"_id": 1, "email": "invalide@x", "full_name": "A", "role": "consultant",
         "last_login_at": None},
        {"_id": 2, "email": "valide@exemple.fr", "full_name": "B", "role": "consultant",
         "last_login_at": None}])
    asyncio.run(N.notify_new_cves(base, 0, 0))
    assert envoyes == ["valide@exemple.fr"]


def test_destinataire_de_supervision_ajoute(monkeypatch):
    """L'adresse de supervision reçoit même si aucun compte consultant ne correspond."""
    envoyes = []
    monkeypatch.setattr(N, "_send_email",
                        lambda d, s, c, h=None: envoyes.append(d[0]))
    monkeypatch.setattr(settings, "EMAIL_NOTIFICATIONS_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "SMTP_USER", "")
    monkeypatch.setattr(settings, "NOTIFY_EXTRA_RECIPIENTS", "supervision@exemple.fr")

    base = _Base(cves=[_fiche("CVE-2026-1")], users=[])
    asyncio.run(N.notify_new_cves(base, 0, 0))
    assert "supervision@exemple.fr" in envoyes
