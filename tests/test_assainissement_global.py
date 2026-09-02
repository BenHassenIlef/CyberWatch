"""Assainissement des textes : distinguer une faute de rendu d'un contenu technique.

La difficulté n'est pas de supprimer le déchet — c'est de ne PAS supprimer ce qui ressemble
à du déchet sans en être. Trois pièges rencontrés en base réelle :

  « extension < 2.4.1 »              le « < » compare des versions, il n'ouvre pas une balise
  « decode-after-sanitize &lt;script&gt; »  le balisage encodé EST le payload documenté
  « Mettre à jour Chrome 151.0… »    remédiation partagée par 370 CVE, et parfaitement juste

Chacun de ces textes serait mutilé par un filtre trop zélé, et un consultant y perdrait une
information exacte.
"""
from app.backend.services.collection import sanitize as sz


# ---------------------------------------------------------------------------------------
# Ce qui doit être ÉCARTÉ : ni description, ni remédiation.
# ---------------------------------------------------------------------------------------

def test_menu_de_portail_ecarte():
    menu = 'CVE List Pricing Book a demo Sign up Log in { "@context": "https://schema.org"}'
    assert sz.clean_text(menu) is None
    assert sz.clean_description(menu) is None


def test_sonde_javascript_ecartee():
    """« NREUM » figurait dans les marqueurs mais la comparaison de casse l'empêchait d'agir."""
    js = 'Updated CVEs | Tenable window.NREUM||(NREUM={});NREUM.info={beacon:"x"} et du texte'
    assert sz.clean_description(js) is None


def test_marqueur_en_capitales_detecte_quelle_que_soit_la_casse():
    for variante in ("NREUM", "nreum", "NrEuM"):
        texte = f"Une description assez longue pour passer le seuil, avec {variante} dedans."
        assert sz.clean_description(texte) is None


def test_page_d_erreur_ecartee():
    assert sz.clean_description("403 Forbidden " + "x" * 60) is None


def test_feuille_de_style_ecartee():
    assert sz.clean_description("@media screen and (max-width:640px){ body { margin:0 } } "
                                + "texte" * 12) is None


# ---------------------------------------------------------------------------------------
# Ce qui doit être CONSERVÉ, éventuellement normalisé.
# ---------------------------------------------------------------------------------------

def test_comparaison_de_version_intacte():
    texte = ("Unrestricted file upload in Balbooa Forms extension < 2.4.1 - "
             "The Joomla extension est vulnerable a un televersement non restreint.")
    assert sz.clean_description(texte) == texte


def test_comparaison_inferieur_ou_egal_intacte():
    texte = ("Improper Access Control in Ad Invalid Click Protector (AICP) <= 1.3.0 "
             "versions, permettant un acces non autorise aux reglages.")
    assert sz.clean_description(texte) == texte


def test_payload_xss_encode_preserve():
    """Décoder « &lt;script&gt; » changerait le sens technique de la description."""
    texte = ("Stored Cross-Site Scripting via decode-after-sanitize (double decoding) "
             "of &lt;script&gt; tags in comment content.")
    assert "&lt;script&gt;" in sz.clean_description(texte)


def test_balise_de_presentation_retiree():
    texte = ("<p>This CVE was assigned by Chrome. Microsoft Edge (Chromium) ingests "
             "Chromium and corrige la faille.</p>")
    propre = sz.clean_description(texte)
    assert propre and not propre.startswith("<p>") and "This CVE was assigned" in propre


def test_entite_typographique_decodee():
    texte = "Anti Spam and list cleaner &#8211; AcyChecker versions concernees par la faille."
    assert "–" in sz.clean_description(texte)


def test_remediation_partagee_par_de_nombreuses_cve_conservee():
    """370 CVE corrigées par la même version de Chrome : le partage n'est pas une faute."""
    texte = "Mettre a jour Chrome avec la version 151.0.7922.71/.72 pour Windows et Mac."
    assert sz.clean_text(texte) == texte


def test_remediation_generique_conservee():
    """Générique n'est pas faux : « appliquer les correctifs de l'editeur » reste exact."""
    assert sz.clean_text("Apply updates per vendor instructions.") is not None


# ---------------------------------------------------------------------------------------
# Retrait des balises : comportement isolé.
# ---------------------------------------------------------------------------------------

def test_sans_balises_est_stable():
    """Une seconde passe ne doit plus rien changer — sinon on décoderait en cascade."""
    texte = "<p>Texte &nbsp; encadre</p>"
    une = sz.sans_balises(texte)
    assert sz.sans_balises(une) == une


def test_sans_balises_ne_decode_pas_le_balisage():
    assert sz.sans_balises("payload &lt;img&gt; ici") == "payload &lt;img&gt; ici"


def test_sans_balises_supporte_une_valeur_vide():
    assert sz.sans_balises("") == "" and sz.sans_balises(None) == ""


def test_valeur_non_textuelle_rejetee():
    for valeur in (None, 42, [], {}):
        assert sz.clean_description(valeur) is None
