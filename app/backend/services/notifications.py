"""Notifications des consultants.

- Notification « in-app » : gérée par le flag `is_new` / `update_unread` sur chaque CVE
  (voir routers/consultant.py). Chaque nouvelle CVE = une notification affichée immédiatement.
- Notification par email : OPTIONNELLE, envoyée uniquement si activée et si un serveur SMTP
  est configuré (settings.EMAIL_NOTIFICATIONS_ENABLED + SMTP_HOST). Best-effort, jamais bloquant.
"""
import asyncio
import logging

from app.backend.core.config import settings

logger = logging.getLogger("cyberwatch.notifications")


def _send_email(recipients: list[str], subject: str, body: str) -> None:
    """Envoi SMTP synchrone (exécuté dans un thread pour ne pas bloquer l'event loop)."""
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(recipients)
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
        if settings.SMTP_USER:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM, recipients, msg.as_string())


_MAX_CVES_IN_EMAIL = 10       # au-delà, l'e-mail renvoie vers l'interface

_SEVERITY_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}


async def _recent_cves_block(db) -> str:
    """Liste des CVE non lues, en FRANÇAIS quand la traduction existe.

    Les valeurs TECHNIQUES (identifiant CVE, score CVSS, produit, éditeur) sont restituées
    telles quelles : seul le texte en langage naturel est localisé.
    """
    from app.backend.services.collection.translation import localized

    from app.backend.routers.consultant import published_today_filter

    try:
        # PUBLIÉES AUJOURD'HUI uniquement : une CVE publiée hier et simplement recollectée
        # aujourd'hui ne doit pas être renvoyée. Le critère porte sur `published_at`, la date
        # officielle de la source, jamais sur la date de collecte.
        docs = await db.cves.find(
            {**published_today_filter(),
             "$or": [{"is_new": True}, {"update_unread": True}]},
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
        cible = d.get("product") or d.get("vendor") or ""
        titre = (localized(d, "title") or d.get("cve_id") or "").strip()
        lignes.append(f"• {d.get('cve_id')} — {titre}")
        lignes.append(f"    Sévérité : {sev} (CVSS {score_txt})"
                      + (f" · Produit : {cible}" if cible else ""))
        resume = (localized(d, "description") or "").strip()
        if resume:
            lignes.append(f"    {resume[:220]}{'…' if len(resume) > 220 else ''}")
    return "Vulnérabilités concernées :\n" + "\n".join(lignes) + "\n\n"


async def notify_new_cves(db, new_count: int, updated_count: int) -> None:
    """Envoie un email de synthèse aux consultants si les notifications email sont activées."""
    if new_count <= 0 and updated_count <= 0:
        return
    if not settings.email_enabled:
        logger.info("Notifications email désactivées — %s nouvelle(s), %s mise(s) à jour (in-app uniquement).",
                    new_count, updated_count)
        return

    consultants = await db.users.find({"role": "consultant"}).to_list(1000)
    recipients = [u["email"] for u in consultants if u.get("email")]
    if not recipients:
        return

    subject = f"CyberWatch AI — {new_count} nouvelle(s) CVE, {updated_count} mise(s) à jour"
    body = (
        "Bonjour,\n\n"
        f"La collecte automatique a détecté {new_count} nouvelle(s) CVE et "
        f"{updated_count} mise(s) à jour importante(s).\n\n"
        + await _recent_cves_block(db) +
        "Connectez-vous à l'espace Consultant pour consulter les détails :\n"
        "  Menu « Notifications »\n\n"
        "— CyberWatch AI"
    )
    try:
        await asyncio.to_thread(_send_email, recipients, subject, body)
        logger.info("Email de notification envoyé à %s consultant(s).", len(recipients))
    except Exception as exc:  # noqa: BLE001 - best-effort
        logger.error("Échec de l'envoi email : %s", exc)
