// Rend le « Bulletin de sécurité » Advancia à partir du MODÈLE NORMALISÉ (moteur générique
// backend : /consultant/cves/:id/bulletin ou /consultant/bulletin?url=…). Même structure quelle
// que soit la source (DGSSI, ANCS, CERT-FR, CISA, MSRC, Cisco, Red Hat, VMware…).
import { SEVERITY_LABELS } from "./cveConstants";

const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const fmtDate = (d) => {
  if (!d) return null;
  const dt = new Date(d);
  return isNaN(dt) ? String(d) : dt.toLocaleDateString("fr-FR");
};

function bulletsHTML(items) {
  const arr = (Array.isArray(items) ? items : items ? [items] : []).filter(Boolean);
  if (!arr.length) return '<span style="color:#999">—</span>';
  return `<ul style="margin:0;padding-left:20px">${arr.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>`;
}

function linksHTML(refs) {
  const arr = (refs || []).filter(Boolean);
  if (!arr.length) return '<span style="color:#999">—</span>';
  return arr.map((r) => `<div style="margin:2px 0">&bull;&nbsp;<a href="${esc(r)}">${esc(r)}</a></div>`).join("");
}

// Rend CLIQUABLES les URL contenues dans un texte libre (solution, remediation).
// L'echappement HTML est fait AVANT : on ne cherche donc que des URL deja neutralisees,
// ce qui interdit toute injection depuis le contenu collecte.
const URL_RE = /(https?:\/\/[^\s<>"')\]]+)/g;

function textWithLinks(value) {
  if (!value) return '<span style="color:#999">—</span>';
  return esc(value).replace(
    URL_RE,
    (u) => `<a href="${u}" target="_blank" rel="noreferrer">${u}</a>`
  );
}

// SOLUTION : trois situations, jamais confondues. Le tiret muet employé jusqu'ici ne disait
// pas si la remédiation manquait ou si elle n'existait pas ; le backend tranche désormais
// (`solution_status`) et le bulletin se contente de rendre sa réponse.
function solutionHTML(b) {
  if (b.solution) return textWithLinks(b.solution);
  const message =
    b.solution_message ||
    (b.solution_status === "aucun_correctif"
      ? "Aucun correctif ou mesure de remédiation officielle identifié."
      : "Les informations de remédiation n'ont pas pu être extraites de manière fiable.");
  return `<span style="color:#666;font-style:italic">${esc(message)}</span>`;
}

const LABEL = "border:1px solid #000;padding:8px 10px;text-align:center;font-weight:bold;vertical-align:middle;width:26%";
const CONTENT = "border:1px solid #000;padding:8px 12px;text-align:left;vertical-align:top";

function row(label, contentHTML) {
  if (contentHTML == null) return "";
  return `<tr><td style="${LABEL}">${esc(label)}</td><td style="${CONTENT}">${contentHTML}</td></tr>`;
}

// Fragment <table> du bulletin normalisé (styles inline -> rendu identique en page et à l'impression).
export function bulletinTableHTML(b, { logoUrl, showReferences = true } = {}) {
  const logo = logoUrl || `${window.location.origin}/logo-advancia.png`;
  const cves = b.cves || [];
  const ghsa = (b.identifiers && b.identifiers.ghsa) || [];
  const severity = b.severity ? SEVERITY_LABELS[b.severity] || b.severity : "—";
  const score = b.cvss_score != null && b.cvss_score !== "" ? Number(b.cvss_score).toFixed(1) : "—";
  const idsLine = [...cves, ...ghsa];

  // CVE la plus grave RÉELLEMENT présente dans ce bulletin. Le maximum est recalculé sur les
  // vulnérabilités listées, et non repris de l'agrégat : un bulletin borné à 80 CVE pourrait
  // afficher un score maximal qui ne figure sur aucune ligne, et aucune ne serait mise en
  // évidence. Plusieurs CVE peuvent partager ce maximum — elles sont toutes signalées.
  const scoreParCve = {};
  (b.vulnerabilities || []).forEach((v) => {
    if (v && v.cve_id && typeof v.cvss_score === "number") scoreParCve[v.cve_id] = v.cvss_score;
  });
  const valeurs = Object.values(scoreParCve);
  const scoreMax = valeurs.length ? Math.max(...valeurs) : null;
  const lesPlusGraves = new Set(
    scoreMax != null ? Object.keys(scoreParCve).filter((c) => scoreParCve[c] === scoreMax) : []
  );
  // LES PLUS GRAVES EN TÊTE : un bulletin qui aligne des dizaines d'identifiants doit
  // commencer par ceux qui appellent une action, et non par le premier venu.
  idsLine.sort((a, b2) => (scoreParCve[b2] ?? -1) - (scoreParCve[a] ?? -1));

  const productCell = `
    <div style="font-weight:bold;font-size:16px;margin-bottom:8px">${esc(b.title || (b.products || [])[0] || "—")}</div>
    ${b.vendor ? `<div style="margin-bottom:8px">Éditeur : <b>${esc(b.vendor)}</b></div>` : ""}
    ${idsLine.length
      ? idsLine.map((c) => {
          const score = scoreParCve[c];
          return lesPlusGraves.has(c)
            // La vulnérabilité la plus grave du lot est signalée EN ROUGE, avec son score :
            // c'est par elle qu'un consultant commence, et un bulletin qui en aligne huit
            // sans hiérarchie l'oblige à ouvrir chaque fiche pour le découvrir.
            ? `<div style="font-weight:bold;color:#b91c1c">${esc(c)}` +
              (score != null ? ` <span style="font-size:12px">(CVSS ${score.toFixed(1)})</span>` : "") +
              `</div>`
            : `<div style="font-weight:bold">${esc(c)}</div>`;
        }).join("")
      : '<span style="color:#999">—</span>'}`;

  // SITE OFFICIEL du produit vulnérable : celui de son ÉDITEUR, ou l'avis de sécurité qu'il
  // publie. Ni la page de collecte, ni une base de vulnérabilités — NVD, CVE.org et les avis
  // GitHub restent dans « Références ». Quand l'éditeur n'est pas identifiable de façon
  // vérifiable, on l'écrit : « Non identifié » informe, un tiret laisse croire à un oubli.
  const official = b.official_source || {};
  const officialUrl = official.url || b.official_url;
  const officialCell = officialUrl
    ? (official.name ? `<div style="font-weight:bold">${esc(official.name)}</div>` : "") +
      `<a href="${esc(officialUrl)}">${esc(officialUrl)}</a>`
    : '<span style="color:#999;font-style:italic">Non identifié</span>';

  return `
<table style="width:100%;border-collapse:collapse;border:1px solid #000;font-family:'Times New Roman',Georgia,serif;font-size:14px;color:#111;line-height:1.4">
  <tbody>
    <tr>
      <td style="border:1px solid #000;padding:8px;text-align:center;vertical-align:middle;width:26%">
        <img src="${esc(logo)}" alt="Advancia IT System" style="max-height:50px;max-width:150px"/>
      </td>
      <td style="border:1px solid #000;padding:10px;text-align:center;color:#1f3c88;font-weight:bold;font-size:16px">
        Bulletin de sécurité &ndash; Nouvelles vulnérabilités CVE
      </td>
    </tr>
    <tr>
      <td style="${LABEL}">Produit / Technologie</td>
      <td style="border:1px solid #000;padding:10px;text-align:center;vertical-align:middle">${productCell}</td>
    </tr>
    ${row("Résumé", b.summary ? esc(b.summary) : '<span style="color:#999">—</span>')}
    ${row("Risque / Impact", bulletsHTML(b.risk))}
    ${row("Systèmes affectés", bulletsHTML(b.affected_systems))}
    ${row("Sévérité / Score", `<b>${esc(severity)}</b>&nbsp;&nbsp;/&nbsp;&nbsp;${esc(score)}`)}
    ${b.vulnerability_type ? row("Type de vulnérabilité", esc(b.vulnerability_type)) : ""}
    ${row("Solution", solutionHTML(b))}
    ${showReferences ? row("Références", linksHTML(b.references)) : ""}
    ${row("Date de publication", fmtDate(b.publication_date) ? esc(fmtDate(b.publication_date)) : '<span style="color:#999">—</span>')}
    ${row("Dernière mise à jour", fmtDate(b.update_date)
        ? esc(fmtDate(b.update_date))
        : '<span style="color:#999;font-style:italic">Non disponible</span>')}
    ${row("Source officielle", officialCell)}
  </tbody>
</table>`;
}

// Bandeau « Résumé analyste » (Phase 4) — au-dessus du tableau.
export function aiSummaryHTML(b) {
  if (!b.ai_summary) return "";
  return `<div style="border-left:4px solid #1f3c88;background:#f4f6fb;padding:12px 16px;margin:0 0 14px;
    font-family:'Times New Roman',Georgia,serif;font-size:14px;color:#111">
    <div style="font-weight:bold;color:#1f3c88;margin-bottom:4px">Résumé (analyste)</div>${esc(b.ai_summary)}</div>`;
}

// Télécharge un VRAI fichier PDF généré par le backend (Chromium headless).
//
// Aucune impression : pas de `window.print()`, pas de boîte de dialogue. Le backend renvoie les
// octets du PDF avec un en-tête `Content-Disposition: attachment` ; on les matérialise ici en
// fichier via une URL d'objet. `api` porte le jeton d'authentification du consultant, d'où le
// `responseType: "blob"` plutôt qu'un simple lien href.
//
// `endpoint` : "/consultant/cves/<id>/bulletin.pdf"
//           ou "/consultant/product-bulletins/<vendorKey>/bulletin.pdf"
export async function downloadBulletinPdf(api, endpoint, fallbackName = "Bulletin.pdf") {
  const res = await api.get(endpoint, { responseType: "blob" });

  // Nom de fichier proposé par le serveur (Bulletin_CVE-2026-0290.pdf), sinon repli.
  const disposition = res.headers?.["content-disposition"] || "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  const filename = match ? match[1] : fallbackName;

  const url = URL.createObjectURL(new Blob([res.data], { type: "application/pdf" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Libère l'URL d'objet une fois le téléchargement amorcé (sinon fuite mémoire).
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
