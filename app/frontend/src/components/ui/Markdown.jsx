// Rendu Markdown des réponses de l'assistant IA.
//
// POURQUOI UN RENDU MAISON PLUTÔT QU'UNE BIBLIOTHÈQUE
// Les réponses sont écrites par un modèle de langage à partir, entre autres, de contenus
// externes (pages d'avis, discussions). Une bibliothèque générique convertit le Markdown en
// HTML, qu'il faut ensuite injecter — et tout `dangerouslySetInnerHTML` sur du texte d'origine
// tierce est une porte d'entrée dans un outil de sécurité. Ici, on ne produit QUE des éléments
// React : le texte reste du texte, jamais du balisage. Aucune injection n'est possible, quoi
// que contienne la réponse.
//
// On ne couvre pas tout Markdown, seulement ce que l'assistant produit réellement : titres,
// gras, italique, code, listes, tableaux, liens. Le reste s'affiche tel quel plutôt que d'être
// mal interprété.

// Découpe une ligne en fragments stylés. Retourne un tableau de nœuds React.
// L'ordre des motifs compte : le code littéral est isolé en premier, pour qu'un `**` à
// l'intérieur d'un extrait de code ne soit pas pris pour du gras.
const INLINE = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\n]+\*|_[^_\n]+_|https?:\/\/[^\s<>"')\]]+)/g;

function inline(texte, cle = "i") {
  if (!texte) return null;
  // Le modèle emploie « <br> » dans les cellules de tableau : c'est une intention de saut de
  // ligne, pas du balisage à exécuter. On la traduit en véritable retour à la ligne.
  const lignes = String(texte).split(/<br\s*\/?>/i);

  return lignes.map((ligne, li) => (
    <span key={`${cle}-l${li}`}>
      {li > 0 && <br />}
      {ligne.split(INLINE).map((fragment, fi) => {
        const k = `${cle}-l${li}-f${fi}`;
        if (!fragment) return null;
        if (fragment.startsWith("`") && fragment.endsWith("`") && fragment.length > 2) {
          return (
            <code key={k} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[0.85em] text-slate-800">
              {fragment.slice(1, -1)}
            </code>
          );
        }
        if (fragment.startsWith("**") && fragment.endsWith("**") && fragment.length > 4) {
          return <strong key={k} className="font-semibold text-slate-900">{fragment.slice(2, -2)}</strong>;
        }
        if ((fragment.startsWith("*") && fragment.endsWith("*") && fragment.length > 2) ||
            (fragment.startsWith("_") && fragment.endsWith("_") && fragment.length > 2)) {
          return <em key={k}>{fragment.slice(1, -1)}</em>;
        }
        if (/^https?:\/\//.test(fragment)) {
          return (
            <a key={k} href={fragment} target="_blank" rel="noreferrer"
               className="break-all text-brand-600 underline decoration-brand-300 underline-offset-2 hover:text-brand-700">
              {fragment}
            </a>
          );
        }
        return <span key={k}>{fragment}</span>;
      })}
    </span>
  ));
}

// Une ligne de tableau Markdown : « | a | b | ». La ligne de séparation « |---|---| » ne porte
// aucune donnée et sert uniquement à confirmer qu'il s'agit bien d'un tableau.
const estLigneTableau = (l) => /^\s*\|.*\|\s*$/.test(l);
const estSeparateur = (l) => /^\s*\|[\s:|-]+\|\s*$/.test(l);

const cellules = (ligne) =>
  ligne.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());

function Tableau({ lignes, cle }) {
  const entetes = cellules(lignes[0]);
  const corps = lignes.slice(estSeparateur(lignes[1]) ? 2 : 1).map(cellules);

  return (
    // Un tableau large doit défiler DANS son cadre : sans cela il pousse toute la
    // conversation horizontalement et rend la lecture pénible sur un écran étroit.
    <div key={cle} className="my-3 overflow-x-auto rounded-xl border border-slate-200">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="bg-slate-50">
            {entetes.map((c, i) => (
              <th key={i} className="border-b border-slate-200 px-3 py-2 text-left font-semibold text-slate-700">
                {inline(c, `th${i}`)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {corps.map((rangee, ri) => (
            <tr key={ri} className="align-top even:bg-slate-50/50">
              {rangee.map((c, ci) => (
                <td key={ci} className="border-b border-slate-100 px-3 py-2 text-slate-600">
                  {inline(c, `td${ri}-${ci}`)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const PUCE = /^\s*[-*•]\s+(.*)$/;
const NUMERO = /^\s*(\d+)[.)]\s+(.*)$/;
const TITRE = /^\s*(#{1,6})\s+(.*)$/;
// Citation Markdown. L'assistant s'en sert pour les mises en garde (« > Note : recoupez avec
// la source officielle »), c'est-à-dire exactement ce qu'un consultant ne doit pas manquer.
// Non gérée, elle s'affichait avec son chevron, comme une coquille.
const CITATION = /^\s*>\s?(.*)$/;

// Regroupe les lignes en blocs (tableau, liste, titre, paragraphe) puis rend chaque bloc.
export default function Markdown({ texte, className = "" }) {
  if (!texte) return null;
  const lignes = String(texte).split("\n");
  const blocs = [];
  let i = 0;

  while (i < lignes.length) {
    const ligne = lignes[i];

    if (!ligne.trim()) { i += 1; continue; }

    // TABLEAU — au moins deux lignes, dont une de séparation : sans cette exigence, une
    // phrase contenant une barre verticale serait prise pour un tableau d'une seule colonne.
    if (estLigneTableau(ligne) && i + 1 < lignes.length && estSeparateur(lignes[i + 1])) {
      const debut = i;
      while (i < lignes.length && estLigneTableau(lignes[i])) i += 1;
      blocs.push(<Tableau key={`t${debut}`} cle={`t${debut}`} lignes={lignes.slice(debut, i)} />);
      continue;
    }

    const titre = TITRE.exec(ligne);
    if (titre) {
      const niveau = titre[1].length;
      blocs.push(
        <div key={`h${i}`}
             className={`mt-4 first:mt-0 font-semibold text-slate-800 ${niveau <= 2 ? "text-base" : "text-sm"}`}>
          {inline(titre[2], `h${i}`)}
        </div>
      );
      i += 1;
      continue;
    }

    // CITATION — mise en garde, note, avertissement.
    if (CITATION.test(ligne)) {
      const debut = i;
      const contenu = [];
      while (i < lignes.length && CITATION.test(lignes[i])) {
        contenu.push(CITATION.exec(lignes[i])[1]);
        i += 1;
      }
      blocs.push(
        <div key={`q${debut}`}
             className="my-3 rounded-r-lg border-l-4 border-brand-300 bg-brand-50/60 px-4 py-2 text-slate-700">
          {inline(contenu.join(" "), `q${debut}`)}
        </div>
      );
      continue;
    }

    // LISTE (à puces ou numérotée)
    if (PUCE.test(ligne) || NUMERO.test(ligne)) {
      const numerotee = NUMERO.test(ligne) && !PUCE.test(ligne);
      const elements = [];
      while (i < lignes.length && (PUCE.test(lignes[i]) || NUMERO.test(lignes[i]))) {
        const m = PUCE.exec(lignes[i]) || NUMERO.exec(lignes[i]);
        elements.push(m[m.length - 1]);
        i += 1;
      }
      const Balise = numerotee ? "ol" : "ul";
      blocs.push(
        <Balise key={`l${i}`}
                className={`my-2 space-y-1 pl-5 ${numerotee ? "list-decimal" : "list-disc"} marker:text-slate-400`}>
          {elements.map((e, ei) => (
            <li key={ei} className="leading-relaxed">{inline(e, `li${i}-${ei}`)}</li>
          ))}
        </Balise>
      );
      continue;
    }

    // PARAGRAPHE : lignes consécutives jusqu'à une ligne vide ou un autre type de bloc.
    const debut = i;
    const paragraphe = [];
    while (i < lignes.length && lignes[i].trim() && !estLigneTableau(lignes[i])
           && !PUCE.test(lignes[i]) && !NUMERO.test(lignes[i]) && !TITRE.test(lignes[i])
           && !CITATION.test(lignes[i])) {
      paragraphe.push(lignes[i]);
      i += 1;
    }
    blocs.push(
      <p key={`p${debut}`} className="my-2 leading-relaxed first:mt-0">
        {inline(paragraphe.join(" "), `p${debut}`)}
      </p>
    );
  }

  return <div className={className}>{blocs}</div>;
}
