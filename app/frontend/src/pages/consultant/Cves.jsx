import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Eye, ShieldAlert, ShieldCheck, Bell, ArrowUpDown, CalendarClock } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Table from "../../components/ui/Table";
import Button from "../../components/ui/Button";
import StatCard from "../../components/ui/StatCard";
import SearchInput from "../../components/ui/SearchInput";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import {
  SEVERITY_LABELS,
  SEVERITY_STYLES,
  SEVERITY_OPTIONS,
  SORT_OPTIONS,
  SEVERITY_ACCENTS,
} from "./cveConstants";

const PAGE_SIZE = 20;
const EMPTY_FILTERS = { severity: "", product: "", category: "", date_from: "", date_to: "" };

const NA = "Non disponible";
const fmtDate = (d) => (d ? new Date(d).toLocaleDateString("fr-FR") : NA);
const fmtDateTime = (d) => (d ? new Date(d).toLocaleString("fr-FR") : NA);
const na = (v) => (v === null || v === undefined || v === "" ? <span className="italic text-slate-400">{NA}</span> : v);

// Chaque vue dit ce que SON absence de résultat signifie. Un « Aucune CVE trouvée » identique
// partout laisse le lecteur conclure à la panne, alors qu'une journée sans vulnérabilité sur
// le parc surveillé est le cas le plus fréquent — et une bonne nouvelle.
const EMPTY_LABELS = {
  published: "Aucune CVE ne correspond à ces critères.",
  published_today:
    "Aucune vulnérabilité n'a été publiée aujourd'hui par les sources consultées. " +
    "C'est fréquent le week-end et les jours fériés.",
  collected:
    "Aucune nouvelle vulnérabilité n'est entrée en base aujourd'hui : les publications du " +
    "jour ne concernent aucun de vos produits surveillés. Les modifications de fiches déjà " +
    "suivies figurent dans l'onglet « Mises à jour aujourd'hui ».",
  updated_today:
    "Aucune vulnérabilité déjà suivie n'a été modifiée aujourd'hui. Les découvertes du jour " +
    "figurent dans l'onglet « Collectées aujourd'hui ».",
};

export default function ConsultantCves() {
  const navItems = useConsultantNavItems();
  const [data, setData] = useState({ total: 0, items: [] });
  const [stats, setStats] = useState(null);
  const [facets, setFacets] = useState({ products: [], categories: [] });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [sortBy, setSortBy] = useState("date");
  const [order, setOrder] = useState("desc");
  const [page, setPage] = useState(0);
  // Deux vues distinctes : "published" (date de publication) / "collected" (collectées aujourd'hui).
  const [view, setView] = useState("published");

  const [sync, setSync] = useState(null);

  useEffect(() => {
    api.get("/consultant/cve-facets").then((res) => setFacets(res.data));
    api.get("/consultant/cve-stats").then((res) => setStats(res.data));
    api.get("/consultant/sync-stats").then((res) => setSync(res.data)).catch(() => {});
  }, []);

  const load = async () => {
    setLoading(true);
    const params = { skip: page * PAGE_SIZE, limit: PAGE_SIZE, sort_by: sortBy, order };
    if (search.trim()) params.q = search.trim();
    Object.entries(filters).forEach(([k, v]) => {
      if (v) params[k] = v;
    });
    if (view === "collected") params.collected_today = true; // vue « activité du jour »
    // Vue « Publiées aujourd'hui » : date OFFICIELLE de publication, filtrée côté MongoDB.
    if (view === "published_today") params.published_today = true;
    // Vue « Mises à jour aujourd'hui » : fiches connues AVANT ce jour dont les données ont
    // réellement changé — distinct des nouveautés, qu'un consultant a déjà traitées.
    if (view === "updated_today") params.updated_today = true;
    const { data } = await api.get("/consultant/cves", { params });
    setData(data);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, search, filters, sortBy, order, view]);

  const refreshStats = () => api.get("/consultant/cve-stats").then((res) => setStats(res.data));
  useEffect(() => { refreshStats(); }, [view]);

  const setFilter = (key, value) => {
    setPage(0);
    setFilters((f) => ({ ...f, [key]: value }));
  };

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  const selectClass =
    "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100";

  const activeCount = useMemo(() => Object.values(filters).filter(Boolean).length, [filters]);

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader title="Vulnérabilités (CVE)" subtitle="Consulter les CVE collectées par les agents" />

      {/* Cartes de synthèse : distinction claire « publiées » vs « collectées aujourd'hui » */}
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="CVE collectées (total)" value={stats?.total ?? "—"} icon={ShieldCheck} accent={SEVERITY_ACCENTS.total} />
        <StatCard label="Collectées aujourd'hui" value={stats?.collected_today ?? "—"} icon={CalendarClock} accent={SEVERITY_ACCENTS.new} />
        <StatCard label="Nouvelles (publiées récemment)" value={stats?.new ?? "—"} icon={Bell} accent={SEVERITY_ACCENTS.high} />
        <StatCard label="Critiques" value={stats?.critical ?? "—"} icon={ShieldAlert} accent={SEVERITY_ACCENTS.critical} />
      </div>

      {/* Tableau de bord de SYNCHRONISATION (moteur type OpenCVE) */}
      {sync && (
        <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm">
          <span className="font-semibold text-slate-600">Synchronisation</span>
          <span className="rounded-full bg-brand-50 px-2 py-0.5 text-brand-700">{sync.by_status?.new ?? 0} nouvelles</span>
          <span className="rounded-full bg-sky-50 px-2 py-0.5 text-sky-700">{sync.by_status?.enriched ?? 0} enrichies</span>
          <span className="rounded-full bg-amber-50 px-2 py-0.5 text-amber-700">{sync.by_status?.updated ?? 0} mises à jour</span>
          <span className="rounded-full bg-slate-50 px-2 py-0.5 text-slate-500">{sync.by_status?.unchanged ?? 0} inchangées</span>
          {sync.failed_syncs > 0 && (
            <span className="rounded-full bg-rose-50 px-2 py-0.5 text-rose-700">{sync.failed_syncs} source(s) en échec</span>
          )}
          <span className="text-slate-500">Complétude moy. <b className="text-slate-700">{sync.avg_completeness}%</b></span>
          {sync.next_sync && (
            <span className="ml-auto text-xs text-slate-400">
              Prochaine synchro : {new Date(sync.next_sync).toLocaleString("fr-FR")}
            </span>
          )}
        </div>
      )}

      {/* Bascule entre les deux vues */}
      <div className="mb-4 inline-flex rounded-xl border border-slate-200 bg-white p-1 text-sm">
        {[
          { key: "published", label: "Publiées récemment" },
          { key: "published_today", label: "Publiées aujourd'hui" },
          { key: "collected", label: "Collectées aujourd'hui" },
          { key: "updated_today", label: "Mises à jour aujourd'hui" },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => { setView(t.key); setPage(0); }}
            className={`rounded-lg px-4 py-1.5 font-medium transition ${
              view === t.key ? "bg-brand-600 text-white" : "text-slate-500 hover:text-slate-700"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SearchInput
          value={search}
          onChange={(v) => {
            setPage(0);
            setSearch(v);
          }}
          placeholder="Rechercher un CVE ou un produit…"
        />
        <select value={filters.severity} onChange={(e) => setFilter("severity", e.target.value)} className={selectClass}>
          <option value="">Toutes criticités</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
        <select value={filters.product} onChange={(e) => setFilter("product", e.target.value)} className={selectClass}>
          <option value="">Tous produits</option>
          {facets.products.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <input type="date" value={filters.date_from} onChange={(e) => setFilter("date_from", e.target.value)} className={selectClass} title="Date de début" />
        <input type="date" value={filters.date_to} onChange={(e) => setFilter("date_to", e.target.value)} className={selectClass} title="Date de fin" />

        {/* Tri par score CVSS ou date */}
        <div className="flex items-center gap-1.5 text-slate-400">
          <ArrowUpDown size={16} />
          <select value={sortBy} onChange={(e) => { setPage(0); setSortBy(e.target.value); }} className={selectClass} title="Trier par">
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <select value={order} onChange={(e) => { setPage(0); setOrder(e.target.value); }} className={selectClass} title="Ordre">
            <option value="desc">Décroissant</option>
            <option value="asc">Croissant</option>
          </select>
        </div>

        {activeCount > 0 && (
          <button onClick={() => setFilters(EMPTY_FILTERS)} className="text-sm font-medium text-brand-600 hover:underline">
            Réinitialiser
          </button>
        )}
      </div>

      <Table
        columns={[
          {
            key: "cve_id",
            label: "CVE ID",
            render: (r) => (
              <span className="flex items-center gap-2">
                <Link to={`/consultant/cves/${r.id}`} className="font-medium text-brand-700 hover:underline">
                  {r.cve_id}
                </Link>
                {r.is_new ? (
                  <span className="rounded-full bg-brand-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-brand-700">
                    Nouvelle
                  </span>
                ) : r.sync_status === "enriched" ? (
                  <span className="rounded-full bg-sky-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-sky-700" title={(r.change_summary || []).join(" · ")}>
                    Enrichie
                  </span>
                ) : r.is_updated ? (
                  <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700" title={(r.change_summary || []).join(" · ")}>
                    Mise à jour
                  </span>
                ) : null}
              </span>
            ),
          },
          // ÉDITEUR AVANT LE PRODUIT — c'est l'ordre dans lequel on identifie un logiciel.
          // « C# Driver » seul ne dit pas de quel produit il s'agit ; « MongoDB » le dit.
          // Renseigné sur 91 % des fiches ; les autres affichent « Non identifié » plutôt
          // qu'un tiret muet, qui laisserait croire à un oubli de l'outil.
          { key: "vendor", label: "Éditeur", render: (r) => na(r.vendor) },
          { key: "product", label: "Produit", render: (r) => na(r.product || (r.affected_products || []).join(", ")) },
          { key: "vuln_type", label: "Type", render: (r) => <span className="line-clamp-1 max-w-[12rem]">{na(r.vuln_type)}</span> },
          { key: "cvss_score", label: "CVSS", render: (r) => (typeof r.cvss_score === "number" ? r.cvss_score.toFixed(1) : na(null)) },
          {
            key: "severity",
            label: "Criticité",
            render: (r) =>
              r.severity ? (
                <span className={`rounded-full px-3 py-1 text-xs font-semibold ${SEVERITY_STYLES[r.severity]}`}>
                  {SEVERITY_LABELS[r.severity]}
                </span>
              ) : (
                na(null)
              ),
          },
          view === "collected"
            ? { key: "collected_at", label: "Collectée le", render: (r) => fmtDateTime(r.collected_at) }
            : view === "updated_today"
            ? {
                // L'ONGLET PORTE SUR DES CVE ANCIENNES : leur ancienneté doit se voir. Sans
                // la date de première détection, rien ne distingue à l'écran une fiche suivie
                // depuis dix jours d'une nouveauté du matin — or c'est exactement ce que
                // cette vue est censée séparer.
                key: "published_at",
                label: "Publiée (CVE)",
                render: (r) => (
                  <div>
                    <div>{fmtDate(r.published_at)}</div>
                    {r.collected_at && (
                      <div className="text-xs text-slate-400">
                        suivie depuis le {fmtDate(r.collected_at)}
                      </div>
                    )}
                  </div>
                ),
              }
            : { key: "published_at", label: "Publiée (CVE)", render: (r) => fmtDate(r.published_at) },
          // DEUX DATES DE « MISE À JOUR », qu'il ne faut jamais confondre :
          //
          //   updated_at            révision annoncée par la SOURCE (l'éditeur, le NVD) ;
          //   last_important_update moment où NOTRE collecte a constaté le changement.
          //
          // L'onglet « Mises à jour aujourd'hui » filtre sur la seconde et affichait la
          // première : une CVE détectée comme modifiée ce matin s'affichait « 13/08 », date
          // de la révision de l'éditeur. La liste paraissait montrer de vieilles mises à
          // jour, alors qu'elle montrait précisément ce qui avait bougé aujourd'hui.
          view === "updated_today"
            ? {
                key: "last_important_update",
                label: "Changement détecté",
                render: (r) => (
                  <div>
                    <div>{fmtDateTime(r.last_important_update)}</div>
                    {/* `change_summary` est une LISTE de champs modifiés. Rendue telle quelle,
                        React la concatène sans séparateur (« RéférencesScore »). */}
                    {(Array.isArray(r.change_summary) ? r.change_summary.length : r.change_summary) ? (
                      <div className="text-xs text-emerald-700">
                        {Array.isArray(r.change_summary) ? r.change_summary.join(" · ") : r.change_summary}
                      </div>
                    ) : null}
                    {r.updated_at && (
                      <div className="text-xs text-slate-400">
                        révision éditeur : {fmtDate(r.updated_at)}
                      </div>
                    )}
                  </div>
                ),
              }
            : { key: "updated_at", label: "Mise à jour", render: (r) => fmtDate(r.updated_at) },
          { key: "source", label: "Source" },
          {
            key: "actions",
            label: "",
            render: (r) => (
              <Link to={`/consultant/cves/${r.id}`} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100" title="Voir détail">
                <Eye size={16} />
              </Link>
            ),
          },
        ]}
        rows={loading ? [] : data.items}
        // UN TABLEAU VIDE DOIT SE JUSTIFIER. « Aucune CVE trouvée » ne dit pas si la journée
        // a été calme ou si la collecte a échoué — et le lecteur tranche presque toujours en
        // faveur de la panne. Chaque vue explique donc ce que son absence de résultat signifie.
        emptyLabel={loading ? "Chargement…" : EMPTY_LABELS[view]}
      />

      <div className="mt-4 flex items-center justify-between text-sm text-slate-500">
        <span>{data.total} CVE au total</span>
        <div className="flex items-center gap-3">
          <Button variant="secondary" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="px-3 py-1.5">
            Précédent
          </Button>
          <span>
            Page {page + 1} / {totalPages}
          </span>
          <Button variant="secondary" onClick={() => setPage((p) => p + 1)} disabled={page + 1 >= totalPages} className="px-3 py-1.5">
            Suivant
          </Button>
        </div>
      </div>
    </Layout>
  );
}
