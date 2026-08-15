import { Component } from "react";

// Capture toute erreur de rendu React et affiche un message au lieu d'une PAGE BLANCHE.
// Sans cette barrière, une exception non gérée pendant le rendu démonte tout l'arbre React
// (écran entièrement blanc, sans en-tête ni navigation).
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Trace visible dans la console du navigateur pour le diagnostic.
    console.error("Erreur de rendu capturée par ErrorBoundary :", error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 p-6">
        <div className="max-w-lg rounded-2xl border border-rose-100 bg-white p-8 text-center shadow-sm">
          <h1 className="text-lg font-semibold text-rose-600">Une erreur est survenue</h1>
          <p className="mt-2 text-sm text-slate-600">
            L'affichage de cette page a rencontré un problème. Vous pouvez recharger la page ;
            si le problème persiste, contactez l'administrateur.
          </p>
          <pre className="mt-4 max-h-40 overflow-auto rounded-lg bg-slate-50 p-3 text-left text-xs text-slate-500">
            {String(this.state.error?.message || this.state.error)}
          </pre>
          <div className="mt-5 flex justify-center gap-2">
            <button
              onClick={() => this.setState({ error: null })}
              className="rounded-xl border border-slate-200 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50"
            >
              Réessayer
            </button>
            <button
              onClick={() => window.location.reload()}
              className="rounded-xl bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
            >
              Recharger la page
            </button>
          </div>
        </div>
      </div>
    );
  }
}
