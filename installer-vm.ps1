# =====================================================================================
#  CyberWatch AI — Installation sur une machine Windows neuve
#
#      .\installer-vm.ps1
#
#  À lancer UNE FOIS après avoir décompressé l'archive. Le script vérifie les logiciels
#  requis, installe les dépendances, prépare la configuration et propose de démarrer.
#
#  Il ne détruit rien : un `.env` déjà présent n'est jamais écrasé, et une dépendance
#  déjà installée n'est pas réinstallée.
# =====================================================================================

$ErrorActionPreference = "Stop"
$racine = $PSScriptRoot
Set-Location $racine

function Titre($texte) {
    Write-Host ""
    Write-Host "  $texte" -ForegroundColor Cyan
    Write-Host "  $('-' * 66)" -ForegroundColor DarkGray
}
function Bon($texte)     { Write-Host "  [OK]     $texte" -ForegroundColor Green }
function Manque($texte)  { Write-Host "  [MANQUE] $texte" -ForegroundColor Red }
function Note($texte)    { Write-Host "           $texte" -ForegroundColor DarkGray }

# -------------------------------------------------------------------------------------
Titre "1. Logiciels requis"
# -------------------------------------------------------------------------------------
#
# On VÉRIFIE avant d'installer quoi que ce soit. Découvrir qu'il manque Node au milieu
# d'une installation laisse la machine à moitié préparée, sans dire où reprendre.

$bloquant = $false

$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $version = (& python --version 2>&1) -replace 'Python\s+', ''
    # Comparaison sur MAJEUR.MINEUR uniquement : « 3.14.3 » et « 3.11.9 » se comparent mal
    # en chaîne (« 3.9 » passerait pour supérieur à « 3.11 »), et le correctif de version
    # n'entre pas dans la décision.
    $morceaux = $version.Trim() -split '\.'
    $majeur = [int]$morceaux[0]
    $mineur = [int]$morceaux[1]
    if ($majeur -gt 3 -or ($majeur -eq 3 -and $mineur -ge 11)) {
        Bon "Python $version"
    } else {
        Manque "Python $version — la version 3.11 ou superieure est requise"
        $bloquant = $true
    }
} else {
    Manque "Python absent"
    Note "https://www.python.org/downloads/  — cocher « Add python.exe to PATH »"
    $bloquant = $true
}

$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) { Bon "Node $(& node --version)" }
else {
    Manque "Node.js absent"
    Note "https://nodejs.org/  — version LTS"
    $bloquant = $true
}

# MongoDB peut tourner ailleurs : on teste le PORT, pas le service local. Une base
# distante est un choix légitime, et exiger un service local le refuserait à tort.
$mongo = Test-NetConnection -ComputerName 127.0.0.1 -Port 27017 -InformationLevel Quiet `
         -WarningAction SilentlyContinue
if ($mongo) { Bon "MongoDB répond sur 127.0.0.1:27017" }
else {
    Manque "MongoDB ne répond pas sur le port 27017"
    Note "https://www.mongodb.com/try/download/community  — cocher « Install as a Service »"
    Note "Si votre base est ailleurs, renseignez MONGO_URI dans .env et ignorez cet avis."
}

if ($bloquant) {
    Write-Host ""
    Write-Host "  Installez les logiciels manquants, puis relancez ce script." -ForegroundColor Yellow
    exit 1
}

# -------------------------------------------------------------------------------------
Titre "2. Dépendances du backend"
# -------------------------------------------------------------------------------------

$venv = Join-Path $racine "app\backend\.venv"
if (Test-Path "$venv\Scripts\python.exe") {
    Bon "Environnement Python déjà présent"
} else {
    Write-Host "  Création de l'environnement Python…"
    & python -m venv $venv
    Bon "Environnement créé"
}

$py = "$venv\Scripts\python.exe"
Write-Host "  Installation des paquets (quelques minutes)…"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r "app\backend\requirements.txt"
Bon "Paquets installés"

# Chromium sert au rendu des portails en JavaScript ET à l'export PDF des bulletins.
# Sans lui, ces deux fonctions échouent — et l'échec ressemble à une panne réseau.
Write-Host "  Installation du navigateur Chromium (première fois : ~150 Mo)…"
& $py -m playwright install chromium 2>&1 | Out-Null
Bon "Chromium installé"

# -------------------------------------------------------------------------------------
Titre "3. Dépendances du frontend"
# -------------------------------------------------------------------------------------

Push-Location "app\frontend"
if (Test-Path "node_modules") {
    Bon "Dépendances déjà présentes"
} else {
    Write-Host "  Installation (quelques minutes)…"
    & npm install --silent
    Bon "Dépendances installées"
}
Pop-Location

# -------------------------------------------------------------------------------------
Titre "4. Configuration"
# -------------------------------------------------------------------------------------

if (Test-Path ".env") {
    Bon "Fichier .env déjà présent — laissé intact"
} else {
    Copy-Item ".env.docker.example" ".env"
    Bon "Fichier .env créé depuis le modèle"

    # SECRET DE SESSION — le seul réglage dont l'oubli est une faille, pas une gêne.
    # Laisser la valeur d'exemple permet à quiconque lit le dépôt de forger un jeton
    # administrateur. On le génère donc d'office.
    $secret = & $py -c "import secrets; print(secrets.token_urlsafe(64))"
    (Get-Content ".env") -replace '^JWT_SECRET=.*', "JWT_SECRET=$secret" |
        Set-Content ".env" -Encoding UTF8
    Bon "Secret de session généré"

    Write-Host ""
    Write-Host "  À COMPLÉTER dans .env :" -ForegroundColor Yellow
    Note "LLM_API_KEY        clé de l'assistant IA"
    Note "MONGO_URI          si la base n'est pas sur cette machine"
    Note "SCHEDULER_TIMEZONE Africa/Tunis  ou  Europe/Paris"
    Note "SMTP_*             ou lancez  .\app\backend\.venv\Scripts\python.exe configurer_smtp.py"
}

# -------------------------------------------------------------------------------------
Titre "5. Vérification"
# -------------------------------------------------------------------------------------

$env:PYTHONPATH = $racine
$verif = & $py -c @"
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from app.backend.core.config import settings, FICHIER_ENV
print('config lue depuis|' + str(FICHIER_ENV))
print('base de donnees|' + settings.MONGO_URI)
print('assistant IA|' + ('configure' if settings.LLM_API_KEY else 'NON configure'))
print('courriels|' + ('configures' if settings.SMTP_PASSWORD else 'NON configures'))
"@ 2>&1

foreach ($ligne in $verif) {
    if ($ligne -match '\|') {
        $parties = $ligne -split '\|', 2
        Write-Host ("  {0,-20} {1}" -f $parties[0], $parties[1])
    }
}

# -------------------------------------------------------------------------------------
Titre "Installation terminée"
# -------------------------------------------------------------------------------------

Write-Host "  Démarrer l'application :" -ForegroundColor Green
Note ".\start.ps1"
Write-Host ""
Write-Host "  Configurer l'envoi de courriels :" -ForegroundColor Green
Note ".\app\backend\.venv\Scripts\python.exe configurer_smtp.py"
Write-Host ""
Write-Host "  Planifier la collecte quotidienne :" -ForegroundColor Green
Note ".\install-daily-collection.ps1        (en tant qu'administrateur)"
Write-Host ""
