# =====================================================================
#  CyberWatch AI - Installation "une fois pour toutes"
#
#  Installe les DEUX taches planifiees necessaires a un fonctionnement
#  autonome, puis verifie que tout est operationnel :
#
#    1. BACKEND       : demarre a l'ouverture de session et reste actif
#                       (sert l'API au frontend). Ne collecte PAS.
#    2. COLLECTE      : lance chaque jour collect_once.py, INDEPENDAMMENT
#                       du backend (delegue a setup_scheduler.ps1).
#
#  POURQUOI DEUX TACHES ?
#  Le projet fonctionne en COLLECTION_TRIGGER=external : le planificateur
#  interne de FastAPI est volontairement DESACTIVE, pour que la collecte
#  ne depende pas d'une fenetre Uvicorn ouverte. Enregistrer le backend
#  seul ne declenche donc AUCUNE collecte -- d'ou la seconde tache.
#
#  Usage (une seule fois) :  clic droit > Executer avec PowerShell
#     .\install-daily-collection.ps1                # collecte a 08:00
#     .\install-daily-collection.ps1 -Time 07:30    # heure personnalisee
#     .\install-daily-collection.ps1 -Uninstall     # retire les deux taches
# =====================================================================
param(
    [string]$Time = "08:00",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$python     = Join-Path $root "app\backend\.venv\Scripts\python.exe"
$collect    = Join-Path $root "collect_once.py"
$setup      = Join-Path $root "setup_scheduler.ps1"
$backendTask = "CyberWatchAI-Backend"
$collectTask = "CyberWatch AI - Daily CVE Collection"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  CyberWatch AI - Installation automatique" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# --------------------------------------------------------------- Desinstallation
if ($Uninstall) {
    foreach ($t in @($backendTask, $collectTask)) {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            & schtasks.exe /Delete /TN $t /F | Out-Null
            Write-Host "[OK] Tache supprimee : $t" -ForegroundColor Green
        } else {
            Write-Host "[i] Aucune tache '$t'." -ForegroundColor Yellow
        }
    }
    exit 0
}

# --------------------------------------------------------------- Verifications
if (-not (Test-Path $python)) {
    Write-Host "[ERREUR] venv backend introuvable : $python" -ForegroundColor Red
    Write-Host "         Creez-le : python -m venv app\backend\.venv" -ForegroundColor Yellow
    Write-Host "         puis     : app\backend\.venv\Scripts\pip install -r app\backend\requirements.txt" -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $collect)) {
    Write-Host "[ERREUR] collect_once.py introuvable : $collect" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $setup)) {
    Write-Host "[ERREUR] setup_scheduler.ps1 introuvable : $setup" -ForegroundColor Red
    exit 1
}
Write-Host "-> Projet : $root"

# Le venv peut avoir ete copie depuis une AUTRE machine : son pyvenv.cfg pointerait alors
# vers un interpreteur inexistant, et la tache echouerait chaque jour sans explication.
& $python -c "import app.backend.main" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERREUR] Le venv ne parvient pas a importer l'application." -ForegroundColor Red
    Write-Host "         Verifiez app\backend\.venv\pyvenv.cfg (chemin 'home' valide ?)" -ForegroundColor Yellow
    exit 1
}
Write-Host "-> venv   : OK (application importable)" -ForegroundColor Green

# --------------------------------------------------------------- Tache OBSOLETE ?
# Une installation precedente a pu enregistrer une tache pointant vers un AUTRE dossier
# (projet deplace ou duplique). Elle echouerait indefiniment avec le code 2 (fichier
# introuvable) sans que rien ne l'indique. On la detecte et on la signale avant de l'ecraser.
$existing = Get-ScheduledTask -TaskName $collectTask -ErrorAction SilentlyContinue
if ($existing) {
    $cmd = ($existing.Actions | Select-Object -First 1).Execute
    if ($cmd -and -not $cmd.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "[!] Tache existante pointant vers un AUTRE dossier :" -ForegroundColor Yellow
        Write-Host "    $cmd" -ForegroundColor Yellow
        Write-Host "    Elle sera remplacee par ce projet." -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------- 1) Tache BACKEND
$action = New-ScheduledTaskAction -Execute $python `
    -Argument "-m uvicorn app.backend.main:app --host 127.0.0.1 --port 8000" `
    -WorkingDirectory $root
$atLogon  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $backendTask -Action $action -Trigger $atLogon -Settings $settings `
    -Description "CyberWatch AI - backend API (toujours actif). Ne collecte pas." -Force | Out-Null
Write-Host "[OK] Tache backend enregistree : $backendTask" -ForegroundColor Green

# --------------------------------------------------------------- 2) Tache COLLECTE
# Deleguee a setup_scheduler.ps1 : c'est lui qui detient la definition XML de la tache
# (rattrapage si PC eteint, politique de reprise, LogonType). Ne pas la dupliquer ici.
Write-Host "-> Installation de la tache de collecte (delegation a setup_scheduler.ps1)..." -ForegroundColor Cyan
& $setup -Time $Time -TaskName $collectTask
# On verifie le RESULTAT (la tache pointe-t-elle bien vers ce projet ?) plutot que le code de
# sortie : setup_scheduler.ps1 ne positionne pas explicitement $LASTEXITCODE en cas de succes.
$created = Get-ScheduledTask -TaskName $collectTask -ErrorAction SilentlyContinue
if (-not $created) {
    Write-Host "[ERREUR] La tache de collecte n'a pas ete creee." -ForegroundColor Red
    exit 1
}
$createdCmd = ($created.Actions | Select-Object -First 1).Execute
if (-not $createdCmd.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host "[ERREUR] La tache pointe vers $createdCmd au lieu de ce projet." -ForegroundColor Red
    exit 1
}

# --------------------------------------------------------------- Coherence .env
# COLLECTION_TRIGGER=internal ferait collecter le backend EN PLUS de la tache -> doublons.
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    $envTrigger = (Select-String -Path $envFile -Pattern '^\s*COLLECTION_TRIGGER\s*=\s*(\S+)' `
                   -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($envTrigger -and $envTrigger.Matches[0].Groups[1].Value -eq "internal") {
        Write-Host "[!] .env contient COLLECTION_TRIGGER=internal : le backend collecterait AUSSI." -ForegroundColor Yellow
        Write-Host "    Mettez 'external' (ou retirez la ligne) pour eviter les collectes en double." -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------- Demarrage + verification
Start-ScheduledTask -TaskName $backendTask
Start-Sleep -Seconds 6
$code = try { (Invoke-WebRequest "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 5).StatusCode } catch { 0 }
if ($code -eq 200) {
    Write-Host "[OK] Backend ACTIF sur http://127.0.0.1:8000" -ForegroundColor Green
} else {
    Write-Host "[!] Backend pas encore joignable (demarrage en cours ?)." -ForegroundColor Yellow
    Write-Host "    Verifiez que le port 8000 n'est pas deja occupe." -ForegroundColor Gray
}

$info = Get-ScheduledTaskInfo -TaskName $collectTask -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  RECAPITULATIF" -ForegroundColor White
Write-Host "    Backend  : $backendTask (a chaque ouverture de session)"
Write-Host "    Collecte : $collectTask (tous les jours a $Time)"
if ($info) { Write-Host ("    Prochaine collecte : " + $info.NextRunTime) }
Write-Host ""
Write-Host "  Frontend (a lancer a part) :" -ForegroundColor Gray
Write-Host "    cd app\frontend ; npm run dev -- --port 5173 --strictPort" -ForegroundColor Gray
Write-Host "  Journal de collecte : logs\collect_once.log" -ForegroundColor Gray
Write-Host "  Test immediat       : Start-ScheduledTask -TaskName '$collectTask'" -ForegroundColor Gray
Write-Host "  Desinstaller        : .\install-daily-collection.ps1 -Uninstall" -ForegroundColor Gray
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
