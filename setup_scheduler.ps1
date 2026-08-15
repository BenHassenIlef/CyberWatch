# =====================================================================
#  CyberWatch AI - Installation de la TÂCHE PLANIFIÉE WINDOWS de collecte
#
#  Crée une tâche qui lance chaque jour `collect_once.py` (collecte CVE), INDÉPENDAMMENT
#  d'Uvicorn/FastAPI. La collecte ne dépend donc plus d'une fenêtre ouverte.
#
#  Usage :
#     .\setup_scheduler.ps1                 # installe la tâche (08:00 par défaut)
#     .\setup_scheduler.ps1 -Time 07:30     # heure personnalisée
#     .\setup_scheduler.ps1 -RunNow         # installe puis lance immédiatement (test)
#     .\setup_scheduler.ps1 -Uninstall      # supprime la tâche
#
#  NB : exécuter dans une console PowerShell (clic droit > Exécuter avec PowerShell).
#       Pour "run whether user is logged on or not" sans mot de passe, la tâche est
#       enregistrée en LogonType S4U pour l'utilisateur courant.
# =====================================================================
param(
    # Vide = heure LUE DANS L'APPLICATION (page Planification). Ne la forcez que pour un besoin
    # particulier : une heure figée ici finirait par diverger de l'echeance applicative, et la
    # tache s'executerait sans rien collecter.
    [string]$Time = "",
    [string]$TaskName = "CyberWatch AI - Daily CVE Collection",
    [switch]$RunNow,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root "app\backend\.venv\Scripts\python.exe"
$script = Join-Path $root "collect_once.py"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  CyberWatch AI - Tache planifiee de collecte" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# --- Désinstallation (schtasks : fonctionne sans elevation pour une tache par-utilisateur) ---
if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        & schtasks.exe /Delete /TN $TaskName /F | Out-Null
        Write-Host "[OK] Tache supprimee : $TaskName" -ForegroundColor Green
    } else {
        Write-Host "[i] Aucune tache nommee '$TaskName' a supprimer." -ForegroundColor Yellow
    }
    exit 0
}

# --- Vérifications ---
if (-not (Test-Path $python)) {
    Write-Host "[ERREUR] Interpreteur Python du venv introuvable :" -ForegroundColor Red
    Write-Host "         $python" -ForegroundColor Red
    Write-Host "         Cree le venv puis installe les dependances :" -ForegroundColor Yellow
    Write-Host "         python -m venv app\backend\.venv ; app\backend\.venv\Scripts\pip install -r app\backend\requirements.txt" -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $script)) {
    Write-Host "[ERREUR] collect_once.py introuvable : $script" -ForegroundColor Red
    exit 1
}

# --- Heure planifiée : ALIGNÉE SUR L'APPLICATION ---
# `collect_once.py` ne collecte que si l'echeance applicative est ECHUE. Une tache declenchee
# AVANT cette heure ne collecte donc RIEN, sans erreur ni message : la collecte automatique
# n'a simplement jamais lieu. On lit donc l'heure directement dans l'application.
if (-not $Time) {
    # NB PowerShell 5.1 : ni « 2>$null » (qui corrompt le code de retour d'un exe natif), ni
    # « | Select-Object -First 1 » (qui interrompt le pipeline et fausse $LASTEXITCODE) avant
    # d'avoir releve le code. On capture donc la sortie brute, PUIS on lit le code.
    $out = & $python $script --print-schedule
    $rc = $LASTEXITCODE
    $first = @($out)[0]
    if ($rc -ne 0 -or -not $first) {
        Write-Host "[ERREUR] Impossible de lire l'heure de planification dans l'application." -ForegroundColor Red
        Write-Host "         MongoDB est-il demarre ? Sinon, forcez l'heure : -Time 10:00" -ForegroundColor Yellow
        exit 1
    }
    $Time = ([string]$first).Trim()
    Write-Host "-> Heure lue dans l'application (page Planification) : $Time" -ForegroundColor Green
}
try { $at = [DateTime]::ParseExact($Time, "HH:mm", $null) }
catch { Write-Host "[ERREUR] Heure invalide '$Time' (format attendu HH:mm, ex. 10:00)." -ForegroundColor Red; exit 1 }

Write-Host "-> Projet     : $root"
Write-Host "-> Python     : $python"
Write-Host "-> Script     : collect_once.py"
Write-Host "-> Heure      : $Time (tous les jours)"
Write-Host "-> Rattrapage : si le PC est eteint a l'heure prevue, execution des que possible."

# --- Élévation (admin) ? Détermine le LogonType : S4U (connecté ou non) si admin, sinon Interactive.
$isAdmin = ([System.Security.Principal.WindowsPrincipal] `
    [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
$userId = "$env:USERDOMAIN\$env:USERNAME"
if ($isAdmin) {
    $logonType = "S4U"; $runLevel = "HighestAvailable"
    Write-Host "-> Mode       : ADMIN -> S4U (s'execute que l'utilisateur soit connecte ou non)."
} else {
    $logonType = "InteractiveToken"; $runLevel = "LeastPrivilege"
    Write-Host "-> Mode       : standard -> Interactive (s'execute quand '$userId' est connecte)."
    Write-Host "                (Pour 'connecte ou non', relance ce script dans une PowerShell ADMIN.)" -ForegroundColor Gray
}

# --- Enregistrement via XML + schtasks : robuste aux espaces dans les chemins et NE requiert PAS
#     d'elevation pour une tache par-utilisateur (contrairement a Register-ScheduledTask).
$startBoundary = (Get-Date).Date.AddDays(1).ToString("yyyy-MM-dd") + "T" + $Time + ":00"
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Collecte quotidienne des CVE (CyberWatch AI), independante d'Uvicorn.</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$startBoundary</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$userId</UserId>
      <LogonType>$logonType</LogonType>
      <RunLevel>$runLevel</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowHardTerminate>true</AllowHardTerminate>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT5M</Interval><Count>2</Count></RestartOnFailure>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$python</Command>
      <Arguments>"$script"</Arguments>
      <WorkingDirectory>$root</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$xmlPath = Join-Path $env:TEMP "cyberwatch_task.xml"
$xml | Out-File -FilePath $xmlPath -Encoding Unicode
& schtasks.exe /Create /TN $TaskName /XML "$xmlPath" /F | Out-Null
$code = $LASTEXITCODE
Remove-Item $xmlPath -ErrorAction SilentlyContinue
if ($code -ne 0 -or -not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    Write-Host "[ERREUR] Enregistrement de la tache echoue (schtasks code=$code)." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Tache enregistree : $TaskName" -ForegroundColor Green

# --- VERIFICATION REELLE ---------------------------------------------------------------
# Une tache « enregistree » n'est pas une tache « fonctionnelle » : celle installee auparavant
# existait bel et bien, mais pointait vers un dossier ou `collect_once.py` etait absent, et
# echouait donc chaque jour avec le code 2 sans que rien ne le signale. On controle donc ce
# que la tache va REELLEMENT executer.
Write-Host "-> Verification de la tache installee..." -ForegroundColor Cyan
$task = Get-ScheduledTask -TaskName $TaskName
$act  = $task.Actions | Select-Object -First 1
$ok   = $true

if (-not (Test-Path $act.Execute)) {
    Write-Host "   [KO] Interpreteur inexistant : $($act.Execute)" -ForegroundColor Red; $ok = $false
} else { Write-Host "   [OK] Interpreteur     : $($act.Execute)" -ForegroundColor Green }

$argPath = $act.Arguments.Trim('"')
if (-not (Test-Path $argPath)) {
    Write-Host "   [KO] Script inexistant : $argPath" -ForegroundColor Red; $ok = $false
} else { Write-Host "   [OK] Script           : $argPath" -ForegroundColor Green }

if (-not (Test-Path $act.WorkingDirectory)) {
    Write-Host "   [KO] Dossier de travail inexistant : $($act.WorkingDirectory)" -ForegroundColor Red; $ok = $false
} else { Write-Host "   [OK] Dossier de travail: $($act.WorkingDirectory)" -ForegroundColor Green }

# Le venv peut provenir d'une autre machine (pyvenv.cfg pointant vers un Python absent).
& $python -c "import app.backend.main" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "   [KO] Le venv n'importe pas l'application (pyvenv.cfg invalide ?)" -ForegroundColor Red; $ok = $false
} else { Write-Host "   [OK] venv             : application importable" -ForegroundColor Green }

if (-not $ok) {
    Write-Host "[ERREUR] La tache est enregistree mais NE POURRA PAS s'executer." -ForegroundColor Red
    exit 1
}

Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  RAPPEL : garde COLLECTION_TRIGGER=external dans app\backend\.env" -ForegroundColor White
Write-Host "           (sinon le scheduler interne de FastAPI collecterait AUSSI)." -ForegroundColor Gray
Write-Host "  Journal de collecte : logs\collect_once.log" -ForegroundColor Gray
Write-Host "  Verifier la tache   : Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host "  Lancer manuellement : Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host "------------------------------------------------------" -ForegroundColor Cyan

if ($RunNow) {
    Write-Host "-> Lancement immediat (test)..." -ForegroundColor Green
    Start-ScheduledTask -TaskName $TaskName
    # Une collecte dure plusieurs minutes : on attend que la tache QUITTE l'etat Running
    # plutot que de lire un resultat encore provisoire.
    $deadline = (Get-Date).AddMinutes(20)
    do {
        Start-Sleep -Seconds 10
        $st = (Get-ScheduledTask -TaskName $TaskName).State
    } while ($st -eq "Running" -and (Get-Date) -lt $deadline)

    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Host ("   LastRunTime    : " + $info.LastRunTime)
    Write-Host ("   LastTaskResult : " + $info.LastTaskResult)
    switch ($info.LastTaskResult) {
        0       { Write-Host "   [OK] Collecte executee avec succes." -ForegroundColor Green }
        2       { Write-Host "   [KO] Code 2 : fichier introuvable (chemin de la tache errone)." -ForegroundColor Red }
        1       { Write-Host "   [KO] Code 1 : echeance NON honoree (voir logs\collect_once.log)." -ForegroundColor Red }
        267009  { Write-Host "   [i] Tache encore en cours d'execution." -ForegroundColor Yellow }
        default { Write-Host "   [KO] Code inattendu : $($info.LastTaskResult)" -ForegroundColor Red }
    }
    Write-Host "   Journal detaille : logs\collect_once.log" -ForegroundColor Gray
}
