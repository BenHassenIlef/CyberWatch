# =====================================================================
#  CyberWatch AI - Lanceur unique (backend + frontend)
#  Usage :  clic droit > "Exécuter avec PowerShell"   OU   .\start.ps1
# =====================================================================
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = Join-Path $root "app\backend\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "[ERREUR] venv backend introuvable : $python" -ForegroundColor Red
    Write-Host "         Cree-le puis : pip install -r app\backend\requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  CyberWatch AI - demarrage" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# --- Verification rapide de MongoDB (localhost:27017) ---
$mongoOk = Test-NetConnection -ComputerName localhost -Port 27017 -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $mongoOk) {
    Write-Host "[ATTENTION] MongoDB ne repond pas sur localhost:27017." -ForegroundColor Yellow
    Write-Host "            Demarre MongoDB avant de continuer (le backend en a besoin)." -ForegroundColor Yellow
}

# --- 1) Backend (FastAPI / uvicorn) dans une nouvelle fenetre ---
Write-Host "-> Backend  : http://127.0.0.1:8000  (docs: /docs)" -ForegroundColor Green
Start-Process -FilePath $python `
    -ArgumentList "-m","uvicorn","app.backend.main:app","--host","127.0.0.1","--port","8000" `
    -WorkingDirectory $root -WindowStyle Normal

# --- 2) Frontend (Vite / React) dans une nouvelle fenetre ---
Write-Host "-> Frontend : http://localhost:5173" -ForegroundColor Green
Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/k","npm run dev" `
    -WorkingDirectory (Join-Path $root "app\frontend") -WindowStyle Normal

Start-Sleep -Seconds 8

# --- Verification ---
function Test-Url($url) {
    try { (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 4).StatusCode } catch { 0 }
}
$b = Test-Url "http://127.0.0.1:8000/docs"
$f = Test-Url "http://localhost:5173/"
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host ("  Backend  : " + $(if ($b -eq 200) {"OK (200)"} else {"pas encore pret ($b)"})) -ForegroundColor $(if ($b -eq 200) {"Green"} else {"Yellow"})
Write-Host ("  Frontend : " + $(if ($f -eq 200) {"OK (200)"} else {"pas encore pret ($f)"})) -ForegroundColor $(if ($f -eq 200) {"Green"} else {"Yellow"})
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  Ouvre :  http://localhost:5173" -ForegroundColor White
Write-Host "     Admin      -> /admin/signin" -ForegroundColor Gray
Write-Host "     Consultant -> /consultant/signin" -ForegroundColor Gray
Write-Host "  (Ferme les 2 fenetres ouvertes pour arreter le projet.)" -ForegroundColor Gray
Write-Host "======================================================" -ForegroundColor Cyan
