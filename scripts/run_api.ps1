# Script to run the API - Windows PowerShell

Write-Host "Starting Email Spoofing Detector API..." -ForegroundColor Cyan

# Sprawdź czy środowisko wirtualne istnieje
if (-not (Test-Path "venv\Scripts\Activate.ps1")) {
    Write-Host "BŁĄD: Środowisko wirtualne nie istnieje!" -ForegroundColor Red
    Write-Host "Uruchom najpierw: .\scripts\setup.ps1" -ForegroundColor Yellow
    exit 1
}

# Aktywuj środowisko wirtualne
Write-Host "Aktywacja środowiska wirtualnego..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Ustaw PYTHONPATH
$env:PYTHONPATH = "$PWD\src;$env:PYTHONPATH"

# Uruchom API z katalogu projektu (żeby działał config/config.yaml i ścieżki względne)
Write-Host "Uruchamianie API..." -ForegroundColor Green
Write-Host "API będzie dostępne pod: http://localhost:8000" -ForegroundColor Cyan
Write-Host "Dokumentacja: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Naciśnij Ctrl+C aby zatrzymać serwer" -ForegroundColor Yellow
Write-Host ""

python -m uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload --reload-dir "$PWD\src"

