# Script to train models - Windows PowerShell

Write-Host "Training Email Spoofing Detection Models..." -ForegroundColor Cyan

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

# Sprawdź czy istnieją dane treningowe
if (-not (Test-Path "data\processed\training_data.csv")) {
    Write-Host "BŁĄD: Dane treningowe nie znalezione: data\processed\training_data.csv" -ForegroundColor Red
    Write-Host "Proszę najpierw przygotować zbiór danych." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Możesz utworzyć przykładowy zbiór danych używając:" -ForegroundColor Yellow
    Write-Host "python -c ""import pandas as pd; pd.DataFrame().to_csv('data\processed\training_data.csv')""" -ForegroundColor White
    exit 1
}

# Uruchom trening
Write-Host "Uruchamianie treningu modeli..." -ForegroundColor Green
python src\ml_models\train.py `
    --data data\processed\training_data.csv `
    --target is_phishing `
    --test-size 0.2 `
    --models-dir models

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Trening zakończony pomyślnie!" -ForegroundColor Green
    Write-Host "Modele zapisane w: models\" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Możesz teraz uruchomić API:" -ForegroundColor Yellow
    Write-Host ".\scripts\run_api.ps1" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "BŁĄD: Trening nie powiódł się!" -ForegroundColor Red
    exit 1
}

