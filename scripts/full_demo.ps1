# Full Demo Script - od danych po uruchomienie systemu
# Uruchom: .\scripts\full_demo.ps1

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Email Spoofing Detector - Full Demo Pipeline"  -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Sprawdz srodowisko
if (-not (Test-Path "venv\Scripts\Activate.ps1")) {
    Write-Host "BLAD: Brak srodowiska wirtualnego. Uruchom: .\scripts\setup.ps1" -ForegroundColor Red
    exit 1
}

& ".\venv\Scripts\Activate.ps1"
$env:PYTHONPATH = "$PWD\src;$env:PYTHONPATH"

# Krok 1: Przygotowanie danych
Write-Host "[1/4] Przygotowanie zbioru danych..." -ForegroundColor Yellow
if (-not (Test-Path "data\processed\training_data.csv")) {
    python scripts\prepare_dataset.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BLAD: Nie udalo sie przygotowac danych." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  -> training_data.csv juz istnieje, pomijam." -ForegroundColor Green
}
Write-Host ""

# Krok 2: Trening modeli
Write-Host "[2/4] Trening modeli ML..." -ForegroundColor Yellow
if (-not (Test-Path "models\random_forest_classifier.joblib")) {
    python src\ml_models\train.py --data data\processed\training_data.csv --target is_phishing --models-dir models
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BLAD: Trening nie powiodl sie." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  -> Modele juz istnieja, pomijam trening." -ForegroundColor Green
}
Write-Host ""

# Krok 3: Uruchomienie API
Write-Host "[3/4] Uruchamianie API na http://localhost:8000 ..." -ForegroundColor Yellow
Write-Host "  Dokumentacja Swagger: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""

# Krok 4: Otworz frontend
Write-Host "[4/4] Otwieranie frontendu..." -ForegroundColor Yellow
Start-Process "frontend\index.html"
Write-Host ""

Write-Host "================================================" -ForegroundColor Green
Write-Host "  System gotowy! Nacisnij Ctrl+C aby zatrzymac." -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""

python -m uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload --reload-dir "$PWD\src"
