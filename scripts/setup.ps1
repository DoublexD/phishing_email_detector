# Setup script dla Email Spoofing Detector - Windows PowerShell

Write-Host "=== Email Spoofing Detector Setup ===" -ForegroundColor Cyan

# Sprawdź wersję Python
Write-Host "`nSprawdzanie wersji Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host $pythonVersion -ForegroundColor Green
} catch {
    Write-Host "BŁĄD: Python nie jest zainstalowany lub nie jest w PATH" -ForegroundColor Red
    Write-Host "Pobierz Python z: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Utwórz środowisko wirtualne
Write-Host "`nTworzenie środowiska wirtualnego..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Środowisko wirtualne już istnieje, pomijam..." -ForegroundColor Yellow
} else {
    python -m venv venv
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Środowisko wirtualne utworzone pomyślnie" -ForegroundColor Green
    } else {
        Write-Host "BŁĄD: Nie udało się utworzyć środowiska wirtualnego" -ForegroundColor Red
        exit 1
    }
}

# Aktywuj środowisko wirtualne
Write-Host "`nAktywacja środowiska wirtualnego..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Aktualizuj pip
Write-Host "`nAktualizacja pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip setuptools wheel

# Instalacja zależności
Write-Host "`nInstalacja zależności..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "Zależności zainstalowane pomyślnie" -ForegroundColor Green
} else {
    Write-Host "BŁĄD: Instalacja zależności nie powiodła się" -ForegroundColor Red
    exit 1
}

# Utwórz katalogi
Write-Host "`nTworzenie katalogów..." -ForegroundColor Yellow
$directories = @("data\raw", "data\processed", "data\sample_emails", "models", "logs")
foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host "Katalogi utworzone" -ForegroundColor Green

# Kopiuj przykładową konfigurację
Write-Host "`nTworzenie pliku konfiguracyjnego..." -ForegroundColor Yellow
if (-not (Test-Path "config\config.yaml")) {
    Copy-Item "config\config.yaml.example" "config\config.yaml"
    Write-Host "Plik config\config.yaml utworzony" -ForegroundColor Green
    Write-Host "UWAGA: Proszę edytować config\config.yaml z własnymi ustawieniami" -ForegroundColor Yellow
} else {
    Write-Host "config\config.yaml już istnieje, pomijam..." -ForegroundColor Yellow
}

Write-Host "`n=== Setup Zakończony ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Następne kroki:" -ForegroundColor Green
Write-Host "1. Aktywuj środowisko: .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "2. Edytuj konfigurację: config\config.yaml" -ForegroundColor White
Write-Host "3. Przygotuj dane treningowe w: data\processed\" -ForegroundColor White
Write-Host "4. Wytrenuj modele: .\scripts\train_models.ps1" -ForegroundColor White
Write-Host "5. Uruchom API: .\scripts\run_api.ps1" -ForegroundColor White
Write-Host "6. Otwórz frontend: Start-Process frontend\index.html" -ForegroundColor White
Write-Host ""

