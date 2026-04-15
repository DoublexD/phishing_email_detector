# Script to run tests - Windows PowerShell

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("unit", "performance", "all")]
    [string]$TestType = "unit"
)

Write-Host "Running Tests..." -ForegroundColor Cyan

# Sprawdź czy środowisko wirtualne istnieje
if (-not (Test-Path "venv\Scripts\Activate.ps1")) {
    Write-Host "BŁĄD: Środowisko wirtualne nie istnieje!" -ForegroundColor Red
    Write-Host "Uruchom najpierw: .\scripts\setup.ps1" -ForegroundColor Yellow
    exit 1
}

# Aktywuj środowisko wirtualne
& ".\venv\Scripts\Activate.ps1"

# Ustaw PYTHONPATH
$env:PYTHONPATH = "$PWD\src;$env:PYTHONPATH"

switch ($TestType) {
    "unit" {
        Write-Host "Uruchamianie testów jednostkowych..." -ForegroundColor Yellow
        pytest tests\ -v --cov=src --cov-report=html
    }
    "performance" {
        Write-Host "Uruchamianie testów wydajności..." -ForegroundColor Yellow
        pytest tests\performance\benchmark_tests.py --benchmark-only
    }
    "all" {
        Write-Host "Uruchamianie wszystkich testów..." -ForegroundColor Yellow
        pytest tests\ -v --cov=src --cov-report=html
        Write-Host ""
        Write-Host "Uruchamianie testów wydajności..." -ForegroundColor Yellow
        pytest tests\performance\benchmark_tests.py --benchmark-only
    }
}

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Testy zakończone pomyślnie!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Niektóre testy nie powiodły się!" -ForegroundColor Red
    exit 1
}

