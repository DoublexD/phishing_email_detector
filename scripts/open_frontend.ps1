# Script to open frontend - Windows PowerShell

Write-Host "Otwieranie panelu frontend..." -ForegroundColor Cyan

# Sprawdź czy plik istnieje
if (-not (Test-Path "frontend\index.html")) {
    Write-Host "BŁĄD: frontend\index.html nie istnieje!" -ForegroundColor Red
    exit 1
}

# Sprawdź czy API działa
Write-Host "Sprawdzanie czy API działa..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 2 -ErrorAction Stop
    Write-Host "✓ API działa prawidłowo" -ForegroundColor Green
} catch {
    Write-Host "⚠ UWAGA: API nie odpowiada na http://localhost:8000" -ForegroundColor Yellow
    Write-Host "Frontend może nie działać poprawnie bez uruchomionego API" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Aby uruchomić API, wykonaj:" -ForegroundColor Cyan
    Write-Host ".\scripts\run_api.ps1" -ForegroundColor White
    Write-Host ""
    $continue = Read-Host "Czy chcesz kontynuować? (t/n)"
    if ($continue -ne "t") {
        exit 0
    }
}

# Otwórz frontend
Write-Host ""
Write-Host "Otwieranie frontend w domyślnej przeglądarce..." -ForegroundColor Green
Start-Process "frontend\index.html"

Write-Host ""
Write-Host "Frontend powinien się otworzyć w przeglądarce" -ForegroundColor Green
Write-Host "Jeśli chcesz użyć serwera HTTP zamiast pliku lokalnego:" -ForegroundColor Yellow
Write-Host "  cd frontend" -ForegroundColor White
Write-Host "  python -m http.server 8080" -ForegroundColor White
Write-Host "  Start-Process http://localhost:8080" -ForegroundColor White

