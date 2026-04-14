# Szybki restart API

Write-Host "Zatrzymywanie API..." -ForegroundColor Yellow
.\scripts\kill_port.ps1

Start-Sleep -Seconds 2

Write-Host "`nUruchamianie API..." -ForegroundColor Green
.\scripts\run_api.ps1

