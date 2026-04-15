# Kill process on specific port

param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8000
)

Write-Host "Szukanie procesu na porcie $Port..." -ForegroundColor Yellow

# Znajdź PID procesu używającego portu
$netstatOutput = netstat -ano | Select-String ":$Port"

if ($netstatOutput) {
    $lines = $netstatOutput -split "`n"
    foreach ($line in $lines) {
        if ($line -match "LISTENING") {
            # Wyciągnij PID (ostatnia kolumna)
            $processId = ($line -split '\s+')[-1]
            
            if ($processId -and $processId -match '^\d+$') {
                Write-Host "Znaleziono proces PID: $processId na porcie $Port" -ForegroundColor Cyan
                
                try {
                    Stop-Process -Id $processId -Force
                    Write-Host "✓ Proces $processId został zatrzymany" -ForegroundColor Green
                } catch {
                    Write-Host "✗ Nie udało się zatrzymać procesu: $_" -ForegroundColor Red
                }
            }
        }
    }
} else {
    Write-Host "✓ Port $Port jest wolny" -ForegroundColor Green
}

