# Test wykrywania phishingu
# Porównuje odpowiedzi dla legalnego vs phishing e-maila

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST WYKRYWANIA PHISHINGU" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$API_URL = "http://localhost:8000"

function Test-Email {
    param($filepath, $name, $expectedSuspicious)
    
    Write-Host "`n=== $name ===" -ForegroundColor Cyan
    
    # Załaduj e-mail
    if (-not (Test-Path $filepath)) {
        Write-Host "✗ Plik nie istnieje: $filepath" -ForegroundColor Red
        return $false
    }
    
    $email = Get-Content $filepath -Raw -Encoding UTF8
    
    # Analizuj
    $body = @{
        email_string = $email
        analyze_authentication = $false
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$API_URL/api/analyze" `
            -Method Post `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop
        
        # Wyświetl wyniki
        $icon = if ($response.risk_level -eq "HIGH") { "🔴" } 
                elseif ($response.risk_level -eq "MEDIUM") { "🟡" }
                else { "🟢" }
        
        Write-Host "`n$icon Risk Level: " -NoNewline
        Write-Host $response.risk_level -ForegroundColor $(
            if ($response.risk_level -eq "HIGH") { "Red" }
            elseif ($response.risk_level -eq "MEDIUM") { "Yellow" }
            else { "Green" }
        )
        
        Write-Host "   Confidence: $([math]::Round($response.confidence * 100, 1))%"
        Write-Host "   Recommendation: $($response.recommendation)"
        
        # Anomalie w nagłówkach
        if ($response.header_analysis.anomalies.Count -gt 0) {
            Write-Host "`n   Wykryte Anomalie:" -ForegroundColor Yellow
            $response.header_analysis.anomalies | ForEach-Object {
                Write-Host "     - $_" -ForegroundColor Gray
            }
        }
        
        # Wskaźniki spoofingu
        if ($response.spoofing_indicators.Count -gt 0) {
            Write-Host "`n   Wskaźniki Spoofingu:" -ForegroundColor Red
            $response.spoofing_indicators | ForEach-Object {
                Write-Host "     ⚠️ $_" -ForegroundColor Yellow
            }
        }
        
        # Anomaly score
        $anomalyScore = $response.header_analysis.anomaly_score
        Write-Host "`n   Anomaly Score: $([math]::Round($anomalyScore, 3))" -ForegroundColor $(
            if ($anomalyScore -gt 0.5) { "Red" }
            elseif ($anomalyScore -gt 0.3) { "Yellow" }
            else { "Green" }
        )
        
        # Sprawdź czy detekcja jest poprawna — używamy wyniku z API
        $detectedAsSuspicious = $response.is_suspicious
        
        Write-Host "`n   Wykryty jako podejrzany: " -NoNewline
        if ($detectedAsSuspicious) {
            Write-Host "TAK" -ForegroundColor Red
        } else {
            Write-Host "NIE" -ForegroundColor Green
        }
        
        # Sprawdź zgodność z oczekiwaniem
        if ($expectedSuspicious -and $detectedAsSuspicious) {
            Write-Host "   ✓ Poprawna detekcja (True Positive)" -ForegroundColor Green
            return $true
        } elseif (-not $expectedSuspicious -and -not $detectedAsSuspicious) {
            Write-Host "   ✓ Poprawna klasyfikacja (True Negative)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "   ✗ Błędna klasyfikacja" -ForegroundColor Red
            return $false
        }
        
    } catch {
        Write-Host "✗ Błąd analizy: $_" -ForegroundColor Red
        return $false
    }
}

# Sprawdź czy API działa
Write-Host "`nSprawdzanie połączenia z API..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$API_URL/health" -Method Get -ErrorAction Stop
    Write-Host "✓ API działa ($($health.status))" -ForegroundColor Green
} catch {
    Write-Host "✗ API nie odpowiada!" -ForegroundColor Red
    Write-Host "Uruchom najpierw: .\scripts\run_api.ps1" -ForegroundColor Yellow
    exit 1
}

# Testuj e-maile
$result1 = Test-Email "data\sample_emails\sample_legitimate.eml" "E-MAIL LEGALNY" $false
$result2 = Test-Email "data\sample_emails\sample_phishing.eml" "E-MAIL PHISHING" $true

# Podsumowanie
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  PODSUMOWANIE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passed = ($result1, $result2 | Where-Object { $_ -eq $true }).Count
$total = 2

Write-Host "`nWynik: $passed/$total testów poprawnych" -ForegroundColor $(
    if ($passed -eq $total) { "Green" } else { "Yellow" }
)

if ($passed -eq $total) {
    Write-Host "`n✅ System wykrywa phishing poprawnie!" -ForegroundColor Green
    Write-Host "   - Legalny e-mail: klasyfikowany jako bezpieczny ✓" -ForegroundColor Gray
    Write-Host "   - Phishing: klasyfikowany jako podejrzany ✓" -ForegroundColor Gray
} else {
    Write-Host "`n⚠️ System wymaga dostrojenia lub treningu modeli ML" -ForegroundColor Yellow
    Write-Host "Bez modeli ML wykrywanie opiera się tylko na:" -ForegroundColor Gray
    Write-Host "  - Analizie nagłówków (From/Return-Path mismatch)" -ForegroundColor Gray
    Write-Host "  - Anomaliach czasowych" -ForegroundColor Gray
    Write-Host "  - Podejrzanych wzorcach" -ForegroundColor Gray
}

Write-Host "`nAby zwiększyć dokładność:" -ForegroundColor Yellow
Write-Host "  1. Wytrenuj modele ML (.\scripts\train_models.ps1)" -ForegroundColor White
Write-Host "  2. Zbierz więcej danych treningowych" -ForegroundColor White
Write-Host "  3. Dostosuj thresholdy w config\config.yaml" -ForegroundColor White

Write-Host "`n========================================`n" -ForegroundColor Cyan

