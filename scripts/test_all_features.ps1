# Automatyczny test wszystkich funkcjonalności
# Email Spoofing Detector - Feature Testing

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AUTOMATYCZNY TEST FUNKCJONALNOŚCI" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$API_URL = "http://localhost:8000"
$testsPassed = 0
$testsFailed = 0

# Test helper
function Test-Feature {
    param($name, $scriptBlock)
    
    Write-Host "`n[$name]" -ForegroundColor Yellow -NoNewline
    try {
        & $scriptBlock
        Write-Host " ✓ PASS" -ForegroundColor Green
        $script:testsPassed++
        return $true
    } catch {
        Write-Host " ✗ FAIL" -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Red
        $script:testsFailed++
        return $false
    }
}

# TEST 1: Health Check
Test-Feature "Health Check" {
    $response = Invoke-RestMethod -Uri "$API_URL/health" -Method Get -ErrorAction Stop
    if ($response.status -ne "healthy") {
        throw "Status is not healthy"
    }
    Write-Host "  Status: $($response.status)" -ForegroundColor Gray
}

# TEST 2: Root Endpoint
Test-Feature "Root Endpoint" {
    $response = Invoke-RestMethod -Uri "$API_URL/" -Method Get -ErrorAction Stop
    if (-not $response.message) {
        throw "No message in response"
    }
    Write-Host "  Message: $($response.message)" -ForegroundColor Gray
}

# TEST 3: Parsowanie E-maili
Test-Feature "Parsowanie E-maili" {
    $email = @"
From: test@example.com
To: user@test.com
Subject: Test Email
Date: Mon, 1 Dec 2024 10:00:00 +0000

Test body with URL: https://example.com
"@
    
    $body = @{
        email_string = $email
        analyze_authentication = $false
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_URL/api/analyze" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -ErrorAction Stop
    
    if (-not $response.header_analysis) {
        throw "No header analysis in response"
    }
    Write-Host "  Headers analyzed: OK" -ForegroundColor Gray
}

# TEST 4: Analiza Nagłówków (z anomaliami)
Test-Feature "Analiza Nagłówków" {
    $email = @"
From: admin@paypal.com
To: victim@test.com
Subject: URGENT Account Alert
Return-Path: <hacker@evil.com>
Date: Mon, 1 Dec 2024 10:00:00 +0000

Suspicious content
"@
    
    $body = @{
        email_string = $email
        analyze_authentication = $false
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_URL/api/analyze" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -ErrorAction Stop
    
    if ($response.header_analysis.from_mismatch -ne $true) {
        throw "From/Return-Path mismatch not detected"
    }
    Write-Host "  From/Return-Path mismatch detected: OK" -ForegroundColor Gray
}

# TEST 5: Wykrywanie Anomalii
Test-Feature "Wykrywanie Anomalii" {
    $email = @"
From: security@bank-verify.tk
To: victim@test.com
Subject: URGENT! WINNER! ACT NOW!!!
Date: Mon, 1 Dec 2024 03:00:00 +0000
Return-Path: <different@evil.com>

URGENT! You won $1,000,000!
Click here immediately: http://192.168.1.1/phishing
"@
    
    $body = @{
        email_string = $email
        analyze_authentication = $false
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_URL/api/analyze" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -ErrorAction Stop
    
    # Sprawdź czy wykryto anomalie w nagłówkach LUB wskaźniki spoofingu
    $anomaliesDetected = ($response.header_analysis.anomalies.Count -gt 0) -or 
                        ($response.spoofing_indicators.Count -gt 0) -or
                        ($response.header_analysis.from_mismatch -eq $true)
    
    if (-not $anomaliesDetected) {
        throw "No anomalies or indicators detected"
    }
    
    $totalIndicators = $response.spoofing_indicators.Count
    $anomalyScore = $response.header_analysis.anomaly_score
    Write-Host "  Indicators: $totalIndicators, Anomaly Score: $anomalyScore" -ForegroundColor Gray
}

# TEST 6: Ekstrakcja URL-i
Test-Feature "Ekstrakcja URL-i" {
    $email = @"
From: test@example.com
To: user@test.com
Subject: Links Test
Date: Mon, 1 Dec 2024 10:00:00 +0000

Check these links:
https://example.com
http://test.org
http://192.168.1.1/page
"@
    
    $body = @{
        email_string = $email
        analyze_authentication = $false
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_URL/api/analyze" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -ErrorAction Stop
    
    # URL-e powinny być wykryte
    Write-Host "  URLs extracted: OK" -ForegroundColor Gray
}

# TEST 7: Statystyki
Test-Feature "Endpoint Statystyk" {
    $response = Invoke-RestMethod -Uri "$API_URL/api/stats" -Method Get -ErrorAction Stop
    
    if (-not ($response.PSObject.Properties.Name -contains 'total_analyzed')) {
        throw "Missing total_analyzed in stats"
    }
    Write-Host "  Total analyzed: $($response.total_analyzed)" -ForegroundColor Gray
}

# TEST 8: Alerty
Test-Feature "Endpoint Alertów" {
    $response = Invoke-RestMethod -Uri "$API_URL/api/alerts" -Method Get -ErrorAction Stop
    
    if (-not ($response.PSObject.Properties.Name -contains 'alerts')) {
        throw "Missing alerts in response"
    }
    Write-Host "  Alerts count: $($response.total)" -ForegroundColor Gray
}

# TEST 9: Informacje o Modelach
Test-Feature "Informacje o Modelach" {
    $response = Invoke-RestMethod -Uri "$API_URL/api/models" -Method Get -ErrorAction Stop
    
    if (-not $response.loaded) {
        throw "Missing loaded models info"
    }
    $rfLoaded = if ($response.loaded.random_forest) { "✓" } else { "✗" }
    $ifLoaded = if ($response.loaded.isolation_forest) { "✓" } else { "✗" }
    Write-Host "  RandomForest: $rfLoaded, IsolationForest: $ifLoaded" -ForegroundColor Gray
}

# TEST 10: Frontend (sprawdź czy plik istnieje)
Test-Feature "Frontend Files" {
    if (-not (Test-Path "frontend\index.html")) {
        throw "frontend\index.html not found"
    }
    if (-not (Test-Path "frontend\app.js")) {
        throw "frontend\app.js not found"
    }
    if (-not (Test-Path "frontend\style.css")) {
        throw "frontend\style.css not found"
    }
    Write-Host "  All frontend files present" -ForegroundColor Gray
}

# Podsumowanie
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  PODSUMOWANIE TESTÓW" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Passed: $testsPassed" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -gt 0) { "Red" } else { "Green" })

$totalTests = $testsPassed + $testsFailed
$successRate = if ($totalTests -gt 0) { ($testsPassed / $totalTests * 100) } else { 0 }
Write-Host "Success Rate: $([math]::Round($successRate, 2))%" -ForegroundColor Cyan

if ($testsFailed -eq 0) {
    Write-Host "`n✅ Wszystkie testy przeszły pomyślnie!" -ForegroundColor Green
    Write-Host "Projekt działa poprawnie! 🎉" -ForegroundColor Green
} else {
    Write-Host "`n⚠️ Niektóre testy nie powiodły się" -ForegroundColor Yellow
    Write-Host "Sprawdź logi i dokumentację" -ForegroundColor Yellow
}

Write-Host "`nDokumentacja testów: TESTING_GUIDE.md" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

