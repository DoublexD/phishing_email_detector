# Phishing Email Detector

System do wykrywania phishingu i email spoofingu oparty na uczeniu maszynowym. Analizuje wiadomości e-mail pod kątem autentyczności nadawcy i cech charakterystycznych dla ataków phishingowych.

## Jak to działa

Pipeline analizy składa się z czterech etapów:

```
[Email (surowy .eml / IMAP)]
         ↓
1. Parsowanie i analiza nagłówków
   - Wyciągnięcie From, Reply-To, Return-Path, X-Originating-IP
   - Wykrycie niespójności między polami nagłówka
         ↓
2. Weryfikacja autentyczności
   - SPF  — czy serwer nadawcy jest upoważniony do wysyłki?
   - DKIM — czy podpis kryptograficzny wiadomości jest poprawny?
   - DMARC — czy domena spełnia politykę właściciela domeny?
         ↓
3. Ekstrakcja cech (Feature Extraction)
   - Cechy autentykacji (wyniki SPF/DKIM/DMARC, alignment)
   - Cechy nagłówka (niespójności, routing)
   - Cechy treści (słowa kluczowe phishingu, PL + EN)
   - Cechy URL (domeny lookalike, przekierowania)
   - Cechy załączników (podejrzane rozszerzenia)
   - Cechy nadawcy (reputacja domeny, wiek)
   - Cechy czasowe (pora wysyłki, strefa czasowa)
         ↓
4. Klasyfikacja ML
   - Random Forest (główny klasyfikator, kalibrowany)
   - Isolation Forest (wykrywanie anomalii)
   - Trening z SMOTE (balansowanie klas)
   - Wynik: phishing / legitymacyjny + prawdopodobieństwo
```

## Funkcje

- **REST API** (FastAPI) — analiza emaili przez HTTP, asynchroniczne zadania
- **Klient IMAP** — pobieranie i analiza emaili bezpośrednio ze skrzynki
- **Frontend webowy** — interfejs do przesyłania i analizy wiadomości
- **Biała lista domen** — znane zaufane domeny (Google, Microsoft, banki PL)
- **Load testing** — testy wydajnościowe z Locust, benchmark `benchmark_results.json`
- **Pełna suite testów** — unit, funkcjonalne, benchmark (`pytest`)

## Struktura projektu

```
phishing_email_detector/
├── src/
│   ├── api/                  # FastAPI — endpointy REST
│   ├── authentication/       # Weryfikacja SPF, DKIM, DMARC
│   ├── email_parser/         # Parser emaili, analiza nagłówków, klient IMAP
│   ├── feature_extraction/   # Ekstrakcja cech dla modeli ML
│   ├── ml_models/            # Trening, predykcja, zarządzanie modelami
│   └── utils/                # Helpery, konfiguracja, narzędzia domenowe
├── tests/                    # Testy pytest (unit + funkcjonalne + benchmark)
├── frontend/                 # Interfejs webowy
├── notebooks/                # Jupyter — eksploracja danych i analiza
├── config/                   # Konfiguracja aplikacji
├── data/                     # Dane treningowe (placeholder)
├── models/                   # Zapisane modele (placeholder)
└── requirements.txt
```

## Technologie

| Warstwa | Technologie |
|---|---|
| API | FastAPI, Uvicorn, Pydantic |
| ML | scikit-learn, RandomForest, IsolationForest, SMOTE (imbalanced-learn) |
| Email auth | dnspython, dkimpy, checkdmarc, pyspf |
| Testowanie | pytest, pytest-asyncio, pytest-benchmark, Locust |
| Inne | pandas, numpy, tldextract, SQLAlchemy |

## Uruchomienie

```bash
# Instalacja zależności
pip install -r requirements.txt

# Uruchomienie API
uvicorn src.api.app:app --reload

# Trening modelu
python -m src.ml_models.train

# Uruchomienie testów
pytest tests/

# Load testing
locust -f tests/performance/locustfile.py
```

## API — główne endpointy

```
POST /analyze          — analiza emaila (raw .eml lub JSON)
POST /analyze/imap     — analiza emaili ze skrzynki IMAP
GET  /model/status     — status załadowanego modelu
POST /model/train      — wyzwolenie treningu modelu
GET  /health           — health check
```

## Wyniki

Wyniki benchmarków wydajnościowych dostępne w `benchmark_results.json`. Testy load testingowe przeprowadzane narzędziem Locust (`locust_results_stats.csv`).
