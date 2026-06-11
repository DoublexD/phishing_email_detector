"""
Locust Performance Tests
Testy wydajnościowe API przy użyciu Locust
"""

from locust import HttpUser, task, between
import random


class EmailAnalysisUser(HttpUser):
    """Użytkownik testujący API analizy e-maili"""

    wait_time = between(1, 3)

    sample_emails = [
        """From: legitimate@company.com
To: user@example.com
Subject: Important Update
Date: Mon, 1 Jan 2024 12:00:00 +0000

Dear user, please review this important update.
""",
        """From: phishing@suspicious.com
To: victim@example.com
Subject: URGENT: Verify Your Account NOW!
Date: Mon, 1 Jan 2024 12:00:00 +0000

Click here immediately to verify your account: http://192.168.1.1/phishing
Your account will be suspended if you don't act now!
Winner! You've won $1,000,000!
""",
        """From: newsletter@service.com
To: subscriber@example.com
Subject: Monthly Newsletter
Date: Mon, 1 Jan 2024 12:00:00 +0000

Welcome to our monthly newsletter with the latest updates.
""",
    ]
    
    def on_start(self):
        """Wykonywane przy starcie użytkownika"""
        self.client.get("/health")
    
    @task(5)
    def analyze_email(self):
        """
        Task: Analizuj e-mail (waga: 5)
        Najczęściej wykonywane zadanie
        """
        email_content = random.choice(self.sample_emails)
        
        payload = {
            "email_string": email_content,
            "analyze_authentication": True
        }
        
        with self.client.post(
            "/api/analyze",
            json=payload,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                result = response.json()
                if "is_suspicious" in result and "confidence" in result:
                    response.success()
                else:
                    response.failure("Invalid response format")
            else:
                response.failure(f"Status code: {response.status_code}")
    
    @task(2)
    def get_statistics(self):
        """
        Task: Pobierz statystyki (waga: 2)
        """
        with self.client.get("/api/stats", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                if "total_analyzed" in data:
                    response.success()
                else:
                    response.failure("Invalid stats format")
            else:
                response.failure(f"Status code: {response.status_code}")
    
    @task(2)
    def get_alerts(self):
        """
        Task: Pobierz alerty (waga: 2)
        """
        limit = random.choice([10, 20, 50])
        
        with self.client.get(
            f"/api/alerts?limit={limit}",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "alerts" in data:
                    response.success()
                else:
                    response.failure("Invalid alerts format")
            else:
                response.failure(f"Status code: {response.status_code}")
    
    @task(1)
    def get_models_info(self):
        """
        Task: Pobierz informacje o modelach (waga: 1)
        """
        with self.client.get("/api/models", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status code: {response.status_code}")
    
    @task(1)
    def get_feature_importance(self):
        """
        Task: Pobierz ważność cech (waga: 1)
        """
        top_n = random.choice([10, 20, 30])
        
        self.client.get(f"/api/feature-importance?top_n={top_n}")
    
    @task(1)
    def health_check(self):
        """
        Task: Health check (waga: 1)
        """
        self.client.get("/health")


class AdminUser(HttpUser):
    """Użytkownik administracyjny - tylko odczyt statystyk"""
    
    wait_time = between(2, 5)
    
    @task(3)
    def monitor_stats(self):
        """Monitoruj statystyki"""
        self.client.get("/api/stats")
    
    @task(2)
    def check_alerts(self):
        """Sprawdź alerty wysokiego ryzyka"""
        self.client.get("/api/alerts?risk_level=HIGH")
    
    @task(1)
    def check_health(self):
        """Sprawdź stan systemu"""
        self.client.get("/health")


class StressTestUser(HttpUser):
    """Użytkownik do testów obciążeniowych - wysyła wiele requestów"""

    wait_time = between(0.1, 0.5)

    sample_email = """From: test@example.com
To: user@example.com
Subject: Stress Test
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a stress test email.
"""
    
    @task
    def rapid_analysis(self):
        """Szybka analiza e-maili"""
        payload = {
            "email_string": self.sample_email,
            "analyze_authentication": False
        }
        
        self.client.post("/api/analyze", json=payload)


"""
Uruchomienie testów:

1. Podstawowy test (10 użytkowników, 2 na sekundę):
   locust -f locustfile.py --users 10 --spawn-rate 2 --host http://localhost:8000

2. Test obciążeniowy (100 użytkowników, 10 na sekundę):
   locust -f locustfile.py --users 100 --spawn-rate 10 --host http://localhost:8000

3. Test bez interfejsu webowego:
   locust -f locustfile.py --headless --users 50 --spawn-rate 5 --run-time 60s --host http://localhost:8000

4. Test konkretnej klasy użytkowników:
   locust -f locustfile.py --users 20 --spawn-rate 2 --host http://localhost:8000 EmailAnalysisUser
"""

