"""
Header Analyzer
Analiza nagłówków e-mail pod kątem anomalii i podejrzanych wzorców
"""

import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
import logging

logger = logging.getLogger(__name__)


class HeaderAnalyzer:
    """Klasa do analizy nagłówków e-mail"""

    REQUIRED_HEADERS = [
        'From', 'Date', 'Message-ID', 'Received'
    ]

    SUSPICIOUS_PATTERNS = {
        'X-Mailer': [
            r'.*YahooMailClassic.*',
            r'.*Microsoft Outlook.*IMO.*',
        ],
        'User-Agent': [
            r'.*curl.*',
            r'.*python.*',
            r'.*wget.*',
        ]
    }

    @staticmethod
    def _as_utc_naive(dt: Optional[datetime]) -> Optional[datetime]:
        """Ujednolica daty hopów"""
        if dt is None:
            return None
        try:
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception:
            return None

    def __init__(self):
        self.anomalies = []

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Główna funkcja analizy nagłówków

        """
        self.anomalies = []

        results = {
            'missing_headers': self._check_missing_headers(email_data),
            'received_chain_analysis': self._analyze_received_chain(email_data),
            'time_anomalies': self._check_time_anomalies(email_data),
            'suspicious_patterns': self._check_suspicious_patterns(email_data),
            'from_mismatch': self._check_from_mismatch(email_data),
            'reply_to_mismatch': self._check_reply_to_mismatch(email_data),
            'hop_count': self._calculate_hop_count(email_data),
            'anomaly_score': 0,
            'anomalies': []
        }

        results['anomaly_score'] = self._calculate_anomaly_score(results)
        results['anomalies'] = self.anomalies

        return results

    def _check_missing_headers(self, email_data: Dict[str, Any]) -> List[str]:
        """Sprawdza brakujące nagłówki"""
        headers = email_data.get('headers', {})
        missing = []

        for required_header in self.REQUIRED_HEADERS:
            if required_header not in headers or not headers[required_header]:
                missing.append(required_header)
                self.anomalies.append(f"Brakujący nagłówek: {required_header}")

        return missing

    def _analyze_received_chain(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analizuje łańcuch nagłówków Received"""
        received = email_data.get('received', [])

        analysis = {
            'total_hops': len(received),
            'suspicious_hops': [],
            'time_deltas': [],
            'geographic_anomalies': []
        }

        if len(received) < 1:
            self.anomalies.append("Brak nagłówków Received")
            return analysis

        if len(received) > 10:
            self.anomalies.append(f"Zbyt wiele hopów: {len(received)}")

        for i in range(len(received) - 1):
            current = received[i]
            previous = received[i + 1]

            d_cur = self._as_utc_naive(current.get('date'))
            d_prev = self._as_utc_naive(previous.get('date'))
            if d_cur and d_prev:
                delta = d_cur - d_prev
                analysis['time_deltas'].append({
                    'from': previous.get('from_host'),
                    'to': current.get('by_host'),
                    'delta_seconds': delta.total_seconds()
                })

                if delta.total_seconds() > 3600:
                    self.anomalies.append(
                        f"Duże opóźnienie między hopami: {delta.total_seconds()}s"
                    )
                elif delta.total_seconds() < 0:
                    self.anomalies.append("Ujemne opóźnienie (błąd zegara)")

        return analysis

    def _check_time_anomalies(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sprawdza anomalie czasowe"""
        anomalies = {
            'date_in_future': False,
            'date_too_old': False,
            'timezone_mismatch': False
        }

        email_date = email_data.get('date')
        if not email_date:
            return anomalies

        now = datetime.now(email_date.tzinfo)

        if email_date > now + timedelta(hours=1):
            anomalies['date_in_future'] = True
            self.anomalies.append("Data e-maila w przyszłości")

        if email_date < now - timedelta(days=365):
            anomalies['date_too_old'] = True

        return anomalies

    def _check_suspicious_patterns(self, email_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Sprawdza podejrzane wzorce w nagłówkach"""
        found_patterns = []
        headers = email_data.get('headers', {})

        for header_name, patterns in self.SUSPICIOUS_PATTERNS.items():
            header_value = headers.get(header_name, '')
            if not header_value:
                continue

            if isinstance(header_value, list):
                header_value = ' '.join(str(v) for v in header_value)
            else:
                header_value = str(header_value)

            for pattern in patterns:
                if re.search(pattern, header_value, re.IGNORECASE):
                    found_patterns.append({
                        'header': header_name,
                        'value': header_value,
                        'pattern': pattern
                    })
                    self.anomalies.append(
                        f"Podejrzany wzorzec w {header_name}: {pattern}"
                    )

        return found_patterns

    def _check_from_mismatch(self, email_data: Dict[str, Any]) -> bool:
        """
        Sprawdza niezgodność między From a Return-Path

        """
        from_addr = email_data.get('from', {}).get('email', '').lower()
        return_path = email_data.get('return_path', '').lower()

        if not from_addr or not return_path:
            return False

        return_path_email = re.search(r'<?([\w\.-]+@[\w\.-]+)>?', return_path)
        if return_path_email:
            return_path_email = return_path_email.group(1)
        else:
            return False

        from_domain = from_addr.split('@')[-1] if '@' in from_addr else ''
        return_domain = return_path_email.split('@')[-1] if '@' in return_path_email else ''

        mismatch = from_domain != return_domain
        if mismatch:
            self.anomalies.append(
                f"Niezgodność domen: From={from_domain}, Return-Path={return_domain}"
            )

        return mismatch

    def _check_reply_to_mismatch(self, email_data: Dict[str, Any]) -> bool:
        """Sprawdza niezgodność między From a Reply-To"""
        from_addr = email_data.get('from', {}).get('email', '').lower()
        reply_to = email_data.get('reply_to', {})

        if not reply_to or not from_addr:
            return False

        reply_to_email = reply_to.get('email', '').lower()
        if not reply_to_email:
            return False

        from_domain = from_addr.split('@')[-1] if '@' in from_addr else ''
        reply_domain = reply_to_email.split('@')[-1] if '@' in reply_to_email else ''

        mismatch = from_domain != reply_domain
        if mismatch:
            self.anomalies.append(
                f"Niezgodność Reply-To: From={from_domain}, Reply-To={reply_domain}"
            )

        return mismatch

    def _calculate_hop_count(self, email_data: Dict[str, Any]) -> int:
        """Oblicza liczbę hopów"""
        return len(email_data.get('received', []))

    def _calculate_anomaly_score(self, results: Dict[str, Any]) -> float:
        """
        Oblicza ogólny wynik anomalii (0-1)
        0 = brak anomalii, 1 = podejrzane
        """
        score = 0.0

        score += len(results['missing_headers']) * 0.15

        if results['from_mismatch']:
            score += 0.25
        if results['reply_to_mismatch']:
            score += 0.15

        time_anomalies = results['time_anomalies']
        if time_anomalies.get('date_in_future'):
            score += 0.20

        score += len(results['suspicious_patterns']) * 0.10

        if results['hop_count'] > 10:
            score += 0.15
        elif results['hop_count'] < 1:
            score += 0.20

        return min(score, 1.0)
