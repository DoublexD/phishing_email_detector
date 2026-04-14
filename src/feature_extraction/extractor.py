"""
Feature Extractor
Ekstrakcja cech z wiadomości e-mail dla modeli ML
"""

import re
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from datetime import datetime
import tldextract
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Klasa do ekstrakcji cech z wiadomości e-mail"""
    
    # Słowa kluczowe często występujące w phishingu
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'verify', 'account', 'suspended', 'confirm', 'password',
        'click', 'immediately', 'expire', 'act now', 'limited time',
        'congratulations', 'winner', 'prize', 'free', 'bonus',
        'security', 'alert', 'warning', 'problem', 'unusual activity'
    ]
    
    def __init__(self):
        self.feature_names = []
    
    def extract_features(self, 
                        email_data: Dict[str, Any],
                        spf_result: Optional[Dict[str, Any]] = None,
                        dkim_result: Optional[Dict[str, Any]] = None,
                        dmarc_result: Optional[Dict[str, Any]] = None,
                        header_analysis: Optional[Dict[str, Any]] = None) -> pd.Series:
        """
        Ekstrahuje wszystkie cechy z wiadomości e-mail
        
        Args:
            email_data: Wyparsowane dane e-maila
            spf_result: Wynik sprawdzenia SPF
            dkim_result: Wynik sprawdzenia DKIM
            dmarc_result: Wynik sprawdzenia DMARC
            header_analysis: Analiza nagłówków
            
        Returns:
            Seria pandas z cechami
        """
        features = {}
        
        # Cechy z autentykacji
        features.update(self._extract_auth_features(spf_result, dkim_result, dmarc_result))
        
        # Cechy z nagłówków
        features.update(self._extract_header_features(email_data, header_analysis))
        
        # Cechy czasowe
        features.update(self._extract_temporal_features(email_data))
        
        # Cechy z treści
        features.update(self._extract_content_features(email_data))
        
        # Cechy URL
        features.update(self._extract_url_features(email_data))
        
        # Cechy załączników
        features.update(self._extract_attachment_features(email_data))
        
        # Cechy adresu nadawcy
        features.update(self._extract_sender_features(email_data))
        
        self.feature_names = list(features.keys())
        return pd.Series(features)
    
    def _extract_auth_features(self,
                               spf_result: Optional[Dict[str, Any]],
                               dkim_result: Optional[Dict[str, Any]],
                               dmarc_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Ekstrahuje cechy z wyników autentykacji"""
        features = {
            # SPF
            'spf_pass': 0,
            'spf_fail': 0,
            'spf_softfail': 0,
            'spf_neutral': 0,
            'spf_none': 0,
            
            # DKIM
            'dkim_valid': 0,
            'dkim_invalid': 0,
            'dkim_none': 0,
            'dkim_signature_count': 0,
            
            # DMARC
            'dmarc_policy_none': 0,
            'dmarc_policy_quarantine': 0,
            'dmarc_policy_reject': 0,
            'dmarc_exists': 0,
        }
        
        # SPF
        if spf_result:
            result = spf_result.get('result', 'none')
            features[f'spf_{result}'] = 1
        
        # DKIM
        if dkim_result:
            if dkim_result.get('valid'):
                features['dkim_valid'] = 1
            elif dkim_result.get('result') == 'fail':
                features['dkim_invalid'] = 1
            else:
                features['dkim_none'] = 1
            
            features['dkim_signature_count'] = len(dkim_result.get('signatures', []))
        
        # DMARC
        if dmarc_result:
            if dmarc_result.get('valid'):
                features['dmarc_exists'] = 1
                policy = dmarc_result.get('policy', 'none')
                features[f'dmarc_policy_{policy}'] = 1
        
        return features
    
    def _extract_header_features(self,
                                 email_data: Dict[str, Any],
                                 header_analysis: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Ekstrahuje cechy z nagłówków"""
        features = {
            'hop_count': 0,
            'missing_headers_count': 0,
            'from_return_path_mismatch': 0,
            'from_reply_to_mismatch': 0,
            'has_x_mailer': 0,
            'has_message_id': 0,
            'anomaly_score': 0.0,
        }
        
        if header_analysis:
            features['hop_count'] = header_analysis.get('hop_count', 0)
            features['missing_headers_count'] = len(header_analysis.get('missing_headers', []))
            features['from_return_path_mismatch'] = 1 if header_analysis.get('from_mismatch') else 0
            features['from_reply_to_mismatch'] = 1 if header_analysis.get('reply_to_mismatch') else 0
            features['anomaly_score'] = header_analysis.get('anomaly_score', 0.0)
        
        # Dodatkowe cechy z nagłówków
        features['has_x_mailer'] = 1 if email_data.get('x_mailer') else 0
        features['has_message_id'] = 1 if email_data.get('message_id') else 0
        
        return features
    
    def _extract_temporal_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy czasowe"""
        features = {
            'hour_of_day': 0,
            'day_of_week': 0,
            'is_weekend': 0,
            'is_night_time': 0,  # 22:00 - 6:00
            'date_in_future': 0,
            'avg_hop_delay': 0.0,
            'max_hop_delay': 0.0,
        }

        def to_naive(dt):
            """Konwertuje datetime do naive (bez timezone) przez utc offset."""
            if dt is None:
                return None
            try:
                if dt.tzinfo is not None:
                    from datetime import timezone
                    return dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except Exception:
                return None

        # Czas wysłania
        email_date = email_data.get('date')
        if email_date:
            try:
                features['hour_of_day'] = email_date.hour
                features['day_of_week'] = email_date.weekday()
                features['is_weekend'] = 1 if email_date.weekday() >= 5 else 0
                features['is_night_time'] = 1 if email_date.hour >= 22 or email_date.hour < 6 else 0

                naive_date = to_naive(email_date)
                if naive_date and naive_date > datetime.utcnow():
                    features['date_in_future'] = 1
            except Exception:
                pass

        # Opóźnienia między hopami
        received = email_data.get('received', [])
        delays = []

        for i in range(len(received) - 1):
            current = received[i]
            previous = received[i + 1]

            try:
                cur_date = to_naive(current.get('date'))
                prev_date = to_naive(previous.get('date'))
                if cur_date and prev_date:
                    delta = cur_date - prev_date
                    delays.append(abs(delta.total_seconds()))
            except Exception:
                pass

        if delays:
            features['avg_hop_delay'] = np.mean(delays)
            features['max_hop_delay'] = np.max(delays)

        return features
    
    def _extract_content_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z treści wiadomości"""
        features = {
            'body_length': 0,
            'html_body_present': 0,
            'plain_body_present': 0,
            'suspicious_keywords_count': 0,
            'exclamation_count': 0,
            'capital_letter_ratio': 0.0,
            'contains_form': 0,
            'contains_script': 0,
        }
        
        body = email_data.get('body', {})
        plain_body = body.get('plain', '')
        html_body = body.get('html', '')
        
        # Długość treści
        features['body_length'] = len(plain_body) + len(html_body)
        features['plain_body_present'] = 1 if plain_body else 0
        features['html_body_present'] = 1 if html_body else 0
        
        # Analiza treści tekstowej
        combined_text = plain_body.lower()
        
        # Podejrzane słowa kluczowe
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in combined_text:
                features['suspicious_keywords_count'] += 1
        
        # Wykrzykniki
        features['exclamation_count'] = plain_body.count('!')
        
        # Stosunek wielkich liter
        if plain_body:
            capitals = sum(1 for c in plain_body if c.isupper())
            features['capital_letter_ratio'] = capitals / len(plain_body)
        
        # Analiza HTML
        if html_body:
            html_lower = html_body.lower()
            features['contains_form'] = 1 if '<form' in html_lower else 0
            features['contains_script'] = 1 if '<script' in html_lower else 0
        
        return features
    
    def _extract_url_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z URL-i"""
        features = {
            'url_count': 0,
            'external_url_count': 0,
            'ip_address_url_count': 0,
            'shortened_url_count': 0,
            'suspicious_tld_count': 0,
            'url_domain_mismatch': 0,
        }
        
        # URL shorteners
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
        # Pobierz domenę nadawcy
        from_email = email_data.get('from', {}).get('email', '')
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''
        
        # Ekstrahuj URL-e z treści
        body = email_data.get('body', {})
        text = body.get('plain', '') + body.get('html', '')
        urls = self._extract_urls(text)
        
        features['url_count'] = len(urls)
        
        for url in urls:
            # IP address w URL
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                features['ip_address_url_count'] += 1
            
            # URL shortener
            for shortener in shorteners:
                if shortener in url:
                    features['shortened_url_count'] += 1
                    break
            
            # Podejrzane TLD
            for tld in suspicious_tlds:
                if url.endswith(tld) or tld + '/' in url:
                    features['suspicious_tld_count'] += 1
                    break
            
            # Niezgodność domeny
            try:
                extracted = tldextract.extract(url)
                url_domain = f"{extracted.domain}.{extracted.suffix}"
                
                if from_domain and url_domain != from_domain:
                    features['external_url_count'] += 1
            except:
                pass
        
        # Sprawdź czy są external URLs
        if features['url_count'] > 0:
            features['url_domain_mismatch'] = 1 if features['external_url_count'] > 0 else 0
        
        return features
    
    def _extract_attachment_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z załączników"""
        features = {
            'attachment_count': 0,
            'has_executable': 0,
            'has_archive': 0,
            'has_document': 0,
            'total_attachment_size': 0,
        }
        
        attachments = email_data.get('attachments', [])
        features['attachment_count'] = len(attachments)
        
        executable_extensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.js', '.vbs']
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        document_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx']
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            size = attachment.get('size', 0)
            
            features['total_attachment_size'] += size
            
            # Sprawdź rozszerzenia
            if any(filename.endswith(ext) for ext in executable_extensions):
                features['has_executable'] = 1
            
            if any(filename.endswith(ext) for ext in archive_extensions):
                features['has_archive'] = 1
            
            if any(filename.endswith(ext) for ext in document_extensions):
                features['has_document'] = 1
        
        return features
    
    def _extract_sender_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z adresu nadawcy"""
        features = {
            'from_name_length': 0,
            'from_contains_reply': 0,
            'from_contains_noreply': 0,
            'from_has_numbers': 0,
            'from_domain_length': 0,
            'to_count': 0,
            'cc_count': 0,
            'bcc_count': 0,
        }
        
        # From
        from_data = email_data.get('from', {})
        from_name = from_data.get('name', '')
        from_email = from_data.get('email', '')
        
        features['from_name_length'] = len(from_name)
        features['from_contains_reply'] = 1 if 'reply' in from_email.lower() else 0
        features['from_contains_noreply'] = 1 if 'noreply' in from_email.lower() else 0
        features['from_has_numbers'] = 1 if any(c.isdigit() for c in from_email) else 0
        
        if '@' in from_email:
            domain = from_email.split('@')[1]
            features['from_domain_length'] = len(domain)
        
        # Recipients
        features['to_count'] = len(email_data.get('to', []))
        features['cc_count'] = len(email_data.get('cc', []))
        features['bcc_count'] = len(email_data.get('bcc', []))
        
        return features
    
    def _extract_urls(self, text: str) -> List[str]:
        """Ekstrahuje URL-e z tekstu"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def get_feature_names(self) -> List[str]:
        """Zwraca nazwy wszystkich cech"""
        return self.feature_names
    
    def extract_batch(self, 
                     email_data_list: List[Dict[str, Any]],
                     **kwargs) -> pd.DataFrame:
        """
        Ekstrahuje cechy z wielu wiadomości
        
        Args:
            email_data_list: Lista wyparsowanych wiadomości
            **kwargs: Dodatkowe parametry (spf_results, dkim_results, etc.)
            
        Returns:
            DataFrame z cechami
        """
        features_list = []
        
        for i, email_data in enumerate(email_data_list):
            # Pobierz odpowiadające wyniki autentykacji
            spf_result = kwargs.get('spf_results', [None])[i] if 'spf_results' in kwargs else None
            dkim_result = kwargs.get('dkim_results', [None])[i] if 'dkim_results' in kwargs else None
            dmarc_result = kwargs.get('dmarc_results', [None])[i] if 'dmarc_results' in kwargs else None
            header_analysis = kwargs.get('header_analyses', [None])[i] if 'header_analyses' in kwargs else None
            
            features = self.extract_features(
                email_data, spf_result, dkim_result, dmarc_result, header_analysis
            )
            features_list.append(features)
        
        return pd.DataFrame(features_list)

