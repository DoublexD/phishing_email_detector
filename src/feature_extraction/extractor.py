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
    
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'verify', 'account', 'suspended', 'confirm', 'password',
        'click', 'immediately', 'expire', 'act now', 'limited time',
        'congratulations', 'winner', 'prize', 'free', 'bonus',
        'security', 'alert', 'warning', 'problem', 'unusual activity',
        'pilne', 'zweryfikuj', 'konto', 'zablokowane', 'potwierdź',
        'hasło', 'kliknij', 'natychmiast', 'wygasa', 'ograniczony czas',
        'gratulacje', 'wygrana', 'nagroda', 'darmowy',
        'bezpieczeństwo', 'ostrzeżenie',
        'nietypowa aktywność', 'przelew', 'faktura', 'zaległość',
        'odblokuj', 'weryfikacja', 'logowanie', 'zmiana hasła',
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
        
        """
        features = {}

        features.update(self._extract_auth_features(spf_result, dkim_result, dmarc_result))

        features.update(self._extract_header_features(email_data, header_analysis))

        features.update(self._extract_temporal_features(email_data))

        features.update(self._extract_content_features(email_data))

        features.update(self._extract_url_features(email_data))

        features.update(self._extract_attachment_features(email_data))

        features.update(self._extract_sender_features(email_data))

        features.update(self._extract_subject_features(email_data))

        features.update(self._extract_network_features(email_data))

        features.update(self._extract_mta_auth_features(email_data))

        features['auth_alignment_score'] = self._calculate_auth_alignment(
            spf_result, dkim_result, dmarc_result
        )

        features['from_display_name_spoofing'] = self._detect_display_name_spoofing(email_data)
        
        self.feature_names = list(features.keys())
        return pd.Series(features)
    
    def _extract_auth_features(self,
                               spf_result: Optional[Dict[str, Any]],
                               dkim_result: Optional[Dict[str, Any]],
                               dmarc_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Ekstrahuje cechy z wyników autentykacji"""
        features = {
            'spf_pass': 0,
            'spf_fail': 0,
            'spf_softfail': 0,
            'spf_neutral': 0,
            'spf_none': 0,

            'dkim_valid': 0,
            'dkim_invalid': 0,
            'dkim_none': 0,
            'dkim_signature_count': 0,

            'dmarc_policy_none': 0,
            'dmarc_policy_quarantine': 0,
            'dmarc_policy_reject': 0,
            'dmarc_exists': 0,
        }

        if spf_result:
            result = spf_result.get('result', 'none')
            if result in ('temperror', 'permerror'):
                result = 'softfail'
            if f'spf_{result}' in features:
                features[f'spf_{result}'] = 1
            else:
                features['spf_none'] = 1

        if dkim_result:
            if dkim_result.get('valid'):
                features['dkim_valid'] = 1
            elif dkim_result.get('result') == 'fail':
                features['dkim_invalid'] = 1
            else:
                features['dkim_none'] = 1
            
            features['dkim_signature_count'] = len(dkim_result.get('signatures', []))

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

        features['has_x_mailer'] = 1 if email_data.get('x_mailer') else 0
        features['has_message_id'] = 1 if email_data.get('message_id') else 0
        
        return features
    
    def _extract_temporal_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy czasowe"""
        features = {
            'hour_of_day': 0,
            'day_of_week': 0,
            'is_weekend': 0,
            'is_night_time': 0,
            'date_in_future': 0,
            'avg_hop_delay': 0.0,
            'max_hop_delay': 0.0,
        }

        def to_naive(dt):
            """Konwertuje datetime do naive"""
            if dt is None:
                return None
            try:
                if dt.tzinfo is not None:
                    from datetime import timezone
                    return dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except Exception:
                return None

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
    
    @staticmethod
    def _strip_html_to_text(html: str) -> str:
        """Odcina tagi do heurystyk na samym tekście widocznym."""
        if not html:
            return ''
        t = re.sub(r'(?is)<script[^>]*>.*?</script>', ' ', html)
        t = re.sub(r'(?is)<style[^>]*>.*?</style>', ' ', t)
        t = re.sub(r'<[^>]+>', ' ', t)
        return re.sub(r'\s+', ' ', t).strip()
    
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
        plain_body = body.get('plain', '') or ''
        html_body = body.get('html', '') or ''

        features['body_length'] = len(plain_body) + len(html_body)
        features['plain_body_present'] = 1 if plain_body else 0
        features['html_body_present'] = 1 if html_body else 0

        combined_text = f'{plain_body}\n{html_body}'.lower()
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in combined_text:
                features['suspicious_keywords_count'] += 1
        
        features['exclamation_count'] = plain_body.count('!') + html_body.count('!')

        cap_sample = plain_body if plain_body else self._strip_html_to_text(html_body)
        if cap_sample:
            capitals = sum(1 for c in cap_sample if c.isupper())
            features['capital_letter_ratio'] = capitals / len(cap_sample)

        if html_body:
            html_lower = html_body.lower()
            features['contains_form'] = 1 if '<form' in html_lower else 0
            features['contains_script'] = 1 if '<script' in html_lower else 0
        
        return features
    
    def _extract_url_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z URL"""
        features = {
            'url_count': 0,
            'external_url_count': 0,
            'ip_address_url_count': 0,
            'shortened_url_count': 0,
            'suspicious_tld_count': 0,
            'url_domain_mismatch': 0,
        }

        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']

        from_email = email_data.get('from', {}).get('email', '')
        from_domain = ''
        if '@' in from_email:
            from_extracted = tldextract.extract(from_email.split('@')[-1])
            from_domain = f"{from_extracted.domain}.{from_extracted.suffix}"

        body = email_data.get('body', {})
        text = body.get('plain', '') + body.get('html', '')
        urls = self._extract_urls(text)

        seen_domains = set()
        features['url_count'] = len(urls)
        
        for url in urls:
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                features['ip_address_url_count'] += 1

            for shortener in shorteners:
                if shortener in url:
                    features['shortened_url_count'] += 1
                    break

            for tld in suspicious_tlds:
                if url.endswith(tld) or tld + '/' in url:
                    features['suspicious_tld_count'] += 1
                    break

            try:
                extracted = tldextract.extract(url)
                url_domain = f"{extracted.domain}.{extracted.suffix}"
                
                if from_domain and url_domain != from_domain and url_domain not in seen_domains:
                    features['external_url_count'] += 1
                    seen_domains.add(url_domain)
            except Exception:
                pass

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

        features['to_count'] = len(email_data.get('to', []))
        features['cc_count'] = len(email_data.get('cc', []))
        features['bcc_count'] = len(email_data.get('bcc', []))
        
        return features
    
    def _extract_subject_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z tematu wiadomości"""
        features = {
            'subject_length': 0,
            'subject_word_count': 0,
            'subject_has_urgent': 0,
            'subject_has_re_fw': 0,
            'subject_suspicious_keywords': 0,
            'subject_has_special_chars': 0,
            'subject_capital_ratio': 0.0,
            'subject_exclamation_count': 0,
        }
        
        subject = email_data.get('subject', '') or ''
        features['subject_length'] = len(subject)
        features['subject_word_count'] = len(subject.split())
        
        subject_lower = subject.lower()
        
        urgent_words = [
            'urgent', 'immediate', 'action required', 'act now',
            'warning', 'alert', 'important', 'attention', 'asap',
            'pilne', 'natychmiast', 'uwaga', 'ostrzeżenie',
        ]
        features['subject_has_urgent'] = 1 if any(w in subject_lower for w in urgent_words) else 0
        
        features['subject_has_re_fw'] = 1 if re.match(r'^(re|fw|fwd)\s*:', subject_lower) else 0
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in subject_lower:
                features['subject_suspicious_keywords'] += 1
        
        features['subject_has_special_chars'] = 1 if re.search(r'[^\w\s.,!?:;\'-]', subject) else 0
        
        if subject:
            capitals = sum(1 for c in subject if c.isupper())
            features['subject_capital_ratio'] = capitals / len(subject)
            features['subject_exclamation_count'] = subject.count('!')
        
        return features
    
    def _extract_network_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy sieciowe z łańcucha Received (adresy IP, hosty)"""
        features = {
            'received_ip_count': 0,
            'received_unique_ip_count': 0,
            'received_has_private_ip': 0,
            'received_hostname_count': 0,
            'received_chain_length': 0,
            'header_count': 0,
        }
        
        received = email_data.get('received', [])
        features['received_chain_length'] = len(received)
        
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        private_ip_pattern = re.compile(
            r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)'
        )
        
        all_ips = []
        hostnames = set()
        
        for hop in received:
            from_host = hop.get('from_host', '') or ''
            by_host = hop.get('by_host', '') or ''
            raw = hop.get('raw', '') or ''
            
            text = f"{from_host} {by_host} {raw}"
            
            ips_found = ip_pattern.findall(text)
            all_ips.extend(ips_found)
            
            for ip in ips_found:
                if private_ip_pattern.match(ip):
                    features['received_has_private_ip'] = 1
            
            if from_host and not ip_pattern.fullmatch(from_host):
                hostnames.add(from_host)
            if by_host and not ip_pattern.fullmatch(by_host):
                hostnames.add(by_host)
        
        features['received_ip_count'] = len(all_ips)
        features['received_unique_ip_count'] = len(set(all_ips))
        features['received_hostname_count'] = len(hostnames)
        
        headers = email_data.get('headers', {})
        features['header_count'] = len(headers)
        
        return features
    
    def _extract_mta_auth_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrahuje cechy z nagłówka Authentication-Results wstawionego przez serwer pocztowy(MTA) odbiorczy."""
        features = {
            'mta_spf_pass': 0,
            'mta_dkim_pass': 0,
            'mta_dmarc_pass': 0,
            'mta_auth_score': 0,
        }

        auth_header = email_data.get('authentication_results', '')
        if not auth_header:
            auth_header = email_data.get('headers', {}).get('Authentication-Results', '')
        if isinstance(auth_header, list):
            auth_header = ' '.join(auth_header)
        if not auth_header:
            return features

        auth_lower = auth_header.lower()
        if 'spf=pass' in auth_lower:
            features['mta_spf_pass'] = 1
        if 'dkim=pass' in auth_lower:
            features['mta_dkim_pass'] = 1
        if 'dmarc=pass' in auth_lower:
            features['mta_dmarc_pass'] = 1

        features['mta_auth_score'] = (
            features['mta_spf_pass'] + features['mta_dkim_pass'] + features['mta_dmarc_pass']
        )
        return features

    def _calculate_auth_alignment(self,
                                   spf_result: Optional[Dict[str, Any]],
                                   dkim_result: Optional[Dict[str, Any]],
                                   dmarc_result: Optional[Dict[str, Any]]) -> float:
        """
        Oblicza łączny wynik alignment autentykacji (0.0 = brak/fail, 1.0 = wszystko pass).
        Silniejsza cecha niż poszczególne flagi SPF/DKIM/DMARC.
        """
        score = 0.0
        checks = 0
        
        if spf_result:
            checks += 1
            result = spf_result.get('result', 'none')
            if result == 'pass':
                score += 1.0
            elif result == 'softfail':
                score += 0.3
            elif result == 'neutral':
                score += 0.5
        
        if dkim_result:
            checks += 1
            if dkim_result.get('valid'):
                score += 1.0
        
        if dmarc_result:
            checks += 1
            if dmarc_result.get('valid'):
                policy = dmarc_result.get('policy', 'none')
                if policy == 'reject':
                    score += 1.0
                elif policy == 'quarantine':
                    score += 0.7
                else:
                    score += 0.4
        
        return score / checks if checks > 0 else 0.0
    
    def _detect_display_name_spoofing(self, email_data: Dict[str, Any]) -> int:
        """
        Wykrywa spoofing display name 
        """
        from_data = email_data.get('from', {})
        from_name = from_data.get('name', '') or ''
        from_email = from_data.get('email', '') or ''
        
        email_in_name = re.search(r'[\w.\-+]+@[\w.\-]+\.\w+', from_name)
        if email_in_name:
            embedded_email = email_in_name.group(0).lower()
            if embedded_email != from_email.lower():
                return 1
        
        return 0
    
    def _extract_urls(self, text: str) -> List[str]:
        """Ekstrahuje URL z tekstu"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def get_feature_names(self) -> List[str]:
        """Zwraca nazwy cech"""
        return self.feature_names
    
    def extract_batch(self, 
                     email_data_list: List[Dict[str, Any]],
                     **kwargs) -> pd.DataFrame:
        """
        Ekstrahuje cechy z wielu wiadomości
        
        """
        features_list = []
        
        for i, email_data in enumerate(email_data_list):
            spf_result = kwargs.get('spf_results', [None])[i] if 'spf_results' in kwargs else None
            dkim_result = kwargs.get('dkim_results', [None])[i] if 'dkim_results' in kwargs else None
            dmarc_result = kwargs.get('dmarc_results', [None])[i] if 'dmarc_results' in kwargs else None
            header_analysis = kwargs.get('header_analyses', [None])[i] if 'header_analyses' in kwargs else None
            
            features = self.extract_features(
                email_data, spf_result, dkim_result, dmarc_result, header_analysis
            )
            features_list.append(features)
        
        return pd.DataFrame(features_list)

