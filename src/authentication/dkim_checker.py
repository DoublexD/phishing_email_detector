"""
DKIM Checker
Sprawdzanie podpisów DKIM (DomainKeys Identified Mail)
"""

import dkim
import dns.resolver
from typing import Dict, Any, Optional, List
import logging
import email

logger = logging.getLogger(__name__)


class DKIMChecker:
    """Klasa do sprawdzania podpisów DKIM"""
    
    def __init__(self, timeout: int = 5):
        """
        Inicjalizacja sprawdzarki DKIM
        
        Args:
            timeout: Timeout dla zapytań DNS (sekundy)
        """
        self.timeout = timeout
    
    def check_dkim(self, raw_email: bytes) -> Dict[str, Any]:
        """
        Sprawdza podpis DKIM wiadomości
        
        Args:
            raw_email: Surowa wiadomość e-mail (bytes)
            
        Returns:
            Wyniki weryfikacji DKIM
        """
        result = {
            'valid': False,
            'result': 'none',
            'signatures': [],
            'errors': []
        }
        
        try:
            # Weryfikuj podpis DKIM
            verified = dkim.verify(raw_email)
            
            result['valid'] = verified
            result['result'] = 'pass' if verified else 'fail'
            
            # Ekstrahuj informacje o podpisie
            signatures = self._extract_dkim_signatures(raw_email)
            result['signatures'] = signatures
            
            logger.info(f"DKIM verification: {'PASS' if verified else 'FAIL'}")
            
        except dkim.ValidationError as e:
            logger.warning(f"DKIM validation error: {e}")
            result['result'] = 'fail'
            result['errors'].append(str(e))
        except Exception as e:
            logger.error(f"Błąd sprawdzania DKIM: {e}")
            result['result'] = 'temperror'
            result['errors'].append(str(e))
        
        return result
    
    def _extract_dkim_signatures(self, raw_email: bytes) -> List[Dict[str, Any]]:
        """
        Ekstrahuje informacje o podpisach DKIM z wiadomości
        
        Args:
            raw_email: Surowa wiadomość
            
        Returns:
            Lista podpisów DKIM
        """
        signatures = []
        
        try:
            # Parsuj e-mail
            msg = email.message_from_bytes(raw_email)
            
            # Szukaj nagłówków DKIM-Signature
            for header in msg.get_all('DKIM-Signature', []):
                signature_info = self._parse_dkim_signature(header)
                if signature_info:
                    signatures.append(signature_info)
        
        except Exception as e:
            logger.error(f"Błąd ekstrakcji podpisów DKIM: {e}")
        
        return signatures
    
    def _parse_dkim_signature(self, signature_header: str) -> Optional[Dict[str, str]]:
        """
        Parsuje nagłówek DKIM-Signature
        
        Args:
            signature_header: Zawartość nagłówka DKIM-Signature
            
        Returns:
            Sparsowane informacje o podpisie
        """
        try:
            signature_info = {}
            
            # Usuń znaki nowej linii i nadmiarowe spacje
            header = signature_header.replace('\n', '').replace('\r', '')
            header = ' '.join(header.split())
            
            # Parsuj pary klucz=wartość
            parts = header.split(';')
            for part in parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    signature_info[key.strip()] = value.strip()
            
            return signature_info
            
        except Exception as e:
            logger.error(f"Błąd parsowania DKIM signature: {e}")
            return None
    
    def get_dkim_public_key(self, selector: str, domain: str) -> Optional[str]:
        """
        Pobiera klucz publiczny DKIM z DNS
        
        Args:
            selector: Selektor DKIM
            domain: Domena
            
        Returns:
            Klucz publiczny lub None
        """
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=self.timeout)
            
            for rdata in answers:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if 'p=' in txt_string:  # Zawiera klucz publiczny
                    return txt_string
            
            return None
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Brak rekordu DKIM: {selector}._domainkey.{domain}")
            return None
        except Exception as e:
            logger.error(f"Błąd pobierania klucza DKIM: {e}")
            return None
    
    def check_from_email_data(self, email_data: Dict[str, Any], raw_email: bytes) -> Dict[str, Any]:
        """
        Sprawdza DKIM na podstawie wyparsowanych danych i surowej wiadomości
        
        Args:
            email_data: Wyparsowane dane e-maila
            raw_email: Surowa wiadomość (bytes)
            
        Returns:
            Wyniki sprawdzenia DKIM
        """
        # Sprawdź czy jest nagłówek DKIM-Signature
        dkim_signature = email_data.get('dkim_signature')
        
        if not dkim_signature:
            logger.info("Brak podpisu DKIM w wiadomości")
            return {
                'valid': False,
                'result': 'none',
                'signatures': [],
                'errors': ['Brak podpisu DKIM']
            }
        
        # Weryfikuj podpis
        return self.check_dkim(raw_email)

