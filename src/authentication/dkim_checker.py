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
        
        """
        self.timeout = timeout
    
    def check_dkim(self, raw_email: bytes) -> Dict[str, Any]:
        """
        Sprawdza podpis DKIM wiadomości
        
        """
        result = {
            'valid': False,
            'result': 'none',
            'signatures': [],
            'errors': []
        }
        
        try:
            verified = dkim.verify(raw_email)
            
            result['valid'] = verified
            result['result'] = 'pass' if verified else 'fail'

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
        
        """
        signatures = []
        
        try:
            msg = email.message_from_bytes(raw_email)

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
        
        """
        try:
            signature_info = {}

            header = signature_header.replace('\n', '').replace('\r', '')
            header = ' '.join(header.split())

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
        
        """
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=self.timeout)
            
            for rdata in answers:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if 'p=' in txt_string:
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
        
        """
        dkim_signature = email_data.get('dkim_signature')
        
        if not dkim_signature:
            logger.info("Brak podpisu DKIM w wiadomości")
            return {
                'valid': False,
                'result': 'none',
                'signatures': [],
                'errors': ['Brak podpisu DKIM']
            }

        return self.check_dkim(raw_email)

