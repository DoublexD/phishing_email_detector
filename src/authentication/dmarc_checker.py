"""
DMARC Checker
Sprawdzanie polityk DMARC (Domain-based Message Authentication, Reporting & Conformance)
"""

import dns.resolver
import checkdmarc
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class DMARCChecker:
    """Klasa do sprawdzania polityk DMARC"""
    
    def __init__(self, timeout: int = 5):
        """
        Inicjalizacja sprawdzarki DMARC
        
        Args:
            timeout: Timeout dla zapytań DNS (sekundy)
        """
        self.timeout = timeout
    
    def check_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Sprawdza politykę DMARC dla domeny
        
        Args:
            domain: Domena do sprawdzenia
            
        Returns:
            Wyniki sprawdzenia DMARC
        """
        result = {
            'valid': False,
            'record': None,
            'policy': 'none',
            'subdomain_policy': 'none',
            'percentage': 100,
            'alignment': {},
            'reporting': {},
            'errors': []
        }
        
        try:
            # Pobierz rekord DMARC
            dmarc_record = self.get_dmarc_record(domain)
            
            if not dmarc_record:
                result['errors'].append('Brak rekordu DMARC')
                return result
            
            result['record'] = dmarc_record
            
            # Parsuj rekord
            parsed = self._parse_dmarc_record(dmarc_record)
            result.update(parsed)
            result['valid'] = True
            
            logger.info(f"DMARC check for {domain}: policy={parsed['policy']}")
            
        except Exception as e:
            logger.error(f"Błąd sprawdzania DMARC: {e}")
            result['errors'].append(str(e))
        
        return result
    
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """
        Pobiera rekord DMARC dla domeny
        
        Args:
            domain: Domena do sprawdzenia
            
        Returns:
            Rekord DMARC lub None
        """
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.timeout)
            
            for rdata in answers:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if txt_string.startswith('v=DMARC'):
                    return txt_string
            
            return None
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Brak rekordu DMARC dla: {domain}")
            return None
        except dns.resolver.NoAnswer:
            logger.warning(f"Brak odpowiedzi DNS dla DMARC: {domain}")
            return None
        except Exception as e:
            logger.error(f"Błąd pobierania rekordu DMARC: {e}")
            return None
    
    def _parse_dmarc_record(self, dmarc_record: str) -> Dict[str, Any]:
        """
        Parsuje rekord DMARC
        
        Args:
            dmarc_record: Rekord DMARC do sparsowania
            
        Returns:
            Sparsowane komponenty rekordu
        """
        parsed = {
            'policy': 'none',
            'subdomain_policy': 'none',
            'percentage': 100,
            'alignment': {
                'spf': 'r',  # relaxed
                'dkim': 'r'  # relaxed
            },
            'reporting': {
                'aggregate': [],
                'forensic': []
            },
            'options': {}
        }
        
        # Parsuj pary tag=value
        parts = dmarc_record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                tag, value = part.split('=', 1)
                tag = tag.strip()
                value = value.strip()
                
                if tag == 'v':
                    parsed['version'] = value
                elif tag == 'p':
                    parsed['policy'] = value
                elif tag == 'sp':
                    parsed['subdomain_policy'] = value
                elif tag == 'pct':
                    try:
                        parsed['percentage'] = int(value)
                    except ValueError:
                        parsed['percentage'] = 100
                elif tag == 'adkim':
                    parsed['alignment']['dkim'] = value
                elif tag == 'aspf':
                    parsed['alignment']['spf'] = value
                elif tag == 'rua':
                    parsed['reporting']['aggregate'] = value.split(',')
                elif tag == 'ruf':
                    parsed['reporting']['forensic'] = value.split(',')
                else:
                    parsed['options'][tag] = value
        
        return parsed
    
    def check_alignment(self, 
                       spf_result: Dict[str, Any],
                       dkim_result: Dict[str, Any],
                       from_domain: str) -> Dict[str, Any]:
        """
        Sprawdza alignment (zgodność) SPF i DKIM z DMARC
        
        Args:
            spf_result: Wynik sprawdzenia SPF
            dkim_result: Wynik sprawdzenia DKIM
            from_domain: Domena z pola From
            
        Returns:
            Wyniki sprawdzenia alignment
        """
        alignment = {
            'spf_aligned': False,
            'dkim_aligned': False,
            'dmarc_pass': False
        }
        
        # Pobierz politykę DMARC
        dmarc_policy = self.check_dmarc(from_domain)
        
        # Sprawdź alignment SPF
        if spf_result.get('valid'):
            alignment['spf_aligned'] = True
        
        # Sprawdź alignment DKIM
        if dkim_result.get('valid'):
            alignment['dkim_aligned'] = True
        
        # DMARC pass wymaga przynajmniej jednego aligned mechanism
        alignment['dmarc_pass'] = (
            alignment['spf_aligned'] or alignment['dkim_aligned']
        )
        
        return alignment
    
    def check_from_email_data(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sprawdza DMARC na podstawie wyparsowanych danych e-maila
        
        Args:
            email_data: Wyparsowane dane e-maila
            
        Returns:
            Wyniki sprawdzenia DMARC
        """
        # Pobierz domenę nadawcy
        from_email = email_data.get('from', {}).get('email', '')
        if not from_email or '@' not in from_email:
            logger.warning("Brak lub nieprawidłowy adres nadawcy")
            return {
                'valid': False,
                'errors': ['Brak adresu nadawcy']
            }
        
        domain = from_email.split('@')[1]
        return self.check_dmarc(domain)
    
    def get_policy_action(self, policy: str) -> str:
        """
        Zwraca rekomendowaną akcję na podstawie polityki DMARC
        
        Args:
            policy: Polityka DMARC (none, quarantine, reject)
            
        Returns:
            Rekomendowana akcja
        """
        actions = {
            'none': 'ALLOW',
            'quarantine': 'QUARANTINE',
            'reject': 'REJECT'
        }
        return actions.get(policy.lower(), 'ALLOW')

