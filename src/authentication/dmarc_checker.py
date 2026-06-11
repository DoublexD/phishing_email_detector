"""
DMARC Checker
Sprawdzanie polityk DMARC (Domain-based Message Authentication, Reporting & Conformance)
"""

import dns.resolver
import checkdmarc
from typing import Dict, Any, Optional
import logging

from utils.domain_utils import get_organizational_domain

logger = logging.getLogger(__name__)


class DMARCChecker:
    """Klasa do sprawdzania polityk DMARC"""
    
    def __init__(self, timeout: int = 5):
        """
        Inicjalizacja sprawdzarki DMARC
        
        """
        self.timeout = timeout
    
    def check_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Sprawdza politykę DMARC dla domeny
        
        """
        result = {
            'valid': False,
            'record': None,
            'policy': 'none',
            'subdomain_policy': 'none',
            'percentage': 100,
            'alignment': {},
            'reporting': {},
            'matched_domain': None,
            'errors': []
        }
        
        try:
            dmarc_record = self.get_dmarc_record(domain)
            matched_domain = domain

            if not dmarc_record:
                org_domain = get_organizational_domain(domain)
                if org_domain and org_domain != domain:
                    org_record = self.get_dmarc_record(org_domain)
                    if org_record:
                        dmarc_record = org_record
                        matched_domain = org_domain

            if not dmarc_record:
                result['errors'].append('Brak rekordu DMARC')
                return result

            result['record'] = dmarc_record
            result['matched_domain'] = matched_domain

            parsed = self._parse_dmarc_record(dmarc_record)
            result.update(parsed)

            if matched_domain != domain:
                subdomain_policy = parsed.get('subdomain_policy')
                if subdomain_policy and subdomain_policy != 'none':
                    result['policy'] = subdomain_policy

            result['valid'] = True

            logger.info(
                f"DMARC check for {domain}: policy={result['policy']} "
                f"(rekord z {matched_domain})"
            )
            
        except Exception as e:
            logger.error(f"Błąd sprawdzania DMARC: {e}")
            result['errors'].append(str(e))
        
        return result
    
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """
        Pobiera rekord DMARC dla domeny
        
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
        
        """
        parsed = {
            'policy': 'none',
            'subdomain_policy': 'none',
            'percentage': 100,
            'alignment': {
                'spf': 'r',
                'dkim': 'r'
            },
            'reporting': {
                'aggregate': [],
                'forensic': []
            },
            'options': {}
        }

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
        
        """
        alignment = {
            'spf_aligned': False,
            'dkim_aligned': False,
            'dmarc_pass': False
        }

        self.check_dmarc(from_domain)

        if spf_result.get('valid'):
            alignment['spf_aligned'] = True

        if dkim_result.get('valid'):
            alignment['dkim_aligned'] = True

        alignment['dmarc_pass'] = (
            alignment['spf_aligned'] or alignment['dkim_aligned']
        )
        
        return alignment
    
    def check_from_email_data(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sprawdza DMARC na podstawie wyparsowanych danych e-maila
        
        """
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
        
        """
        actions = {
            'none': 'ALLOW',
            'quarantine': 'QUARANTINE',
            'reject': 'REJECT'
        }
        return actions.get(policy.lower(), 'ALLOW')

