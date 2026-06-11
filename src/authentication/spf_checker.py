"""
SPF Checker
Sprawdzanie rekordów SPF (Sender Policy Framework)
"""

import spf
import dns.resolver
import re
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SPFChecker:
    """Klasa do sprawdzania rekordów SPF"""

    RESULTS = {
        'pass': 'Weryfikacja SPF pomyślna',
        'fail': 'Weryfikacja SPF nieudana',
        'softfail': 'Weryfikacja SPF: soft fail',
        'neutral': 'Weryfikacja SPF: neutralna',
        'none': 'Brak rekordu SPF',
        'temperror': 'Tymczasowy błąd DNS',
        'permerror': 'Błąd w rekordzie SPF'
    }
    
    def __init__(self, timeout: int = 5):
        """
        Inicjalizacja sprawdzarki SPF
        
        """
        self.timeout = timeout
    
    def check_spf(self, 
                  sender_ip: str, 
                  sender_email: str, 
                  helo_domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Sprawdza rekord SPF dla danej wiadomości
        
        """
        result = {
            'result': 'none',
            'explanation': '',
            'valid': False,
            'header': '',
            'raw_result': None
        }
        
        try:
            if '@' in sender_email:
                domain = sender_email.split('@')[1]
            else:
                domain = sender_email

            spf_result, explanation = spf.check2(
                i=sender_ip,
                s=sender_email,
                h=helo_domain or domain
            )
            
            result['result'] = spf_result
            result['explanation'] = explanation
            result['valid'] = spf_result == 'pass'
            result['raw_result'] = spf_result

            result['header'] = self._generate_spf_header(
                spf_result, sender_ip, sender_email, explanation
            )
            
            logger.info(f"SPF check for {sender_email} from {sender_ip}: {spf_result}")
            
        except Exception as e:
            logger.error(f"Błąd sprawdzania SPF: {e}")
            result['result'] = 'temperror'
            result['explanation'] = str(e)
        
        return result
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """
        Pobiera rekord SPF dla domeny
        
        """
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
            
            for rdata in answers:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if txt_string.startswith('v=spf1'):
                    return txt_string
            
            return None
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domena nie istnieje: {domain}")
            return None
        except dns.resolver.NoAnswer:
            logger.warning(f"Brak rekordu SPF dla: {domain}")
            return None
        except Exception as e:
            logger.error(f"Błąd pobierania rekordu SPF: {e}")
            return None
    
    def parse_spf_record(self, spf_record: str) -> Dict[str, Any]:
        """
        Parsuje rekord SPF
        
        """
        parsed = {
            'version': '',
            'mechanisms': [],
            'modifiers': {},
            'all_policy': 'neutral'
        }
        
        if not spf_record:
            return parsed
        
        parts = spf_record.split()

        if parts and parts[0].startswith('v=spf'):
            parsed['version'] = parts[0]
            parts = parts[1:]

        for part in parts:
            if '=' in part and not part.startswith(('+', '-', '~', '?')):
                key, value = part.split('=', 1)
                parsed['modifiers'][key] = value
            else:
                parsed['mechanisms'].append(part)

                if part in ['all', '+all', '-all', '~all', '?all']:
                    if part.startswith('-'):
                        parsed['all_policy'] = 'fail'
                    elif part.startswith('~'):
                        parsed['all_policy'] = 'softfail'
                    elif part.startswith('?'):
                        parsed['all_policy'] = 'neutral'
                    elif part.startswith('+') or part == 'all':
                        parsed['all_policy'] = 'pass'
        
        return parsed
    
    def _generate_spf_header(self, 
                            result: str, 
                            client_ip: str, 
                            sender: str, 
                            explanation: str) -> str:
        """Generuje nagłówek Received-SPF"""
        return (
            f"{result} (spf-detector: {explanation}) "
            f"client-ip={client_ip}; envelope-from={sender};"
        )
    
    def check_from_email_data(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sprawdza SPF na podstawie wyparsowanych danych e-maila

        SPF weryfikuje adres koperty (MAIL FROM / Return-Path), a nie pola
        ``From`` widocznego dla użytkownika. Adres IP brany jest z pierwszego
        (najnowszego) nagłówka ``Received``, który zawiera publiczny adres IP,
        czyli z serwera, który nawiązał połączenie z MTA odbiorcy.
        """
        received = email_data.get('received', [])
        sender_ip = None

        for entry in received:
            if entry.get('ip'):
                sender_ip = entry['ip']
                break
        if not sender_ip and received:
            sender_ip = received[-1].get('ip')

        if not sender_ip:
            logger.warning("Nie znaleziono IP nadawcy w nagłówkach")
            return {
                'result': 'none',
                'explanation': 'Brak informacji o IP nadawcy',
                'valid': False
            }

        sender_email = self._get_envelope_sender(email_data)
        if not sender_email:
            logger.warning("Brak adresu nadawcy")
            return {
                'result': 'none',
                'explanation': 'Brak adresu nadawcy',
                'valid': False
            }

        return self.check_spf(sender_ip, sender_email)

    def _get_envelope_sender(self, email_data: Dict[str, Any]) -> str:
        """
        Zwraca adres koperty (Return-Path) używany do weryfikacji SPF.

        Gdy Return-Path jest niedostępny, jako rozwiązanie awaryjne używane jest
        pole From.
        """
        return_path = email_data.get('return_path', '') or ''
        match = re.search(r'<?\s*([^<>@\s]+@[\w.\-]+)\s*>?', return_path)
        if match:
            return match.group(1).lower()
        return email_data.get('from', {}).get('email', '')

