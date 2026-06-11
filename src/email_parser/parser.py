"""
Email Parser
Parsowanie wiadomości e-mail i ekstrakcja podstawowych informacji
"""

import email
import email.message
import base64
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EmailParser:
    """Klasa do parsowania wiadomości e-mail"""
    
    def __init__(self):
        self.parser = BytesParser(policy=policy.default)
    
    def parse_raw_email(self, raw_email: bytes) -> Dict[str, Any]:
        try:
            msg = self.parser.parsebytes(raw_email)
            return self._extract_email_data(msg)
        except Exception as e:
            logger.error(f"Błąd parsowania e-maila: {e}")
            raise
    
    def parse_email_string(self, email_string: str) -> Dict[str, Any]:
        return self.parse_raw_email(email_string.encode('utf-8'))
    
    def _extract_email_data(self, msg: email.message.EmailMessage) -> Dict[str, Any]:
        """Ekstrahuje dane z obiektu EmailMessage"""
        
        email_data = {
            'headers': self._extract_headers(msg),
            'from': self._parse_email_address(msg.get('From', '')),
            'to': self._parse_email_addresses(msg.get('To', '')),
            'cc': self._parse_email_addresses(msg.get('Cc', '')),
            'bcc': self._parse_email_addresses(msg.get('Bcc', '')),
            'subject': msg.get('Subject', ''),
            'date': self._parse_date(msg.get('Date', '')),
            'message_id': msg.get('Message-ID', ''),
            'reply_to': self._parse_email_address(msg.get('Reply-To', '')),
            'return_path': msg.get('Return-Path', ''),
            'received': self._extract_received_headers(msg),
            'body': self._extract_body(msg),
            'attachments': self._extract_attachments(msg),
            'authentication_results': msg.get('Authentication-Results', ''),
            'received_spf': msg.get('Received-SPF', ''),
            'dkim_signature': msg.get('DKIM-Signature', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'mime_version': msg.get('MIME-Version', ''),
            'content_type': msg.get_content_type(),
        }
        
        return email_data
    
    def _extract_headers(self, msg: email.message.EmailMessage) -> Dict[str, str]:
        headers = {}
        for key, value in msg.items():
            if key in headers:
                if not isinstance(headers[key], list):
                    headers[key] = [headers[key]]
                headers[key].append(value)
            else:
                headers[key] = value
        return headers
    
    def _parse_email_address(self, address_str: str) -> Dict[str, str]:
        if not address_str:
            return {'name': '', 'email': ''}

        from email.utils import parseaddr
        name, email_addr = parseaddr(address_str)
        
        return {
            'name': name,
            'email': email_addr.lower() if email_addr else ''
        }
    
    def _parse_email_addresses(self, addresses_str: str) -> List[Dict[str, str]]:
        """Parsuje wiele adresów e-mail"""
        if not addresses_str:
            return []
        
        from email.utils import getaddresses
        addresses = getaddresses([addresses_str])
        
        return [
            {'name': name, 'email': addr.lower() if addr else ''}
            for name, addr in addresses
        ]
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parsuje datę z nagłówka Date"""
        if not date_str:
            return None
        s = date_str.strip()
        if not s:
            return None

        from email.utils import parsedate_to_datetime
        try:
            return parsedate_to_datetime(s)
        except (TypeError, ValueError):
            pass

        try:
            from dateutil import parser as date_parser
        except ImportError:
            date_parser = None

        if date_parser:
            try:
                return date_parser.parse(s, dayfirst=True)
            except (ValueError, OverflowError, TypeError):
                pass

        rfc_infix = re.search(
            r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+\w{3}\s+\d{4}\s+[\d:]+\s*'
            r'(?:[+-]\d{4}|[+-]\d{2}:\d{2}|\w+)?',
            s,
            re.IGNORECASE,
        )
        if rfc_infix:
            frag = rfc_infix.group(0)
            try:
                return parsedate_to_datetime(frag)
            except (TypeError, ValueError):
                if date_parser:
                    try:
                        return date_parser.parse(frag)
                    except (ValueError, OverflowError, TypeError):
                        pass

        if date_parser:
            try:
                return date_parser.parse(s, fuzzy=True)
            except (ValueError, OverflowError, TypeError):
                pass

        logger.debug("Nie można sparsować daty: %r", s[:120])
        return None
    
    def _extract_received_headers(self, msg: email.message.EmailMessage) -> List[Dict[str, Any]]:
        """Ekstrahuje i parsuje nagłówki Received"""
        received_headers = []
        
        for header in msg.get_all('Received', []):
            parsed = self._parse_received_header(header)
            if parsed:
                received_headers.append(parsed)
        
        return received_headers
    
    def _parse_received_header(self, header: str) -> Optional[Dict[str, Any]]:
        """Parsuje pojedynczy nagłówek Received"""
        try:
            ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
            ip_match = re.search(ip_pattern, header)

            date_pattern = r';\s*(.+)$'
            date_match = re.search(date_pattern, header)

            from_pattern = r'from\s+([^\s\[]+)'
            from_match = re.search(from_pattern, header)
            
            by_pattern = r'by\s+([^\s]+)'
            by_match = re.search(by_pattern, header)
            
            return {
                'raw': header,
                'ip': ip_match.group(1) if ip_match else None,
                'date': self._parse_date(date_match.group(1)) if date_match else None,
                'from_host': from_match.group(1) if from_match else None,
                'by_host': by_match.group(1) if by_match else None,
            }
        except Exception as e:
            logger.warning(f"Nie można sparsować nagłówka Received: {e}")
            return None
    
    def _extract_body(self, msg: email.message.EmailMessage) -> Dict[str, str]:
        """Ekstrahuje treść wiadomości"""
        body = {
            'plain': '',
            'html': ''
        }
        
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain':
                        body['plain'] += part.get_content()
                    elif content_type == 'text/html':
                        body['html'] += part.get_content()
            else:
                content_type = msg.get_content_type()
                content = msg.get_content()
                if content_type == 'text/plain':
                    body['plain'] = content
                elif content_type == 'text/html':
                    body['html'] = content
        except Exception as e:
            logger.warning(f"Nie można wyekstrahować treści: {e}")
        
        return body
    
    def _extract_attachments(self, msg: email.message.EmailMessage) -> List[Dict[str, Any]]:
        """Ekstrahuje informacje o załącznikach"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True) or b'')
                        })
        
        return attachments
    
    def extract_urls(self, text: str) -> List[str]:
        """Ekstrahuje URL z tekstu"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def get_all_urls(self, email_data: Dict[str, Any]) -> List[str]:
        """Ekstrahuje wszystkie URL z wiadomości"""
        urls = []

        if email_data.get('body', {}).get('plain'):
            urls.extend(self.extract_urls(email_data['body']['plain']))

        if email_data.get('body', {}).get('html'):
            urls.extend(self.extract_urls(email_data['body']['html']))

        return list(set(urls))

