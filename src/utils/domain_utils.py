"""
Narzędzia do analizy domen.

Zawiera funkcje wyznaczające domenę organizacyjną (rejestrowalną) oraz
sprawdzające zgodność (alignment) domen wg zasad DMARC. Pozwala to odróżnić
legalny mailing masowy (np. From=spotify.com, Return-Path=em.spotify.com)
od faktycznego podszywania się pod inną domenę.
"""

import re
import tldextract
from typing import Optional

_ENVELOPE_RE = re.compile(r'<?\s*([^<>@\s]+@[\w.\-]+)\s*>?')


def _hostname_from(value: str) -> str:
    """Sprowadza dowolne pole (adres e-mail, host, URL) do samej nazwy hosta."""
    if not value:
        return ''
    host = value.strip().strip('<>').strip().lower()
    if '@' in host:
        host = host.rsplit('@', 1)[-1]
    host = host.split('/')[0].split(':')[0]
    return host.strip().strip('.')


def get_organizational_domain(value: str) -> str:
    """Zwraca domenę organizacyjną, np. ``legal.spotify.com`` -> ``spotify.com``."""
    host = _hostname_from(value)
    if not host:
        return ''
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


def same_organizational_domain(a: str, b: str) -> bool:
    """Sprawdza, czy dwa pola należą do tej samej domeny organizacyjnej."""
    da = get_organizational_domain(a)
    db = get_organizational_domain(b)
    return bool(da) and da == db


def extract_email_address(value: str) -> Optional[str]:
    """Wyciąga adres e-mail z pola w stylu ``<bounces+...@em.spotify.com>``."""
    if not value:
        return None
    match = _ENVELOPE_RE.search(value)
    return match.group(1).lower() if match else None
