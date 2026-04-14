"""
Authentication Module
Moduł weryfikacji autentyczności e-maili (SPF, DKIM, DMARC)
"""

from .spf_checker import SPFChecker
from .dkim_checker import DKIMChecker
from .dmarc_checker import DMARCChecker

__all__ = ['SPFChecker', 'DKIMChecker', 'DMARCChecker']

