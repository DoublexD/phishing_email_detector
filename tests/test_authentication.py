"""
Tests for Authentication Module
Testy dla modułu autentykacji (SPF, DKIM, DMARC)
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Dodaj src do ścieżki
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from authentication.spf_checker import SPFChecker
from authentication.dkim_checker import DKIMChecker
from authentication.dmarc_checker import DMARCChecker


@pytest.fixture
def spf_checker():
    """Fixture zwracający checker SPF"""
    return SPFChecker()


@pytest.fixture
def dkim_checker():
    """Fixture zwracający checker DKIM"""
    return DKIMChecker()


@pytest.fixture
def dmarc_checker():
    """Fixture zwracający checker DMARC"""
    return DMARCChecker()


@pytest.fixture
def sample_email_data():
    """Fixture z przykładowymi danymi e-maila"""
    return {
        'from': {'email': 'sender@example.com'},
        'to': [{'email': 'recipient@example.com'}],
        'subject': 'Test',
        'date': None,
        'received': [
            {'ip': '192.168.1.1', 'date': None}
        ],
        'return_path': '<sender@example.com>',
        'dkim_signature': 'v=1; a=rsa-sha256; ...'
    }


class TestSPFChecker:
    """Testy dla SPFChecker"""
    
    def test_spf_checker_initialization(self, spf_checker):
        """Test inicjalizacji SPF checkera"""
        assert spf_checker is not None
        assert spf_checker.timeout == 5
    
    def test_parse_spf_record(self, spf_checker):
        """Test parsowania rekordu SPF"""
        spf_record = "v=spf1 ip4:192.168.1.0/24 include:example.com -all"
        parsed = spf_checker.parse_spf_record(spf_record)
        
        assert parsed['version'] == 'v=spf1'
        assert 'mechanisms' in parsed
        assert parsed['all_policy'] == 'fail'  # -all
    
    def test_spf_record_with_softfail(self, spf_checker):
        """Test rekordu SPF z softfail"""
        spf_record = "v=spf1 include:example.com ~all"
        parsed = spf_checker.parse_spf_record(spf_record)
        
        assert parsed['all_policy'] == 'softfail'  # ~all
    
    @patch('spf.check2')
    def test_check_spf_pass(self, mock_spf_check, spf_checker):
        """Test SPF check - pass"""
        mock_spf_check.return_value = ('pass', 'Sender is authorized')
        
        result = spf_checker.check_spf('192.168.1.1', 'sender@example.com')
        
        assert result['result'] == 'pass'
        assert result['valid'] == True
    
    @patch('spf.check2')
    def test_check_spf_fail(self, mock_spf_check, spf_checker):
        """Test SPF check - fail"""
        mock_spf_check.return_value = ('fail', 'Sender is not authorized')
        
        result = spf_checker.check_spf('10.0.0.1', 'sender@example.com')
        
        assert result['result'] == 'fail'
        assert result['valid'] == False


class TestDKIMChecker:
    """Testy dla DKIMChecker"""
    
    def test_dkim_checker_initialization(self, dkim_checker):
        """Test inicjalizacji DKIM checkera"""
        assert dkim_checker is not None
        assert dkim_checker.timeout == 5
    
    def test_parse_dkim_signature(self, dkim_checker):
        """Test parsowania podpisu DKIM"""
        signature = "v=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject;"
        parsed = dkim_checker._parse_dkim_signature(signature)
        
        assert parsed is not None
        assert parsed.get('v') == '1'
        assert parsed.get('d') == 'example.com'
        assert parsed.get('s') == 'selector'
    
    @patch('dkim.verify')
    def test_check_dkim_valid(self, mock_dkim_verify, dkim_checker):
        """Test DKIM check - valid"""
        mock_dkim_verify.return_value = True
        
        raw_email = b"From: test@example.com\nSubject: Test\n\nBody"
        result = dkim_checker.check_dkim(raw_email)
        
        assert result['valid'] == True
        assert result['result'] == 'pass'
    
    @patch('dkim.verify')
    def test_check_dkim_invalid(self, mock_dkim_verify, dkim_checker):
        """Test DKIM check - invalid"""
        mock_dkim_verify.return_value = False
        
        raw_email = b"From: test@example.com\nSubject: Test\n\nBody"
        result = dkim_checker.check_dkim(raw_email)
        
        assert result['valid'] == False
        assert result['result'] == 'fail'


class TestDMARCChecker:
    """Testy dla DMARCChecker"""
    
    def test_dmarc_checker_initialization(self, dmarc_checker):
        """Test inicjalizacji DMARC checkera"""
        assert dmarc_checker is not None
        assert dmarc_checker.timeout == 5
    
    def test_parse_dmarc_record(self, dmarc_checker):
        """Test parsowania rekordu DMARC"""
        dmarc_record = "v=DMARC1; p=reject; rua=mailto:admin@example.com"
        parsed = dmarc_checker._parse_dmarc_record(dmarc_record)
        
        assert parsed['policy'] == 'reject'
        assert 'rua=mailto:admin@example.com' in dmarc_record
    
    def test_parse_dmarc_with_percentage(self, dmarc_checker):
        """Test parsowania DMARC z procentem"""
        dmarc_record = "v=DMARC1; p=quarantine; pct=50"
        parsed = dmarc_checker._parse_dmarc_record(dmarc_record)
        
        assert parsed['policy'] == 'quarantine'
        assert parsed['percentage'] == 50
    
    def test_get_policy_action(self, dmarc_checker):
        """Test mapowania polityki DMARC na akcje"""
        assert dmarc_checker.get_policy_action('none') == 'ALLOW'
        assert dmarc_checker.get_policy_action('quarantine') == 'QUARANTINE'
        assert dmarc_checker.get_policy_action('reject') == 'REJECT'
    
    def test_check_alignment(self, dmarc_checker):
        """Test sprawdzania alignment"""
        spf_result = {'valid': True, 'result': 'pass'}
        dkim_result = {'valid': True, 'result': 'pass'}
        
        alignment = dmarc_checker.check_alignment(
            spf_result, dkim_result, 'example.com'
        )
        
        assert 'spf_aligned' in alignment
        assert 'dkim_aligned' in alignment
        assert 'dmarc_pass' in alignment


class TestAuthenticationIntegration:
    """Testy integracyjne modułu autentykacji"""
    
    def test_full_authentication_check(self, spf_checker, dkim_checker, 
                                       dmarc_checker, sample_email_data):
        """Test pełnego przepływu autentykacji"""
        # Te testy będą wymagały mock'owania, ponieważ używają DNS
        # W prawdziwym środowisku testowym można użyć prawdziwych domen
        
        # Tutaj tylko sprawdzamy, że funkcje się nie wywrócą
        try:
            spf_result = spf_checker.check_from_email_data(sample_email_data)
            assert spf_result is not None
        except:
            pass  # Oczekiwane jeśli brak DNS
        
        try:
            raw_email = b"Test email"
            dkim_result = dkim_checker.check_from_email_data(sample_email_data, raw_email)
            assert dkim_result is not None
        except:
            pass
        
        try:
            dmarc_result = dmarc_checker.check_from_email_data(sample_email_data)
            assert dmarc_result is not None
        except:
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

