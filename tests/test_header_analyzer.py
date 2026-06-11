"""
Tests for Header Analyzer fixes
Testy naprawionej obsługi zduplikowanych nagłówków i anomaly score
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from email_parser.header_analyzer import HeaderAnalyzer


@pytest.fixture
def analyzer():
    return HeaderAnalyzer()


@pytest.fixture
def email_with_all_headers():
    return {
        'from': {'email': 'sender@example.com'},
        'to': [{'email': 'recipient@example.com'}],
        'date': None,
        'headers': {
            'From': 'sender@example.com',
            'Date': 'Mon, 1 Jan 2024 12:00:00 +0000',
            'Message-ID': '<abc@example.com>',
            'Received': 'from mail.example.com',
        },
        'received': [
            {'ip': '192.168.1.1', 'date': None, 'from_host': 'mail.example.com', 'by_host': 'server.example.com'}
        ],
        'return_path': '<sender@example.com>',
        'reply_to': None,
    }


class TestDuplicateHeaders:
    """Testy obsługi zduplikowanych nagłówków"""

    def test_list_header_value_no_crash(self, analyzer):
        """Bug fix: gdy header_value jest listą, nie powinno crashować na re.search"""
        email = {
            'from': {'email': 'sender@example.com'},
            'headers': {
                'X-Mailer': ['YahooMailClassic', 'SomethingElse'],
                'From': 'sender@example.com',
                'Date': 'Mon, 1 Jan 2024 12:00:00 +0000',
                'Message-ID': '<abc@example.com>',
                'Received': 'from mail.example.com',
            },
            'received': [],
            'date': None,
            'return_path': '',
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert 'suspicious_patterns' in result
        assert len(result['suspicious_patterns']) > 0

    def test_string_header_value_still_works(self, analyzer):
        """Zwykły string header nadal działa poprawnie"""
        email = {
            'from': {'email': 'sender@example.com'},
            'headers': {
                'User-Agent': 'python-requests/2.28',
                'From': 'sender@example.com',
                'Date': 'Mon, 1 Jan 2024 12:00:00 +0000',
                'Message-ID': '<abc@example.com>',
                'Received': 'from mail.example.com',
            },
            'received': [],
            'date': None,
            'return_path': '',
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert any(p['header'] == 'User-Agent' for p in result['suspicious_patterns'])

    def test_empty_header_skipped(self, analyzer):
        """Pusty nagłówek nie powinien generować wzorców"""
        email = {
            'from': {'email': 'sender@example.com'},
            'headers': {
                'X-Mailer': '',
                'From': 'sender@example.com',
                'Date': 'Mon, 1 Jan 2024 12:00:00 +0000',
                'Message-ID': '<abc@example.com>',
                'Received': 'from mail.example.com',
            },
            'received': [],
            'date': None,
            'return_path': '',
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert not any(p['header'] == 'X-Mailer' for p in result['suspicious_patterns'])


class TestMissingHeaders:
    """Testy brakujących nagłówków"""

    def test_all_headers_present(self, analyzer, email_with_all_headers):
        result = analyzer.analyze(email_with_all_headers)
        assert len(result['missing_headers']) == 0

    def test_missing_from(self, analyzer):
        email = {
            'from': {},
            'headers': {
                'Date': 'Mon, 1 Jan 2024 12:00:00 +0000',
                'Message-ID': '<abc@example.com>',
                'Received': 'from mail.example.com',
            },
            'received': [{'ip': '1.1.1.1', 'date': None}],
            'date': None,
            'return_path': '',
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert 'From' in result['missing_headers']


class TestFromMismatch:
    """Testy niezgodności From/Return-Path"""

    def test_matching_domains(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'return_path': '<sender@example.com>',
            'headers': {},
            'received': [],
            'date': None,
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert result['from_mismatch'] is False

    def test_mismatched_domains(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'return_path': '<bounce@different.com>',
            'headers': {},
            'received': [],
            'date': None,
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert result['from_mismatch'] is True

    def test_no_return_path(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'return_path': '',
            'headers': {},
            'received': [],
            'date': None,
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert result['from_mismatch'] is False


class TestReplyToMismatch:
    """Testy niezgodności Reply-To"""

    def test_matching_reply_to(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'reply_to': {'email': 'other@example.com'},
            'return_path': '',
            'headers': {},
            'received': [],
            'date': None,
        }
        result = analyzer.analyze(email)
        assert result['reply_to_mismatch'] is False

    def test_mismatched_reply_to(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'reply_to': {'email': 'attacker@evil.com'},
            'return_path': '',
            'headers': {},
            'received': [],
            'date': None,
        }
        result = analyzer.analyze(email)
        assert result['reply_to_mismatch'] is True


class TestAnomalyScore:
    """Testy obliczania anomaly score"""

    def test_score_in_range(self, analyzer, email_with_all_headers):
        result = analyzer.analyze(email_with_all_headers)
        assert 0.0 <= result['anomaly_score'] <= 1.0

    def test_clean_email_low_score(self, analyzer, email_with_all_headers):
        result = analyzer.analyze(email_with_all_headers)
        assert result['anomaly_score'] < 0.5

    def test_suspicious_email_high_score(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'return_path': '<bounce@other.com>',
            'reply_to': {'email': 'attacker@evil.com'},
            'headers': {},
            'received': [],
            'date': None,
        }
        result = analyzer.analyze(email)
        assert result['anomaly_score'] > 0.3

    def test_score_capped_at_1(self, analyzer):
        """Score nie powinno przekroczyć 1.0 nawet przy wielu anomaliach"""
        email = {
            'from': {'email': 'sender@example.com'},
            'return_path': '<bounce@other.com>',
            'reply_to': {'email': 'attacker@evil.com'},
            'headers': {
                'X-Mailer': 'YahooMailClassic',
                'User-Agent': 'python-requests',
            },
            'received': [],
            'date': None,
        }
        result = analyzer.analyze(email)
        assert result['anomaly_score'] <= 1.0


class TestHopCount:
    """Testy liczby hopów"""

    def test_hop_count(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'headers': {},
            'received': [
                {'ip': '1.1.1.1', 'date': None},
                {'ip': '2.2.2.2', 'date': None},
                {'ip': '3.3.3.3', 'date': None},
            ],
            'date': None,
            'return_path': '',
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert result['hop_count'] == 3

    def test_no_hops(self, analyzer):
        email = {
            'from': {'email': 'sender@example.com'},
            'headers': {},
            'received': [],
            'date': None,
            'return_path': '',
            'reply_to': None,
        }
        result = analyzer.analyze(email)
        assert result['hop_count'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
