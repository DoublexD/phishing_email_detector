"""
Tests for Email Parser
Testy dla modułu parsowania e-maili
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from email_parser.parser import EmailParser
from email_parser.header_analyzer import HeaderAnalyzer


@pytest.fixture
def email_parser():
    """Fixture zwracający parser e-maili"""
    return EmailParser()


@pytest.fixture
def header_analyzer():
    """Fixture zwracający analizator nagłówków"""
    return HeaderAnalyzer()


@pytest.fixture
def sample_email():
    """Fixture z przykładową wiadomością e-mail"""
    return """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.
"""


@pytest.fixture
def sample_email_with_received():
    """Fixture z wiadomością zawierającą nagłówki Received"""
    return """Received: from mail.example.com ([192.168.1.1])
    by server.example.com with ESMTP id ABC123
    for <recipient@example.com>; Mon, 1 Jan 2024 12:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

Test body
"""


class TestEmailParser:
    """Testy dla EmailParser"""
    
    def test_parse_email_string(self, email_parser, sample_email):
        """Test parsowania e-maila z string"""
        result = email_parser.parse_email_string(sample_email)
        
        assert result is not None
        assert result['from']['email'] == 'sender@example.com'
        assert result['to'][0]['email'] == 'recipient@example.com'
        assert result['subject'] == 'Test Email'
    
    def test_parse_from_address(self, email_parser):
        """Test parsowania adresu nadawcy"""
        result = email_parser._parse_email_address('John Doe <john@example.com>')
        
        assert result['name'] == 'John Doe'
        assert result['email'] == 'john@example.com'
    
    def test_parse_multiple_addresses(self, email_parser):
        """Test parsowania wielu adresów"""
        addresses = 'john@example.com, jane@example.com'
        result = email_parser._parse_email_addresses(addresses)
        
        assert len(result) == 2
        assert result[0]['email'] == 'john@example.com'
        assert result[1]['email'] == 'jane@example.com'
    
    def test_extract_received_headers(self, email_parser, sample_email_with_received):
        """Test ekstrakcji nagłówków Received"""
        email_data = email_parser.parse_email_string(sample_email_with_received)
        received = email_data['received']
        
        assert len(received) > 0
        assert received[0]['ip'] is not None or received[0]['from_host'] is not None
    
    def test_extract_urls(self, email_parser):
        """Test ekstrakcji URL-i"""
        text = "Visit https://example.com and http://test.com for more info"
        urls = email_parser.extract_urls(text)
        
        assert len(urls) == 2
        assert 'https://example.com' in urls
        assert 'http://test.com' in urls
    
    def test_empty_email(self, email_parser):
        """Test parsowania pustej wiadomości — zwraca dane z pustymi polami"""
        result = email_parser.parse_email_string("")
        assert isinstance(result, dict)
        assert result.get('subject') is None or result.get('subject') == ''


class TestHeaderAnalyzer:
    """Testy dla HeaderAnalyzer"""
    
    def test_analyze_headers(self, header_analyzer, email_parser, sample_email):
        """Test analizy nagłówków"""
        email_data = email_parser.parse_email_string(sample_email)
        result = header_analyzer.analyze(email_data)
        
        assert 'missing_headers' in result
        assert 'anomaly_score' in result
        assert isinstance(result['anomaly_score'], float)
    
    def test_check_missing_headers(self, header_analyzer, email_parser):
        """Test wykrywania brakujących nagłówków"""
        minimal_email = "Subject: Test\n\nBody"
        email_data = email_parser.parse_email_string(minimal_email)
        result = header_analyzer.analyze(email_data)
        
        assert len(result['missing_headers']) > 0
        assert 'From' in result['missing_headers'] or 'Date' in result['missing_headers']
    
    def test_from_mismatch_detection(self, header_analyzer, email_parser):
        """Test wykrywania niezgodności From/Return-Path"""
        email = """From: sender@example.com
Return-Path: <different@other.com>
To: recipient@example.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 +0000

Body
"""
        email_data = email_parser.parse_email_string(email)
        result = header_analyzer.analyze(email_data)
        
        assert result['from_mismatch'] == True
    
    def test_anomaly_score_calculation(self, header_analyzer, email_parser, sample_email):
        """Test obliczania wyniku anomalii"""
        email_data = email_parser.parse_email_string(sample_email)
        result = header_analyzer.analyze(email_data)
        
        assert 0 <= result['anomaly_score'] <= 1


class TestEmailParserIntegration:
    """Testy integracyjne parsera"""
    
    def test_full_parsing_workflow(self, email_parser, header_analyzer, sample_email_with_received):
        """Test pełnego workflow parsowania i analizy"""
        email_data = email_parser.parse_email_string(sample_email_with_received)

        header_analysis = header_analyzer.analyze(email_data)

        assert email_data is not None
        assert header_analysis is not None
        assert 'anomaly_score' in header_analysis
        
    def test_malformed_email_handling(self, email_parser):
        """Nieprawidłowy e-mail nie crashuje — parser zwraca spójną strukturę danych"""
        malformed = "This is not a valid email format"

        result = email_parser.parse_email_string(malformed)

        assert isinstance(result, dict)
        assert 'from' in result
        assert isinstance(result['body'], dict)
        assert 'received' in result
        assert not result['from'].get('email')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

