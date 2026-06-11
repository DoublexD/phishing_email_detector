"""
Tests for Feature Extractor
Testy ekstrakcji cech
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from feature_extraction.extractor import FeatureExtractor


@pytest.fixture
def extractor():
    return FeatureExtractor()


@pytest.fixture
def minimal_email():
    return {
        'from': {'email': 'sender@example.com', 'name': 'Sender'},
        'to': [{'email': 'recipient@example.com'}],
        'subject': 'Test',
        'date': None,
        'body': {'plain': 'Hello world', 'html': ''},
        'received': [],
        'attachments': [],
        'cc': [],
        'bcc': [],
        'headers': {},
    }


class TestAuthFeatures:
    """Testy ekstrakcji cech autentykacji"""

    def test_spf_pass(self, extractor):
        features = extractor._extract_auth_features(
            {'result': 'pass'}, None, None
        )
        assert features['spf_pass'] == 1
        assert features['spf_fail'] == 0

    def test_spf_fail(self, extractor):
        features = extractor._extract_auth_features(
            {'result': 'fail'}, None, None
        )
        assert features['spf_fail'] == 1
        assert features['spf_pass'] == 0

    def test_spf_temperror_mapped_to_softfail(self, extractor):
        """Bug fix: SPF temperror powinien być mapowany na softfail, nie tworzyć klucz spf_temperror"""
        features = extractor._extract_auth_features(
            {'result': 'temperror'}, None, None
        )
        assert features['spf_softfail'] == 1
        assert 'spf_temperror' not in features

    def test_spf_permerror_mapped_to_softfail(self, extractor):
        """Bug fix: SPF permerror powinien być mapowany na softfail"""
        features = extractor._extract_auth_features(
            {'result': 'permerror'}, None, None
        )
        assert features['spf_softfail'] == 1
        assert 'spf_permerror' not in features

    def test_spf_unknown_result_falls_to_none(self, extractor):
        """Całkowicie nieznany wynik powinien mapować na spf_none"""
        features = extractor._extract_auth_features(
            {'result': 'GARBAGE_VALUE'}, None, None
        )
        assert features['spf_none'] == 1

    def test_spf_none_input(self, extractor):
        features = extractor._extract_auth_features(None, None, None)
        assert features['spf_pass'] == 0
        assert features['spf_fail'] == 0
        assert features['spf_none'] == 0

    def test_dkim_valid(self, extractor):
        features = extractor._extract_auth_features(
            None, {'valid': True, 'signatures': ['sig1']}, None
        )
        assert features['dkim_valid'] == 1
        assert features['dkim_signature_count'] == 1

    def test_dkim_fail(self, extractor):
        features = extractor._extract_auth_features(
            None, {'valid': False, 'result': 'fail', 'signatures': []}, None
        )
        assert features['dkim_invalid'] == 1

    def test_dkim_none(self, extractor):
        features = extractor._extract_auth_features(
            None, {'valid': False, 'result': 'none', 'signatures': []}, None
        )
        assert features['dkim_none'] == 1

    def test_dmarc_valid_reject(self, extractor):
        features = extractor._extract_auth_features(
            None, None, {'valid': True, 'policy': 'reject'}
        )
        assert features['dmarc_exists'] == 1
        assert features['dmarc_policy_reject'] == 1

    def test_dmarc_no_record(self, extractor):
        features = extractor._extract_auth_features(
            None, None, {'valid': False}
        )
        assert features['dmarc_exists'] == 0


class TestURLFeatures:
    """Testy ekstrakcji cech URL"""

    def test_url_count(self, extractor):
        email = {
            'from': {'email': 'sender@example.com'},
            'body': {'plain': 'Visit https://example.com and https://test.com', 'html': ''},
        }
        features = extractor._extract_url_features(email)
        assert features['url_count'] == 2

    def test_url_domain_deduplication(self, extractor):
        """Bug fix: wiele linków do tej samej domeny nie powinno zawyżać external_url_count"""
        email = {
            'from': {'email': 'sender@example.com'},
            'body': {
                'plain': '',
                'html': 'https://other.com/page1 https://other.com/page2 https://other.com/page3'
            },
        }
        features = extractor._extract_url_features(email)
        assert features['external_url_count'] == 1

    def test_subdomain_matching(self, extractor):
        """Bug fix: mail.aliexpress.com i aliexpress.com to ta sama domena"""
        email = {
            'from': {'email': 'noreply@mail.aliexpress.com'},
            'body': {
                'plain': 'https://aliexpress.com/item1 https://aliexpress.com/item2',
                'html': ''
            },
        }
        features = extractor._extract_url_features(email)
        assert features['external_url_count'] == 0

    def test_ip_address_url(self, extractor):
        email = {
            'from': {'email': 'sender@example.com'},
            'body': {'plain': 'http://192.168.1.1/login', 'html': ''},
        }
        features = extractor._extract_url_features(email)
        assert features['ip_address_url_count'] == 1

    def test_shortened_url(self, extractor):
        email = {
            'from': {'email': 'sender@example.com'},
            'body': {'plain': 'https://bit.ly/abc123', 'html': ''},
        }
        features = extractor._extract_url_features(email)
        assert features['shortened_url_count'] == 1

    def test_suspicious_tld(self, extractor):
        email = {
            'from': {'email': 'sender@example.com'},
            'body': {'plain': 'https://evil.xyz/phish', 'html': ''},
        }
        features = extractor._extract_url_features(email)
        assert features['suspicious_tld_count'] == 1

    def test_no_urls(self, extractor):
        email = {
            'from': {'email': 'sender@example.com'},
            'body': {'plain': 'Just plain text no links', 'html': ''},
        }
        features = extractor._extract_url_features(email)
        assert features['url_count'] == 0
        assert features['external_url_count'] == 0


class TestContentFeatures:
    """Testy ekstrakcji cech z treści"""

    def test_suspicious_keywords(self, extractor):
        email = {
            'body': {
                'plain': 'URGENT! Verify your account immediately or it will be suspended.',
                'html': ''
            }
        }
        features = extractor._extract_content_features(email)
        assert features['suspicious_keywords_count'] >= 3

    def test_suspicious_keywords_html_only(self, extractor):
        """Phishing często jest tylko text/html — słowa kluczowe muszą być widoczne w HTML."""
        email = {
            'body': {
                'plain': '',
                'html': '<p>URGENT! Verify your account immediately.</p>',
            }
        }
        features = extractor._extract_content_features(email)
        assert features['suspicious_keywords_count'] >= 3

    def test_exclamation_marks(self, extractor):
        email = {'body': {'plain': 'Act now!!! Do it!!', 'html': ''}}
        features = extractor._extract_content_features(email)
        assert features['exclamation_count'] == 5

    def test_capital_ratio(self, extractor):
        email = {'body': {'plain': 'AAAA', 'html': ''}}
        features = extractor._extract_content_features(email)
        assert features['capital_letter_ratio'] == 1.0

    def test_html_form_detection(self, extractor):
        email = {'body': {'plain': '', 'html': '<form action="/steal">Login</form>'}}
        features = extractor._extract_content_features(email)
        assert features['contains_form'] == 1

    def test_html_script_detection(self, extractor):
        email = {'body': {'plain': '', 'html': '<script>alert("xss")</script>'}}
        features = extractor._extract_content_features(email)
        assert features['contains_script'] == 1

    def test_empty_body(self, extractor):
        email = {'body': {'plain': '', 'html': ''}}
        features = extractor._extract_content_features(email)
        assert features['body_length'] == 0
        assert features['suspicious_keywords_count'] == 0


class TestAttachmentFeatures:
    """Testy ekstrakcji cech załączników"""

    def test_executable_detection(self, extractor):
        email = {'attachments': [{'filename': 'malware.exe', 'size': 1024}]}
        features = extractor._extract_attachment_features(email)
        assert features['has_executable'] == 1

    def test_archive_detection(self, extractor):
        email = {'attachments': [{'filename': 'data.zip', 'size': 2048}]}
        features = extractor._extract_attachment_features(email)
        assert features['has_archive'] == 1

    def test_no_attachments(self, extractor):
        email = {'attachments': []}
        features = extractor._extract_attachment_features(email)
        assert features['attachment_count'] == 0
        assert features['has_executable'] == 0


class TestSenderFeatures:
    """Testy ekstrakcji cech nadawcy"""

    def test_noreply_detection(self, extractor):
        email = {'from': {'email': 'noreply@example.com', 'name': ''}, 'to': [], 'cc': [], 'bcc': []}
        features = extractor._extract_sender_features(email)
        assert features['from_contains_noreply'] == 1

    def test_numbers_in_email(self, extractor):
        email = {'from': {'email': 'user123@example.com', 'name': ''}, 'to': [], 'cc': [], 'bcc': []}
        features = extractor._extract_sender_features(email)
        assert features['from_has_numbers'] == 1


class TestSubjectFeatures:
    """Testy ekstrakcji cech tematu (subject)"""

    def test_subject_urgency(self, extractor):
        email = {'subject': 'URGENT: Action Required Immediately!'}
        features = extractor._extract_subject_features(email)
        assert features['subject_has_urgent'] == 1
        assert features['subject_exclamation_count'] == 1

    def test_subject_re_fw(self, extractor):
        email = {'subject': 'Re: Meeting tomorrow'}
        features = extractor._extract_subject_features(email)
        assert features['subject_has_re_fw'] == 1

    def test_subject_empty(self, extractor):
        email = {'subject': ''}
        features = extractor._extract_subject_features(email)
        assert features['subject_length'] == 0
        assert features['subject_has_urgent'] == 0

    def test_subject_none(self, extractor):
        email = {}
        features = extractor._extract_subject_features(email)
        assert features['subject_length'] == 0

    def test_subject_capital_ratio(self, extractor):
        email = {'subject': 'ALL CAPS HERE'}
        features = extractor._extract_subject_features(email)
        assert features['subject_capital_ratio'] > 0.5


class TestNetworkFeatures:
    """Testy ekstrakcji cech sieciowych"""

    def test_received_chain(self, extractor):
        email = {
            'received': [
                {'from_host': 'mail1.example.com', 'by_host': 'mail2.example.com',
                 'raw': 'from mail1.example.com (1.2.3.4) by mail2.example.com'},
            ],
            'headers': {'From': 'test', 'Date': 'today'},
        }
        features = extractor._extract_network_features(email)
        assert features['received_chain_length'] == 1
        assert features['received_ip_count'] >= 1
        assert features['received_hostname_count'] >= 1

    def test_private_ip_detection(self, extractor):
        email = {
            'received': [
                {'from_host': '', 'by_host': '', 'raw': 'from 192.168.1.1 by 10.0.0.1'},
            ],
            'headers': {},
        }
        features = extractor._extract_network_features(email)
        assert features['received_has_private_ip'] == 1

    def test_empty_received(self, extractor):
        email = {'received': [], 'headers': {}}
        features = extractor._extract_network_features(email)
        assert features['received_chain_length'] == 0
        assert features['received_ip_count'] == 0


class TestDisplayNameSpoofing:
    """Testy wykrywania spoofingu display name"""

    def test_spoofed_display_name(self, extractor):
        email = {
            'from': {
                'name': 'admin@bank.com',
                'email': 'attacker@evil.com'
            }
        }
        assert extractor._detect_display_name_spoofing(email) == 1

    def test_matching_display_name(self, extractor):
        email = {
            'from': {
                'name': 'admin@example.com',
                'email': 'admin@example.com'
            }
        }
        assert extractor._detect_display_name_spoofing(email) == 0

    def test_normal_display_name(self, extractor):
        email = {
            'from': {
                'name': 'John Doe',
                'email': 'john@example.com'
            }
        }
        assert extractor._detect_display_name_spoofing(email) == 0


class TestAuthAlignment:
    """Testy obliczania alignment score autentykacji"""

    def test_all_pass(self, extractor):
        score = extractor._calculate_auth_alignment(
            {'result': 'pass'},
            {'valid': True},
            {'valid': True, 'policy': 'reject'}
        )
        assert score == 1.0

    def test_all_fail(self, extractor):
        score = extractor._calculate_auth_alignment(
            {'result': 'fail'},
            {'valid': False},
            {'valid': False}
        )
        assert score < 0.2

    def test_no_auth(self, extractor):
        score = extractor._calculate_auth_alignment(None, None, None)
        assert score == 0.0


class TestFullExtraction:
    """Testy pełnej ekstrakcji cech"""

    def test_full_extraction_returns_series(self, extractor, minimal_email):
        import pandas as pd
        features = extractor.extract_features(minimal_email)
        assert isinstance(features, pd.Series)
        assert len(features) > 40

    def test_new_features_present(self, extractor, minimal_email):
        features = extractor.extract_features(minimal_email)
        assert 'subject_length' in features.index
        assert 'auth_alignment_score' in features.index
        assert 'from_display_name_spoofing' in features.index
        assert 'received_chain_length' in features.index

    def test_feature_names_stored(self, extractor, minimal_email):
        extractor.extract_features(minimal_email)
        assert len(extractor.feature_names) > 0

    def test_batch_extraction(self, extractor, minimal_email):
        import pandas as pd
        df = extractor.extract_batch([minimal_email, minimal_email])
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
