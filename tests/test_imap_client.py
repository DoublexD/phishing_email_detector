"""
Tests for IMAPClient
Testy klienta IMAP — połączenie, pobieranie wiadomości i monitorowanie
z zamockowaną biblioteką imaplib (bez kontaktu z prawdziwym serwerem).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from email_parser.imap_client import IMAPClient


def make_client():
    return IMAPClient(
        server='imap.example.com',
        username='user@example.com',
        password='secret',
        folder='INBOX',
    )


class TestInitialization:
    """Testy inicjalizacji klienta"""

    def test_initial_state(self):
        client = make_client()
        assert client.server == 'imap.example.com'
        assert client.is_connected is False
        assert client.connection is None
        assert client._last_seen_uid is None
        assert client._processed_uids == set()


class TestConnect:
    """Testy nawiązywania połączenia"""

    @patch('imaplib.IMAP4_SSL')
    def test_connect_success_uses_ssl(self, mock_ssl):
        mock_conn = MagicMock()
        mock_ssl.return_value = mock_conn

        client = make_client()
        assert client.connect() is True
        assert client.is_connected is True
        mock_ssl.assert_called_once_with('imap.example.com', 993)
        mock_conn.login.assert_called_once_with('user@example.com', 'secret')
        mock_conn.select.assert_called_once_with('INBOX')

    @patch('imaplib.IMAP4')
    def test_connect_plaintext_when_ssl_disabled(self, mock_imap):
        mock_imap.return_value = MagicMock()
        client = IMAPClient('imap.example.com', 'u', 'p', use_ssl=False, port=143)
        assert client.connect() is True
        mock_imap.assert_called_once_with('imap.example.com', 143)

    @patch('imaplib.IMAP4_SSL', side_effect=OSError('connection refused'))
    def test_connect_failure_returns_false(self, mock_ssl):
        client = make_client()
        assert client.connect() is False
        assert client.is_connected is False


class TestFetchNewEmails:
    """Testy inkrementalnego pobierania wiadomości po UID"""

    def test_first_call_initializes_baseline(self):
        """Pierwsze wywołanie ustala punkt odniesienia i nie zwraca starych wiadomości"""
        client = make_client()
        conn = MagicMock()
        conn.noop.return_value = ('OK', [b''])
        conn.uid.return_value = ('OK', [b'1 2 3'])
        client.connection = conn
        client.is_connected = True

        result = client.fetch_new_emails()

        assert result == []
        assert client._last_seen_uid == 3
        assert client._processed_uids == {1, 2, 3}

    def test_returns_only_new_uids(self):
        """Po inicjalizacji zwracane są tylko nowe UID-y, a stan jest aktualizowany"""
        client = make_client()
        conn = MagicMock()
        conn.noop.return_value = ('OK', [b''])

        def uid_side_effect(command, *args):
            if command == 'search':
                return ('OK', [b'1 2 3 4'])
            if command == 'fetch':
                return ('OK', [(b'4 (BODY[] {11}', b'raw-email-4')])
            return ('NO', [b''])

        conn.uid.side_effect = uid_side_effect
        client.connection = conn
        client.is_connected = True
        client._last_seen_uid = 3
        client._processed_uids = {1, 2, 3}

        emails = client.fetch_new_emails()

        assert emails == [b'raw-email-4']
        assert 4 in client._processed_uids
        assert client._last_seen_uid == 4

    @patch.object(IMAPClient, 'connect', return_value=False)
    def test_returns_empty_when_connect_fails(self, mock_connect):
        client = make_client()
        client.is_connected = False
        assert client.fetch_new_emails() == []

    def test_search_error_returns_empty(self):
        client = make_client()
        conn = MagicMock()
        conn.noop.return_value = ('OK', [b''])
        conn.uid.return_value = ('NO', [b''])
        client.connection = conn
        client.is_connected = True
        client._last_seen_uid = 0
        client._processed_uids = set()

        assert client.fetch_new_emails() == []


class TestFetchAllEmails:
    """Testy pobierania wszystkich wiadomości"""

    def test_fetch_all_with_limit(self):
        client = make_client()
        conn = MagicMock()
        conn.search.return_value = ('OK', [b'1 2 3'])
        conn.fetch.return_value = ('OK', [(b'header', b'raw')])
        client.connection = conn
        client.is_connected = True

        emails = client.fetch_all_emails(limit=2)
        assert len(emails) == 2

    def test_fetch_all_search_error(self):
        client = make_client()
        conn = MagicMock()
        conn.search.return_value = ('NO', [b''])
        client.connection = conn
        client.is_connected = True

        assert client.fetch_all_emails() == []


class TestFolderList:
    """Testy listy folderów"""

    def test_parses_folder_names(self):
        client = make_client()
        conn = MagicMock()
        conn.list.return_value = (
            'OK',
            [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "Sent"'],
        )
        client.connection = conn
        client.is_connected = True

        folders = client.get_folder_list()
        assert 'INBOX' in folders
        assert 'Sent' in folders


class TestDisconnect:
    """Testy rozłączania"""

    def test_disconnect_calls_close_and_logout(self):
        client = make_client()
        conn = MagicMock()
        client.connection = conn
        client.is_connected = True

        client.disconnect()

        conn.close.assert_called_once()
        conn.logout.assert_called_once()
        assert client.is_connected is False


class TestContextManager:
    """Testy menedżera kontekstu"""

    @patch('imaplib.IMAP4_SSL')
    def test_context_manager_connects_and_disconnects(self, mock_ssl):
        mock_ssl.return_value = MagicMock()
        with make_client() as client:
            assert client.is_connected is True
        assert client.is_connected is False


class TestMonitorContinuous:
    """Testy monitorowania ciągłego"""

    def test_callback_invoked_for_each_email(self):
        client = make_client()
        client.fetch_new_emails = MagicMock(return_value=[b'e1', b'e2'])
        received = []

        client.monitor_continuous(
            callback=received.append, interval=0, max_iterations=1
        )

        assert received == [b'e1', b'e2']

    def test_callback_error_does_not_stop_monitor(self):
        client = make_client()
        client.fetch_new_emails = MagicMock(return_value=[b'bad', b'good'])
        handled = []

        def callback(raw):
            if raw == b'bad':
                raise ValueError('boom')
            handled.append(raw)

        client.monitor_continuous(callback=callback, interval=0, max_iterations=1)
        assert handled == [b'good']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
