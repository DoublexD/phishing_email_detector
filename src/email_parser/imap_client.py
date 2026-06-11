"""
IMAP Client
Klient do pobierania wiadomości
"""

import imaplib
import email
from typing import List, Dict, Any, Optional, Callable, Union
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class IMAPClient:
    """Klasa do pobierania e-maili z serwera IMAP"""
    
    def __init__(self, 
                 server: str,
                 username: str,
                 password: str,
                 port: int = 993,
                 use_ssl: bool = True,
                 folder: str = 'INBOX'):
        self.server = server
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.folder = folder
        self.connection: Optional[Union[imaplib.IMAP4_SSL, imaplib.IMAP4]] = None
        self.is_connected = False
        self._last_seen_uid: Optional[int] = None
        self._processed_uids: set = set()
    
    def connect(self) -> bool:
        """Nawiązuje połączenie z serwerem IMAP"""
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.server, self.port)
            else:
                self.connection = imaplib.IMAP4(self.server, self.port)
            
            assert self.connection is not None
            self.connection.login(self.username, self.password)
            self.connection.select(self.folder)
            self.is_connected = True
            logger.info(f"Połączono z serwerem IMAP: {self.server}")
            return True
            
        except Exception as e:
            logger.error(f"Błąd połączenia z IMAP: {e}")
            self.is_connected = False
            return False
    
    def disconnect(self):
        """Rozłącza się z serwerem IMAP"""
        try:
            if self.connection:
                self.connection.close()
                self.connection.logout()
                self.is_connected = False
                logger.info("Rozłączono z serwerem IMAP")
        except Exception as e:
            logger.error(f"Błąd rozłączania z IMAP: {e}")
    
    def fetch_new_emails(self, mark_as_seen: bool = False) -> List[bytes]:
        """Pobiera nowe wiadomości, śledząc ostatni przetworzony UID."""
        if not self.is_connected:
            if not self.connect():
                return []
        
        try:
            assert self.connection is not None
            self.connection.noop()

            status, messages = self.connection.uid('search', None, 'ALL')  # type: ignore[arg-type]
            if status != 'OK':
                logger.error("Błąd wyszukiwania wiadomości")
                return []

            all_uids = [int(u) for u in messages[0].split()] if messages[0] else []

            if self._last_seen_uid is None:
                self._processed_uids = set(all_uids)
                self._last_seen_uid = max(all_uids) if all_uids else 0
                logger.info(f"Inicjalizacja: {len(all_uids)} istniejących wiadomości, ostatni UID={self._last_seen_uid}")
                return []

            new_uids = [u for u in all_uids if u not in self._processed_uids]

            emails = []
            for uid in new_uids:
                fetch_cmd = '(RFC822)' if mark_as_seen else '(BODY.PEEK[])'
                status, msg_data = self.connection.uid('fetch', str(uid), fetch_cmd)

                if status == 'OK' and msg_data[0] is not None:
                    part = msg_data[0]
                    if isinstance(part, tuple):
                        raw_email = part[1]
                        emails.append(raw_email)  # type: ignore[arg-type]
                    self._processed_uids.add(uid)
                    self._last_seen_uid = max(self._last_seen_uid, uid)

            logger.info(f"Pobrano {len(emails)} nowych wiadomości")
            return emails
            
        except Exception as e:
            logger.error(f"Błąd pobierania wiadomości: {e}")
            self.is_connected = False
            return []
    
    def fetch_all_emails(self, limit: Optional[int] = None) -> List[bytes]:
        """Pobiera wszystkie wiadomości z folderu"""
        if not self.is_connected:
            if not self.connect():
                return []
        
        try:
            assert self.connection is not None
            status, messages = self.connection.search(None, 'ALL')
            
            if status != 'OK':
                logger.error("Błąd wyszukiwania wiadomości")
                return []
            
            email_ids = messages[0].split()
            
            if limit:
                email_ids = email_ids[-limit:]
            
            emails = []
            for email_id in email_ids:
                status, msg_data = self.connection.fetch(email_id, '(BODY.PEEK[])')
                
                if status == 'OK' and msg_data[0] is not None:
                    part = msg_data[0]
                    if isinstance(part, tuple):
                        raw_email = part[1]
                        emails.append(raw_email)  # type: ignore[arg-type]
            
            logger.info(f"Pobrano {len(emails)} wiadomości")
            return emails
            
        except Exception as e:
            logger.error(f"Błąd pobierania wiadomości: {e}")
            return []
    
    def monitor_continuous(self, 
                          callback: Callable[[bytes], None],
                          interval: int = 60,
                          max_iterations: Optional[int] = None):
        """Monitoruje folder w trybie ciągłym"""
        iteration = 0
        
        logger.info(f"Start monitorowania ciągłego (interwał: {interval}s)")
        
        try:
            while True:
                if max_iterations and iteration >= max_iterations:
                    break

                new_emails = self.fetch_new_emails(mark_as_seen=False)

                for raw_email in new_emails:
                    try:
                        callback(raw_email)
                    except Exception as e:
                        logger.error(f"Błąd przetwarzania wiadomości: {e}")

                time.sleep(interval)
                iteration += 1
                
        except KeyboardInterrupt:
            logger.info("Przerwano monitorowanie")
        except Exception as e:
            logger.error(f"Błąd w monitorowaniu ciągłym: {e}")
        finally:
            self.disconnect()
    
    def get_folder_list(self) -> List[str]:
        """Pobiera listę folderów na serwerze"""
        if not self.is_connected:
            if not self.connect():
                return []
        
        try:
            assert self.connection is not None
            status, folders = self.connection.list()
            if status == 'OK':
                folder_list = []
                for folder in folders:
                    if isinstance(folder, bytes):
                        folder_name = folder.decode().split('"')[-2]
                        folder_list.append(folder_name)
                return folder_list
            return []
            
        except Exception as e:
            logger.error(f"Błąd pobierania listy folderów: {e}")
            return []
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

