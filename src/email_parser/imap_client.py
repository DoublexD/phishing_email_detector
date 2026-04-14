"""
IMAP Client
Klient do pobierania wiadomości z serwera IMAP w trybie ciągłym
"""

import imaplib
import email
from typing import List, Dict, Any, Optional, Callable
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
        """
        Inicjalizacja klienta IMAP
        
        Args:
            server: Adres serwera IMAP
            username: Nazwa użytkownika
            password: Hasło
            port: Port (domyślnie 993 dla SSL)
            use_ssl: Czy używać SSL
            folder: Folder do monitorowania
        """
        self.server = server
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.folder = folder
        self.connection: Optional[imaplib.IMAP4_SSL] = None
        self.is_connected = False
    
    def connect(self) -> bool:
        """
        Nawiązuje połączenie z serwerem IMAP
        
        Returns:
            True jeśli połączenie udane
        """
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.server, self.port)
            else:
                self.connection = imaplib.IMAP4(self.server, self.port)
            
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
        """
        Pobiera nowe (nieodczytane) wiadomości
        
        Args:
            mark_as_seen: Czy oznaczyć wiadomości jako przeczytane
            
        Returns:
            Lista surowych wiadomości e-mail
        """
        if not self.is_connected:
            if not self.connect():
                return []
        
        try:
            # Szukaj nieodczytanych wiadomości
            status, messages = self.connection.search(None, 'UNSEEN')
            
            if status != 'OK':
                logger.error("Błąd wyszukiwania wiadomości")
                return []
            
            email_ids = messages[0].split()
            emails = []
            
            for email_id in email_ids:
                # Pobierz wiadomość
                status, msg_data = self.connection.fetch(
                    email_id, 
                    '(RFC822)' if mark_as_seen else '(BODY.PEEK[])'
                )
                
                if status == 'OK':
                    raw_email = msg_data[0][1]
                    emails.append(raw_email)
            
            logger.info(f"Pobrano {len(emails)} nowych wiadomości")
            return emails
            
        except Exception as e:
            logger.error(f"Błąd pobierania wiadomości: {e}")
            self.is_connected = False
            return []
    
    def fetch_all_emails(self, limit: Optional[int] = None) -> List[bytes]:
        """
        Pobiera wszystkie wiadomości z folderu
        
        Args:
            limit: Maksymalna liczba wiadomości do pobrania
            
        Returns:
            Lista surowych wiadomości e-mail
        """
        if not self.is_connected:
            if not self.connect():
                return []
        
        try:
            status, messages = self.connection.search(None, 'ALL')
            
            if status != 'OK':
                logger.error("Błąd wyszukiwania wiadomości")
                return []
            
            email_ids = messages[0].split()
            
            if limit:
                email_ids = email_ids[-limit:]  # Pobierz ostatnie N wiadomości
            
            emails = []
            for email_id in email_ids:
                status, msg_data = self.connection.fetch(email_id, '(BODY.PEEK[])')
                
                if status == 'OK':
                    raw_email = msg_data[0][1]
                    emails.append(raw_email)
            
            logger.info(f"Pobrano {len(emails)} wiadomości")
            return emails
            
        except Exception as e:
            logger.error(f"Błąd pobierania wiadomości: {e}")
            return []
    
    def monitor_continuous(self, 
                          callback: Callable[[bytes], None],
                          interval: int = 60,
                          max_iterations: Optional[int] = None):
        """
        Monitoruje folder w trybie ciągłym
        
        Args:
            callback: Funkcja wywoływana dla każdej nowej wiadomości
            interval: Interwał sprawdzania (w sekundach)
            max_iterations: Maksymalna liczba iteracji (None = nieskończenie)
        """
        iteration = 0
        
        logger.info(f"Start monitorowania ciągłego (interwał: {interval}s)")
        
        try:
            while True:
                if max_iterations and iteration >= max_iterations:
                    break
                
                # Pobierz nowe wiadomości
                new_emails = self.fetch_new_emails(mark_as_seen=False)
                
                # Przetwórz każdą nową wiadomość
                for raw_email in new_emails:
                    try:
                        callback(raw_email)
                    except Exception as e:
                        logger.error(f"Błąd przetwarzania wiadomości: {e}")
                
                # Czekaj przed kolejnym sprawdzeniem
                time.sleep(interval)
                iteration += 1
                
        except KeyboardInterrupt:
            logger.info("Przerwano monitorowanie")
        except Exception as e:
            logger.error(f"Błąd w monitorowaniu ciągłym: {e}")
        finally:
            self.disconnect()
    
    def get_folder_list(self) -> List[str]:
        """
        Pobiera listę folderów na serwerze
        
        Returns:
            Lista nazw folderów
        """
        if not self.is_connected:
            if not self.connect():
                return []
        
        try:
            status, folders = self.connection.list()
            if status == 'OK':
                folder_list = []
                for folder in folders:
                    # Parsuj nazwę folderu
                    folder_name = folder.decode().split('"')[-2]
                    folder_list.append(folder_name)
                return folder_list
            return []
            
        except Exception as e:
            logger.error(f"Błąd pobierania listy folderów: {e}")
            return []
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

