"""
Pobieranie e-maili z serwera IMAP
"""

import sys
sys.path.append('src')

from email_parser.imap_client import IMAPClient
from pathlib import Path
from datetime import datetime

# Konfiguracja (ZMIEŃ NA SWOJE DANE!)
IMAP_CONFIG = {
    'server': 'imap.gmail.com',  # Dla Gmail
    # 'server': 'outlook.office365.com',  # Dla Outlook
    'port': 993,
    'username': 'your-email@gmail.com',  # ZMIEŃ!
    'password': 'your-app-password',     # ZMIEŃ! (App Password, nie zwykłe hasło)
    'folder': 'INBOX',
    'use_ssl': True
}

def download_emails(max_emails=10, output_dir='data/raw'):
    """
    Pobiera e-maile z serwera IMAP
    
    Args:
        max_emails: Maksymalna liczba e-maili do pobrania
        output_dir: Katalog gdzie zapisać e-maile
    """
    
    print("=" * 60)
    print("POBIERANIE E-MAILI Z SERWERA IMAP")
    print("=" * 60)
    
    # Sprawdź konfigurację
    if 'your-email' in IMAP_CONFIG['username']:
        print("\n BŁĄD: Musisz skonfigurować IMAP_CONFIG!")
        print("\nEdytuj scripts/download_emails_imap.py i zmień:")
        print("  - username: Twój adres e-mail")
        print("  - password: App Password (nie zwykłe hasło!)")
        print("\n Jak uzyskać App Password:")
        print("  Gmail: https://support.google.com/accounts/answer/185833")
        print("  Outlook: https://support.microsoft.com/en-us/account-billing/")
        return
    
    # Utwórz katalog
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print(f"\n Łączenie z: {IMAP_CONFIG['server']}")
    print(f" Maksymalnie: {max_emails} e-maili")
    print(f" Zapisywanie do: {output_dir}/\n")
    
    try:
        # Połącz z serwerem
        with IMAPClient(**IMAP_CONFIG) as client:
            print("✓ Połączono z serwerem IMAP")
            
            # Pobierz e-maile
            emails = client.fetch_all_emails(limit=max_emails)
            
            if not emails:
                print("\n Brak e-maili do pobrania")
                return
            
            print(f"\n Pobrano {len(emails)} e-maili. Zapisywanie...\n")
            
            # Zapisz każdy e-mail
            for i, raw_email in enumerate(emails, 1):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = output_path / f"email_{timestamp}_{i:03d}.eml"
                
                with open(filename, 'wb') as f:
                    f.write(raw_email)
                
                print(f"  ✓ {filename.name}")
            
            print(f"\n Zapisano {len(emails)} e-maili w: {output_dir}/")
            print(f"\n Możesz teraz analizować te e-maile używając API lub skryptów")
            
    except Exception as e:
        print(f"\n BŁĄD: {e}")
        print("\n Sprawdź:")
        print("  1. Czy dane logowania są poprawne")
        print("  2. Czy IMAP jest włączony na koncie")
        print("  3. Czy używasz App Password (nie zwykłego hasła)")
        print("  4. Czy firewall nie blokuje połączenia")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Pobierz e-maile z IMAP')
    parser.add_argument('--max', type=int, default=10, help='Maksymalna liczba e-maili')
    parser.add_argument('--output', type=str, default='data/raw', help='Katalog wyjściowy')
    
    args = parser.parse_args()
    
    download_emails(max_emails=args.max, output_dir=args.output)

