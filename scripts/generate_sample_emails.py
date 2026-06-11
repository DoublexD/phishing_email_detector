"""
Generator polskich przykładowych e-maili do testowania.

Generuje wiadomości typowe dla polskiego ruchu pocztowego z lat 2024-2025:
- Phishing: banki, telekomy, paczki/dostawy, urzędy, portale aukcyjne
- Legitymne: faktury, newslettery, powiadomienia o dostawach, HR

Każde uruchomienie tworzy losowe warianty (kwoty, daty, numery, frazy),
dzięki czemu skrypt produkuje sensowny zbiór różnorodnych wiadomości
zamiast powtarzających się szablonów.
"""

import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

POLISH_NAMES = [
    "Anna Kowalska", "Jan Nowak", "Katarzyna Wiśniewska", "Piotr Wójcik",
    "Małgorzata Kowalczyk", "Tomasz Kamiński", "Agnieszka Lewandowska",
    "Marcin Zieliński", "Joanna Szymańska", "Krzysztof Woźniak",
    "Magdalena Dąbrowska", "Adam Kozłowski", "Barbara Jankowska",
    "Paweł Mazur", "Ewa Krawczyk", "Łukasz Piotrowski",
]

POLISH_CITIES = [
    "Warszawa", "Kraków", "Wrocław", "Poznań", "Gdańsk", "Łódź",
    "Szczecin", "Bydgoszcz", "Lublin", "Białystok", "Katowice", "Gdynia",
]

BANKS = [
    ("mBank", "mbank.pl"),
    ("PKO Bank Polski", "pkobp.pl"),
    ("ING Bank Śląski", "ing.pl"),
    ("Santander Bank Polska", "santander.pl"),
    ("Bank Pekao", "pekao.com.pl"),
    ("Millennium Bank", "bankmillennium.pl"),
    ("Alior Bank", "aliorbank.pl"),
    ("Credit Agricole", "credit-agricole.pl"),
]

TELCOS = [
    ("Orange Polska", "orange.pl"),
    ("Play", "play.pl"),
    ("T-Mobile Polska", "t-mobile.pl"),
    ("Plus", "plus.pl"),
    ("Netia", "netia.pl"),
]

COURIERS = [
    ("InPost", "inpost.pl"),
    ("DPD Polska", "dpd.com.pl"),
    ("DHL Express", "dhl.com"),
    ("Poczta Polska", "poczta-polska.pl"),
    ("UPS Polska", "ups.com"),
]

MARKETPLACES = [
    ("Allegro", "allegro.pl"),
    ("OLX", "olx.pl"),
    ("Vinted", "vinted.pl"),
    ("Booksy", "booksy.com"),
]

GOV = [
    ("Urząd Skarbowy", "podatki.gov.pl"),
    ("ZUS", "zus.pl"),
    ("e-Urząd Skarbowy", "gov.pl"),
    ("KRUS", "krus.gov.pl"),
]

PHISH_TLDS = [
    "xyz", "top", "site", "online", "click", "link", "tk", "info",
    "shop", "store", "buzz", "icu", "cyou",
]

EVIL_HOSTS = [
    "bezpieczenstwo", "weryfikacja", "logowanie", "konto",
    "potwierdzenie", "platnosc", "alert", "system", "obsluga",
    "twoje-konto", "panel-klienta", "centrum-pomocy",
]


def _evil_domain(base_name: str) -> str:
    """Tworzy podejrzaną domenę przypominającą legitymną."""
    base = base_name.lower().replace(" ", "").replace("ł", "l").replace("ą", "a")
    base = base.replace("ę", "e").replace("ś", "s").replace("ć", "c")
    base = base.replace("ó", "o").replace("ń", "n").replace("ż", "z").replace("ź", "z")
    variants = [
        f"{base}-{random.choice(EVIL_HOSTS)}.{random.choice(PHISH_TLDS)}",
        f"{random.choice(EVIL_HOSTS)}-{base}.{random.choice(PHISH_TLDS)}",
        f"{base}.{random.choice(PHISH_TLDS)}",
        f"{base}-pl.{random.choice(PHISH_TLDS)}",
        f"{base}{random.randint(2024, 2026)}.{random.choice(PHISH_TLDS)}",
    ]
    return random.choice(variants)


def _evil_url(domain: str | None = None) -> str:
    """Tworzy podejrzany URL phishingowy."""
    if domain is None:
        domain = f"{random.choice(EVIL_HOSTS)}-{random.choice(EVIL_HOSTS)}.{random.choice(PHISH_TLDS)}"
    path = random.choice([
        "login", "verify", "auth", "secure", "panel/login.php",
        "platnosc.php", "weryfikacja", "konto/odblokuj", "potwierdz",
    ])
    if random.random() < 0.3:
        return f"http://{random.randint(10, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(2, 254)}/{path}"
    return f"https://{domain}/{path}"


def _random_message_id(domain: str) -> str:
    return f"<{uuid.uuid4().hex}@{domain}>"


def _random_recent_date(days_back: int = 30) -> str:
    delta = random.randint(0, days_back * 24 * 60)
    dt = datetime.now() - timedelta(minutes=delta)
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0200")


def _amount() -> str:
    return f"{random.randint(20, 4999)},{random.randint(0, 99):02d} zł"


def _random_ip() -> str:
    return f"{random.randint(10, 250)}.{random.randint(0, 250)}.{random.randint(0, 250)}.{random.randint(2, 254)}"


def _wrap_email(headers: dict, body: str, is_phishing: bool) -> str:
    """Składa surowy e-mail z nagłówkami i treścią."""
    lines = []
    for key, value in headers.items():
        if value is not None:
            lines.append(f"{key}: {value}")
    lines.append("MIME-Version: 1.0")
    lines.append("Content-Type: text/plain; charset=UTF-8")
    lines.append("Content-Transfer-Encoding: 8bit")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines)


def gen_phish_bank() -> str:
    bank_name, real_domain = random.choice(BANKS)
    evil_domain = _evil_domain(bank_name.split()[0])
    customer = random.choice(POLISH_NAMES)
    amount = _amount()
    last4 = f"****{random.randint(1000, 9999)}"

    subjects = [
        f"PILNE: Wykryto nietypową transakcję na koncie {last4}",
        f"{bank_name}: Twoje konto zostało zablokowane",
        f"Potwierdź transakcję na kwotę {amount}",
        f"Weryfikacja danych - konto wygasa w ciągu 24h",
        f"Próba nieautoryzowanego logowania - {bank_name}",
        f"Nowa autoryzacja BLIK - wymagane potwierdzenie",
    ]
    bodies = [
        f"""Szanowny Kliencie,

Wykryliśmy próbę logowania do Twojego konta z nietypowej lokalizacji:
{random.choice(POLISH_CITIES)}, IP: {_random_ip()}.

Jeżeli to nie Ty, natychmiast zweryfikuj swoje dane logowania:
{_evil_url(evil_domain)}

Brak reakcji w ciągu 24 godzin spowoduje czasowe zablokowanie konta.

{bank_name}
Centrum Bezpieczeństwa""",
        f"""Drogi Kliencie {customer},

Z dniem dzisiejszym Twoje konto bankowe zostało tymczasowo zawieszone
z powodu zaległej weryfikacji danych. Aby przywrócić dostęp do bankowości
elektronicznej, kliknij w poniższy link i potwierdź swoją tożsamość:

{_evil_url(evil_domain)}

UWAGA: Niezweryfikowanie konta w ciągu 12 godzin spowoduje jego trwałe
zablokowanie i przekazanie sprawy do windykacji.

Zespół {bank_name}""",
        f"""POTWIERDŹ TRANSAKCJĘ

Wykryto autoryzację płatności:
- Kwota: {amount}
- Odbiorca: SHOP-PAYMENTS LTD
- Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}

Jeżeli NIE autoryzowałeś tej transakcji, anuluj ją natychmiast:
>>> {_evil_url(evil_domain)} <<<

Po 30 minutach środki zostaną pobrane bezpowrotnie.

Dział Bezpieczeństwa {bank_name}""",
    ]

    headers = {
        "From": f'"{bank_name} - Bezpieczeństwo" <obsluga@{evil_domain}>',
        "Reply-To": f"noreply@{_evil_domain('contact')}",
        "Return-Path": f"<bounce@{evil_domain}>",
        "To": f"klient@example.com",
        "Subject": random.choice(subjects),
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(evil_domain),
        "X-Mailer": random.choice(["PHPMailer 5.2.9", "Python/3.10", "Mailer-Bulk/1.0"]),
        "Received": f"from unknown ({_random_ip()}) by mail.example.com",
    }
    return _wrap_email(headers, random.choice(bodies), is_phishing=True)


def gen_phish_telco() -> str:
    telco_name, real_domain = random.choice(TELCOS)
    evil_domain = _evil_domain(telco_name.split()[0])
    amount = _amount()
    invoice_no = f"FV/{random.randint(1, 12):02d}/{random.randint(100000, 999999)}/{datetime.now().year}"

    subjects = [
        f"Zaległa płatność: {amount} - ostatnie wezwanie",
        f"{telco_name}: Faktura {invoice_no} - przeterminowana",
        f"Wstrzymanie usług - brak opłaty za fakturę {invoice_no}",
        f"Ostatnie wezwanie do zapłaty - {telco_name}",
    ]
    body = f"""Szanowny Kliencie,

Informujemy, że na Twoim koncie abonenckim widnieje zaległa płatność
w kwocie {amount} z tytułu faktury {invoice_no}.

Aby uniknąć zawieszenia usług oraz naliczenia odsetek karnych,
prosimy o niezwłoczne uregulowanie należności:

{_evil_url(evil_domain)}

Brak płatności do końca dnia roboczego spowoduje:
- Wstrzymanie usług głosowych i transmisji danych
- Naliczenie opłaty za wznowienie (150 zł)
- Przekazanie sprawy do firmy windykacyjnej

{telco_name}
Dział Obsługi Klienta"""

    headers = {
        "From": f'"{telco_name} Faktura" <faktura@{evil_domain}>',
        "Reply-To": f"oplaty@{evil_domain}",
        "Return-Path": f"<bounce@{evil_domain}>",
        "To": "klient@example.com",
        "Subject": random.choice(subjects),
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(evil_domain),
        "X-Mailer": "BulkMail Pro 4.1",
    }
    return _wrap_email(headers, body, is_phishing=True)


def gen_phish_courier() -> str:
    courier_name, real_domain = random.choice(COURIERS)
    evil_domain = _evil_domain(courier_name.split()[0])
    tracking = f"{random.choice(['IP', 'PL', 'EU'])}{random.randint(100000000, 999999999)}{random.choice(['PL', 'XX'])}"
    fee = f"{random.randint(1, 19)},{random.randint(0, 99):02d}"

    subjects = [
        f"Paczka {tracking} oczekuje na dopłatę {fee} zł",
        f"{courier_name}: Nieudana próba doręczenia",
        f"Twoja przesyłka wymaga potwierdzenia adresu",
        f"Paczka wstrzymana w sortowni - wymagana dopłata",
    ]
    body = f"""Witaj,

Twoja przesyłka o numerze {tracking} została wstrzymana w naszej sortowni
w {random.choice(POLISH_CITIES)} z powodu niedopłaty w wysokości {fee} zł.

Aby kontynuować doręczenie, opłać brakującą kwotę online:
{_evil_url(evil_domain)}

Czas na opłatę: 48 godzin. Po tym okresie przesyłka zostanie zwrócona
do nadawcy, a Ty otrzymasz powiadomienie o kosztach magazynowania.

Wybierz wygodny termin doręczenia po opłaceniu.

{courier_name}"""

    headers = {
        "From": f'"{courier_name} Powiadomienia" <powiadomienia@{evil_domain}>',
        "Reply-To": f"noreply@{evil_domain}",
        "Return-Path": f"<noreply@{evil_domain}>",
        "To": "odbiorca@example.com",
        "Subject": random.choice(subjects),
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(evil_domain),
        "X-Mailer": "PHPMailer 6.0",
    }
    return _wrap_email(headers, body, is_phishing=True)


def gen_phish_gov() -> str:
    gov_name, _real_domain = random.choice(GOV)
    evil_domain = _evil_domain(gov_name.split()[0] if gov_name.split() else "urzad")
    refund = _amount()

    subjects = [
        f"Zwrot podatku w wysokości {refund} - wymagana weryfikacja",
        f"{gov_name}: Wezwanie do złożenia korekty deklaracji",
        f"Nadpłata podatku - kliknij aby odebrać",
        f"PILNE: Nieprawidłowości w rozliczeniu rocznym",
    ]
    body = f"""Szanowny Podatniku,

W wyniku analizy Twojej deklaracji podatkowej za rok poprzedni
{gov_name} ustalił nadpłatę w kwocie {refund}.

Aby otrzymać zwrot na konto, prosimy o weryfikację danych identyfikacyjnych
oraz numeru rachunku bankowego pod poniższym adresem:

{_evil_url(evil_domain)}

Termin weryfikacji: 7 dni roboczych. Po jego upływie sprawa zostanie
zamknięta, a środki zaksięgowane na koncie depozytowym urzędu.

{gov_name}
Departament Obsługi Podatnika"""

    headers = {
        "From": f'"{gov_name}" <kontakt@{evil_domain}>',
        "Reply-To": f"noreply@{evil_domain}",
        "Return-Path": f"<bounce@{evil_domain}>",
        "To": "podatnik@example.com",
        "Subject": random.choice(subjects),
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(evil_domain),
        "X-Mailer": "wget/1.20.3",
    }
    return _wrap_email(headers, body, is_phishing=True)


def gen_phish_marketplace() -> str:
    market_name, _real_domain = random.choice(MARKETPLACES)
    evil_domain = _evil_domain(market_name)
    code = f"{random.randint(100000, 999999)}"

    subjects = [
        f"{market_name}: Twoje konto zostanie zamknięte - zweryfikuj dane",
        f"Wygrałeś aukcję! Potwierdź zakup w ciągu 24h",
        f"{market_name} Smart: Twoja subskrypcja wymaga odnowienia",
        f"Nowa wiadomość od kupującego - kod {code}",
    ]
    body = f"""Cześć,

Wykryliśmy nietypową aktywność na Twoim koncie {market_name}.
Aby uniknąć trwałego zablokowania, potwierdź swoją tożsamość
w ciągu najbliższych 24 godzin:

{_evil_url(evil_domain)}

Wymagane będą:
- Dane logowania
- Numer karty płatniczej powiązanej z kontem
- Kod weryfikacyjny otrzymany SMS-em

Konta niezweryfikowane zostaną zawieszone bezterminowo.

Zespół {market_name}"""

    headers = {
        "From": f'"{market_name}" <powiadomienia@{evil_domain}>',
        "Reply-To": f"support@{evil_domain}",
        "Return-Path": f"<bounce@{evil_domain}>",
        "To": "uzytkownik@example.com",
        "Subject": random.choice(subjects),
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(evil_domain),
    }
    return _wrap_email(headers, body, is_phishing=True)


PHISH_GENERATORS = [
    gen_phish_bank,
    gen_phish_telco,
    gen_phish_courier,
    gen_phish_gov,
    gen_phish_marketplace,
]


def gen_legit_bank_newsletter() -> str:
    bank_name, real_domain = random.choice(BANKS)
    customer = random.choice(POLISH_NAMES)

    body = f"""Witaj {customer.split()[0]},

W tym miesiącu w {bank_name} przygotowaliśmy dla Ciebie kilka nowości:

1. Rozszerzona aplikacja mobilna z obsługą BLIK kontaktowego
2. Promocja na lokatę 6-miesięczną - 5,5% w skali roku
3. Nowe funkcje w bankowości elektronicznej

Wszystkie szczegóły znajdziesz po zalogowaniu do serwisu transakcyjnego.

W razie pytań - infolinia 800 100 200 (połączenie bezpłatne).

Z poważaniem,
Zespół {bank_name}

---
Ta wiadomość ma charakter informacyjny. Aby zrezygnować z subskrypcji
newslettera, zaloguj się do bankowości elektronicznej."""

    headers = {
        "From": f'"{bank_name}" <newsletter@{real_domain}>',
        "Return-Path": f"<newsletter@{real_domain}>",
        "To": "klient@example.com",
        "Subject": f"Nowości w {bank_name} - {datetime.now().strftime('%B %Y')}",
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(real_domain),
        "X-Mailer": "Microsoft Outlook 16.0",
        "List-Unsubscribe": f"<mailto:unsubscribe@{real_domain}>",
        "Received": f"from mx.{real_domain} ({real_domain} [{_random_ip()}]) by mail.example.com",
        "Authentication-Results": f"mail.example.com; spf=pass smtp.mailfrom={real_domain}; dkim=pass header.d={real_domain}; dmarc=pass",
    }
    return _wrap_email(headers, body, is_phishing=False)


def gen_legit_telco_invoice() -> str:
    telco_name, real_domain = random.choice(TELCOS)
    amount = _amount()
    invoice_no = f"FV/{random.randint(1, 12):02d}/{random.randint(100000, 999999)}/{datetime.now().year}"
    due = (datetime.now() + timedelta(days=14)).strftime("%d.%m.%Y")

    body = f"""Dzień dobry,

Udostępniamy Twoją fakturę za usługi {telco_name} za bieżący okres rozliczeniowy.

- Numer faktury: {invoice_no}
- Kwota do zapłaty: {amount}
- Termin płatności: {due}
- Numer konta do wpłat: PL{random.randint(10, 99)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}

Płatność można zrealizować również przez panel klienta po zalogowaniu
na stronę {real_domain}.

W przypadku pytań prosimy o kontakt z BOK pod numerem *500.

Pozdrawiamy,
{telco_name}"""

    headers = {
        "From": f'"{telco_name} Faktury" <efaktura@{real_domain}>',
        "Return-Path": f"<bounce@{real_domain}>",
        "To": "abonent@example.com",
        "Subject": f"Twoja faktura {invoice_no} - {telco_name}",
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(real_domain),
        "X-Mailer": "Mailgun",
        "Received": f"from mta.{real_domain} (mta.{real_domain} [{_random_ip()}]) by mail.example.com",
        "Authentication-Results": f"mail.example.com; spf=pass smtp.mailfrom={real_domain}; dkim=pass header.d={real_domain}; dmarc=pass",
    }
    return _wrap_email(headers, body, is_phishing=False)


def gen_legit_courier_notification() -> str:
    courier_name, real_domain = random.choice(COURIERS)
    tracking = f"{random.choice(['IP', 'PL', 'EU'])}{random.randint(100000000, 999999999)}{random.choice(['PL', 'XX'])}"
    locker = f"WAW{random.randint(1, 99):02d}M"

    body = f"""Witaj,

Twoja paczka jest gotowa do odbioru.

- Numer paczki: {tracking}
- Lokalizacja: Paczkomat {locker}, {random.choice(POLISH_CITIES)}
- Kod odbioru zostanie wysłany SMS-em
- Czas na odbiór: 48 godzin

Adres do nawigacji oraz status przesyłki dostępne są w aplikacji
{courier_name} (sklepy Google Play i App Store).

Dziękujemy za wybór naszych usług.
{courier_name}"""

    headers = {
        "From": f'"{courier_name}" <powiadomienia@{real_domain}>',
        "Return-Path": f"<noreply@{real_domain}>",
        "To": "odbiorca@example.com",
        "Subject": f"Paczka {tracking} czeka w paczkomacie",
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(real_domain),
        "X-Mailer": "SendGrid",
        "Received": f"from o1.email.{real_domain} ([{_random_ip()}]) by mail.example.com",
        "Authentication-Results": f"mail.example.com; spf=pass smtp.mailfrom={real_domain}; dkim=pass header.d={real_domain}; dmarc=pass",
    }
    return _wrap_email(headers, body, is_phishing=False)


def gen_legit_marketplace_order() -> str:
    market_name, real_domain = random.choice(MARKETPLACES)
    order = f"{random.randint(100000000, 999999999)}"
    amount = _amount()

    body = f"""Cześć,

Dziękujemy za zakup w serwisie {market_name}!

Szczegóły zamówienia:
- Numer: {order}
- Kwota: {amount}
- Status: Opłacone
- Szacowana dostawa: {(datetime.now() + timedelta(days=random.randint(2, 7))).strftime('%d.%m.%Y')}

Status zamówienia możesz śledzić w zakładce „Moje zakupy" po zalogowaniu.

Pamiętaj o ocenie sprzedawcy po otrzymaniu przesyłki - pomaga to budować
zaufaną społeczność użytkowników.

Pozdrawiamy,
Zespół {market_name}"""

    headers = {
        "From": f'"{market_name}" <powiadomienia@{real_domain}>',
        "Return-Path": f"<bounce@{real_domain}>",
        "To": "kupujacy@example.com",
        "Subject": f"{market_name}: Potwierdzenie zamówienia #{order}",
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(real_domain),
        "X-Mailer": "Mailjet",
        "Received": f"from mta.{real_domain} (mta.{real_domain} [{_random_ip()}]) by mail.example.com",
        "Authentication-Results": f"mail.example.com; spf=pass smtp.mailfrom={real_domain}; dkim=pass header.d={real_domain}; dmarc=pass",
    }
    return _wrap_email(headers, body, is_phishing=False)


def gen_legit_hr_announcement() -> str:
    company = random.choice(["Comarch", "Asseco Poland", "CD Projekt", "Allegro", "Żabka Polska"])
    domain = company.lower().replace(" ", "") + ".pl"
    sender = random.choice(POLISH_NAMES)

    body = f"""Drodzy Współpracownicy,

Z przyjemnością informujemy, że w przyszłym tygodniu, w dniach
{(datetime.now() + timedelta(days=7)).strftime('%d-%m')}-{(datetime.now() + timedelta(days=9)).strftime('%d.%m.%Y')},
odbędzie się cykl szkoleń z zakresu cyberbezpieczeństwa dla wszystkich
pracowników działów IT oraz operacji.

Tematyka:
- Wykrywanie ataków phishingowych
- Zarządzanie hasłami i 2FA
- Bezpieczeństwo poczty elektronicznej (SPF/DKIM/DMARC)

Zapisy poprzez wewnętrzny portal HR do końca tygodnia.

W razie pytań - bezpośredni kontakt z działem HR.

Pozdrawiam,
{sender}
Dział HR | {company}"""

    headers = {
        "From": f'"{sender} ({company})" <hr@{domain}>',
        "Return-Path": f"<hr@{domain}>",
        "To": "pracownicy@example.com",
        "Subject": "Szkolenia z cyberbezpieczeństwa - zapisy",
        "Date": _random_recent_date(),
        "Message-ID": _random_message_id(domain),
        "X-Mailer": "Microsoft Outlook 16.0",
        "Received": f"from smtp.{domain} (smtp.{domain} [{_random_ip()}]) by mail.example.com",
        "Authentication-Results": f"mail.example.com; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}",
    }
    return _wrap_email(headers, body, is_phishing=False)


LEGIT_GENERATORS = [
    gen_legit_bank_newsletter,
    gen_legit_telco_invoice,
    gen_legit_courier_notification,
    gen_legit_marketplace_order,
    gen_legit_hr_announcement,
]


def main(n_phishing: int = 60, n_legitimate: int = 60, seed: int = 42) -> None:
    """Generuje zbiór polskich wiadomości testowych."""
    random.seed(seed)

    output_dir = Path(__file__).parent.parent / "data" / "sample_emails" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)

    for old_file in output_dir.glob("*.eml"):
        old_file.unlink()

    print(f"Generowanie {n_legitimate} wiadomości legitymnych...")
    for i in range(1, n_legitimate + 1):
        generator = LEGIT_GENERATORS[(i - 1) % len(LEGIT_GENERATORS)]
        email = generator()
        path = output_dir / f"legitimate_{i:03d}.eml"
        path.write_bytes(email.encode("utf-8"))

    print(f"Generowanie {n_phishing} wiadomości phishingowych...")
    for i in range(1, n_phishing + 1):
        generator = PHISH_GENERATORS[(i - 1) % len(PHISH_GENERATORS)]
        email = generator()
        path = output_dir / f"phishing_{i:03d}.eml"
        path.write_bytes(email.encode("utf-8"))

    total = n_phishing + n_legitimate
    print(f"\nWygenerowano {total} wiadomości w: {output_dir}")
    print(f"  - Legitymne: {n_legitimate}")
    print(f"  - Phishing:  {n_phishing}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generator polskich wiadomości testowych")
    parser.add_argument("--phishing", type=int, default=60, help="Liczba wiadomości phishingowych")
    parser.add_argument("--legitimate", type=int, default=60, help="Liczba wiadomości legitymnych")
    parser.add_argument("--seed", type=int, default=42, help="Ziarno losowości")
    args = parser.parse_args()

    main(n_phishing=args.phishing, n_legitimate=args.legitimate, seed=args.seed)
