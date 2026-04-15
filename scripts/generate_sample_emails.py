"""
Generator przykładowych e-maili do testowania
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

# Szablony legitymnych e-maili
LEGITIMATE_TEMPLATES = [
    {
        "from": "newsletter@{domain}",
        "subject": "Monthly Newsletter - {month}",
        "body": """Hello valued customer,

Welcome to our {month} newsletter! Here are the latest updates:

1. New features and improvements
2. Special offers for our customers
3. Company news and announcements

Thank you for being part of our community!

Best regards,
The Team"""
    },
    {
        "from": "support@{domain}",
        "subject": "Your Support Ticket #{ticket}",
        "body": """Hello,

Thank you for contacting our support team.

Your ticket #{ticket} has been received and is being processed.
We will respond within 24 hours.

Best regards,
Support Team"""
    },
    {
        "from": "noreply@{domain}",
        "subject": "Order Confirmation #{order}",
        "body": """Dear Customer,

Your order #{order} has been confirmed.

Order Details:
- Order Number: #{order}
- Date: {date}
- Status: Processing

Thank you for your purchase!"""
    }
]

# Szablony phishingowych e-maili
PHISHING_TEMPLATES = [
    {
        "from": "security@paypa1-verify.com",  # Zwróć uwagę: paypa1 (cyfra 1)
        "subject": "URGENT: Verify Your Account NOW!!!",
        "body": """URGENT SECURITY ALERT!

Your account has been suspended due to unusual activity!

Click here immediately to verify: http://192.168.1.100/verify.php

URGENT! ACT NOW! Your account will be closed within 24 hours!

Congratulations! You've also won $1,000,000!

Click here: http://evil-site.tk/claim"""
    },
    {
        "from": "noreply@amazon-security.tk",
        "subject": "Your Amazon Account Has Been Locked",
        "body": """Dear Customer,

Your Amazon account has been locked due to suspicious activity.

Click here to unlock: http://10.0.0.1/amazon-unlock.php

Failure to verify will result in permanent suspension.

Amazon Security Team
(This is not really Amazon)"""
    },
    {
        "from": "winner@lottery-2024.xyz",
        "subject": "YOU WON $5,000,000 - CLAIM NOW!!!",
        "body": """CONGRATULATIONS!!!

You have won $5,000,000 in our international lottery!

To claim your prize, send us your:
- Full name
- Address  
- Bank account number
- Social security number

ACT NOW! WINNER! FREE MONEY! URGENT! CLICK HERE!

http://suspicious-site.tk/claim-prize.php"""
    }
]

DOMAINS = ["company.com", "example.com", "business.org", "service.net"]
MONTHS = ["January", "February", "March", "April", "May", "June"]

def generate_email(template, is_phishing=False):
    """Generuje e-mail z szablonu"""
    
    # Podstawienia
    domain = random.choice(DOMAINS)
    month = random.choice(MONTHS)
    ticket = random.randint(10000, 99999)
    order = random.randint(100000, 999999)
    date = datetime.now().strftime("%Y-%m-%d")
    
    from_addr = template["from"].format(domain=domain)
    subject = template["subject"].format(
        month=month, ticket=ticket, order=order
    )
    body = template["body"].format(
        month=month, ticket=ticket, order=order, date=date
    )
    
    # Data
    random_days = random.randint(-30, 0)
    email_date = datetime.now() + timedelta(days=random_days)
    date_str = email_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    
    # Zwróć niezgodność w phishingu
    if is_phishing:
        return_path = f"<spam@different-domain.xyz>"
        reply_to = f"Reply-To: {random.choice(['scam@evil.com', 'phishing@bad.tk'])}"
        x_mailer = "X-Mailer: Python/3.8"
    else:
        return_path = f"<{from_addr}>"
        reply_to = ""
        x_mailer = "X-Mailer: Microsoft Outlook 16.0"
    
    # Konstruuj e-mail
    email = f"""From: {from_addr}
To: victim@example.com
Subject: {subject}
Date: {date_str}
Message-ID: <{random.randint(1000000, 9999999)}@{domain}>
Return-Path: {return_path}
{reply_to}
{x_mailer}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

{body}
"""
    
    return email.strip()

def main():
    """Generuje przykładowe e-maile"""
    
    # Utwórz katalog
    output_dir = Path("data/sample_emails/generated")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("Generowanie przykładowych e-maili...\n")
    
    # Generuj legitymne e-maile
    print(" Legitymne e-maile:")
    for i, template in enumerate(LEGITIMATE_TEMPLATES * 3):  # 3x każdy szablon
        email = generate_email(template, is_phishing=False)
        filename = output_dir / f"legitimate_{i+1:03d}.eml"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(email)
        
        print(f"  ✓ {filename.name}")
    
    # Generuj phishingowe e-maile
    print("\n Phishingowe e-maile:")
    for i, template in enumerate(PHISHING_TEMPLATES * 3):  # 3x każdy szablon
        email = generate_email(template, is_phishing=True)
        filename = output_dir / f"phishing_{i+1:03d}.eml"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(email)
        
        print(f"  ✓ {filename.name}")
    
    total = len(LEGITIMATE_TEMPLATES) * 3 + len(PHISHING_TEMPLATES) * 3
    print(f"\n Wygenerowano {total} e-maili w: {output_dir}")
    print(f"   - Legitymne: {len(LEGITIMATE_TEMPLATES) * 3}")
    print(f"   - Phishing: {len(PHISHING_TEMPLATES) * 3}")

if __name__ == "__main__":
    main()

