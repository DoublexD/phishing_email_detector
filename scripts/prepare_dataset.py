"""
Skrypt do przygotowania datasetu z surowych plików e-mail (SpamAssassin format).
Przetwarza foldery data/raw/ham/ i data/raw/spam/ i zapisuje CSV do data/processed/training_data.csv
"""

import sys
import os
from pathlib import Path
import pandas as pd
import logging

# Dodaj src do ścieżki
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from email_parser.parser import EmailParser
from feature_extraction.extractor import FeatureExtractor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def load_emails_from_dir(directory: Path, label: int, parser: EmailParser, extractor: FeatureExtractor):
    """
    Wczytuje wszystkie pliki e-mail z katalogu i ekstrahuje cechy.

    Args:
        directory: Katalog z plikami e-mail
        label: 0 = ham (bezpieczne), 1 = spam/phishing
        parser: Instancja EmailParser
        extractor: Instancja FeatureExtractor

    Returns:
        Lista słowników z cechami
    """
    records = []
    files = [f for f in directory.iterdir() if f.is_file()]
    total = len(files)
    logger.info(f"Przetwarzanie {total} plików z: {directory}")

    for i, filepath in enumerate(files, 1):
        if i % 200 == 0 or i == total:
            logger.info(f"  {i}/{total} plików przetworzono...")

        try:
            raw_bytes = filepath.read_bytes()
            email_data = parser.parse_raw_email(raw_bytes)
            features = extractor.extract_features(email_data)
            features_dict = features.to_dict()
            features_dict["is_phishing"] = label
            features_dict["source_file"] = filepath.name
            records.append(features_dict)
        except Exception as e:
            logger.warning(f"  Pominięto {filepath.name}: {e}")

    logger.info(f"  Załadowano {len(records)}/{total} e-maili z {directory.name}")
    return records


def main():
    project_root = Path(__file__).parent.parent
    data_raw = project_root / "data" / "raw"
    data_processed = project_root / "data" / "processed"
    data_processed.mkdir(parents=True, exist_ok=True)
    output_csv = data_processed / "training_data.csv"

    # Foldery z hamem i spamem
    ham_dirs = [
        data_raw / "ham" / "easy_ham",
        data_raw / "ham" / "easy_ham_2",
    ]
    spam_dirs = [
        data_raw / "spam" / "spam",
        data_raw / "spam" / "spam_2",
    ]

    parser = EmailParser()
    extractor = FeatureExtractor()
    all_records = []

    # Wczytaj ham (label = 0)
    for ham_dir in ham_dirs:
        if ham_dir.exists():
            records = load_emails_from_dir(ham_dir, label=0, parser=parser, extractor=extractor)
            all_records.extend(records)
        else:
            logger.warning(f"Folder nie istnieje, pomijam: {ham_dir}")

    # Wczytaj spam (label = 1)
    for spam_dir in spam_dirs:
        if spam_dir.exists():
            records = load_emails_from_dir(spam_dir, label=1, parser=parser, extractor=extractor)
            all_records.extend(records)
        else:
            logger.warning(f"Folder nie istnieje, pomijam: {spam_dir}")

    if not all_records:
        logger.error("Nie znaleziono żadnych e-maili! Sprawdź ścieżki w data/raw/")
        sys.exit(1)

    # Tworzenie DataFrame
    df = pd.DataFrame(all_records)

    # Usuń kolumnę pomocniczą source_file przed treningiem
    if "source_file" in df.columns:
        df = df.drop(columns=["source_file"])

    # Wypełnij brakujące wartości
    df = df.fillna(0)

    # Statystyki
    total = len(df)
    ham_count = (df["is_phishing"] == 0).sum()
    spam_count = (df["is_phishing"] == 1).sum()
    logger.info("=" * 50)
    logger.info(f"Łącznie próbek:  {total}")
    logger.info(f"  Ham (bezpieczne): {ham_count} ({ham_count/total*100:.1f}%)")
    logger.info(f"  Spam/phishing:    {spam_count} ({spam_count/total*100:.1f}%)")
    logger.info(f"  Liczba cech:      {df.shape[1] - 1}")
    logger.info("=" * 50)

    # Zapisz CSV
    df.to_csv(output_csv, index=False)
    logger.info(f"Dataset zapisany: {output_csv}")
    logger.info("Możesz teraz uruchomić trening: .\\scripts\\train_models.ps1")


if __name__ == "__main__":
    main()
