"""
Skrypt do przygotowania datasetu z surowych plików e-mail (SpamAssassin format).
Przetwarza foldery data/raw/ham/ i data/raw/spam/ i zapisuje CSV do data/processed/training_data.csv
"""

import sys
import os
from pathlib import Path
import pandas as pd
import logging

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from email_parser.parser import EmailParser
from email_parser.header_analyzer import HeaderAnalyzer
from feature_extraction.extractor import FeatureExtractor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def _features_for_training_email(
    raw_bytes: bytes,
    label: int,
    source_name: str,
    parser: EmailParser,
    extractor: FeatureExtractor,
    header_analyzer: HeaderAnalyzer,
) -> dict:
    """Ta sama ścieżka cech co w API (bez live DNS): parser + analiza nagłówków."""
    email_data = parser.parse_raw_email(raw_bytes)
    header_analysis = header_analyzer.analyze(email_data)
    features = extractor.extract_features(
        email_data,
        spf_result=None,
        dkim_result=None,
        dmarc_result=None,
        header_analysis=header_analysis,
    )
    features_dict = features.to_dict()
    features_dict["is_phishing"] = label
    features_dict["source_file"] = source_name
    return features_dict


def load_emails_from_dir(
    directory: Path,
    label: int,
    parser: EmailParser,
    extractor: FeatureExtractor,
    header_analyzer: HeaderAnalyzer,
):
    """
    Wczytuje wszystkie pliki e-mail z katalogu i ekstrahuje cechy.

    Args:
        directory: Katalog z plikami e-mail
        label: 0 = ham (bezpieczne), 1 = spam/phishing
        parser: Instancja EmailParser
        extractor: Instancja FeatureExtractor
        header_analyzer: Analiza nagłówków (zgodna z pipeline API)

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
            features_dict = _features_for_training_email(
                raw_bytes, label, filepath.name, parser, extractor, header_analyzer
            )
            records.append(features_dict)
        except Exception as e:
            logger.warning(f"  Pominięto {filepath.name}: {e}")

    logger.info(f"  Załadowano {len(records)}/{total} e-maili z {directory.name}")
    return records


def load_sample_emails_supplement(
    sample_root: Path,
    parser: EmailParser,
    extractor: FeatureExtractor,
    header_analyzer: HeaderAnalyzer,
    repeat: int = 20,
):
    """
    Dodaje próbki z data/sample_emails (legitimate_* / phishing_* / sample_*).
    Powtórzenia pomagają nauczyć model wzorców z Twoich plików testowych bez
    przebudowy całego korpusu SpamAssassin.
    """
    records = []
    if not sample_root.is_dir():
        return records

    for path in sorted(sample_root.rglob("*.eml")):
        stem = path.stem.lower()
        if "legitimate" in stem:
            label = 0
        elif "phishing" in stem:
            label = 1
        else:
            continue
        try:
            raw_bytes = path.read_bytes()
            feat = _features_for_training_email(
                raw_bytes, label, path.name, parser, extractor, header_analyzer
            )
            for _ in range(max(1, repeat)):
                records.append({**feat, "source_file": f"{path.name}__dup{_}"})
        except Exception as e:
            logger.warning("  Pominięto sample %s: %s", path.name, e)

    logger.info(
        "Dodano %s wierszy z sample_emails (repeat=%s)", len(records), repeat
    )
    return records


def main():
    project_root = Path(__file__).parent.parent
    data_raw = project_root / "data" / "raw"
    data_processed = project_root / "data" / "processed"
    data_processed.mkdir(parents=True, exist_ok=True)
    output_csv = data_processed / "training_data.csv"

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
    header_analyzer = HeaderAnalyzer()
    all_records = []

    for ham_dir in ham_dirs:
        if ham_dir.exists():
            records = load_emails_from_dir(
                ham_dir, label=0, parser=parser, extractor=extractor,
                header_analyzer=header_analyzer,
            )
            all_records.extend(records)
        else:
            logger.warning(f"Folder nie istnieje, pomijam: {ham_dir}")

    for spam_dir in spam_dirs:
        if spam_dir.exists():
            records = load_emails_from_dir(
                spam_dir, label=1, parser=parser, extractor=extractor,
                header_analyzer=header_analyzer,
            )
            all_records.extend(records)
        else:
            logger.warning(f"Folder nie istnieje, pomijam: {spam_dir}")

    sample_supp = load_sample_emails_supplement(
        project_root / "data" / "sample_emails",
        parser,
        extractor,
        header_analyzer,
        repeat=1,
    )
    all_records.extend(sample_supp)

    if not all_records:
        logger.error("Nie znaleziono żadnych e-maili! Sprawdź ścieżki w data/raw/")
        sys.exit(1)

    df = pd.DataFrame(all_records)

    if "source_file" in df.columns:
        df = df.drop(columns=["source_file"])

    df = df.fillna(0)

    total = len(df)
    ham_count = (df["is_phishing"] == 0).sum()
    spam_count = (df["is_phishing"] == 1).sum()
    logger.info("=" * 50)
    logger.info(f"Łącznie próbek:  {total}")
    logger.info(f"  Ham (bezpieczne): {ham_count} ({ham_count/total*100:.1f}%)")
    logger.info(f"  Spam/phishing:    {spam_count} ({spam_count/total*100:.1f}%)")
    logger.info(f"  Liczba cech:      {df.shape[1] - 1}")
    logger.info("=" * 50)

    df.to_csv(output_csv, index=False)
    logger.info(f"Dataset zapisany: {output_csv}")
    logger.info("Możesz teraz uruchomić trening: .\\scripts\\train_models.ps1")


if __name__ == "__main__":
    main()
