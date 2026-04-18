"""
Benchmark Tests
Testy wydajności poszczególnych komponentów
"""

import pytest
import sys
from pathlib import Path
import time
import numpy as np
import pandas as pd

# Dodaj src do ścieżki
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from email_parser.parser import EmailParser
from email_parser.header_analyzer import HeaderAnalyzer
from feature_extraction.extractor import FeatureExtractor


@pytest.fixture
def sample_emails():
    """Fixture z przykładowymi e-mailami"""
    return [
        """From: sender{}@example.com
To: recipient@example.com
Subject: Test Email {}
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test{}@example.com>

This is test email number {}.
Visit https://example.com for more information.
""".format(i, i, i, i) for i in range(100)
    ]


@pytest.fixture
def email_parser():
    return EmailParser()


@pytest.fixture
def header_analyzer():
    return HeaderAnalyzer()


@pytest.fixture
def feature_extractor():
    return FeatureExtractor()


class TestParserBenchmarks:
    """Benchmarki dla parsera e-maili"""
    
    def test_parse_single_email(self, benchmark, email_parser, sample_emails):
        """Benchmark parsowania pojedynczego e-maila"""
        result = benchmark(email_parser.parse_email_string, sample_emails[0])
        assert result is not None
    
    def test_parse_batch_emails(self, benchmark, email_parser, sample_emails):
        """Benchmark parsowania wielu e-maili"""
        def parse_batch():
            return [email_parser.parse_email_string(email) for email in sample_emails[:10]]
        
        results = benchmark(parse_batch)
        assert len(results) == 10
    
    def test_extract_urls(self, benchmark, email_parser):
        """Benchmark ekstrakcji URL-i"""
        text = """
        Check out these links:
        https://example.com
        http://test.com
        https://another-site.org
        """ * 10
        
        urls = benchmark(email_parser.extract_urls, text)
        assert len(urls) > 0


class TestHeaderAnalyzerBenchmarks:
    """Benchmarki dla analizatora nagłówków"""
    
    def test_analyze_headers(self, benchmark, header_analyzer, email_parser, sample_emails):
        """Benchmark analizy nagłówków"""
        email_data = email_parser.parse_email_string(sample_emails[0])
        
        result = benchmark(header_analyzer.analyze, email_data)
        assert 'anomaly_score' in result
    
    def test_batch_header_analysis(self, benchmark, header_analyzer, 
                                   email_parser, sample_emails):
        """Benchmark analizy wielu nagłówków"""
        email_data_list = [
            email_parser.parse_email_string(email) 
            for email in sample_emails[:20]
        ]
        
        def analyze_batch():
            return [header_analyzer.analyze(data) for data in email_data_list]
        
        results = benchmark(analyze_batch)
        assert len(results) == 20


class TestFeatureExtractionBenchmarks:
    """Benchmarki dla ekstrakcji cech"""
    
    def test_extract_features_single(self, benchmark, feature_extractor,
                                     email_parser, sample_emails):
        """Benchmark ekstrakcji cech pojedynczego e-maila"""
        email_data = email_parser.parse_email_string(sample_emails[0])
        
        features = benchmark(feature_extractor.extract_features, email_data)
        assert isinstance(features, pd.Series)
        assert len(features) > 0
    
    def test_extract_features_batch(self, benchmark, feature_extractor,
                                   email_parser, sample_emails):
        """Benchmark ekstrakcji cech wielu e-maili"""
        email_data_list = [
            email_parser.parse_email_string(email) 
            for email in sample_emails[:50]
        ]
        
        def extract_batch():
            return [feature_extractor.extract_features(data) for data in email_data_list]
        
        results = benchmark(extract_batch)
        assert len(results) == 50


class TestEndToEndBenchmarks:
    """Benchmarki end-to-end workflow"""
    
    def test_full_analysis_pipeline(self, benchmark, email_parser, 
                                    header_analyzer, feature_extractor,
                                    sample_emails):
        """Benchmark pełnego pipeline'u analizy"""
        def full_pipeline():
            email_data = email_parser.parse_email_string(sample_emails[0])
            header_analysis = header_analyzer.analyze(email_data)
            features = feature_extractor.extract_features(
                email_data, 
                header_analysis=header_analysis
            )
            return features
        
        result = benchmark(full_pipeline)
        assert result is not None
    
    def test_batch_processing(self, benchmark, email_parser,
                             header_analyzer, feature_extractor,
                             sample_emails):
        """Benchmark przetwarzania wsadowego"""
        def batch_pipeline():
            results = []
            for email in sample_emails[:25]:
                email_data = email_parser.parse_email_string(email)
                header_analysis = header_analyzer.analyze(email_data)
                features = feature_extractor.extract_features(
                    email_data,
                    header_analysis=header_analysis
                )
                results.append(features)
            return results
        
        results = benchmark(batch_pipeline)
        assert len(results) == 25


class TestMemoryUsage:
    """Testy wykorzystania pamięci"""
    
    def test_memory_parsing_large_batch(self, email_parser, sample_emails):
        """Test pamięci przy parsowaniu dużej liczby e-maili"""
        import tracemalloc
        
        tracemalloc.start()
        
        # Parsuj 1000 e-maili
        large_batch = sample_emails * 10
        results = [email_parser.parse_email_string(email) for email in large_batch]
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"\nMemory usage: Current={current / 1024 / 1024:.2f} MB, "
              f"Peak={peak / 1024 / 1024:.2f} MB")
        
        assert len(results) == len(large_batch)
        # Sprawdź że zużycie pamięci jest rozsądne (< 500 MB)
        assert peak < 500 * 1024 * 1024


class TestScalability:
    """Testy skalowalności"""
    
    def test_scalability_parsing(self, email_parser, sample_emails):
        """Test skalowalności parsowania"""
        batch_sizes = [10, 50, 100, 500]
        times = []
        
        for size in batch_sizes:
            emails_to_process = sample_emails * (size // len(sample_emails) + 1)
            emails_to_process = emails_to_process[:size]
            
            start = time.time()
            results = [email_parser.parse_email_string(email) 
                      for email in emails_to_process]
            elapsed = time.time() - start
            
            times.append(elapsed)
            throughput = size / elapsed
            
            print(f"\nBatch size: {size}, Time: {elapsed:.2f}s, "
                  f"Throughput: {throughput:.2f} emails/s")
        
        # Sprawdź że czas rośnie mniej więcej liniowo
        # (jeśli doubled size, time should be roughly doubled)
        assert len(times) == len(batch_sizes)


class TestPerformanceRegression:
    """Testy regresji wydajności"""
    
    # Oczekiwane czasy (w sekundach)
    EXPECTED_TIMES = {
        'parse_single': 0.01,
        'analyze_headers': 0.005,
        'extract_features': 0.02,
        'full_pipeline': 0.05
    }
    
    def test_parse_performance(self, email_parser, sample_emails):
        """Test że parsowanie nie jest wolniejsze niż oczekiwane"""
        start = time.time()
        email_parser.parse_email_string(sample_emails[0])
        elapsed = time.time() - start
        
        print(f"\nParsing time: {elapsed:.4f}s (expected < {self.EXPECTED_TIMES['parse_single']}s)")
        assert elapsed < self.EXPECTED_TIMES['parse_single']
    
    def test_full_pipeline_performance(self, email_parser, header_analyzer,
                                      feature_extractor, sample_emails):
        """Test że pełny pipeline nie jest wolniejszy niż oczekiwany"""
        email_data = email_parser.parse_email_string(sample_emails[0])
        
        start = time.time()
        header_analysis = header_analyzer.analyze(email_data)
        features = feature_extractor.extract_features(
            email_data,
            header_analysis=header_analysis
        )
        elapsed = time.time() - start
        
        print(f"\nFull pipeline time: {elapsed:.4f}s "
              f"(expected < {self.EXPECTED_TIMES['full_pipeline']}s)")
        assert elapsed < self.EXPECTED_TIMES['full_pipeline']


# Konfiguracja pytest-benchmark
"""
Uruchomienie testów:

1. Podstawowe benchmarki:
   pytest tests/performance/benchmark_tests.py --benchmark-only

2. Z porównaniem do poprzednich wyników:
   pytest tests/performance/benchmark_tests.py --benchmark-only --benchmark-compare

3. Z zapisem wyników:
   pytest tests/performance/benchmark_tests.py --benchmark-only --benchmark-save=baseline

4. Generowanie raportu HTML:
   pytest tests/performance/benchmark_tests.py --benchmark-only --benchmark-html=benchmark_report.html

5. Z verbose output:
   pytest tests/performance/benchmark_tests.py --benchmark-only -v
"""

if __name__ == '__main__':
    pytest.main([__file__, '--benchmark-only', '-v'])

