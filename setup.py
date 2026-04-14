from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="email-spoofing-detector",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="System wykrywania spoofingu i phishingu w e-mailach",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/email-spoofing-detector",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Communications :: Email",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
        ],
        "test": [
            "pytest>=7.4.3",
            "pytest-benchmark>=4.0.0",
            "locust>=2.17.0",
            "faker>=20.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "email-detector=api.app:main",
            "train-models=ml_models.train:main",
        ],
    },
)

