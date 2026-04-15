#!/bin/bash
# Setup script for Email Spoofing Detector

echo "=== Email Spoofing Detector Setup ==="

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p data/raw
mkdir -p data/processed
mkdir -p data/sample_emails
mkdir -p models
mkdir -p logs

# Copy config example
if [ ! -f "config/config.yaml" ]; then
    echo "Creating config file..."
    cp config/config.yaml.example config/config.yaml
    echo "Please edit config/config.yaml with your settings"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Edit config/config.yaml with your settings"
echo "3. Prepare training data in data/processed/"
echo "4. Train models: bash scripts/train_models.sh"
echo "5. Run API: bash scripts/run_api.sh"
echo "6. Open frontend: open frontend/index.html"
echo ""

