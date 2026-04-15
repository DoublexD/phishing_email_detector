#!/bin/bash
# Script to train models

echo "Training Email Spoofing Detection Models..."

# Activate virtual environment if exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Check if data file exists
if [ ! -f "data/processed/training_data.csv" ]; then
    echo "Error: Training data not found at data/processed/training_data.csv"
    echo "Please prepare your dataset first."
    exit 1
fi

# Run training
python src/ml_models/train.py \
    --data data/processed/training_data.csv \
    --target is_phishing \
    --test-size 0.2 \
    --models-dir models

echo "Training completed! Models saved in models/"

