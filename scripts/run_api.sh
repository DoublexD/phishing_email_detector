#!/bin/bash
# Script to run the API

echo "Starting Email Spoofing Detector API..."

# Activate virtual environment if exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run the API
cd src
python -m uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload

