#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Main Script ---
# Navigate to the backend directory
cd backend

# Create the virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run pytest
python -m pytest
