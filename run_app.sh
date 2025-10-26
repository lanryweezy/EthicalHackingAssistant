#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Helper Functions ---
print_step() {
  echo "🚀  $1"
}

# --- Main Script ---
# Navigate to the script's directory
cd "$(dirname "$0")"

# 1. Install Backend Dependencies in a subshell
(
  print_step "Installing backend dependencies..."
  cd backend
  python3 -m venv venv
  ./venv/bin/python3 -m pip install --upgrade pip
  ./venv/bin/python3 -m pip install -r requirements.txt
)

# 2. Install Frontend Dependencies in a subshell
(
  print_step "Installing frontend dependencies..."
  cd frontend
  npm install
)

# 3. Run the Application
print_step "Starting the application..."
cd frontend
xvfb-run --auto-servernum --server-num=1 npm start &
