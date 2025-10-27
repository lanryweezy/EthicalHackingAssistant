# Ethical Hacking Assistant (WhiteHat)

A comprehensive ethical hacking terminal application with a cross-platform GUI.

## Overview

This repository contains the Ethical Hacking Assistant (codename WhiteHat), an Electron application designed for ethical hackers and penetration testers. It features a modern GUI, a powerful Python backend, and a suite of integrated security tools.

## Architecture

The application is composed of two main components:

- **Frontend**: An Electron-based user interface that provides a rich, interactive experience.
- **Backend**: A Flask server that powers the application's core logic, including agent management, task execution, and tool integration.

This separation of concerns allows for a modular and maintainable codebase.

## File Structure

```
EthicalHackingAssistant/
├── backend/                # Python/Flask backend source code
│   ├── app.py              # Main Flask application
│   ├── requirements.txt    # Backend Python dependencies
│   └── ...
├── frontend/               # Electron frontend source code
│   ├── electron/
│   │   └── main.js         # Main Electron process
│   ├── static/             # Frontend assets (CSS, JS, images)
│   ├── templates/          # HTML templates
│   ├── package.json        # Frontend Node.js dependencies
│   └── ...
├── run_app.sh              # Application startup script
└── README.md               # This documentation file
```

## Getting Started

### Prerequisites

- **Python 3.8+**: Ensure you have a recent version of Python installed.
- **Node.js**: Required for the Electron frontend and its dependencies.
- **Platform-Specific Build Tools**: Depending on your OS, you may need additional tools to build native Node.js modules.

### Installation and Running

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/EthicalHackingAssistant.git
   cd EthicalHackingAssistant
   ```
2. **Run the application:**
   The `run_app.sh` script automates the process of installing dependencies and launching the application.
   ```bash
   chmod +x run_app.sh
   ./run_app.sh
   ```
   This will:
   - Create a Python virtual environment for the backend and install its dependencies.
   - Install the Node.js dependencies for the frontend.
   - Launch the Electron application.
## Development
To run the application in development mode with live reloading:
1. **Start the backend:**
   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   flask run
   ```
2. **Start the frontend:**
   In a separate terminal:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
## Building for Production
To build the application for your specific platform, use the following commands from the `frontend` directory:
- **Windows**: `npm run build-win`
- **macOS**: `npm run build-mac`
- **Linux**: `npm run build-linux`

Executables will be placed in the `frontend/dist` directory.
## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
