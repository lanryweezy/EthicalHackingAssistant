const { app, BrowserWindow, Menu, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess;

// Enable live reload for Electron
if (process.env.NODE_ENV === 'development') {
    require('electron-reload')(__dirname);
}

function createWindow() {
    // Create the browser window
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        },
        icon: path.join(__dirname, '../assets/icon.png'),
        frame: false, // Frameless window for custom title bar
        backgroundColor: '#0a0e0a',
        titleBarStyle: 'hidden',
        trafficLightPosition: { x: 20, y: 20 }
    });

    // Custom menu
    const menu = Menu.buildFromTemplate([
        {
            label: 'File',
            submenu: [
                {
                    label: 'New Session',
                    accelerator: 'CmdOrCtrl+N',
                    click: () => {
                        mainWindow.webContents.send('new-session');
                    }
                },
                { type: 'separator' },
                {
                    label: 'Exit',
                    accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
                    click: () => {
                        app.quit();
                    }
                }
            ]
        },
        {
            label: 'Edit',
            submenu: [
                { label: 'Copy', accelerator: 'CmdOrCtrl+C', role: 'copy' },
                { label: 'Paste', accelerator: 'CmdOrCtrl+V', role: 'paste' },
                { label: 'Select All', accelerator: 'CmdOrCtrl+A', role: 'selectAll' }
            ]
        },
        {
            label: 'View',
            submenu: [
                { label: 'Reload', accelerator: 'CmdOrCtrl+R', role: 'reload' },
                { label: 'Toggle DevTools', accelerator: 'F12', role: 'toggleDevTools' },
                { type: 'separator' },
                { label: 'Actual Size', accelerator: 'CmdOrCtrl+0', role: 'resetZoom' },
                { label: 'Zoom In', accelerator: 'CmdOrCtrl+Plus', role: 'zoomIn' },
                { label: 'Zoom Out', accelerator: 'CmdOrCtrl+-', role: 'zoomOut' },
                { type: 'separator' },
                { label: 'Toggle Fullscreen', accelerator: 'F11', role: 'togglefullscreen' }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'Documentation',
                    click: () => {
                        shell.openExternal('https://github.com/yourusername/ethical-hacking-assistant');
                    }
                },
                {
                    label: 'Report Issue',
                    click: () => {
                        shell.openExternal('https://github.com/yourusername/ethical-hacking-assistant/issues');
                    }
                }
            ]
        }
    ]);

    Menu.setApplicationMenu(menu);

    // Start Python backend
    startPythonBackend();

    // Wait a bit for the server to start, then load the URL
    setTimeout(() => {
        mainWindow.loadURL('http://localhost:5000');
    }, 2000);

    // Handle window closed
    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    // Add window controls for frameless window
    ipcMain.on('minimize-window', () => {
        mainWindow.minimize();
    });

    ipcMain.on('maximize-window', () => {
        if (mainWindow.isMaximized()) {
            mainWindow.unmaximize();
        } else {
            mainWindow.maximize();
        }
    });

    ipcMain.on('close-window', () => {
        app.quit();
    });
}

function startPythonBackend() {
    // Path to Python executable
    const pythonPath = process.platform === 'win32' ? 'python' : 'python3';
    
    // Start the Flask server
    const pythonExecutable = process.platform === 'win32' ? 'python.exe' : 'python3';
    const venvPath = process.platform === 'win32' ? 'Scripts' : 'bin';
    const pythonPath = path.join(__dirname, '..', '..', 'backend', 'venv', venvPath, pythonExecutable);

    pythonProcess = spawn(pythonPath, [path.join(__dirname, '..', '..', 'backend', 'app.py')], {
        cwd: path.join(__dirname, '..', '..', 'backend'),
        env: { ...process.env, FLASK_ENV: 'production' }
    });

    pythonProcess.stdout.on('data', (data) => {
        console.log(`Python: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python Error: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python process exited with code ${code}`);
    });
}

// App event handlers
app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    // Kill Python process
    if (pythonProcess) {
        pythonProcess.kill();
    }
    
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// Handle app termination
app.on('before-quit', () => {
    // Ensure Python process is killed
    if (pythonProcess) {
        pythonProcess.kill();
    }
});
