#!/usr/bin/env python3
"""
GUI wrapper for the Ethical Hacking Assistant
Creates a desktop application with terminal emulation
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import threading
import queue
import sys
import os
import subprocess
import platform
from datetime import datetime
import json
import webbrowser
import configparser
from tkinter import colorchooser, filedialog
import shutil

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
sys.path.insert(0, os.path.dirname(__file__))

# Simple backend adapter for the GUI
class EthicalHackingAssistant:
    """Simple backend adapter for the GUI"""
    
    def __init__(self):
        pass
    
    def process_command(self, mode, command):
        """Process a command and return result"""
        if mode == 'agent':
            return f"Agent mode: Processing '{command}'"
        elif mode == 'terminal':
            return f"Terminal mode: Would execute '{command}'"
        elif mode == 'more':
            return f"More mode: Suggesting command for '{command}'"
        elif mode == 'auto':
            return f"Auto mode: Running automated workflow for '{command}'"
        else:
            return f"Unknown mode: {mode}"

class TerminalEmulator:
    """Terminal emulator widget using tkinter"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
        self.command_history = []
        self.history_index = 0
        self.current_mode = "agent"
        
        # Initialize the backend
        self.backend = EthicalHackingAssistant()
        
        # Queue for thread-safe communication
        self.output_queue = queue.Queue()
        
        # Start the output processing thread
        self.output_thread = threading.Thread(target=self.process_output, daemon=True)
        self.output_thread.start()
        
        # Initial welcome message
        self.display_welcome()
        
    def setup_ui(self):
        """Setup the terminal UI components"""
        # Main frame
        main_frame = ttk.Frame(self.parent)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Configure grid weights
        self.parent.grid_rowconfigure(0, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Terminal output area
        self.terminal_output = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            width=100,
            height=30,
            bg="#0C0C0C",
            fg="#00FF00",
            insertbackground="#00FF00",
            selectbackground="#333333",
            font=("Consolas", 10)
        )
        self.terminal_output.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=1, column=0, sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)
        
        # Mode indicator
        self.mode_label = ttk.Label(input_frame, text="[agent]", foreground="#00BFFF")
        self.mode_label.grid(row=0, column=0, padx=(0, 5))
        
        # Command input
        self.command_input = ttk.Entry(input_frame, font=("Consolas", 10))
        self.command_input.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.command_input.bind("<Return>", self.on_command_enter)
        self.command_input.bind("<Up>", self.on_history_up)
        self.command_input.bind("<Down>", self.on_history_down)
        self.command_input.bind("<Tab>", self.on_tab_complete)
        
        # Send button
        send_button = ttk.Button(input_frame, text="Send", command=self.on_command_enter)
        send_button.grid(row=0, column=2)
        
        # Status bar
        self.status_bar = ttk.Label(main_frame, text="Ready", relief=tk.SUNKEN)
        self.status_bar.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        
        # Focus on input
        self.command_input.focus_set()
        
    def display_welcome(self):
        """Display the welcome message"""
        welcome_text = """
============================================
    Ethical Hacking Assistant v1.0
============================================

DISCLAIMER:
This tool is intended for ETHICAL HACKING and SECURITY RESEARCH only.
You are responsible for complying with all applicable laws and regulations.
Use only on systems you own or have explicit permission to test.

USE AT YOUR OWN RISK: The developers are not responsible for misuse.

Type '/help' for commands or '/ethical' for ethical guidelines.
============================================

"""
        self.append_output(welcome_text, "#FFFF00")  # Yellow
        
    def append_output(self, text, color="#00FF00"):
        """Append text to the terminal output"""
        self.terminal_output.configure(state='normal')
        
        # Create a tag for the color
        tag_name = f"color_{color.replace('#', '')}"
        self.terminal_output.tag_configure(tag_name, foreground=color)
        
        # Insert the text with the color tag
        self.terminal_output.insert(tk.END, text, tag_name)
        self.terminal_output.insert(tk.END, "\n")
        
        # Auto-scroll to bottom
        self.terminal_output.see(tk.END)
        self.terminal_output.configure(state='disabled')
        
    def on_command_enter(self, event=None):
        """Handle command input"""
        command = self.command_input.get().strip()
        if not command:
            return
            
        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Display the command
        prompt = f"[{self.current_mode}] > {command}"
        self.append_output(prompt, "#00BFFF")  # Cyan
        
        # Clear input
        self.command_input.delete(0, tk.END)
        
        # Process command in background thread
        threading.Thread(target=self.process_command, args=(command,), daemon=True).start()
        
    def process_command(self, command):
        """Process command in background thread"""
        try:
            # Check for mode changes
            if command.startswith('/mode '):
                parts = command.split()
                if len(parts) == 2 and parts[1] in ['agent', 'terminal', 'more', 'auto']:
                    self.current_mode = parts[1]
                    self.parent.after(0, self.update_mode_display)
                    self.output_queue.put(f"Switched to {parts[1]} mode.")
                    return
                else:
                    self.output_queue.put("Invalid mode. Available: agent, terminal, more, auto")
                    return
            
            # Handle special commands
            if command.startswith('/'):
                result = self.handle_special_command(command)
                self.output_queue.put(result)
                return
                
            # Process regular commands
            result = self.backend.process_command(self.current_mode, command)
            self.output_queue.put(str(result))
            
        except Exception as e:
            self.output_queue.put(f"Error: {str(e)}")
            
    def handle_special_command(self, command):
        """Handle special commands"""
        cmd = command[1:].lower()
        
        if cmd == 'help':
            return self.get_help_text()
        elif cmd == 'clear':
            self.parent.after(0, self.clear_terminal)
            return ""
        elif cmd == 'exit':
            self.parent.after(0, self.parent.quit)
            return "Goodbye!"
        elif cmd == 'ethical':
            return self.get_ethical_guidelines()
        elif cmd == 'info':
            return self.get_system_info()
        else:
            return f"Unknown command: {command}"
            
    def get_help_text(self):
        """Get help text"""
        return """
Available Commands:
/help          - Show this help
/mode [mode]   - Switch modes (agent, terminal, more, auto)
/clear         - Clear terminal
/ethical       - Show ethical guidelines
/info          - System information
/exit          - Exit application

Modes:
agent    - AI interprets commands
terminal - Direct shell execution
more     - AI suggests, user approves
auto     - Automated workflows
"""

    def get_ethical_guidelines(self):
        """Get ethical guidelines"""
        return """
ETHICAL HACKING GUIDELINES:
1. AUTHORIZATION: Only test systems you own or have permission to test
2. SCOPE: Stay within defined testing scope
3. DATA PROTECTION: Do not access or modify sensitive data
4. REPORTING: Document and report findings appropriately
5. MINIMAL IMPACT: Minimize disruption to systems
6. LEGAL COMPLIANCE: Follow all applicable laws
7. CONFIDENTIALITY: Maintain confidentiality of findings
8. NO BACKDOORS: Don't install persistent access without permission
9. DOCUMENTATION: Maintain detailed logs
10. RESPONSIBLE DISCLOSURE: Follow responsible disclosure practices

VIOLATION MAY RESULT IN LEGAL CONSEQUENCES!
"""

    def get_system_info(self):
        """Get system information"""
        return f"""
System Information:
OS: {platform.system()} {platform.release()}
Python: {platform.python_version()}
Architecture: {platform.architecture()[0]}
Processor: {platform.processor()}
Node: {platform.node()}
"""

class SettingsManager:
    """Manager for application settings"""

    def __init__(self, filename="settings.ini"):
        self.config = configparser.ConfigParser()
        self.filename = filename
        self.load_settings()

    def load_settings(self):
        """Load settings from a file"""
        self.config.read(self.filename)
        if not self.config.sections():
            self.create_default_settings()
            self.save_settings()

    def create_default_settings(self):
        """Create default settings if none exist"""
        self.config['Account'] = {
            'username': 'user',
            'email': 'user@example.com'
        }
        self.config['AI'] = {
            'model': 'GPT-4'
        }
        self.config['Appearance'] = {
            'theme': 'Dark',
            'background_color': '#0C0C0C',
            'text_color': '#00FF00',
        }
        self.config['Editor'] = {
            'font_size': '10',
            'syntax_highlighting': 'yes',
            'line_numbers': 'yes',
            'auto_indent': 'yes'
        }
        
    def save_settings(self):
        with open(self.filename, 'w') as configfile:
            self.config.write(configfile)

    def update_setting(self, section, option, value):
        if section in self.config and option in self.config[section]:
            self.config[section][option] = value
            self.save_settings()


    def update_mode_display(self):
        """Update mode display in UI thread"""
        self.mode_label.config(text=f"[{self.current_mode}]")
        
    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output.configure(state='normal')
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.configure(state='disabled')
        self.display_welcome()
        
    def process_output(self):
        """Process output queue in background thread"""
        while True:
            try:
                message = self.output_queue.get(timeout=0.1)
                self.parent.after(0, self.append_output, message)
            except queue.Empty:
                continue
                
    def on_history_up(self, event):
        """Handle up arrow for command history"""
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.command_input.delete(0, tk.END)
            self.command_input.insert(0, self.command_history[self.history_index])
            
    def on_history_down(self, event):
        """Handle down arrow for command history"""
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_input.delete(0, tk.END)
            self.command_input.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index = len(self.command_history)
            self.command_input.delete(0, tk.END)
            
    def on_tab_complete(self, event):
        """Handle tab completion"""
        # Basic tab completion - can be expanded
        current_text = self.command_input.get()
        if current_text.startswith('/'):
            commands = ['help', 'mode', 'clear', 'exit', 'ethical', 'info']
            matches = [cmd for cmd in commands if cmd.startswith(current_text[1:])]
            if len(matches) == 1:
                self.command_input.delete(0, tk.END)
                self.command_input.insert(0, f"/{matches[0]}")
        return "break"


class EthicalHackingGUI:
    """Main GUI application class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.settings = SettingsManager()
        self.setup_window()
        self.create_menu()
        self.terminal = TerminalEmulator(self.root)
        self.apply_settings()
        
    def setup_window(self):
        """Setup the main window"""
        self.root.title("Ethical Hacking Assistant")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Set window icon (if available)
        try:
            if platform.system() == "Windows":
                self.root.iconbitmap("assets/icon.ico")
            else:
                # For Linux/Mac, you'd use a different method
                pass
        except:
            pass  # Icon not found, continue without it
            
        # Configure grid
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_menu(self):
        """Create the application menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Sign In", command=self.sign_in)
        file_menu.add_separator()
        file_menu.add_command(label="Settings", command=self.open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Clear Terminal", command=self.clear_terminal)
        edit_menu.add_command(label="Copy", command=self.copy_text)

        # Mode menu
        mode_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Mode", menu=mode_menu)
        mode_menu.add_command(label="Agent Mode", command=lambda: self.change_mode("agent"))
        mode_menu.add_command(label="Terminal Mode", command=lambda: self.change_mode("terminal"))
        mode_menu.add_command(label="More Mode", command=lambda: self.change_mode("more"))
        mode_menu.add_command(label="Auto Mode", command=lambda: self.change_mode("auto"))

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Show Help", command=self.show_help)
        help_menu.add_command(label="Ethical Guidelines", command=self.show_ethical)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        

    def sign_in(self):
        """Open the website for sign-in."""
        # The server runs on localhost:3000
        url = "http://localhost:3000"
        webbrowser.open_new(url)
        self.terminal.append_output(f"Opening {url} for sign-in...", "#00BFFF")

    def apply_settings(self):
        """Apply saved settings to the UI"""
        # Apply appearance settings
        if 'Appearance' in self.settings.config:
            bg_color = self.settings.config['Appearance'].get('background_color', '#0C0C0C')
            text_color = self.settings.config['Appearance'].get('text_color', '#00FF00')
            
            if hasattr(self, 'terminal'):
                self.terminal.terminal_output.configure(bg=bg_color, fg=text_color)

        # Apply editor settings
        if 'Editor' in self.settings.config:
            font_size = int(self.settings.config['Editor'].get('font_size', '10'))
            if hasattr(self, 'terminal'):
                self.terminal.terminal_output.configure(font=("Consolas", font_size))
                self.terminal.command_input.configure(font=("Consolas", font_size))

    def open_settings(self):
        """Open the settings window"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("700x500")
        settings_window.resizable(True, True)
        settings_window.grab_set()  # Make window modal

        notebook = ttk.Notebook(settings_window)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Account Tab
        account_frame = ttk.Frame(notebook)
        notebook.add(account_frame, text="Account")
        self.create_account_tab(account_frame)

        # AI Tab
        ai_frame = ttk.Frame(notebook)
        notebook.add(ai_frame, text="AI")
        self.create_ai_tab(ai_frame)

        # Billing and Usage Tab
        billing_frame = ttk.Frame(notebook)
        notebook.add(billing_frame, text="Billing and Usage")
        self.create_billing_tab(billing_frame)

        # Code Tab
        code_frame = ttk.Frame(notebook)
        notebook.add(code_frame, text="Code")
        self.create_code_tab(code_frame)

        # Teams Tab
        teams_frame = ttk.Frame(notebook)
        notebook.add(teams_frame, text="Teams")
        self.create_teams_tab(teams_frame)

        # Appearance Tab
        appearance_frame = ttk.Frame(notebook)
        notebook.add(appearance_frame, text="Appearance")
        self.create_appearance_tab(appearance_frame)

        # Features Tab
        features_frame = ttk.Frame(notebook)
        notebook.add(features_frame, text="Features")
        self.create_features_tab(features_frame)

        # Keyboard Shortcuts Tab
        shortcuts_frame = ttk.Frame(notebook)
        notebook.add(shortcuts_frame, text="Keyboard Shortcuts")
        self.create_shortcuts_tab(shortcuts_frame)

        # Wrapify Tab
        wrapify_frame = ttk.Frame(notebook)
        notebook.add(wrapify_frame, text="Wrapify")
        self.create_wrapify_tab(wrapify_frame)

        # Referrals Tab
        referrals_frame = ttk.Frame(notebook)
        notebook.add(referrals_frame, text="Referrals")
        self.create_referrals_tab(referrals_frame)

        # Shared Blocks Tab
        shared_frame = ttk.Frame(notebook)
        notebook.add(shared_frame, text="Shared Blocks")
        self.create_shared_blocks_tab(shared_frame)

        # Privacy Tab
        privacy_frame = ttk.Frame(notebook)
        notebook.add(privacy_frame, text="Privacy")
        self.create_privacy_tab(privacy_frame)

        # About Tab
        about_frame = ttk.Frame(notebook)
        notebook.add(about_frame, text="About")
        self.create_about_tab(about_frame)

        # Add Apply and Cancel buttons
        button_frame = ttk.Frame(settings_window)
        button_frame.pack(side='bottom', fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="Apply", command=self.apply_settings).pack(side='right', padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side='right', padx=5)

    def create_account_tab(self, parent):
        """Create the Account settings tab"""
        ttk.Label(parent, text="Account Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # User info frame
        user_frame = ttk.LabelFrame(parent, text="User Information")
        user_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(user_frame, text="Username:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(user_frame, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(user_frame, text="Email:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(user_frame, width=30).grid(row=1, column=1, padx=5, pady=5)
        
        # Account actions
        actions_frame = ttk.LabelFrame(parent, text="Account Actions")
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(actions_frame, text="Change Password").pack(side='left', padx=5, pady=5)
        ttk.Button(actions_frame, text="Delete Account").pack(side='left', padx=5, pady=5)

    def create_ai_tab(self, parent):
        """Create the AI settings tab"""
        ttk.Label(parent, text="AI Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # AI Model selection
        model_frame = ttk.LabelFrame(parent, text="AI Model")
        model_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(model_frame, text="Select AI Model:").pack(anchor='w', padx=5, pady=5)
        model_var = tk.StringVar(value="GPT-4")
        ttk.Radiobutton(model_frame, text="GPT-4", variable=model_var, value="GPT-4").pack(anchor='w', padx=20)
        ttk.Radiobutton(model_frame, text="GPT-3.5", variable=model_var, value="GPT-3.5").pack(anchor='w', padx=20)
        ttk.Radiobutton(model_frame, text="Claude", variable=model_var, value="Claude").pack(anchor='w', padx=20)
        
        # AI behavior
        behavior_frame = ttk.LabelFrame(parent, text="AI Behavior")
        behavior_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(behavior_frame, text="Enable auto-completion").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(behavior_frame, text="Enable code suggestions").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(behavior_frame, text="Enable context awareness").pack(anchor='w', padx=5, pady=2)

    def create_billing_tab(self, parent):
        """Create the Billing and Usage settings tab"""
        ttk.Label(parent, text="Billing and Usage", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Subscription info
        sub_frame = ttk.LabelFrame(parent, text="Subscription")
        sub_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(sub_frame, text="Current Plan: Free").pack(anchor='w', padx=5, pady=5)
        ttk.Button(sub_frame, text="Upgrade to Pro", command=lambda: webbrowser.open('http://localhost:3000')).pack(anchor='w', padx=5, pady=5)
        
        # Usage stats
        usage_frame = ttk.LabelFrame(parent, text="Usage Statistics")
        usage_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(usage_frame, text="Commands executed this month: 156").pack(anchor='w', padx=5, pady=2)
        ttk.Label(usage_frame, text="AI queries made: 42").pack(anchor='w', padx=5, pady=2)
        ttk.Label(usage_frame, text="Sessions created: 12").pack(anchor='w', padx=5, pady=2)

    def create_code_tab(self, parent):
        """Create the Code settings tab"""
        ttk.Label(parent, text="Code Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Editor settings
        editor_frame = ttk.LabelFrame(parent, text="Editor")
        editor_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(editor_frame, text="Font Size:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        font_scale = tk.Scale(editor_frame, from_=8, to=24, orient='horizontal')
        font_scale.set(10)
        font_scale.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Checkbutton(editor_frame, text="Enable syntax highlighting").grid(row=1, column=0, columnspan=2, sticky='w', padx=5, pady=2)
        ttk.Checkbutton(editor_frame, text="Enable line numbers").grid(row=2, column=0, columnspan=2, sticky='w', padx=5, pady=2)
        ttk.Checkbutton(editor_frame, text="Enable auto-indent").grid(row=3, column=0, columnspan=2, sticky='w', padx=5, pady=2)

    def create_teams_tab(self, parent):
        """Create the Teams settings tab"""
        ttk.Label(parent, text="Teams Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Team info
        team_frame = ttk.LabelFrame(parent, text="Team Information")
        team_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(team_frame, text="Not part of any team").pack(anchor='w', padx=5, pady=5)
        ttk.Button(team_frame, text="Create Team").pack(anchor='w', padx=5, pady=5)
        ttk.Button(team_frame, text="Join Team").pack(anchor='w', padx=5, pady=5)

    def create_appearance_tab(self, parent):
        """Create the Appearance settings tab"""
        ttk.Label(parent, text="Appearance Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Theme selection
        theme_frame = ttk.LabelFrame(parent, text="Theme")
        theme_frame.pack(fill='x', padx=10, pady=5)
        
        theme_var = tk.StringVar(value="Dark")
        ttk.Radiobutton(theme_frame, text="Dark Theme", variable=theme_var, value="Dark").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(theme_frame, text="Light Theme", variable=theme_var, value="Light").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(theme_frame, text="System Theme", variable=theme_var, value="System").pack(anchor='w', padx=5, pady=2)
        
        # Terminal colors
        colors_frame = ttk.LabelFrame(parent, text="Terminal Colors")
        colors_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(colors_frame, text="Background Color:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Button(colors_frame, text="Choose Color").grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(colors_frame, text="Text Color:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Button(colors_frame, text="Choose Color").grid(row=1, column=1, padx=5, pady=5)

    def create_features_tab(self, parent):
        """Create the Features settings tab"""
        ttk.Label(parent, text="Features Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Feature toggles
        features_frame = ttk.LabelFrame(parent, text="Enable/Disable Features")
        features_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(features_frame, text="Command auto-completion").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(features_frame, text="Command history").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(features_frame, text="Session saving").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(features_frame, text="Real-time notifications").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(features_frame, text="AI suggestions").pack(anchor='w', padx=5, pady=2)

    def create_shortcuts_tab(self, parent):
        """Create the Keyboard Shortcuts settings tab"""
        ttk.Label(parent, text="Keyboard Shortcuts", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Shortcuts list
        shortcuts_frame = ttk.LabelFrame(parent, text="Current Shortcuts")
        shortcuts_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create a scrollable frame for shortcuts
        canvas = tk.Canvas(shortcuts_frame)
        scrollbar = ttk.Scrollbar(shortcuts_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        shortcuts = [
            ("Clear Terminal", "Ctrl+L"),
            ("New Session", "Ctrl+N"),
            ("Copy", "Ctrl+C"),
            ("Paste", "Ctrl+V"),
            ("Search History", "Ctrl+R"),
            ("Exit", "Ctrl+Q")
        ]
        
        for i, (action, shortcut) in enumerate(shortcuts):
            ttk.Label(scrollable_frame, text=action).grid(row=i, column=0, sticky='w', padx=5, pady=2)
            ttk.Label(scrollable_frame, text=shortcut).grid(row=i, column=1, sticky='e', padx=5, pady=2)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_wrapify_tab(self, parent):
        """Create the Wrapify settings tab"""
        ttk.Label(parent, text="Wrapify Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Wrapify info
        info_frame = ttk.LabelFrame(parent, text="Wrapify Information")
        info_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(info_frame, text="Wrapify allows you to wrap and share your terminal sessions.").pack(anchor='w', padx=5, pady=5)
        
        # Wrapify settings
        settings_frame = ttk.LabelFrame(parent, text="Wrapify Settings")
        settings_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(settings_frame, text="Enable automatic wrapping").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(settings_frame, text="Include command history in wraps").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(settings_frame, text="Make wraps public by default").pack(anchor='w', padx=5, pady=2)

    def create_referrals_tab(self, parent):
        """Create the Referrals settings tab"""
        ttk.Label(parent, text="Referrals Program", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Referral info
        referral_frame = ttk.LabelFrame(parent, text="Your Referral Code")
        referral_frame.pack(fill='x', padx=10, pady=5)
        
        code_frame = ttk.Frame(referral_frame)
        code_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(code_frame, text="Referral Code:").pack(side='left')
        code_entry = ttk.Entry(code_frame, value="HACK2025", state='readonly')
        code_entry.pack(side='left', padx=5)
        ttk.Button(code_frame, text="Copy").pack(side='left', padx=5)
        
        # Referral stats
        stats_frame = ttk.LabelFrame(parent, text="Referral Statistics")
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(stats_frame, text="Referrals made: 0").pack(anchor='w', padx=5, pady=2)
        ttk.Label(stats_frame, text="Bonus earned: $0").pack(anchor='w', padx=5, pady=2)

    def create_shared_blocks_tab(self, parent):
        """Create the Shared Blocks settings tab"""
        ttk.Label(parent, text="Shared Blocks", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Shared blocks info
        info_frame = ttk.LabelFrame(parent, text="Shared Blocks Settings")
        info_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(info_frame, text="Enable shared blocks").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(info_frame, text="Allow others to view my blocks").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(info_frame, text="Auto-sync blocks across devices").pack(anchor='w', padx=5, pady=2)
        
        # Block management
        manage_frame = ttk.LabelFrame(parent, text="Block Management")
        manage_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(manage_frame, text="View Shared Blocks").pack(side='left', padx=5, pady=5)
        ttk.Button(manage_frame, text="Export Blocks").pack(side='left', padx=5, pady=5)
        ttk.Button(manage_frame, text="Import Blocks").pack(side='left', padx=5, pady=5)

    def create_privacy_tab(self, parent):
        """Create the Privacy settings tab"""
        ttk.Label(parent, text="Privacy Settings", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Privacy controls
        privacy_frame = ttk.LabelFrame(parent, text="Privacy Controls")
        privacy_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(privacy_frame, text="Enable telemetry").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(privacy_frame, text="Share usage statistics").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(privacy_frame, text="Allow crash reports").pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(privacy_frame, text="Enable analytics").pack(anchor='w', padx=5, pady=2)
        
        # Data management
        data_frame = ttk.LabelFrame(parent, text="Data Management")
        data_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(data_frame, text="Clear All Data").pack(side='left', padx=5, pady=5)
        ttk.Button(data_frame, text="Export Data").pack(side='left', padx=5, pady=5)
        ttk.Button(data_frame, text="Delete Account").pack(side='left', padx=5, pady=5)

    def create_about_tab(self, parent):
        """Create the About settings tab"""
        ttk.Label(parent, text="About", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # App info
        info_frame = ttk.LabelFrame(parent, text="Application Information")
        info_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(info_frame, text="Ethical Hacking Assistant").pack(anchor='w', padx=5, pady=2)
        ttk.Label(info_frame, text="Version: 1.0.0").pack(anchor='w', padx=5, pady=2)
        ttk.Label(info_frame, text="© 2025 - For Educational and Ethical Use Only").pack(anchor='w', padx=5, pady=2)
        
        # Links
        links_frame = ttk.LabelFrame(parent, text="Links")
        links_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(links_frame, text="Documentation").pack(side='left', padx=5, pady=5)
        ttk.Button(links_frame, text="Support").pack(side='left', padx=5, pady=5)
        ttk.Button(links_frame, text="GitHub").pack(side='left', padx=5, pady=5)

    def new_session(self):
        """Start a new session"""
        self.terminal.clear_terminal()
        
    def clear_terminal(self):
        """Clear the terminal"""
        self.terminal.clear_terminal()
        
    def copy_text(self):
        """Copy selected text"""
        try:
            self.root.clipboard_clear()
            selected_text = self.terminal.terminal_output.selection_get()
            self.root.clipboard_append(selected_text)
        except tk.TclError:
            pass  # No text selected
            
    def change_mode(self, mode):
        """Change the current mode"""
        self.terminal.current_mode = mode
        self.terminal.update_mode_display()
        self.terminal.append_output(f"Switched to {mode} mode.", "#00BFFF")
        
    def show_help(self):
        """Show help dialog"""
        help_text = self.terminal.get_help_text()
        messagebox.showinfo("Help", help_text)
        
    def show_ethical(self):
        """Show ethical guidelines"""
        ethical_text = self.terminal.get_ethical_guidelines()
        messagebox.showinfo("Ethical Guidelines", ethical_text)
        
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
Ethical Hacking Assistant v1.0

A comprehensive tool for ethical hacking and security research.

Platform: {platform.system()} {platform.release()}
Python: {platform.python_version()}

© 2025 - For Educational and Ethical Use Only
"""
        messagebox.showinfo("About", about_text)
        
    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
            
    def run(self):
        """Run the GUI application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    app = EthicalHackingGUI()
    app.run()


if __name__ == "__main__":
    main()
