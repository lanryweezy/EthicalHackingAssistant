// Modern Ethical Hacking Terminal - Main JavaScript

class EthicalHackingTerminal {
    constructor() {
        this.socket = null;
        this.currentMode = 'agent';
        this.commandHistory = [];
        this.historyIndex = -1;
        this.isConnected = false;
        this.aiModels = [];
        this.currentAiModel = null;
        this.settings = {};

        this.initializeElements();
        this.loadSettings();
        this.initializeSocketConnection();
        this.initializeEventListeners();
        this.startStatsUpdate();
    }
    
    initializeElements() {
        // Terminal elements
        this.terminalOutput = document.getElementById('terminal-output');
        this.terminalInput = document.getElementById('terminal-input');
        this.prompt = document.getElementById('prompt');
        
        // Mode buttons
        this.modeButtons = document.querySelectorAll('.mode-btn');
        
        // AI Model Selector
        this.aiModelDropdown = document.getElementById('ai-model-dropdown');
        this.aiModelCurrent = document.getElementById('ai-model-current');
        this.aiModelOptions = document.getElementById('ai-model-options');
        this.aiModelList = document.getElementById('ai-model-list');
        this.aiLoadingIndicator = document.getElementById('ai-loading-indicator');
        
        // Stats elements
        this.cpuStat = document.getElementById('cpu-stat');
        this.memStat = document.getElementById('mem-stat');
        this.cmdStat = document.getElementById('cmd-stat');
        
        // Side panel
        this.sidePanel = document.getElementById('side-panel');
        this.panelContent = document.getElementById('panel-content');
        
        // Settings modal
        this.settingsModal = document.getElementById('settings-modal');
        this.settingsBtn = document.getElementById('settings-btn');
        this.closeSettings = document.getElementById('close-settings');
        this.activeAiToggle = document.getElementById('active-ai-toggle');
        this.nextCommandToggle = document.getElementById('next-command-toggle');
        
        // Close panel button
        this.closePanel = document.getElementById('close-panel');
    }
    
    initializeSocketConnection() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            this.isConnected = true;
            this.showNotification('Connected to server', 'success');
            this.terminalInput.disabled = false;
            this.terminalInput.focus();
            
            // Request AI models on connect
            this.socket.emit('get_ai_models');
        });
        
        this.socket.on('disconnect', () => {
            this.isConnected = false;
            this.showNotification('Disconnected from server', 'error');
            this.terminalInput.disabled = true;
        });
        
        this.socket.on('connected', (data) => {
            this.updatePrompt(data.mode);
            setTimeout(() => {
                this.clearWelcomeAnimation();
            }, 2000);
        });
        
        this.socket.on('output', (data) => {
            this.handleOutput(data);
        });
        
        this.socket.on('mode_changed', (data) => {
            this.currentMode = data.mode;
            this.updatePrompt(data.mode);
            this.updateModeButtons(data.mode);
        });
        
        this.socket.on('stats', (data) => {
            this.updateStats(data);
        });
        
        this.socket.on('scan_update', (data) => {
            this.updateScanProgress(data);
        });
        
        this.socket.on('service_found', (data) => {
            this.addServiceToPanel(data);
        });
        
        // AI model related events
        this.socket.on('ai_models', (data) => {
            this.handleAiModels(data.available_models);
        });
        
        this.socket.on('ai_model_set', (data) => {
            this.setCurrentAiModel(data.model);
            this.showNotification(`AI model changed to ${data.model.name}`, 'success');
        });
        
        this.socket.on('ai_response', (data) => {
            this.handleAiResponse(data);
            this.setAiLoading(false);
        });
        
        this.socket.on('ai_error', (data) => {
            this.appendOutput({
                type: 'error',
                content: `AI Error: ${data.message}`
            });
            this.setAiLoading(false);
        });
    }
    
    initializeEventListeners() {
        // Terminal input
        this.terminalInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.executeCommand();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateHistory(-1);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateHistory(1);
            } else if (e.key === 'Tab') {
                e.preventDefault();
                this.autocomplete();
            }
        });
        
        // Mode buttons
        this.modeButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const mode = btn.dataset.mode;
                this.changeMode(mode);
            });
        });
        
        // Settings
        this.settingsBtn.addEventListener('click', () => {
            this.settingsModal.classList.add('active');
        });
        
        this.closeSettings.addEventListener('click', () => {
            this.settingsModal.classList.remove('active');
        });
        
        this.themeSelect.addEventListener('change', (e) => {
            this.changeTheme(e.target.value);
        });

        this.activeAiToggle.addEventListener('change', (e) => {
            this.saveSetting('active-ai', e.target.checked);
        });

        this.nextCommandToggle.addEventListener('change', (e) => {
            this.saveSetting('next-command', e.target.checked);
        });
        
        // Close panel button
        this.closePanel.addEventListener('click', () => {
            this.sidePanel.classList.remove('active');
        });
        
        // AI Model Selector
        if (this.aiModelCurrent) {
            this.aiModelCurrent.addEventListener('click', () => {
                this.toggleAiModelDropdown();
            });
            
            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                if (!this.aiModelDropdown.contains(e.target)) {
                    this.aiModelOptions.classList.remove('active');
                    this.aiModelCurrent.classList.remove('active');
                }
            });
        }
        
        // Click outside modal to close
        this.settingsModal.addEventListener('click', (e) => {
            if (e.target === this.settingsModal) {
                this.settingsModal.classList.remove('active');
            }
        });

        // Settings tabs
        const tabs = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                const target = document.getElementById(tab.dataset.tab);
                tabContents.forEach(c => c.classList.remove('active'));
                target.classList.add('active');
            });
        });

        // Save settings on change
        document.querySelectorAll('[data-setting]').forEach(element => {
            element.addEventListener('change', (e) => {
                const setting = e.target.dataset.setting;
                const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
                this.saveSetting(setting, value);
            });
        });
    }
    
    clearWelcomeAnimation() {
        const welcome = document.getElementById('welcome');
        if (welcome) {
            welcome.style.opacity = '0';
            setTimeout(() => {
                welcome.remove();
                this.appendOutput({
                    type: 'system',
                    content: 'System initialized. Ready for commands.'
                });
            }, 500);
        }
    }
    
    executeCommand() {
        const command = this.terminalInput.value.trim();
        if (!command) return;
        
        // Add to history
        this.commandHistory.push(command);
        this.historyIndex = this.commandHistory.length;
        
        // Display command in terminal
        this.appendCommand(command);
        
        // Clear input
        this.terminalInput.value = '';
        
        // Handle local commands
        if (command === '/clear') {
            this.clearTerminal();
            return;
        }
        
        // Send to server
        if (this.isConnected) {
            // Set loading state for AI modes
            if (this.currentMode === 'agent') {
                this.setAiLoading(true);
            }
            
            this.socket.emit('command', {
                command: command,
                mode: this.currentMode,
                model_id: this.currentAiModel ? this.currentAiModel.id : null
            });
        }
    }
    
    appendCommand(command) {
        const commandLine = document.createElement('div');
        commandLine.className = 'command-line';
        commandLine.innerHTML = `
            <span class="command-prompt">${this.getPromptText()}</span>
            <span class="command-text">${this.escapeHtml(command)}</span>
        `;
        this.terminalOutput.appendChild(commandLine);
        this.scrollToBottom();
    }
    
    appendOutput(data) {
        const outputBlock = document.createElement('div');
        outputBlock.className = 'output-block';
        
        if (data.type === 'error') {
            outputBlock.classList.add('error-output');
        } else if (data.type === 'warning') {
            outputBlock.classList.add('warning-output');
        } else {
            outputBlock.classList.add('success-output');
        }
        
        outputBlock.textContent = data.content || data.data || data;
        this.terminalOutput.appendChild(outputBlock);
        this.scrollToBottom();
    }
    
    handleOutput(data) {
        switch (data.type) {
            case 'welcome':
                this.handleWelcomeMessage(data.data);
                break;
            case 'agent_response':
                this.handleAgentResponse(data.data);
                break;
            case 'terminal_output':
                this.handleTerminalOutput(data.data);
                break;
            case 'scan_progress':
                this.handleScanProgress(data.data);
                break;
            case 'exploit_results':
                this.handleExploitResults(data.data);
                break;
            case 'help':
                this.handleHelpOutput(data.data);
                break;
            default:
                this.appendOutput(data);
        }
    }
    
    handleWelcomeMessage(data) {
        const welcomeBlock = document.createElement('div');
        welcomeBlock.className = 'output-block welcome-message';
        welcomeBlock.innerHTML = `
            <div class="welcome-header">
                <span class="version">v${data.version}</span>
                <span class="motd">${data.motd}</span>
            </div>
        `;
        this.terminalOutput.appendChild(welcomeBlock);
    }
    
    handleAgentResponse(data) {
        const responseBlock = document.createElement('div');
        responseBlock.className = 'output-block agent-response';
        responseBlock.innerHTML = `
            <div class="agent-interpretation">${data.interpretation}</div>
            <div class="agent-suggestions">
                <div class="suggestions-header">Suggested commands:</div>
                ${data.suggestions.map(cmd => `
                    <div class="suggestion-item" onclick="terminal.insertCommand('${cmd}')">
                        <span class="suggestion-icon">▶</span>
                        <code>${cmd}</code>
                    </div>
                `).join('')}
            </div>
            <div class="agent-meta">
                <span class="risk-level risk-${data.risk_level}">Risk: ${data.risk_level}</span>
                <span class="eta">ETA: ${data.eta}</span>
            </div>
        `;
        this.terminalOutput.appendChild(responseBlock);
        this.scrollToBottom();
    }
    
    handleTerminalOutput(data) {
        const outputBlock = document.createElement('div');
        outputBlock.className = 'output-block terminal-output';
        outputBlock.innerHTML = `<pre>${this.escapeHtml(data.output)}</pre>`;
        if (data.exit_code !== 0) {
            outputBlock.classList.add('error-output');
        }
        this.terminalOutput.appendChild(outputBlock);
        this.scrollToBottom();
    }
    
    handleScanProgress(data) {
        this.sidePanel.classList.add('active');
        this.panelContent.innerHTML = `
            <div class="scan-progress">
                <h4>Scanning: ${data.target}</h4>
                <div class="phases">
                    ${data.phases.map(phase => `
                        <div class="phase-item ${phase.status}" data-phase="${phase.name}">
                            <span class="phase-name">${phase.name}</span>
                            <span class="phase-status status-${phase.status}">${phase.status}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="services-found">
                    <h5>Discovered Services</h5>
                    <div id="services-list"></div>
                </div>
            </div>
        `;
    }
    
    handleExploitResults(data) {
        const exploitBlock = document.createElement('div');
        exploitBlock.className = 'output-block exploit-results';
        exploitBlock.innerHTML = `
            <div class="exploit-header">Vulnerability Assessment: ${data.target}</div>
            <div class="vulnerabilities">
                ${data.vulnerabilities.map(vuln => `
                    <div class="vulnerability-item severity-${vuln.severity}">
                        <div class="vuln-header">
                            <span class="cve">${vuln.cve}</span>
                            <span class="severity">${vuln.severity.toUpperCase()}</span>
                        </div>
                        <div class="vuln-description">${vuln.description}</div>
                        ${vuln.exploit_available ? 
                            '<div class="exploit-available">⚡ Exploit available</div>' : 
                            '<div class="no-exploit">No known exploit</div>'
                        }
                    </div>
                `).join('')}
            </div>
        `;
        this.terminalOutput.appendChild(exploitBlock);
        this.scrollToBottom();
    }
    
    handleHelpOutput(data) {
        const helpBlock = document.createElement('div');
        helpBlock.className = 'output-block help-output';
        helpBlock.innerHTML = `
            <div class="help-header">Available Commands</div>
            <div class="help-commands">
                ${Object.entries(data.commands).map(([cmd, desc]) => `
                    <div class="help-item">
                        <code class="help-command">${cmd}</code>
                        <span class="help-description">${desc}</span>
                    </div>
                `).join('')}
            </div>
        `;
        this.terminalOutput.appendChild(helpBlock);
        this.scrollToBottom();
    }
    
    updateScanProgress(data) {
        const phaseElement = document.querySelector(`[data-phase="${data.phase}"]`);
        if (phaseElement) {
            phaseElement.classList.remove('pending', 'running');
            phaseElement.classList.add('completed');
            phaseElement.querySelector('.phase-status').textContent = 'completed';
            phaseElement.querySelector('.phase-status').className = 'phase-status status-completed';
        }
        
        // Update progress bar if exists
        const progressBar = document.getElementById('scan-progress-bar');
        if (progressBar) {
            progressBar.style.width = `${data.progress}%`;
        }
    }
    
    addServiceToPanel(service) {
        const servicesList = document.getElementById('services-list');
        if (servicesList) {
            const serviceItem = document.createElement('div');
            serviceItem.className = 'service-item';
            serviceItem.innerHTML = `
                <span class="service-port">${service.port}</span>
                <span class="service-name">${service.service}</span>
                <span class="service-version">${service.version}</span>
            `;
            servicesList.appendChild(serviceItem);
        }
    }
    
    changeMode(mode) {
        this.socket.emit('change_mode', { mode: mode });
    }
    
    updatePrompt(mode) {
        const prompts = {
            'agent': { user: 'agent', symbol: '🤖' },
            'terminal': { user: 'root', symbol: '$' },
            'scan': { user: 'scanner', symbol: '🔍' },
            'exploit': { user: 'exploit', symbol: '🚀' }
        };
        
        const promptConfig = prompts[mode] || prompts['agent'];
        this.prompt.innerHTML = `
            <span class="prompt-user">${promptConfig.user}</span>@<span class="prompt-host">ethicalhack</span>
            <span class="prompt-path">~</span>
            <span class="prompt-symbol">${promptConfig.symbol}</span>
        `;
    }
    
    updateModeButtons(mode) {
        this.modeButtons.forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.mode === mode) {
                btn.classList.add('active');
            }
        });
    }
    
    getPromptText() {
        return this.prompt.textContent.trim();
    }
    
    navigateHistory(direction) {
        if (this.commandHistory.length === 0) return;
        
        this.historyIndex += direction;
        
        if (this.historyIndex < 0) {
            this.historyIndex = 0;
        } else if (this.historyIndex >= this.commandHistory.length) {
            this.historyIndex = this.commandHistory.length;
            this.terminalInput.value = '';
            return;
        }
        
        this.terminalInput.value = this.commandHistory[this.historyIndex];
    }
    
    autocomplete() {
        const input = this.terminalInput.value;
        const commands = ['/help', '/scan', '/exploit', '/clear', '/theme', '/report', '/workflow'];
        
        const matches = commands.filter(cmd => cmd.startsWith(input));
        
        if (matches.length === 1) {
            this.terminalInput.value = matches[0];
        } else if (matches.length > 1) {
            this.showSuggestions(matches);
        }
    }
    
    showSuggestions(suggestions) {
        const suggestionsDiv = document.getElementById('suggestions');
        suggestionsDiv.innerHTML = suggestions.map(cmd => 
            `<div class="suggestion" onclick="terminal.insertCommand('${cmd}')">${cmd}</div>`
        ).join('');
        suggestionsDiv.style.display = 'block';
        
        setTimeout(() => {
            suggestionsDiv.style.display = 'none';
        }, 3000);
    }
    
    insertCommand(command) {
        this.terminalInput.value = command;
        this.terminalInput.focus();
    }
    
    clearTerminal() {
        this.terminalOutput.innerHTML = '';
        this.appendOutput({
            type: 'system',
            content: 'Terminal cleared.'
        });
    }
    
    changeTheme(theme) {
        document.body.className = theme;
        localStorage.setItem('terminal-theme', theme);
        this.showNotification(`Theme changed to ${theme}`, 'success');
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    updateStats(stats) {
        this.cpuStat.textContent = `${stats.cpu.toFixed(1)}%`;
        this.memStat.textContent = `${stats.memory.toFixed(1)}%`;
        this.cmdStat.textContent = stats.commands_executed;
    }
    
    startStatsUpdate() {
        // Update stats every 5 seconds
        setInterval(() => {
            if (this.isConnected) {
                this.socket.emit('get_stats');
            }
        }, 5000);
    }
    
    scrollToBottom() {
        this.terminalOutput.scrollTop = this.terminalOutput.scrollHeight;
    }
    
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    
    // AI Model related methods
    toggleAiModelDropdown() {
        if (!this.aiModelOptions || !this.aiModelCurrent) return;
        this.aiModelOptions.classList.toggle('active');
        this.aiModelCurrent.classList.toggle('active');
    }
    
    handleAiModels(models) {
        this.aiModels = models;
        
        if (!this.aiModelList) return;
        
        this.aiModelList.innerHTML = '';
        
        models.forEach(model => {
            const option = document.createElement('div');
            option.className = 'ai-model-option';
            option.dataset.id = model.id;
            option.innerHTML = `
                ${model.name}
                <span class="model-provider">${model.provider}</span>
            `;
            
            // Add tooltip with model details
            option.title = `${model.name} - ${model.description}\nContext: ${model.context_length} tokens | Cost: ${model.cost_per_token} per token`;
            
            option.addEventListener('click', () => {
                this.selectAiModel(model.id);
            });
            
            this.aiModelList.appendChild(option);
        });
        
        // If we have a stored preference, use it, otherwise use first model
        if (this.currentAiModel) {
            this.selectAiModel(this.currentAiModel.id);
        } else if (models.length > 0) {
            this.selectAiModel(models[0].id);
        }
    }
    
    selectAiModel(modelId) {
        if (!this.isConnected) return;
        
        this.socket.emit('set_ai_model', { model_id: modelId });
        this.toggleAiModelDropdown();
        
        // Highlight the selected model in the list
        if (this.aiModelList) {
            const options = this.aiModelList.querySelectorAll('.ai-model-option');
            options.forEach(option => {
                if (option.dataset.id === modelId) {
                    option.classList.add('active');
                } else {
                    option.classList.remove('active');
                }
            });
        }
    }
    
    setCurrentAiModel(model) {
        this.currentAiModel = model;
        
        // Save preference to localStorage
        localStorage.setItem('preferred-ai-model', model.id);
        
        // Update UI
        if (this.aiModelCurrent) {
            this.aiModelCurrent.innerHTML = `
                ${model.name}
                <span class="dropdown-arrow">▼</span>
            `;
        }
    }
    
    loadAiModelPreference() {
        const preferredModelId = localStorage.getItem('preferred-ai-model');
        if (preferredModelId) {
            this.currentAiModel = { id: preferredModelId };
        }
    }
    
    setAiLoading(isLoading) {
        this.isAiLoading = isLoading;
        
        if (this.aiLoadingIndicator) {
            if (isLoading) {
                this.aiLoadingIndicator.classList.add('active');
            } else {
                this.aiLoadingIndicator.classList.remove('active');
            }
        }
    }
    
    handleAiResponse(data) {
        // For AI responses in agent mode
        const responseBlock = document.createElement('div');
        responseBlock.className = 'output-block ai-response';
        responseBlock.innerHTML = `
            ${data.content}
            div class="feedback-buttons"
                button class="feedback-btn" data-feedback="useful"Useful/button
                button class="feedback-btn" data-feedback="not-useful"Not Useful/button
            /div
        `;
        this.terminalOutput.appendChild(responseBlock);
        this.scrollToBottom();

        // Add event listeners for feedback buttons
        responseBlock.querySelectorAll('.feedback-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const feedback = {
                    feedback: e.target.dataset.feedback,
                    suggestion: data.content
                };
                this.sendFeedback(feedback);
                responseBlock.querySelector('.feedback-buttons').remove(); // Remove buttons after feedback
            });
        });
    },

    sendFeedback(feedback) {
        this.socket.emit('ai_feedback', feedback);
        this.showNotification('Thank you for your feedback!', 'success');
    }
}

// Initialize terminal when DOM is loaded
let terminal;
document.addEventListener('DOMContentLoaded', () => {
    terminal = new EthicalHackingTerminal();
    
    // Load saved theme
    const savedTheme = localStorage.getItem('terminal-theme');
    if (savedTheme) {
        document.body.className = savedTheme;
        document.getElementById('theme-select').value = savedTheme;
    }
});
