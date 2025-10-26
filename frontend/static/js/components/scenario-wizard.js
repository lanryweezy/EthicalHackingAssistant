const ScenarioWizard = {
    data() {
        return {
            currentStep: 1,
            selectedScenario: null,
            target: '',
            scope: '',
            toolStatus: {},
            requiredTools: [],
            currentSteps: [],
            executingStep: null
        }
    },
    computed: {
        canProceed() {
            switch (this.currentStep) {
                case 1:
                    return !!this.selectedScenario;
                case 2:
                    return !!this.target;
                case 3:
                    return Object.values(this.toolStatus).every(status => status);
                default:
                    return true;
            }
        }
    },
    methods: {
        async nextStep() {
            if (this.currentStep < 4) {
                if (this.currentStep === 1) {
                    await this.prepareScenario();
                }
                this.currentStep++;
            } else {
                this.finishScenario();
            }
        },
        previousStep() {
            if (this.currentStep > 1) {
                this.currentStep--;
            }
        },
        async prepareScenario() {
            // Get required tools
            this.requiredTools = this.selectedScenario.steps.flatMap(step => step.tools);
            
            // Check tool status
            for (const tool of this.requiredTools) {
                try {
                    const response = await fetch(`/api/tools/check/${tool}`);
                    const data = await response.json();
                    this.$set(this.toolStatus, tool, data.installed);
                } catch (error) {
                    console.error(`Error checking tool ${tool}:`, error);
                    this.$set(this.toolStatus, tool, false);
                }
            }

            // Prepare steps
            this.currentSteps = this.selectedScenario.steps.map(step => ({
                ...step,
                running: false,
                completed: false,
                output: ''
            }));
        },
        async installTool(tool) {
            try {
                const response = await fetch(`/api/tools/install/${tool}`, {
                    method: 'POST'
                });
                const data = await response.json();
                if (data.success) {
                    this.$set(this.toolStatus, tool, true);
                }
            } catch (error) {
                console.error(`Error installing tool ${tool}:`, error);
            }
        },
        async executeStep(step) {
            try {
                step.running = true;
                const response = await fetch('/api/execute_step', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        command: step.command,
                        target: this.target
                    })
                });
                const data = await response.json();
                step.output = data.output;
                step.completed = true;
            } catch (error) {
                console.error('Error executing step:', error);
                step.output = `Error: ${error.message}`;
            } finally {
                step.running = false;
            }
        },
        async finishScenario() {
            // Gather results and emit completion event
            this.$emit('scenario-complete', {
                scenario: this.selectedScenario,
                target: this.target,
                steps: this.currentSteps,
                timestamp: new Date().toISOString()
            });
        }
    }
};
