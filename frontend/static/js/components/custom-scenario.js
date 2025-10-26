const CustomScenarioCreator = {
    data() {
        return {
            scenario: {
                name: '',
                description: '',
                category: '',
                steps: []
            },
            scenarioCategories: [
                'Web Application',
                'Network Infrastructure',
                'Mobile Application',
                'Cloud Infrastructure',
                'IoT/Embedded',
                'Social Engineering',
                'Other'
            ],
            availableTools: [],
            saving: false
        }
    },
    methods: {
        async loadTools() {
            try {
                const response = await fetch('/api/tools/all');
                this.availableTools = await response.json();
            } catch (error) {
                console.error('Error loading tools:', error);
            }
        },
        addStep() {
            this.scenario.steps.push({
                name: '',
                description: '',
                tools: [],
                commands: [],
                variables: [],
                checks: []
            });
        },
        removeStep(index) {
            this.scenario.steps.splice(index, 1);
        },
        addCommand(step) {
            step.commands.push({
                command: '',
                description: ''
            });
        },
        removeCommand(step, index) {
            step.commands.splice(index, 1);
        },
        addVariable(step) {
            step.variables.push({
                name: '',
                description: '',
                type: 'string'
            });
        },
        removeVariable(step, index) {
            step.variables.splice(index, 1);
        },
        addCheck(step) {
            step.checks.push({
                condition: '',
                message: ''
            });
        },
        removeCheck(step, index) {
            step.checks.splice(index, 1);
        },
        async createScenario() {
            try {
                this.saving = true;
                
                // Validate scenario
                if (!this.scenario.name) {
                    throw new Error('Scenario name is required');
                }
                if (!this.scenario.steps.length) {
                    throw new Error('At least one step is required');
                }

                // Validate steps
                for (const step of this.scenario.steps) {
                    if (!step.name) {
                        throw new Error('All steps must have a name');
                    }
                    if (!step.commands.length) {
                        throw new Error('Each step must have at least one command');
                    }
                }

                // Save scenario
                const response = await fetch('/api/scenarios/custom', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(this.scenario)
                });

                const data = await response.json();
                if (data.success) {
                    // Reset form
                    this.scenario = {
                        name: '',
                        description: '',
                        category: '',
                        steps: []
                    };
                    
                    // Notify parent
                    this.$emit('scenario-created', data.scenario);
                }
            } catch (error) {
                console.error('Error creating scenario:', error);
                // You might want to show this error to the user
            } finally {
                this.saving = false;
            }
        }
    },
    mounted() {
        this.loadTools();
    }
};
