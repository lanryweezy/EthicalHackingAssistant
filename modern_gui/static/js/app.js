// Create Vue Application
const app = Vue.createApp({
    data() {
        return {
            drawer: true,
            currentView: 'scenarios',
            scenarios: [],
            availableTools: [],
            pentestData: {
                target: '',
                findings: []
            }
        }
    },
    methods: {
        async loadScenarios() {
            try {
                const response = await fetch('/api/scenarios');
                const data = await response.json();
                this.scenarios = [...data.built_in, ...data.custom];
            } catch (error) {
                console.error('Error loading scenarios:', error);
            }
        },
        async startScenario(scenario) {
            // Handle scenario start
            console.log('Starting scenario:', scenario);
        }
    },
    mounted() {
        this.loadScenarios();
    }
});

// Create Vuetify instance
const vuetify = Vuetify.createVuetify();
app.use(vuetify);

// Register components
app.component('scenario-wizard', ScenarioWizard);
app.component('tools-manager', ToolsManager);
app.component('report-generator', ReportGenerator);
app.component('custom-scenario-creator', CustomScenarioCreator);

// Mount the app
app.mount('#app');
