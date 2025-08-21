const ToolsManager = {
    data() {
        return {
            activeTab: 'installed',
            searchTool: '',
            installedTools: [],
            toolCategories: [],
            newTool: {
                name: '',
                command: '',
                checkCommand: '',
                description: '',
                category: ''
            }
        }
    },
    computed: {
        filteredTools() {
            return (tools) => {
                if (!this.searchTool) return tools;
                const searchLower = this.searchTool.toLowerCase();
                return tools.filter(tool => 
                    tool.name.toLowerCase().includes(searchLower) ||
                    tool.description.toLowerCase().includes(searchLower)
                );
            }
        }
    },
    methods: {
        async loadTools() {
            try {
                // Load installed tools
                const installedResponse = await fetch('/api/tools/installed');
                this.installedTools = await installedResponse.json();

                // Load tool categories
                const categoriesResponse = await fetch('/api/tools/categories');
                this.toolCategories = await categoriesResponse.json();
            } catch (error) {
                console.error('Error loading tools:', error);
            }
        },
        async updateTool(tool) {
            try {
                const response = await fetch(`/api/tools/update/${tool.name}`, {
                    method: 'POST'
                });
                const data = await response.json();
                if (data.success) {
                    // Refresh installed tools
                    await this.loadTools();
                }
            } catch (error) {
                console.error('Error updating tool:', error);
            }
        },
        async installTool(tool) {
            try {
                tool.installing = true;
                const response = await fetch(`/api/tools/install/${tool.name}`, {
                    method: 'POST'
                });
                const data = await response.json();
                if (data.success) {
                    // Refresh installed tools
                    await this.loadTools();
                }
            } catch (error) {
                console.error('Error installing tool:', error);
            } finally {
                tool.installing = false;
            }
        },
        async addCustomTool() {
            try {
                const response = await fetch('/api/tools/custom', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(this.newTool)
                });
                const data = await response.json();
                if (data.success) {
                    // Reset form and refresh tools
                    this.newTool = {
                        name: '',
                        command: '',
                        checkCommand: '',
                        description: '',
                        category: ''
                    };
                    await this.loadTools();
                }
            } catch (error) {
                console.error('Error adding custom tool:', error);
            }
        }
    },
    mounted() {
        this.loadTools();
    }
};
