const ReportGenerator = {
    data() {
        return {
            report: {
                title: '',
                template: null,
                findings: [],
                executiveSummary: '',
                format: 'PDF'
            },
            reportTemplates: [],
            generating: false
        }
    },
    methods: {
        async loadTemplates() {
            try {
                const response = await fetch('/api/reports/templates');
                this.reportTemplates = await response.json();
            } catch (error) {
                console.error('Error loading report templates:', error);
            }
        },
        addFinding() {
            this.report.findings.push({
                title: '',
                severity: 'Medium',
                cveId: '',
                description: '',
                technicalDetails: '',
                remediation: '',
                evidence: [],
                cveDetails: null,
                exploits: []
            });
        },
        async fetchCVEDetails(finding) {
            if (!finding.cveId) return;
            
            try {
                const response = await fetch(`/api/vulnerability/cve/${finding.cveId}`);
                const data = await response.json();
                finding.cveDetails = data;

                // Also fetch related exploits
                const exploitsResponse = await fetch(`/api/vulnerability/exploits/${finding.cveId}`);
                const exploitsData = await exploitsResponse.json();
                finding.exploits = exploitsData;
            } catch (error) {
                console.error('Error fetching CVE details:', error);
            }
        },
        async generateReport() {
            try {
                this.generating = true;
                
                // Process screenshots/evidence
                for (const finding of this.report.findings) {
                    if (finding.evidence && finding.evidence.length) {
                        const formData = new FormData();
                        finding.evidence.forEach(file => formData.append('files', file));
                        
                        const uploadResponse = await fetch('/api/reports/upload-evidence', {
                            method: 'POST',
                            body: formData
                        });
                        const uploadData = await uploadResponse.json();
                        finding.evidencePaths = uploadData.paths;
                    }
                }

                // Generate the report
                const response = await fetch('/api/reports/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(this.report)
                });

                const data = await response.json();
                if (data.success) {
                    // Download the generated report
                    window.location.href = `/api/reports/download/${data.reportId}`;
                }
            } catch (error) {
                console.error('Error generating report:', error);
            } finally {
                this.generating = false;
            }
        }
    },
    mounted() {
        this.loadTemplates();
    }
};
