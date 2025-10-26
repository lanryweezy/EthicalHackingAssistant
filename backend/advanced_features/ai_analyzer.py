"""
AI-powered vulnerability analysis and intelligence module.
"""
import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

class AIAnalyzer:
    """AI-powered analysis for vulnerabilities and security findings."""
    
    def __init__(self, openai_key: Optional[str] = None):
        self.openai_key = openai_key
        self.risk_patterns = self._load_risk_patterns()
        self.attack_patterns = self._load_attack_patterns()
        
    def _load_risk_patterns(self) -> Dict[str, float]:
        """Load risk scoring patterns."""
        return {
            'remote_code_execution': 9.5,
            'sql_injection': 8.5,
            'authentication_bypass': 8.0,
            'information_disclosure': 6.5,
            'denial_of_service': 6.0,
            'cross_site_scripting': 5.5,
            'privilege_escalation': 7.5,
            'configuration_error': 4.5
        }
        
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load common attack patterns for analysis."""
        return {
            'injection': [
                r'sql\s*injection',
                r'command\s*injection',
                r'code\s*injection',
                r'(exec|system|eval)\s*\(',
            ],
            'authentication': [
                r'auth.*bypass',
                r'weak\s*password',
                r'default\s*credentials',
                r'brute\s*force',
            ],
            'authorization': [
                r'privilege\s*escalation',
                r'unauthorized\s*access',
                r'missing\s*permission',
                r'broken\s*access\s*control',
            ],
            'data_exposure': [
                r'information\s*disclosure',
                r'data\s*leak',
                r'sensitive\s*data',
                r'pii',
            ]
        }
    
    def analyze_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive vulnerability analysis."""
        analysis = {
            'risk_score': self.calculate_risk(finding),
            'exploitation_difficulty': self.assess_difficulty(finding),
            'attack_vector': self.identify_attack_vector(finding),
            'remediation_steps': self.generate_remediation(finding),
            'attack_scenarios': self.generate_attack_scenarios(finding),
            'affected_systems': self.identify_affected_systems(finding),
            'mitigation_priority': self.calculate_priority(finding),
            'compliance_impact': self.assess_compliance_impact(finding),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Add AI-generated insights
        if self.openai_key:
            analysis.update(self._get_ai_insights(finding))
            
        return analysis
    
    def calculate_risk(self, finding: Dict[str, Any]) -> float:
        """Calculate risk score based on multiple factors."""
        base_score = 5.0  # Default medium risk
        
        # Check for known risk patterns
        description = finding.get('description', '').lower()
        for pattern, score in self.risk_patterns.items():
            if pattern in description:
                base_score = max(base_score, score)
        
        # Adjust based on impact and exploitability
        impact_multiplier = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.0,
            'low': 0.5
        }.get(finding.get('severity', 'medium').lower(), 1.0)
        
        # Adjust based on existing exploits
        if finding.get('has_exploit', False):
            base_score *= 1.2
            
        # Cap the final score at 10.0
        return min(base_score * impact_multiplier, 10.0)
    
    def assess_difficulty(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Assess exploitation difficulty and requirements."""
        difficulty = {
            'level': 'medium',  # Default
            'requires_authentication': False,
            'requires_user_interaction': False,
            'technical_complexity': 'medium',
            'automated_exploit_available': False,
            'prerequisites': []
        }
        
        description = finding.get('description', '').lower()
        
        # Check for authentication requirements
        if 'authenticated' in description or 'requires login' in description:
            difficulty['requires_authentication'] = True
            difficulty['prerequisites'].append('Valid user credentials')
        
        # Check for user interaction
        if 'user click' in description or 'social engineering' in description:
            difficulty['requires_user_interaction'] = True
            difficulty['prerequisites'].append('User interaction')
        
        # Assess technical complexity
        if any(term in description for term in ['complex', 'chained', 'sophisticated']):
            difficulty['technical_complexity'] = 'high'
        elif any(term in description for term in ['simple', 'straightforward', 'easy']):
            difficulty['technical_complexity'] = 'low'
            
        # Check for automated exploits
        if finding.get('exploits', []):
            difficulty['automated_exploit_available'] = True
            
        # Determine overall level
        if difficulty['technical_complexity'] == 'high' and difficulty['requires_authentication']:
            difficulty['level'] = 'hard'
        elif difficulty['technical_complexity'] == 'low' and not difficulty['requires_authentication']:
            difficulty['level'] = 'easy'
            
        return difficulty
    
    def identify_attack_vector(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Identify and categorize attack vectors."""
        description = finding.get('description', '').lower()
        vectors = []
        
        # Check against known attack patterns
        for category, patterns in self.attack_patterns.items():
            if any(re.search(pattern, description) for pattern in patterns):
                vectors.append(category)
                
        return {
            'primary_vector': vectors[0] if vectors else 'unknown',
            'all_vectors': vectors,
            'network_required': 'remote' in description or 'network' in description,
            'local_required': 'local' in description,
            'physical_required': 'physical' in description
        }
    
    def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed remediation steps."""
        vulnerability_type = self._categorize_vulnerability(finding)
        
        # Get base remediation template
        remediation = self._get_remediation_template(vulnerability_type)
        
        # Enhance with specific details
        remediation['steps'] = self._customize_remediation_steps(
            remediation['steps'],
            finding
        )
        
        # Add verification steps
        remediation['verification'] = self._generate_verification_steps(finding)
        
        return remediation
    
    def _categorize_vulnerability(self, finding: Dict[str, Any]) -> str:
        """Categorize the vulnerability type."""
        description = finding.get('description', '').lower()
        
        for category, patterns in self.attack_patterns.items():
            if any(re.search(pattern, description) for pattern in patterns):
                return category
                
        return 'general'
    
    def _get_remediation_template(self, vulnerability_type: str) -> Dict[str, Any]:
        """Get remediation template based on vulnerability type."""
        templates = {
            'injection': {
                'steps': [
                    'Implement input validation',
                    'Use parameterized queries',
                    'Apply output encoding',
                    'Update framework/libraries'
                ],
                'priority': 'high',
                'effort': 'medium'
            },
            'authentication': {
                'steps': [
                    'Implement strong password policy',
                    'Enable multi-factor authentication',
                    'Apply rate limiting',
                    'Review session management'
                ],
                'priority': 'critical',
                'effort': 'high'
            },
            'authorization': {
                'steps': [
                    'Review access control model',
                    'Implement role-based access control',
                    'Add authorization checks',
                    'Audit permission assignments'
                ],
                'priority': 'high',
                'effort': 'high'
            },
            'data_exposure': {
                'steps': [
                    'Encrypt sensitive data',
                    'Review data handling practices',
                    'Implement secure storage',
                    'Add data access logging'
                ],
                'priority': 'critical',
                'effort': 'medium'
            },
            'general': {
                'steps': [
                    'Review security configuration',
                    'Update affected components',
                    'Apply security patches',
                    'Implement monitoring'
                ],
                'priority': 'medium',
                'effort': 'medium'
            }
        }
        
        return templates.get(vulnerability_type, templates['general'])
    
    def _customize_remediation_steps(self, base_steps: List[str], finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Customize remediation steps with specific details."""
        customized_steps = []
        
        for step in base_steps:
            step_details = {
                'description': step,
                'technical_details': self._generate_technical_details(step, finding),
                'verification_method': self._generate_verification_method(step),
                'effort_level': self._estimate_effort(step),
                'prerequisites': self._identify_prerequisites(step)
            }
            customized_steps.append(step_details)
            
        return customized_steps
    
    def _generate_technical_details(self, step: str, finding: Dict[str, Any]) -> str:
        """Generate technical implementation details for a step."""
        # This would be enhanced with actual AI-generated content
        return f"Technical implementation details for: {step}"
    
    def _generate_verification_method(self, step: str) -> Dict[str, Any]:
        """Generate verification method for a remediation step."""
        return {
            'method': 'testing',
            'automated_possible': True,
            'test_steps': [
                f"Verify {step.lower()}",
                "Run security scan",
                "Validate changes"
            ]
        }
    
    def _estimate_effort(self, step: str) -> Dict[str, Any]:
        """Estimate effort required for a remediation step."""
        return {
            'level': 'medium',
            'estimated_hours': 4,
            'required_skills': ['security', 'development'],
            'dependencies': []
        }
    
    def _identify_prerequisites(self, step: str) -> List[str]:
        """Identify prerequisites for a remediation step."""
        return [
            "Access to affected systems",
            "Development environment",
            "Security testing tools"
        ]
    
    def _generate_verification_steps(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate verification steps for remediation."""
        return [
            {
                'step': 'Verify vulnerability remediation',
                'method': 'security testing',
                'tools': ['appropriate security testing tools'],
                'expected_outcome': 'Vulnerability no longer present'
            },
            {
                'step': 'Regression testing',
                'method': 'functional testing',
                'tools': ['testing framework'],
                'expected_outcome': 'No adverse effects on functionality'
            },
            {
                'step': 'Security scan',
                'method': 'automated scanning',
                'tools': ['security scanner'],
                'expected_outcome': 'No related vulnerabilities detected'
            }
        ]
    
    def generate_attack_scenarios(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate possible attack scenarios."""
        vulnerability_type = self._categorize_vulnerability(finding)
        
        scenarios = []
        base_scenario = self._get_base_attack_scenario(vulnerability_type)
        
        # Generate variations
        for complexity in ['simple', 'complex']:
            scenario = base_scenario.copy()
            scenario['complexity'] = complexity
            scenario['steps'] = self._generate_attack_steps(
                vulnerability_type,
                complexity,
                finding
            )
            scenarios.append(scenario)
            
        return scenarios
    
    def _get_base_attack_scenario(self, vulnerability_type: str) -> Dict[str, Any]:
        """Get base attack scenario template."""
        return {
            'type': vulnerability_type,
            'prerequisites': [],
            'steps': [],
            'success_probability': 'medium',
            'impact': 'significant'
        }
    
    def _generate_attack_steps(
        self,
        vulnerability_type: str,
        complexity: str,
        finding: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate detailed attack steps."""
        # This would be enhanced with actual AI-generated content
        return [
            {
                'step': 'Initial Access',
                'description': 'Gain initial access to the system',
                'complexity': complexity
            },
            {
                'step': 'Exploit Execution',
                'description': 'Execute the exploit',
                'complexity': complexity
            },
            {
                'step': 'Post Exploitation',
                'description': 'Perform post-exploitation activities',
                'complexity': complexity
            }
        ]
    
    def identify_affected_systems(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Identify systems affected by the vulnerability."""
        return {
            'direct_systems': self._identify_direct_systems(finding),
            'indirect_systems': self._identify_indirect_systems(finding),
            'dependencies': self._identify_dependencies(finding),
            'data_flows': self._identify_data_flows(finding)
        }
    
    def _identify_direct_systems(self, finding: Dict[str, Any]) -> List[str]:
        """Identify directly affected systems."""
        systems = []
        description = finding.get('description', '').lower()
        
        if 'web' in description or 'http' in description:
            systems.append('web_server')
        if 'database' in description or 'sql' in description:
            systems.append('database_server')
        if 'api' in description:
            systems.append('api_server')
            
        return systems
    
    def _identify_indirect_systems(self, finding: Dict[str, Any]) -> List[str]:
        """Identify indirectly affected systems."""
        return ['connected_services', 'dependent_systems']
    
    def _identify_dependencies(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify system dependencies."""
        return [
            {
                'type': 'service',
                'name': 'example_service',
                'impact': 'moderate'
            }
        ]
    
    def _identify_data_flows(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify affected data flows."""
        return [
            {
                'source': 'user_input',
                'destination': 'application',
                'data_type': 'user_data',
                'risk_level': 'high'
            }
        ]
    
    def calculate_priority(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate remediation priority."""
        risk_score = self.calculate_risk(finding)
        
        priority = {
            'level': 'medium',
            'score': risk_score,
            'factors': [],
            'timeframe': '30 days'
        }
        
        # Determine priority level
        if risk_score >= 8.0:
            priority['level'] = 'critical'
            priority['timeframe'] = '7 days'
        elif risk_score >= 6.0:
            priority['level'] = 'high'
            priority['timeframe'] = '14 days'
        elif risk_score >= 4.0:
            priority['level'] = 'medium'
        else:
            priority['level'] = 'low'
            priority['timeframe'] = '90 days'
            
        # Add contributing factors
        priority['factors'] = self._identify_priority_factors(finding)
        
        return priority
    
    def _identify_priority_factors(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify factors affecting priority."""
        factors = []
        
        if finding.get('has_exploit', False):
            factors.append({
                'name': 'exploit_available',
                'impact': 'high',
                'description': 'Public exploit is available'
            })
            
        if 'customer' in finding.get('affected_systems', []):
            factors.append({
                'name': 'customer_impact',
                'impact': 'high',
                'description': 'Customer systems affected'
            })
            
        return factors
    
    def assess_compliance_impact(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Assess impact on compliance requirements."""
        return {
            'frameworks': self._identify_affected_frameworks(finding),
            'requirements': self._identify_compliance_requirements(finding),
            'violations': self._identify_compliance_violations(finding),
            'reporting_requirements': self._identify_reporting_requirements(finding)
        }
    
    def _identify_affected_frameworks(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify affected compliance frameworks."""
        frameworks = []
        description = finding.get('description', '').lower()
        
        if 'pii' in description or 'personal' in description:
            frameworks.append({
                'name': 'GDPR',
                'relevance': 'high',
                'requirements': ['data_protection', 'breach_notification']
            })
            
        if 'payment' in description or 'credit' in description:
            frameworks.append({
                'name': 'PCI-DSS',
                'relevance': 'high',
                'requirements': ['data_encryption', 'access_control']
            })
            
        return frameworks
    
    def _identify_compliance_requirements(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify specific compliance requirements."""
        return [
            {
                'requirement': 'data_protection',
                'description': 'Protect sensitive data',
                'status': 'violated'
            }
        ]
    
    def _identify_compliance_violations(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify specific compliance violations."""
        return [
            {
                'requirement': 'data_protection',
                'violation': 'Inadequate data protection',
                'severity': 'high'
            }
        ]
    
    def _identify_reporting_requirements(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify reporting requirements."""
        return [
            {
                'framework': 'GDPR',
                'requirement': 'breach_notification',
                'deadline': '72 hours'
            }
        ]
    
    def _get_ai_insights(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI-generated insights about the vulnerability."""
        # This would be enhanced with actual AI integration
        return {
            'ai_analysis': 'AI-generated analysis would go here',
            'recommendations': ['AI-generated recommendations'],
            'similar_cases': ['Similar vulnerability cases']
        }
