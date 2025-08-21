# main.py

import sys
import os
import logging
from src.core.ai_parser import AIParser
from src.core.executor import Executor
from src.core.agent_registry import AgentRegistry
from src.workflows.recon_workflow import ReconWorkflow
from src.agents import recon_agent, exploit_agent, cleanup_agent
from src.agents.context_aware_agent import ContextAwareAgent
from src.ui.cli_ui import EthicalHackingCLI

class EthicalHackingAssistant:
    """Main application class for the Ethical Hacking Assistant"""
    
    def __init__(self):
        """Initialize the main application components"""
        # Initialize core components
        self.ai_parser = AIParser()
        self.executor = Executor()
        self.agent_registry = AgentRegistry()
        
        # Set up logging
        self.setup_logging()
        
        # Register agents
        self.register_agents()
        
        # Initialize the CLI
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config/ui_config.yaml")
        self.cli = EthicalHackingCLI(config_path)
        
        # Register command handlers
        self.register_command_handlers()
    
    def setup_logging(self):
        """Set up application-level logging"""
        self.logger = logging.getLogger("ethical_hacking_assistant")
    
    def register_agents(self):
        """Register all available agents"""
        self.agent_registry.register('recon', recon_agent)
        self.agent_registry.register('exploit', exploit_agent)
        self.agent_registry.register('cleanup', cleanup_agent)
        
        # Initialize and register the context-aware agent
        self.context_agent = ContextAwareAgent()
        self.agent_registry.register('context_aware', self.context_agent)
        
        # Log available agents
        self.logger.info(f"Registered agents: {list(self.agent_registry.agents.keys())}")
    
    def register_command_handlers(self):
        """Register handlers for CLI commands"""
        # These handlers will process commands after they're parsed by the CLI
        self.cli.register_command('agent', self.handle_agent_command)
        self.cli.register_command('workflow', self.handle_workflow_command)
        self.cli.register_command('target', self.handle_target_command)
    
    def handle_agent_command(self, args):
        """Handle agent-mode commands
        
        Args:
            args: Command arguments
            
        Returns:
            True to continue execution
        """
        # This would be called when the user runs a command in agent mode
        # We'll implement this in a future update
        return True
    
    def handle_workflow_command(self, args):
        """Handle workflow commands
        
        Args:
            args: Command arguments
            
        Returns:
            True to continue execution
        """
        # This would be called when the user runs a workflow command
        # We'll implement this in a future update
        return True
    
    def handle_target_command(self, args):
        """Handle target setting commands
        
        Args:
            args: Command arguments
            
        Returns:
            True to continue execution
        """
        # This would be called when the user sets a target
        # We'll implement this in a future update
        return True
    
    def process_command(self, mode, command):
        """Process a user command and update context-aware agent accordingly
        
        Args:
            mode: The current CLI mode
            command: The command text
        Returns:
            Result of command execution (plus learning and suggested next steps)
        """
        try:
            if mode == 'agent':
                # AI interprets and runs
                task = self.ai_parser.parse(command)
                agent = self.agent_registry.get(task['agent'])
                if agent:
                    result = agent.run(task)
                    # Feed the input/output into context-aware agent for persistent learning
                    if agent == self.context_agent and isinstance(result, dict) and 'data' in result:
                        # Results are already context-updating
                        pass
                    elif agent != self.context_agent:
                        # If another agent, try to pass output to context-agent if possible
                        self.context_agent.update_context(command, str(result))
                    # After every agent run, suggest next actions based on new context
                    next_suggestions = self.context_agent.suggest_next_actions()
                    if next_suggestions:
                        result_str = result if isinstance(result, str) else ''
                        result_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            result_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                        return result_str
                    return result
                else:
                    return "Could not determine the appropriate agent."

            elif mode == 'terminal':
                # Raw shell command with safety checks
                if self.is_safe_command(command):
                    output = self.executor.run(command)
                    # Always push output to the context-aware agent
                    self.context_agent.update_context(command, str(output))
                    # Suggest next steps
                    next_suggestions = self.context_agent.suggest_next_actions()
                    output_str = str(output)
                    if next_suggestions:
                        output_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            output_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                    return output_str
                else:
                    return "Command rejected for security reasons. Use with caution."

            elif mode == 'more':
                # AI suggests, user confirms
                task = self.ai_parser.parse(command)
                self.cli.terminal.print_message(f"AI Suggestion: {task['command']}", "info")
                confirm = self.cli.input_prompt("Run this command? (y/n): ", "warning")
                if confirm.lower() == 'y':
                    output = self.executor.run(task['command'])
                    self.context_agent.update_context(command, str(output))
                    next_suggestions = self.context_agent.suggest_next_actions()
                    output_str = str(output)
                    if next_suggestions:
                        output_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            output_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                    return output_str
                return "Command cancelled by user."

            elif mode == 'auto':
                # Fully autonomous workflow
                if 'recon' in command.lower():
                    workflow = ReconWorkflow(command)
                    result = workflow.run()
                    self.context_agent.update_context(command, str(result))
                    next_suggestions = self.context_agent.suggest_next_actions()
                    result_str = str(result)
                    if next_suggestions:
                        result_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            result_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                    return result_str
                else:
                    return "Auto mode only supports recon workflow for now."
            
            return "Unknown mode. This should not happen."
            
        except Exception as e:
            self.logger.error(f"Error processing command: {e}", exc_info=True)
            return f"An error occurred: {e}"
    
    def is_safe_command(self, command):
        """Check if a command is safe to execute
        
        Args:
            command: The command string
            
        Returns:
            True if the command is considered safe, False otherwise
        """
        # List of potentially dangerous commands/patterns
        dangerous_patterns = [
            "rm -rf", "format", "mkfs", "dd if=", "fdisk", 
            ":(){ :|:& };:", # Fork bomb
            "chmod -R 777 /", "chmod -R 000 /",
            "wget .* | bash", "curl .* | bash",
            "> /dev/sda", "> /dev/hda"
        ]
        
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if pattern in command.lower():
                self.logger.warning(f"Potentially dangerous command detected: {command}")
                return False
        
        return True
    
    def run(self):
        """Run the main application"""
        # Start the CLI interface with our command processor
        self.cli.run(command_processor=self.process_command)

# Main entry point
def main():
    app = EthicalHackingAssistant()
    app.run()

if __name__ == "__main__":
    main()

