class ContextAwareAgent:
    def __init__(self, logger):
        self.context_history = []
        self.logger = logger

    def update_context(self, command: str, result: str):
        """Stores the command and its result in the context history.
        In a real scenario, this would involve more sophisticated context analysis.
        """
        self.context_history.append({"command": command, "result": result})
        self.logger.info(f"Context updated with command: '{command}' and result: '{result[:50]}...'")
        # Keep history manageable
        if len(self.context_history) > 10:
            self.context_history.pop(0)

    def suggest_next_actions(self) -> list:
        """Suggests basic next actions based on recent context.
        This is a placeholder; real AI suggestions would be more dynamic.
        """
        self.logger.info("Generating next action suggestions.")
        suggestions = []
        last_command = self.context_history[-1]["command"] if self.context_history else ""
        last_result = self.context_history[-1]["result"] if self.context_history else ""

        if "nmap" in last_command.lower() and "open" in last_result.lower():
            suggestions.append({"action": "Scan for vulnerabilities", "command": "scan_vulnerabilities {target}", "description": "Run a vulnerability scan on the discovered open ports."})
            suggestions.append({"action": "Exploit discovered services", "command": "exploit_service {target}", "description": "Attempt to exploit services found on open ports."})
        elif "exploit" in last_command.lower() and "successful" in last_result.lower():
            suggestions.append({"action": "Cleanup and report", "command": "cleanup_report {target}", "description": "Automate post-exploitation cleanup and generate a report."})
            suggestions.append({"action": "Pivot to other systems", "command": "pivot {target}", "description": "Look for ways to move to other systems in the network."})
        elif "cleanup" in last_command.lower() and "successful" in last_result.lower():
            suggestions.append({"action": "Generate final report", "command": "generate_report {target}", "description": "Create a comprehensive report of the assessment."})
        elif "error" in last_result.lower():
            suggestions.append({"action": "Review logs", "command": "view_logs", "description": "Check logs for more details on the error."})
            suggestions.append({"action": "Try a different approach", "command": "try_different_tool", "description": "Consider using an alternative tool or method."})
        else:
            suggestions.append({"action": "Explore further", "command": "ls -la", "description": "List files in the current directory."})
            suggestions.append({"action": "Get help", "command": "help", "description": "Display available commands and modes."})

        return suggestions