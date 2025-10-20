import re

class CleanupAgent:
    def __init__(self, platform_tools, logger):
        self.platform_tools = platform_tools
        self.logger = logger

    def run(self, task: dict) -> str:
        """Simulates a cleanup task.
        This is a basic implementation; a real agent would be more sophisticated.
        """
        action = task.get("command", "").lower()
        # Extract target from the command string
        target_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', action)
        target = target_match.group(0) if target_match else "example.com"

        self.logger.info(f"Cleanup Agent received task: {task}")
        results = []

        if "remove_backdoor" in action:
            cleanup_command = f"rm /tmp/backdoor.sh; rm /var/log/evil.log" # Simulated cleanup
            self.logger.info(f"Executing: {cleanup_command}")
            try:
                output, exit_code = self.platform_tools.execute_command(cleanup_command)
                results.append(f"Backdoor Removal Result (Exit Code: {exit_code}):\n{output}")
                if exit_code == 0:
                    results.append("Backdoor removed successfully.")
                else:
                    results.append("Backdoor removal failed.")
            except Exception as e:
                self.logger.error(f"Error executing remove_backdoor command: {e}", exc_info=True)
                results.append(f"Backdoor Removal Error: {e}")
        elif "clear_logs" in action:
            clear_logs_command = f"find /var/log -type f -name '*.log' -delete" # Simulated log clearing
            self.logger.info(f"Executing: {clear_logs_command}")
            try:
                output, exit_code = self.platform_tools.execute_command(clear_logs_command)
                results.append(f"Log Clearing Result (Exit Code: {exit_code}):\n{output}")
                if exit_code == 0:
                    results.append("Logs cleared successfully.")
                else:
                    results.append("Log clearing failed.")
            except Exception as e:
                self.logger.error(f"Error executing clear_logs command: {e}", exc_info=True)
                results.append(f"Log Clearing Error: {e}")
        else:
            results.append(f"Cleanup Agent: Unknown action '{action}' for target '{target}'.")

        return "\n".join(results)