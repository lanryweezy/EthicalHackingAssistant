import re

class ReconAgent:
    def __init__(self, platform_tools, logger):
        self.platform_tools = platform_tools
        self.logger = logger

    def run(self, task: dict) -> str:
        """Executes reconnaissance tasks based on the parsed command.
        This is a basic implementation; a real agent would be more sophisticated.
        """
        action = task.get("command", "").lower()
        # Extract target from the command string
        target_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', action)
        target = target_match.group(0) if target_match else "example.com"

        self.logger.info(f"Recon Agent received task: {task}")
        results = []

        if "scan" in action:
            nmap_command = f"nmap -sS -sV {target}"
            self.logger.info(f"Executing: {nmap_command}")
            try:
                output, exit_code = self.platform_tools.execute_command(nmap_command)
                results.append(f"Nmap Scan Result (Exit Code: {exit_code}):\n{output}")
            except Exception as e:
                self.logger.error(f"Error executing Nmap command: {e}", exc_info=True)
                results.append(f"Nmap Scan Error: {e}")
        elif "subdomain" in action:
            subfinder_command = f"subfinder -d {target}"
            self.logger.info(f"Executing: {subfinder_command}")
            try:
                output, exit_code = self.platform_tools.execute_command(subfinder_command)
                results.append(f"Subdomain Enumeration Result (Exit Code: {exit_code}):\n{output}")
            except Exception as e:
                self.logger.error(f"Error executing Subfinder command: {e}", exc_info=True)
                results.append(f"Subdomain Enumeration Error: {e}")
        else:
            results.append(f"Recon Agent: Unknown action '{action}' for target '{target}'.")

        return "\n".join(results)

recon_agent = ReconAgent(None, None) # Placeholder for instantiation with actual tools