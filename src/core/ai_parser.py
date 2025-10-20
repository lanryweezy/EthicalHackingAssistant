class AIParser:
    def __init__(self, logger):
        self.logger = logger

    def parse(self, command: str) -> dict:
        """Parses a command string to extract agent and command.
        This version uses keyword-based parsing to simulate AI understanding.
        """
        self.logger.info(f"Parsing command: '{command}'")
        command_lower = command.strip().lower()
        
        if command_lower.startswith("scan"): 
            parsed_command = {"agent": "recon", "command": command_lower.replace("scan", "").strip(), "task_type": "scan"}
        elif command_lower.startswith("exploit"): 
            parsed_command = {"agent": "exploit", "command": command_lower.replace("exploit", "").strip(), "task_type": "exploit"}
        elif command_lower.startswith("cleanup"): 
            parsed_command = {"agent": "cleanup", "command": command_lower.replace("cleanup", "").strip(), "task_type": "cleanup"}
        elif command_lower.startswith("nmap"): 
            parsed_command = {"agent": "nmap_helper", "command": command_lower.replace("nmap", "").strip(), "task_type": "nmap_command"}
        elif command_lower.startswith("oscp"): 
            parsed_command = {"agent": "oscp_resources", "command": command_lower.replace("oscp", "").strip(), "task_type": "oscp_info"}
        elif command_lower.startswith("help"): 
            parsed_command = {"agent": "system", "command": "display_help", "task_type": "info"}
        elif command_lower.startswith("info"): 
            parsed_command = {"agent": "system", "command": "display_info", "task_type": "info"}
        else:
            # Default to terminal mode if no specific agent is identified
            parsed_command = {"agent": "terminal", "command": command, "task_type": "execute"}
        
        self.logger.info(f"Parsed command to agent: {parsed_command['agent']}, task_type: {parsed_command['task_type']}")
        return parsed_command