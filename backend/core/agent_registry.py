class AgentRegistry:
    def __init__(self, logger):
        self.agents = {}
        self.logger = logger
    def register(self, name, agent):
        self.agents[name] = agent
        self.logger.info(f"Registered agent: {name}")

    def get(self, name):
        self.logger.info(f"Retrieving agent: {name}")
        return self.agents.get(name)