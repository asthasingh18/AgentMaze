class Environment:

    def __init__(self):
        self.agents = {}
        self.tools = {}

    def add_agent(self, agent):
        self.agents[agent.agent_id] = agent

    def add_tool(self, tool):
        self.tools[tool.tool_id] = tool

    def run_tool(self, agent_id, tool_id):

        agent = self.agents[agent_id]
        tool = self.tools[tool_id]

        return tool.execute(agent)