class Agent:

    def __init__(self, agent_id, name, permissions=None):
        self.agent_id = agent_id
        self.name = name
        self.permissions = permissions or []
        self.memory = []

    def can_use(self, capability):
        return capability in self.permissions

    def remember(self, data):
        self.memory.append(data)

    def __str__(self):
        return f"{self.name} ({self.agent_id})"