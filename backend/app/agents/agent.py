from app.memory.memory import AgentMemory


class Agent:

    def __init__(self, agent_id, name, permissions=None):

        self.agent_id = agent_id
        self.name = name
        self.permissions = permissions or []

        self.memory = AgentMemory()

    def can_use(self, capability):

        return capability in self.permissions

    def has_capability(self, capability):

        return capability in self.permissions       

    def remember(self, content, source, trust_level):

        return self.memory.store(
            content=content,
            source=source,
            trust_level=trust_level
        )

    def get_memory(self):

        return self.memory.get_all()
    
    def delegate(self, target_agent, task):

        return {
            "from_agent": self.agent_id,
            "to_agent": target_agent.agent_id,
            "task": task
       }

    def verify_capability(self, capability):
        return {
            "agent_id": self.agent_id,
            "capability": capability,
            "verified": self.has_capability(capability)
      }   

    def __str__(self):

        return f"{self.name} ({self.agent_id})"