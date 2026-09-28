class Tool:

    def __init__(self, tool_id, name, required_permission):
        self.tool_id = tool_id
        self.name = name
        self.required_permission = required_permission

    def execute(self, agent, logger):

        allowed = agent.can_use(self.required_permission)

        logger.log(
            event_type="PERMISSION_CHECK",
            agent_id=agent.agent_id,
            details={
                "tool_id": self.tool_id,
                "required_permission": self.required_permission
            },
            status="GRANTED" if allowed else "DENIED"
        )

        if not allowed:
            return {
                "success": False,
                "message": f"{agent.name} does not have permission to use {self.name}"
            }

        return {
            "success": True,
            "message": f"{agent.name} executed {self.name}"
        }