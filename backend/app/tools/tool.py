class Tool:

    def __init__(self, tool_id, name, required_permission):
        self.tool_id = tool_id
        self.name = name
        self.required_permission = required_permission

    def execute(self, agent):

        if not agent.can_use(self.required_permission):
            return {
                "success": False,
                "message": f"{agent.name} does not have permission to use {self.name}"
            }

        return {
            "success": True,
            "message": f"{agent.name} executed {self.name}"
        }