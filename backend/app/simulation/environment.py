from app.logging.event_logger import EventLogger


class Environment:

    def __init__(self):

        self.agents = {}
        self.tools = {}

        self.logger = EventLogger()

    def add_agent(self, agent):

        self.agents[agent.agent_id] = agent

        self.logger.log(
            event_type="AGENT_CREATED",
            agent_id=agent.agent_id,
            details={
                "name": agent.name,
                "permissions": agent.permissions
            },
            status="SUCCESS"
        )

    def add_tool(self, tool):
        self.tools[tool.tool_id] = tool

    def run_tool(self, agent_id, tool_id):
        agent = self.agents[agent_id]
        tool = self.tools[tool_id]

        self.logger.log(
            event_type="TOOL_REQUEST",
            agent_id=agent_id,
            details={
                "tool_id": tool_id,
                "tool_name": tool.name
            },
            status="REQUESTED"
        )

        result = tool.execute(agent, self.logger)

        self.logger.log(
            event_type="TOOL_EXECUTION",
            agent_id=agent_id,
            details={
                "tool_id": tool_id,
                "tool_name": tool.name,
                "required_permission": tool.required_permission
            },
            status="ALLOWED" if result["success"] else "BLOCKED"
        )

        return result
    def get_events(self):
        return self.logger.get_events()

    def store_memory(self, agent_id, content, source, trust_level):

        agent = self.agents[agent_id]

        item = agent.remember(
            content=content,
            source=source,
            trust_level=trust_level
        )

        self.logger.log(
            event_type="MEMORY_WRITE",
            agent_id=agent_id,
            details={
                "source": source,
                "trust_level": trust_level,
                "content": content
            },
            status="SUCCESS"
        )

        return item

    def delegate_task(self, from_agent_id, to_agent_id, task, required_capability):

        from_agent = self.agents.get(from_agent_id)
        target_agent = self.agents.get(to_agent_id)

        if from_agent is None or target_agent is None:
            return {
                "success": False,
                "message": "Delegation failed: unknown agent id",
                "from_agent": from_agent_id,
                "to_agent": to_agent_id,
                "task": task
            }

        verification = target_agent.verify_capability(required_capability)
        verified = verification.get("verified", False) if isinstance(verification, dict) else bool(verification)

        self.logger.log(
            event_type="CAPABILITY_VERIFICATION",
            agent_id=to_agent_id,
            details={
                "requested_by": from_agent_id,
                "capability": required_capability,
                "verified": verified
            },
            status="VERIFIED" if verified else "DENIED"
        )

        if not verified:
            self.logger.log(
                event_type="DELEGATION_BLOCKED",
                agent_id=from_agent_id,
                details={
                    "target_agent": to_agent_id,
                    "task": task,
                    "required_capability": required_capability
                },
                status="BLOCKED"
            )

            self.logger.log_security_event(
                event_type="INTER_AGENT_TRUST_ESCALATION",
                agent_id=from_agent_id,
                details={
                    "target_agent": to_agent_id,
                    "task": task,
                    "required_capability": required_capability,
                    "reason": "Target agent lacks required capability"
                },
                severity="HIGH"
            )

            return {
                "success": False,
                "message": "Delegation blocked: target agent lacks required capability",
                "from_agent": from_agent_id,
                "to_agent": to_agent_id,
                "task": task
            }

        delegation = from_agent.delegate(target_agent, task)

        self.logger.log(
            event_type="AGENT_DELEGATION",
            agent_id=from_agent_id,
            details={
                "target_agent": to_agent_id,
                "task": task,
                "required_capability": required_capability
            },
            status="SUCCESS"
        )

        return {
            "success": True,
            "from_agent": from_agent_id,
            "to_agent": to_agent_id,
            "task": task,
            "delegation": delegation
        }