from app.logging.event_logger import EventLogger
from app.security.attack_manager import AttackManager

class Environment:

    def __init__(self):

        self.agents = {}
        self.tools = {}

        self.logger = EventLogger()
        self.attack_manager = AttackManager()

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

        agent = self.agents.get(agent_id)
        tool = self.tools.get(tool_id)

        if not agent:
            return {
                "success": False,
                "message": f"Agent {agent_id} not found"
            }

        if not tool:
            return {
                "success": False,
                "message": f"Tool {tool_id} not found"
            }

        from app.database import agent_has_tool

        if not agent_has_tool(agent_id, tool_id):

            # Normal security event
            self.logger.log(
                event_type="TOOL_ACCESS_DENIED",
                agent_id=agent_id,
                details={
                    "tool_id": tool_id,
                    "reason": "Tool not assigned to agent"
                },
                status="DENIED"
            )

            # Attack event
            self.attack_manager.record_event(
                event_type="MCP_PLUGIN_ABUSE",
                agent_id=agent_id,
                description=(
                    f"{agent.name} attempted to access "
                    f"unauthorized tool {tool.name}"
                ),
                severity="HIGH",
                source=agent_id,
                target=tool_id
            )

            return {
                "success": False,
                "message": f"{agent.name} is not assigned to {tool.name}"
            }

        result = tool.execute(agent, self.logger)

        if not result["success"]:
            self.attack_manager.record_event(
                event_type="CAPABILITY_ABUSE",
                agent_id=agent_id,
                description=(
                    f"{agent.name} attempted to use {tool.name} "
                    f"without the required capability "
                    f"'{tool.required_permission}'"
                ),
                severity="HIGH",
                source=agent_id,
                target=tool_id
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

            self.attack_manager.record_event(
                event_type="INTER_AGENT_TRUST_ESCALATION",
                agent_id=from_agent_id,
                description="Agent attempted to delegate a task requiring an unauthorized capability",
                severity="HIGH",
                source=from_agent_id,
                target=to_agent_id
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
    
    def get_attack_events(self):

        return self.attack_manager.get_events()