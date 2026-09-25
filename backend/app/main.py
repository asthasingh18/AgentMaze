from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment


def main():

    environment = Environment()

    agent_a = Agent(
        agent_id="A001",
        name="Agent-A",
        permissions=[]
    )

    search_tool = Tool(
        tool_id="T001",
        name="search_customer",
        required_permission="customer_search"
    )

    environment.add_agent(agent_a)
    environment.add_tool(search_tool)

    print("AgentMaze")
    print("-----------------")

    print(f"Agent: {agent_a.name}")
    print("Status: ACTIVE")

    print()
    print("Available capability:")
    print("- customer_search")

    print()

    result = environment.run_tool(
        agent_id="A001",
        tool_id="T001"
    )

    print("Action:")
    print(result["message"])

    print()

    print(
        "Status:",
        "SUCCESS" if result["success"] else "BLOCKED"
    )


if __name__ == "__main__":
    main()