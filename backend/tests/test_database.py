
from app.database import create_tables
from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment


# Create database tables
create_tables()


# Create environment
environment = Environment()


# Create Agent-B
agent = Agent(
    agent_id="A002",
    name="Agent-B"
)

environment.add_agent(agent)


# Create Customer Search tool
tool = Tool(
    tool_id="T001",
    name="Customer Search",
    required_permission="customer_search"
)

environment.add_tool(tool)


# Try to execute the tool using Agent-B
# A002 has the customer_search capability
# BUT A002 is NOT assigned to T001

result = environment.run_tool(
    agent_id="A002",
    tool_id="T001"
)


print("Tool execution result:")
print(result)


print("\nEvents:")

for event in environment.get_events():
    print(event)
