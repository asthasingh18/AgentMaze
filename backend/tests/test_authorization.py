from app.database import get_connection
from app.database import create_tables
from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment



# Create database tables
create_tables()


# --------------------------------------------------
# Setup
# --------------------------------------------------

environment = Environment()


agent_a = Agent(
    agent_id="A001",
    name="Agent-A"
)

agent_b = Agent(
    agent_id="A002",
    name="Agent-B"
)

environment.add_agent(agent_a)
environment.add_agent(agent_b)


# Customer Search requires customer_search capability
customer_search = Tool(
    tool_id="T001",
    name="Customer Search",
    required_permission="customer_search"
)

environment.add_tool(customer_search)


# --------------------------------------------------
# TEST 1
# A001 has capability + tool assignment
# Expected: ALLOW
# --------------------------------------------------

print("\nTEST 1: A001 -> Customer Search")

result_1 = environment.run_tool(
    agent_id="A001",
    tool_id="T001"
)

print(result_1)


# --------------------------------------------------
# TEST 2
# A002 has capability but NO tool assignment
# Expected: DENY
# --------------------------------------------------

print("\nTEST 2: A002 -> Customer Search")

result_2 = environment.run_tool(
    agent_id="A002",
    tool_id="T001"
)

print(result_2)


# --------------------------------------------------
# TEST 3
# A001 has tool assignment but wrong capability
# --------------------------------------------------

print("\nTEST 3: A001 -> Payment Access")


payment_tool = Tool(
    tool_id="T002",
    name="Payment Access",
    required_permission="payment_access"
)

environment.add_tool(payment_tool)

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    INSERT OR IGNORE INTO capabilities
    (capability_id, name, description)
    VALUES (?, ?, ?)
""", (
    "CAP003",
    "payment_access",
    "Access payment information"
))

cursor.execute("""
    INSERT OR IGNORE INTO tools
    (tool_id, scenario_id, name, required_capability_id)
    VALUES (?, ?, ?, ?)
""", (
    "T002",
    "S001",
    "Payment Access",
    "CAP003"
))

cursor.execute("""
    INSERT OR IGNORE INTO agent_tools
    (agent_id, tool_id)
    VALUES (?, ?)
""", (
    "A001",
    "T002"
))

connection.commit()
connection.close()
result_3 = environment.run_tool(
    agent_id="A001",
    tool_id="T002"
)

print(result_3)


# --------------------------------------------------
# Print all events
# --------------------------------------------------

print("\nALL EVENTS:")

for event in environment.get_events():
    print(event)

print("\nATTACK EVENTS:")

for event in environment.get_attack_events():
    print(event)
