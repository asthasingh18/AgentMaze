
from app.security.attack_manager import AttackManager
from app.database import get_event_dependencies


manager = AttackManager()

# Create a parent event
parent = manager.record_event(
    event_type="GOAL_HIJACKING",
    agent_id="A001",
    description="Controlled test: parent attack event",
    severity="HIGH"
)

# Create a child event linked to the parent
child = manager.record_event(
    event_type="INTER_AGENT_TRUST_ESCALATION",
    agent_id="A002",
    description="Controlled test: child attack event",
    severity="HIGH",
    parent_event_ids=[parent.event_id],
    relation="leads_to"
)

print("\nCREATED EVENTS:")
print(parent.event_id, parent.event_type)
print(child.event_id, child.event_type)

print("\nSTORED DEPENDENCIES:")
for dependency in get_event_dependencies():
    print(dependency)
