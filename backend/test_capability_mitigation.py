
from app.security.attack_event import AttackEvent
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine

# Create a standalone capability-abuse event
event = AttackEvent(
    event_type="CAPABILITY_ABUSE",
    agent_id="A001",
    description="Agent attempted an operation without the required capability.",
    severity="HIGH"
)

path = [event]

# Test before mitigation
retest = RetestEngine()
before = retest.retest_path(path)

# Generate and apply the mitigation
mitigation = MitigationEngine()
plan = mitigation.generate_plan(path)
retest.apply_mitigation(plan)

# Test after mitigation
after = retest.retest_path(path)

print("BEFORE:", before["status"])
print("AFTER:", after["status"])
print("BLOCKED AT:", after["blocked_at"])
print("BLOCKED CONTROL:", after.get("blocked_control"))

assert before["status"] == "FAIL"
assert after["status"] == "PASS"
assert after["blocked_control"] == "CAPABILITY_ENFORCEMENT"

print("CAPABILITY MITIGATION TEST PASSED")
