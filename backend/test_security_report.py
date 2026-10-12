
from app.security.attack_event import AttackEvent
from app.security.security_report import SecurityReport

path = [
    AttackEvent(
        event_type="GOAL_HIJACKING",
        agent_id="A001",
        description="Controlled test event",
        severity="HIGH",
    ),
    AttackEvent(
        event_type="SESSION_CONTEXT_CONTAMINATION",
        agent_id="A001",
        description="Controlled child event",
        severity="HIGH",
        parent_event_ids=["TEST-001"],
        relation="ENABLES",
    ),
]

path[0].event_id = "TEST-001"
path[1].event_id = "TEST-002"

report = SecurityReport().generate_report(path)

print("REPORT STATUS:", report["status"])
print("PATH SCORE:", report["risk"]["score"])
print("RISK LEVEL:", report["risk"]["risk_level"])
print("ROOT CAUSE:", report["explanation"]["root_cause"]["event_type"])
print("MITIGATION CONTROLS:", report["mitigation_plan"]["controls"])
print("BEFORE:", report["before_retest"]["status"])
print("AFTER:", report["after_retest"]["status"])
print("BLOCKED AT:", report["after_retest"]["blocked_at"])

assert report["status"] == "GENERATED"
assert report["before_retest"]["status"] == "FAIL"
assert report["after_retest"]["status"] == "PASS"

print("SECURITY REPORT TEST PASSED")
