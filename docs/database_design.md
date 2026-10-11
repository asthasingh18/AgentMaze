# AgentMaze Database Design

## Tables

1. Scenarios
2. Agents
3. Tools
4. Attack Events
5. Attack Paths
6. Mitigations
7. Re-test Runs

### 1. Agents

| Column | Purpose |
|---|---|
| agent_id | Unique ID of the agent (PK) |
| name | Name of the agent |
| scenario_id | Scenario this agent belongs to (FK) |

### Design Problem — Permissions

Example:

| agent_id | name | permissions |
|---|---|---|
| A001 | Agent-A | customer_search, database_admin, file_read |

Problem:
The permissions column contains multiple values in a single cell.

### 2. Tools

| Column | Purpose |
|---|---|
| tool_id | Unique ID of the tool (PK) |
| scenario_id | Scenario this tool belongs to (FK → Scenarios) |
| name | Name of the tool |
| required_capabilities_id | Capabilities required to use the tool (FK -> capabilities)|

### 3. Attack Events

| Column | Purpose |
|---|---|
| event_id | Unique ID of the attack event (PK) |
| timestamp | When the event occurred |
| event_type | Type of security event |
| agent_id | Agent involved in the event (FK) |
| description | Explanation of what happened |
| severity | Severity of the event |
| source | Source of the event |
| target | Target of the event |

### 4. Attack Paths

| Column | Purpose |
|---|---|
| path_id | Unique ID of the attack path (PK) |
| scenario_id | Scenario this attack path belongs to (FK → Scenarios) |
| created_at | When the attack path was discovered |
| risk_score | Calculated risk score |
| risk_level | LOW, MEDIUM, HIGH, or CRITICAL |

### 5. Mitigations

| Column | Purpose |
|---|---|
| mitigation_id | Unique ID of the mitigation (PK) |
| event_id | Attack event being mitigated  (FK → Attack Events) |
| control | Security control applied |
| action | Description of what the mitigation does |
| created_at | When the mitigation was created |

### 6. Re-test Runs

| Column | Purpose |
|---|---|
| retest_id | Unique ID of the re-test (PK) |
| path_id | Attack path that was tested (FK → Attack Paths) |
| started_at | When the re-test started |
| status | PASS or FAIL |
| original_length | Number of steps in the original attack path |
| blocked_event_id | Attack event where the attack was blocked (FK → Attack Events) |
| blocked_mitigation_id | Mitigation that blocked the attack (FK → Mitigations) |
| message | Explanation of the re-test result |

### 7. Scenarios

| Column | Purpose |
|---|---|
| scenario_id | Unique ID of the scenario |
| name | Name of the security scenario |
| description | What the scenario is testing |
| created_at | When the scenario was created |
| status | Current scenario status |

### 8. Agent Tools

| Column | Purpose |
|---|---|
| agent_id | Agent using the tool (FK) |
| tool_id | Tool being used (FK) |

### 9. Attack Path Events

| Column | Purpose |
|---|---|
| path_id | Attack path (FK) |
| event_id | Attack event belonging to the path (FK) |
| step_number | Position of the event in the attack path |

### 10. Capabilities

| Column | Purpose |
|---|---|
| capability_id | Unique ID of the capability (PK) |
| name | Name of the capability |
| description | What the capability allows |

### 11. Agent Capabilities

| Column | Purpose |
|---|---|
| agent_id | Agent ID (FK → Agents, part of composite PK) |
| capability_id | Capability ID (FK → Capabilities, part of composite PK) |

### 12. Event Dependencies

| Column | Purpose |
|---|---|
| parent_event_id | Previous attack event (FK → Attack Events, part of composite PK) |
| child_event_id | Attack event enabled by the parent (FK → Attack Events, part of composite PK) |
| relation | Relationship between the two events |

### 13. Attack Path Events

| Column | Purpose |
|---|---|
| path_id | Attack path ID (FK → Attack Paths, part of composite PK) |
| event_id | Attack event ID (FK → Attack Events, part of composite PK) |
| step_number | Order of the event within the attack path |

### 14. Agent Tools

| Column | Purpose |
|---|---|
| agent_id | Agent ID (FK → Agents, part of composite PK) |
| tool_id | Tool ID (FK → Tools, part of composite PK) |