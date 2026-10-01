class AttackGraph:

    def __init__(self):

        self.nodes = []
        self.edges = []

    def add_node(self, event):

        node = {
            "id": event.event_id,
            "type": event.event_type,
            "agent": event.agent_id,
            "severity": event.severity
        }

        self.nodes.append(node)

    def add_edge(self, source_event, target_event):

        edge = {
            "source": source_event.event_id,
            "target": target_event.event_id,
            "relation": target_event.relation,
            "severity": target_event.severity
        }

        self.edges.append(edge)

    def build_from_events(self, events):

        for event in events:

            self.add_node(event)

        for event in events:

            for parent_id in event.parent_event_ids:

                parent_event = next(
                    (
                        e for e in events
                        if e.event_id == parent_id
                    ),
                    None
                )

                if parent_event:

                    self.add_edge(
                        parent_event,
                        event
                    )

    def get_graph(self):

        return {
            "nodes": self.nodes,
            "edges": self.edges
        }

    def calculate_risk_score(self):

        if not self.nodes:
            return 0

        severity_weights = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        total_score = 0

        for node in self.nodes:

            severity = node["severity"]

            total_score += severity_weights.get(
                severity,
                1
            )

        # Extra weight for multi-step attack chains
        if len(self.edges) >= 2:
            total_score += 2

        if len(self.edges) >= 4:
            total_score += 3

        return total_score

    def get_risk_level(self):

        score = self.calculate_risk_score()

        if score >= 12:
            return "CRITICAL"

        if score >= 8:
            return "HIGH"

        if score >= 4:
            return "MEDIUM"

        return "LOW"    

    def find_root_causes(self):

        root_causes = []

        # Events that never appear as a target
        # are potential starting points of the attack.
        target_ids = {
            edge["target"]
            for edge in self.edges
        }

        for node in self.nodes:

            if node["id"] not in target_ids:
                root_causes.append(node)

        return root_causes    

    def find_terminal_events(self):

        source_ids = {
            edge["source"]
            for edge in self.edges
        }

        terminal_events = []

        for node in self.nodes:

            if node["id"] not in source_ids:
                terminal_events.append(node)

        return terminal_events