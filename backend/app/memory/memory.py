from datetime import datetime


class MemoryItem:

    def __init__(self, content, source, trust_level):

        self.content = content
        self.source = source
        self.trust_level = trust_level
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):

        return {
            "content": self.content,
            "source": self.source,
            "trust_level": self.trust_level,
            "timestamp": self.timestamp
        }


class AgentMemory:

    def __init__(self):

        self.items = []

    def store(self, content, source, trust_level):

        item = MemoryItem(
            content=content,
            source=source,
            trust_level=trust_level
        )

        self.items.append(item)

        return item

    def get_all(self):

        return [item.to_dict() for item in self.items]