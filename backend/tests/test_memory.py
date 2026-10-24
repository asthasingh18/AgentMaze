
from datetime import datetime

from app.memory.memory import AgentMemory, MemoryItem


def test_memory_item_stores_its_fields():
    item = MemoryItem(
        content="Verify agent permissions",
        source="security_test",
        trust_level="HIGH",
    )

    assert item.content == "Verify agent permissions"
    assert item.source == "security_test"
    assert item.trust_level == "HIGH"


def test_memory_item_timestamp_is_valid_iso_format():
    item = MemoryItem(
        content="Test memory",
        source="test",
        trust_level="LOW",
    )

    parsed_timestamp = datetime.fromisoformat(item.timestamp)

    assert isinstance(parsed_timestamp, datetime)


def test_memory_item_to_dict():
    item = MemoryItem(
        content="Check access",
        source="agent_a",
        trust_level="MEDIUM",
    )

    result = item.to_dict()

    assert result["content"] == "Check access"
    assert result["source"] == "agent_a"
    assert result["trust_level"] == "MEDIUM"
    assert result["timestamp"] == item.timestamp
    assert len(result) == 4


def test_agent_memory_starts_empty():
    memory = AgentMemory()

    assert memory.items == []
    assert memory.get_all() == []


def test_store_returns_memory_item():
    memory = AgentMemory()

    item = memory.store(
        content="Authorized task",
        source="agent_a",
        trust_level="HIGH",
    )

    assert isinstance(item, MemoryItem)
    assert item.content == "Authorized task"
    assert len(memory.items) == 1


def test_store_multiple_items():
    memory = AgentMemory()

    memory.store("First event", "agent_a", "HIGH")
    memory.store("Second event", "agent_b", "LOW")

    results = memory.get_all()

    assert len(results) == 2
    assert results[0]["content"] == "First event"
    assert results[1]["content"] == "Second event"


def test_get_all_returns_dictionaries():
    memory = AgentMemory()
    memory.store("Permission verified", "security", "HIGH")

    results = memory.get_all()

    assert isinstance(results, list)
    assert isinstance(results[0], dict)
    assert set(results[0].keys()) == {
        "content",
        "source",
        "trust_level",
        "timestamp",
    }
