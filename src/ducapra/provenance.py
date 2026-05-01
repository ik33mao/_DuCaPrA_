from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProvenanceNode:
    node_id: str
    trust_level: str
    origin: str
    session_id: str
    parent_id: str | None = None
    metadata: dict = field(default_factory=dict)


class ProvenanceGraph:
    ROOT_PREFIX = "root:"

    def __init__(self):
        self._nodes: dict[str, ProvenanceNode] = {}
        self._parents: dict[str, str] = {}

    def register_root(self, session_id: str) -> str:
        node_id = f"{self.ROOT_PREFIX}{session_id}"
        self._nodes[node_id] = ProvenanceNode(
            node_id=node_id,
            trust_level="system",
            origin="root",
            session_id=session_id,
        )
        return node_id

    def add_node(self, node: ProvenanceNode) -> bool:
        if node.parent_id and node.parent_id not in self._nodes:
            return False
        self._nodes[node.node_id] = node
        if node.parent_id:
            self._parents[node.node_id] = node.parent_id
        return True

    def validate_chain(self, provenance_chain: list[str], session_id: str) -> bool:
        if not provenance_chain:
            return False
        expected_root = f"{self.ROOT_PREFIX}{session_id}"
        if provenance_chain[0] != expected_root:
            return False
        if expected_root not in self._nodes:
            return False
        for parent, child in zip(provenance_chain, provenance_chain[1:]):
            if self._parents.get(child) != parent:
                return False
            child_node = self._nodes.get(child)
            if child_node is None or child_node.session_id != session_id:
                return False
        return True

    def get_lineage(self, node_id: str, session_id: str) -> list[str]:
        root_id = f"{self.ROOT_PREFIX}{session_id}"
        lineage = []
        cursor: str | None = node_id
        while cursor:
            node = self._nodes.get(cursor)
            if node is None or node.session_id != session_id:
                return []
            lineage.append(cursor)
            if cursor == root_id:
                return list(reversed(lineage))
            cursor = self._parents.get(cursor)
        return []
