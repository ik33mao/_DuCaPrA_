from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .state import InMemoryStateStore, StateStore
from .scanner import PromptInjectionScanner


PROTOCOL = "DuCaPra-TLA-v1"
NODE_NAMES = ("ROOT", "NodeA", "NodeB")


def canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class Node:
    """A DuCaPra control-plane participant with an Ed25519 keypair."""

    def __init__(self, name: str):
        if name not in NODE_NAMES:
            raise ValueError(f"unknown node name: {name}")
        self.name = name
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    @property
    def public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes) -> str:
        return self.private_key.sign(data).hex()


@dataclass(frozen=True)
class LivenessBlock:
    node_name: str
    timestamp_ms: int
    round_id: int
    block_nonce: str
    state_hash: str
    self_sig: str
    peer_sigs: dict[str, str]

    def to_dict(self) -> dict:
        return {
            "node_name": self.node_name,
            "timestamp_ms": self.timestamp_ms,
            "round_id": self.round_id,
            "block_nonce": self.block_nonce,
            "state_hash": self.state_hash,
            "self_sig": self.self_sig,
            "peer_sigs": dict(sorted(self.peer_sigs.items())),
        }


@dataclass(frozen=True)
class ExecutionRequest:
    command: str
    nonce: str
    source_id: str
    expires_at_ms: int
    instruction_sig: str
    tla_blocks: tuple[LivenessBlock, LivenessBlock, LivenessBlock]


@dataclass(frozen=True)
class VerifiedTriangle:
    round_id: int
    triangle_hash: str


class TlaEngine:
    """Triangular Liveness Attestation engine.

    This is an all-of-3 fail-closed topology, not an availability-oriented quorum.
    Every block must be fresh, self-signed, and cross-signed by the other two
    registered nodes.
    """

    def __init__(self, block_ttl_seconds: int = 30, max_clock_skew_seconds: int = 5):
        self.nodes = {
            "ROOT": Node("ROOT"),
            "NodeA": Node("NodeA"),
            "NodeB": Node("NodeB"),
        }
        self.public_keys = {name: node.public_key for name, node in self.nodes.items()}
        self.block_ttl_ms = block_ttl_seconds * 1000
        self.max_clock_skew_ms = max_clock_skew_seconds * 1000
        self.current_round = 0
        self.last_valid_triangle_hash: str | None = None

    @property
    def root(self) -> Node:
        return self.nodes["ROOT"]

    @property
    def node_a(self) -> Node:
        return self.nodes["NodeA"]

    @property
    def node_b(self) -> Node:
        return self.nodes["NodeB"]

    def generate_liveness_block(
        self,
        node_name: str,
        timestamp_ms: int | None = None,
        block_nonce: str | None = None,
    ) -> LivenessBlock:
        node = self.nodes[node_name]
        timestamp_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
        block_nonce = block_nonce or secrets.token_hex(8)
        state_hash = self.compute_state_hash(
            node_name=node.name,
            timestamp_ms=timestamp_ms,
            round_id=self.current_round,
            block_nonce=block_nonce,
        )
        signed_payload = state_hash.encode()
        peer_sigs = {
            peer_name: peer.sign(signed_payload)
            for peer_name, peer in self.nodes.items()
            if peer_name != node.name
        }
        return LivenessBlock(
            node_name=node.name,
            timestamp_ms=timestamp_ms,
            round_id=self.current_round,
            block_nonce=block_nonce,
            state_hash=state_hash,
            self_sig=node.sign(signed_payload),
            peer_sigs=peer_sigs,
        )

    def generate_triangle(self) -> tuple[LivenessBlock, LivenessBlock, LivenessBlock]:
        return tuple(self.generate_liveness_block(name) for name in NODE_NAMES)  # type: ignore[return-value]

    def compute_state_hash(
        self,
        node_name: str,
        timestamp_ms: int,
        round_id: int,
        block_nonce: str,
    ) -> str:
        payload = {
            "protocol": PROTOCOL,
            "node_name": node_name,
            "timestamp_ms": timestamp_ms,
            "round_id": round_id,
            "block_nonce": block_nonce,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    def verify_triangle(
        self,
        blocks: Iterable[LivenessBlock],
        now_ms: int | None = None,
    ) -> VerifiedTriangle:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        block_list = list(blocks)
        if len(block_list) != 3:
            raise ValueError("incomplete triangle: expected exactly three blocks")

        block_map = {block.node_name: block for block in block_list}
        if set(block_map) != set(NODE_NAMES):
            raise ValueError("incomplete triangle: expected ROOT, NodeA, and NodeB")

        round_ids = {block.round_id for block in block_list}
        if len(round_ids) != 1:
            raise ValueError("round mismatch")

        for block in block_list:
            self._verify_block(block, now_ms)

        triangle_hash = self.compute_triangle_hash(block_map[name] for name in NODE_NAMES)
        self.last_valid_triangle_hash = triangle_hash
        return VerifiedTriangle(round_id=round_ids.pop(), triangle_hash=triangle_hash)

    def compute_triangle_hash(self, blocks: Iterable[LivenessBlock]) -> str:
        payload = {
            "protocol": PROTOCOL,
            "blocks": [block.to_dict() for block in blocks],
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    def _verify_block(self, block: LivenessBlock, now_ms: int) -> None:
        if block.node_name not in self.public_keys:
            raise ValueError(f"unknown node: {block.node_name}")

        age_ms = now_ms - block.timestamp_ms
        if age_ms > self.block_ttl_ms:
            raise ValueError("expired liveness block")
        if age_ms < -self.max_clock_skew_ms:
            raise ValueError("future-dated liveness block")

        expected_hash = self.compute_state_hash(
            node_name=block.node_name,
            timestamp_ms=block.timestamp_ms,
            round_id=block.round_id,
            block_nonce=block.block_nonce,
        )
        if block.state_hash != expected_hash:
            raise ValueError("state hash does not match canonical block fields")

        signed_payload = block.state_hash.encode()
        self._verify_signature(self.public_keys[block.node_name], block.self_sig, signed_payload)

        expected_peers = set(NODE_NAMES) - {block.node_name}
        if set(block.peer_sigs) != expected_peers:
            raise ValueError("peer signature set mismatch")

        for peer_name, signature in block.peer_sigs.items():
            self._verify_signature(self.public_keys[peer_name], signature, signed_payload)

    @staticmethod
    def _verify_signature(public_key: Ed25519PublicKey, signature_hex: str, data: bytes) -> None:
        try:
            public_key.verify(bytes.fromhex(signature_hex), data)
        except Exception as exc:
            raise ValueError("invalid signature") from exc

    def next_round(self) -> None:
        self.current_round += 1


class NonceStore(InMemoryStateStore):
    """TTL-bounded nonce registry for replay protection without unbounded growth."""

    def __init__(self, ttl_seconds: int):
        super().__init__(nonce_ttl_seconds=ttl_seconds)

    def reserve(self, nonce: str, now_ms: int | None = None) -> None:
        self.reserve_nonce(nonce, now_ms=now_ms)

    def evict(self, now_ms: int | None = None) -> None:
        self.evict_nonces(now_ms=now_ms)


class DuCaPraPipeline:
    def __init__(
        self,
        block_ttl_seconds: int = 30,
        state_store: StateStore | None = None,
        tla_engine: TlaEngine | None = None,
        command_scanner: PromptInjectionScanner | None = None,
    ):
        self.tla_engine = tla_engine or TlaEngine(block_ttl_seconds=block_ttl_seconds)
        self.state_store = (
            state_store
            if state_store is not None
            else InMemoryStateStore(nonce_ttl_seconds=block_ttl_seconds * 10)
        )
        self.nonce_store = self.state_store
        self.command_scanner = command_scanner or PromptInjectionScanner()
        self.tla_engine.current_round = self.state_store.get_round()

    def sign_instruction(
        self,
        command: str,
        nonce: str,
        source_id: str,
        expires_at_ms: int,
        triangle_hash: str,
        round_id: int,
    ) -> str:
        return self.tla_engine.root.sign(
            self._instruction_payload(
                command=command,
                nonce=nonce,
                source_id=source_id,
                expires_at_ms=expires_at_ms,
                triangle_hash=triangle_hash,
                round_id=round_id,
            )
        )

    def build_request(
        self,
        command: str,
        nonce: str,
        source_id: str = "admin",
        expires_in_seconds: int = 30,
        allow_unsafe_command: bool = False,
    ) -> ExecutionRequest:
        scan = self.command_scanner.scan(command)
        if not scan.allowed and not allow_unsafe_command:
            raise ValueError(f"command rejected by pre-sign scanner: {scan.reason}")

        self.tla_engine.current_round = self.state_store.get_round()
        blocks = self.tla_engine.generate_triangle()
        verified = self.tla_engine.verify_triangle(blocks)
        expires_at_ms = int(time.time() * 1000) + expires_in_seconds * 1000
        instruction_sig = self.sign_instruction(
            command=command,
            nonce=nonce,
            source_id=source_id,
            expires_at_ms=expires_at_ms,
            triangle_hash=verified.triangle_hash,
            round_id=verified.round_id,
        )
        return ExecutionRequest(
            command=command,
            nonce=nonce,
            source_id=source_id,
            expires_at_ms=expires_at_ms,
            instruction_sig=instruction_sig,
            tla_blocks=blocks,
        )

    def attempt_execution(self, request: ExecutionRequest, now_ms: int | None = None) -> str:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        try:
            self.tla_engine.current_round = self.state_store.get_round()
            scan = self.command_scanner.scan(request.command)
            if not scan.allowed:
                return self._reject(
                    "Command rejected by scanner",
                    now_ms,
                    event_type="execution_rejected",
                    details={
                        "nonce": request.nonce,
                        "source_id": request.source_id,
                        "reason": scan.reason,
                    },
                )

            verified = self.tla_engine.verify_triangle(request.tla_blocks, now_ms=now_ms)
            if verified.round_id != self.tla_engine.current_round:
                return self._reject(
                    "Stale liveness round",
                    now_ms,
                    details={"nonce": request.nonce, "round_id": verified.round_id},
                )
            if request.expires_at_ms < now_ms:
                return self._reject(
                    "Instruction expired",
                    now_ms,
                    details={"nonce": request.nonce, "expires_at_ms": request.expires_at_ms},
                )

            payload = self._instruction_payload(
                command=request.command,
                nonce=request.nonce,
                source_id=request.source_id,
                expires_at_ms=request.expires_at_ms,
                triangle_hash=verified.triangle_hash,
                round_id=verified.round_id,
            )
            self.tla_engine.root.public_key.verify(
                bytes.fromhex(request.instruction_sig),
                payload,
            )
            self.state_store.reserve_nonce(request.nonce, now_ms=now_ms)
            self.state_store.record_triangle(
                verified.round_id,
                verified.triangle_hash,
                now_ms=now_ms,
            )
            self.state_store.advance_round(verified.round_id)
        except ValueError as exc:
            return self._reject(str(exc), now_ms, details={"nonce": request.nonce})
        except Exception:
            return self._reject(
                "Invalid instruction signature",
                now_ms,
                details={"nonce": request.nonce, "source_id": request.source_id},
            )

        self.tla_engine.current_round = self.state_store.get_round()
        self.state_store.append_audit_event(
            "execution",
            "executed",
            {
                "command_hash": hashlib.sha256(request.command.encode()).hexdigest(),
                "nonce": request.nonce,
                "source_id": request.source_id,
                "round_id": verified.round_id,
                "triangle_hash": verified.triangle_hash,
            },
            now_ms=now_ms,
        )
        return f"EXECUTING COMMAND: {request.command}"

    def _reject(
        self,
        reason: str,
        now_ms: int,
        event_type: str = "execution_rejected",
        details: dict | None = None,
    ) -> str:
        self.state_store.append_audit_event(
            event_type,
            "rejected",
            details or {"reason": reason},
            now_ms=now_ms,
        )
        return f"SYSTEM: REJECTED - {reason}."

    @staticmethod
    def _instruction_payload(
        command: str,
        nonce: str,
        source_id: str,
        expires_at_ms: int,
        triangle_hash: str,
        round_id: int,
    ) -> bytes:
        return canonical_json(
            {
                "protocol": PROTOCOL,
                "command": command,
                "nonce": nonce,
                "source_id": source_id,
                "expires_at_ms": expires_at_ms,
                "triangle_hash": triangle_hash,
                "round_id": round_id,
            }
        )


def run_pentest_suite() -> None:
    pipeline = DuCaPraPipeline(block_ttl_seconds=1)
    checks = [
        ("valid command", pipeline.attempt_execution(pipeline.build_request("SAFE_COMMAND", "n1"))),
        ("replay", pipeline.attempt_execution(pipeline.build_request("SAFE_COMMAND", "n1"))),
    ]
    for name, result in checks:
        print(f"{name}: {result}")
