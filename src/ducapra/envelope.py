from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


TrustLevel = Literal["system", "user_direct", "tool_output", "rag_chunk", "unknown"]


def envelope_payload(
    *,
    content_hash: str,
    nonce: str,
    trust_level: TrustLevel,
    origin: str,
    provenance_chain: list[str],
    timestamp_ms: int,
    version: str,
) -> bytes:
    return json.dumps(
        {
            "content_hash": content_hash,
            "nonce": nonce,
            "trust_level": trust_level,
            "origin": origin,
            "provenance_chain": provenance_chain,
            "timestamp_ms": timestamp_ms,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


@dataclass(frozen=True)
class Envelope:
    ducapra_version: str
    trust_level: TrustLevel
    origin: str
    content: str
    content_hash: str
    nonce: str
    signature: str
    provenance_chain: list[str]
    timestamp_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_dict(self) -> dict:
        return {
            "ducapra_version": self.ducapra_version,
            "trust_level": self.trust_level,
            "origin": self.origin,
            "content": self.content,
            "content_hash": self.content_hash,
            "nonce": self.nonce,
            "signature": self.signature,
            "provenance_chain": self.provenance_chain,
            "timestamp_ms": self.timestamp_ms,
        }

    def to_context_tag(self, verified: bool = True) -> str:
        chain = " -> ".join(self.provenance_chain)
        verified_value = "true" if verified else "partial"
        return (
            f"[DuCaPra trust={self.trust_level} origin={self.origin} "
            f"chain={chain} verified={verified_value}]\n"
            f"{self.content}\n"
            f"[/DuCaPra]"
        )


class EnvelopeSigner:
    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._key.public_key()

    @classmethod
    def from_pem(cls, pem_bytes: bytes, password: bytes | None = None) -> "EnvelopeSigner":
        key = serialization.load_pem_private_key(pem_bytes, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("expected an Ed25519 private key")
        return cls(private_key=key)

    def sign(
        self,
        content: str,
        origin: str,
        session_id: str,
        trust_level: TrustLevel = "user_direct",
        provenance_chain: list[str] | None = None,
        position: int = 0,
        timestamp_ms: int | None = None,
    ) -> Envelope:
        timestamp_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
        content_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        nonce = f"{session_id}:{timestamp_ms}:{position}:{uuid.uuid4().hex[:8]}"
        chain = provenance_chain or [f"root:{session_id}"]
        version = "0.1"
        payload = envelope_payload(
            content_hash=content_hash,
            nonce=nonce,
            trust_level=trust_level,
            origin=origin,
            provenance_chain=chain,
            timestamp_ms=timestamp_ms,
            version=version,
        )
        signature = base64.b64encode(self._key.sign(payload)).decode()
        return Envelope(
            ducapra_version=version,
            trust_level=trust_level,
            origin=origin,
            content=content,
            content_hash=content_hash,
            nonce=nonce,
            signature=signature,
            provenance_chain=chain,
            timestamp_ms=timestamp_ms,
        )

    def public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def load_public_key(pem_bytes: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    return key
