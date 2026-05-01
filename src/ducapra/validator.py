from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .envelope import Envelope, envelope_payload, load_public_key


@dataclass(frozen=True)
class ValidationResult:
    verified: bool
    envelope: Envelope | None
    reason: str
    layer: str = "infrastructure"

    def __bool__(self) -> bool:
        return self.verified


class EnvelopeValidator:
    def __init__(
        self,
        public_key: Ed25519PublicKey,
        nonce_ttl_seconds: int = 300,
        require_provenance_depth: int = 1,
    ):
        self._public_key = public_key
        self._seen_nonces: dict[str, int] = {}
        self._nonce_ttl_ms = nonce_ttl_seconds * 1000
        self._min_provenance_depth = require_provenance_depth

    @classmethod
    def from_pem(cls, pem_bytes: bytes, **kwargs) -> "EnvelopeValidator":
        return cls(public_key=load_public_key(pem_bytes), **kwargs)

    def validate(self, envelope: Envelope, now_ms: int | None = None) -> ValidationResult:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)

        expected_hash = "sha256:" + hashlib.sha256(envelope.content.encode()).hexdigest()
        if envelope.content_hash != expected_hash:
            return ValidationResult(False, envelope, "content_hash mismatch")

        age_ms = now_ms - envelope.timestamp_ms
        if age_ms > self._nonce_ttl_ms:
            return ValidationResult(False, envelope, "envelope expired")
        if age_ms < -self._nonce_ttl_ms:
            return ValidationResult(False, envelope, "envelope timestamp is too far in the future")

        if len(envelope.provenance_chain) < self._min_provenance_depth:
            return ValidationResult(False, envelope, "provenance chain too shallow")

        payload = envelope_payload(
            content_hash=envelope.content_hash,
            nonce=envelope.nonce,
            trust_level=envelope.trust_level,
            origin=envelope.origin,
            provenance_chain=envelope.provenance_chain,
            timestamp_ms=envelope.timestamp_ms,
            version=envelope.ducapra_version,
        )
        try:
            self._public_key.verify(base64.b64decode(envelope.signature), payload)
        except (InvalidSignature, ValueError):
            return ValidationResult(False, envelope, "signature invalid")

        self._purge_expired_nonces(now_ms)
        if envelope.nonce in self._seen_nonces:
            return ValidationResult(False, envelope, "nonce already used")

        self._seen_nonces[envelope.nonce] = now_ms
        return ValidationResult(True, envelope, "ok")

    def _purge_expired_nonces(self, now_ms: int) -> None:
        self._seen_nonces = {
            nonce: seen_at_ms
            for nonce, seen_at_ms in self._seen_nonces.items()
            if now_ms - seen_at_ms <= self._nonce_ttl_ms
        }
