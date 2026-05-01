from __future__ import annotations

from dataclasses import dataclass

from .envelope import Envelope
from .provenance import ProvenanceGraph
from .validator import EnvelopeValidator, ValidationResult


@dataclass(frozen=True)
class PipelineResult:
    passed: bool
    envelope: Envelope | None
    layer1: ValidationResult | None
    layer2_provenance_valid: bool
    reason: str

    def to_context_tag(self) -> str:
        if not self.passed or self.envelope is None:
            raise ValueError("cannot generate a context tag for failed validation")
        return self.envelope.to_context_tag(verified=self.layer2_provenance_valid)


class ValidationPipeline:
    def __init__(self, validator: EnvelopeValidator, provenance_graph: ProvenanceGraph):
        self._validator = validator
        self._graph = provenance_graph

    def validate(self, envelope: Envelope, session_id: str) -> PipelineResult:
        layer1 = self._validator.validate(envelope)
        if not layer1.verified:
            return PipelineResult(
                passed=False,
                envelope=envelope,
                layer1=layer1,
                layer2_provenance_valid=False,
                reason=f"Layer 1 rejected: {layer1.reason}",
            )

        chain_valid = self._graph.validate_chain(envelope.provenance_chain, session_id)
        reason = "ok" if chain_valid else "Layer 2 provenance chain not registered"
        return PipelineResult(
            passed=True,
            envelope=envelope,
            layer1=layer1,
            layer2_provenance_valid=chain_valid,
            reason=reason,
        )

    def validate_batch(self, envelopes: list[Envelope], session_id: str) -> list[PipelineResult]:
        return [self.validate(envelope, session_id) for envelope in envelopes]

    def assemble_context(self, results: list[PipelineResult]) -> str:
        parts = []
        quarantined = 0
        for result in results:
            if result.passed:
                parts.append(result.to_context_tag())
            else:
                quarantined += 1
        if quarantined:
            parts.append(
                f"[DuCaPra-SYSTEM] {quarantined} input(s) were quarantined due to "
                "failed verification and excluded from this context. [/DuCaPra-SYSTEM]"
            )
        return "\n\n".join(parts)
