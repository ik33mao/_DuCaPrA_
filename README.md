# DuCaPra

DuCaPra is a research prototype for **Dual-Layer Cryptographically Anchored Prompt Authentication** with **Triangular Liveness Attestation**. It separates trusted executable instructions from untrusted natural-language data by verifying cryptographic envelopes and liveness proofs before any privileged command is allowed to run.

## Author Intent

This repository is shared by a non-technical founder/research originator to put forward an idea for discussion, testing, and extension by security engineers, cryptographers, AI researchers, and privacy-focused builders.

The core motivation is simple: as AI systems become more capable, private conversations and privileged execution rights should not depend only on natural-language promises or model behavior. DuCaPra explores whether trust can be moved down into a more fundamental cryptographic layer, so future systems can better protect private discussions, distinguish data from executable authority, and support enterprise-grade authentication before actions are allowed to run.

This is not presented as a finished production security product. It is a working prototype and research artifact intended to invite stronger designs, criticism, implementations, and formal review.

It demonstrates a fail-closed control plane for privileged LLM-adjacent instructions:

1. Instructions are signed in cryptographic envelopes.
2. Execution requires a valid three-node liveness triangle.
3. The instruction signature is bound to the specific verified triangle hash.
4. Nonces are tracked with TTL-based eviction to limit replay and memory growth.
5. Optional provenance chains allow verified envelopes to be assembled into model context while failed inputs are quarantined.
6. High-signal prompt-injection content is blocked before signing unless explicitly overridden for security fixtures.
7. Execution and rejection events are written to a hash-chained audit log.

This prototype protects command execution boundaries by decoupling instruction execution from data processing via cryptographic enforcement. It does not claim to solve every form of prompt injection affecting ordinary model text generation, summarization, or classification.

Suggested GitHub repo description:

> DuCaPra is a research prototype for cryptographically protected AI conversations and enterprise-grade execution authentication, using signed instruction envelopes, triangular liveness attestation, durable replay protection, and audit logs.

## Collaboration

Contributions are welcome from both technical and non-technical collaborators. Useful areas include threat modeling, cryptographic review, distributed liveness protocols, key-management design, privacy-preserving conversation storage, enterprise authorization policy, documentation, and plain-language explanations.

## Run

```bash
python3 -m unittest discover -s tests
python3 -m ducapra
PYTHONPATH=src python3 examples/basic_usage.py
```

## Citation

GitHub renders citation metadata from [CITATION.cff](CITATION.cff). Update the DOI/arXiv fields there when the preprint is live, then pin the arXiv URL in the repository description.

## License

MIT. See [LICENSE](LICENSE).

## Durable State

The default pipeline uses memory state for prototypes. Production deployments should use durable state so nonce replay protection and the TLA round counter survive process restarts:

```python
from ducapra import DuCaPraPipeline, SQLiteStateStore

state = SQLiteStateStore("ducapra-state.db", nonce_ttl_seconds=300)
pipeline = DuCaPraPipeline(state_store=state)
```

SQLite is the local reference implementation. Multi-node deployments should put the same semantics behind a transactional service or database with compare-and-swap round advancement.

Because this workspace contains a read-only placeholder `.git` directory, the repo metadata is initialized in `.duca-git`. Use:

```bash
GIT_DIR=.duca-git GIT_WORK_TREE=. git status
```
