# DuCaPra

DuCaPra is a prototype for **Dual-Layer Cryptographically Anchored Prompt Authentication** with **Triangular Liveness Attestation**.

It demonstrates a fail-closed control plane for privileged LLM-adjacent instructions:

1. Instructions are signed in cryptographic envelopes.
2. Execution requires a valid three-node liveness triangle.
3. The instruction signature is bound to the specific verified triangle hash.
4. Nonces are tracked with TTL-based eviction to limit replay and memory growth.
5. Optional provenance chains allow verified envelopes to be assembled into model context while failed inputs are quarantined.

This prototype protects command execution boundaries by decoupling instruction execution from data processing via cryptographic enforcement. It does not claim to solve every form of prompt injection affecting ordinary model text generation, summarization, or classification.

## Run

```bash
python3 -m unittest discover -s tests
python3 -m ducapra
PYTHONPATH=src python3 examples/basic_usage.py
```

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
