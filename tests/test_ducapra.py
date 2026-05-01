import time
import unittest
from dataclasses import replace

from ducapra import DuCaPraPipeline, TlaEngine


class DuCaPraSecurityTests(unittest.TestCase):
    def test_valid_request_executes(self):
        pipeline = DuCaPraPipeline()
        request = pipeline.build_request("SAFE_COMMAND", "nonce-valid")

        self.assertIn("EXECUTING COMMAND", pipeline.attempt_execution(request))

    def test_stale_liveness_blocks_are_rejected(self):
        engine = TlaEngine(block_ttl_seconds=1)
        old_ms = int(time.time() * 1000) - 60_000
        blocks = tuple(engine.generate_liveness_block(name, timestamp_ms=old_ms) for name in ("ROOT", "NodeA", "NodeB"))

        with self.assertRaisesRegex(ValueError, "expired"):
            engine.verify_triangle(blocks)

    def test_future_dated_liveness_blocks_are_rejected(self):
        engine = TlaEngine(max_clock_skew_seconds=1)
        future_ms = int(time.time() * 1000) + 60_000
        blocks = tuple(engine.generate_liveness_block(name, timestamp_ms=future_ms) for name in ("ROOT", "NodeA", "NodeB"))

        with self.assertRaisesRegex(ValueError, "future-dated"):
            engine.verify_triangle(blocks)

    def test_instruction_signature_is_bound_to_triangle_hash(self):
        pipeline = DuCaPraPipeline()
        request = pipeline.build_request("SAFE_COMMAND", "nonce-bound")
        replacement_triangle = pipeline.tla_engine.generate_triangle()
        tampered = replace(request, tla_blocks=replacement_triangle)

        self.assertIn("Invalid instruction signature", pipeline.attempt_execution(tampered))

    def test_block_order_does_not_matter(self):
        pipeline = DuCaPraPipeline()
        request = pipeline.build_request("SAFE_COMMAND", "nonce-order")
        reordered = replace(request, tla_blocks=tuple(reversed(request.tla_blocks)))

        self.assertIn("EXECUTING COMMAND", pipeline.attempt_execution(reordered))

    def test_replay_nonce_is_rejected(self):
        pipeline = DuCaPraPipeline()
        first = pipeline.build_request("SAFE_COMMAND", "nonce-replay")
        self.assertIn("EXECUTING COMMAND", pipeline.attempt_execution(first))

        second = pipeline.build_request("SAFE_COMMAND", "nonce-replay")
        self.assertIn("replay detected", pipeline.attempt_execution(second))

    def test_nonce_store_evicts_expired_entries(self):
        pipeline = DuCaPraPipeline(block_ttl_seconds=1)
        pipeline.nonce_store.reserve("old", now_ms=0)
        pipeline.nonce_store.reserve("fresh", now_ms=11_001)

        self.assertEqual(len(pipeline.nonce_store), 1)

    def test_same_millisecond_triangles_have_distinct_hashes(self):
        engine = TlaEngine()
        now_ms = int(time.time() * 1000)
        triangle_one = tuple(engine.generate_liveness_block(name, timestamp_ms=now_ms) for name in ("ROOT", "NodeA", "NodeB"))
        triangle_two = tuple(engine.generate_liveness_block(name, timestamp_ms=now_ms) for name in ("ROOT", "NodeA", "NodeB"))

        hash_one = engine.verify_triangle(triangle_one, now_ms=now_ms).triangle_hash
        hash_two = engine.verify_triangle(triangle_two, now_ms=now_ms).triangle_hash

        self.assertNotEqual(hash_one, hash_two)

    def test_tampered_peer_signature_is_rejected(self):
        engine = TlaEngine()
        blocks = list(engine.generate_triangle())
        broken = replace(blocks[1], peer_sigs={**blocks[1].peer_sigs, "ROOT": "00" * 64})
        blocks[1] = broken

        with self.assertRaisesRegex(ValueError, "invalid signature"):
            engine.verify_triangle(blocks)

    def test_rogue_node_name_is_rejected(self):
        engine = TlaEngine()
        blocks = list(engine.generate_triangle())
        blocks[0] = replace(blocks[0], node_name="Rogue")

        with self.assertRaisesRegex(ValueError, "expected ROOT"):
            engine.verify_triangle(blocks)


if __name__ == "__main__":
    unittest.main()
