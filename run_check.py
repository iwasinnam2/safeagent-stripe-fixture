"""Offline cross-check: Python JCS / Node, pinned vectors, local mock.

Python 3.10+, rfc8785==0.1.4, Node required. No silent parity skips.
Only loopback networking; owns an ephemeral port and closes every resource.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import rfc8785

import identity
import server
from identity import canonical_bytes, claim_id, claim_id_naive, compute_action_ref

HERE = Path(__file__).resolve().parent


def load(path):
    return json.loads((HERE / path).read_text(encoding="utf-8"))


def node_result(value):
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required: parity cannot be reported as passed without it")
    return subprocess.run(
        [node, str(HERE / "identity.js")],
        input=json.dumps(value, ensure_ascii=True, allow_nan=False).encode("ascii"),
        capture_output=True,
        timeout=10,
        check=False,
    )


def node_identity(value):
    result = node_result(value)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return json.loads(result.stdout)


@contextmanager
def mock_api():
    with server._LOCK:
        server._INTENTS.clear()
        server._BY_CLAIM.clear()
        server._METRICS.update(created=0, replayed=0, retrieved=0)
    with ThreadingHTTPServer(("127.0.0.1", 0), server.Handler) as httpd:
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        base = f"http://127.0.0.1:{httpd.server_port}"

        def request(path, body=None, raw=None):
            data = raw if raw is not None else (
                json.dumps(body).encode("utf-8") if body is not None else None
            )
            req = Request(base + path, data=data, headers={"Content-Type": "application/json"})
            # Never send loopback requests through a machine's configured proxy.
            with build_opener(ProxyHandler({})).open(req, timeout=10) as response:
                return json.loads(response.read())

        try:
            yield request
        finally:
            httpd.shutdown()
            worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError("mock server failed to stop")


class CrossCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if rfc8785.__version__ != "0.1.4":
            raise RuntimeError("Install the pinned requirements.txt (rfc8785==0.1.4)")
        if shutil.which("node") is None:
            raise RuntimeError("Node.js is required; no parity checks are skipped")

    def assert_parity(self, value):
        expected = canonical_bytes(value)
        actual = node_identity(value)
        self.assertEqual(actual["canonical"].encode("utf-8"), expected)
        self.assertEqual(actual["sha256"], hashlib.sha256(expected).hexdigest())

    def test_01_upstream_file_integrity(self):
        for source in load("SOURCES.json")["sources"]:
            with self.subTest(path=source["local_path"]):
                self.assertEqual(
                    hashlib.sha256((HERE / source["local_path"]).read_bytes()).hexdigest(),
                    source["sha256"],
                )

    def test_02_safeagent_python_node_parity_and_negative_controls(self):
        vectors = load("vendor/safeagent/jcs_vectors.json")
        for name, value in vectors.items():
            with self.subTest(vector=name):
                self.assert_parity(value)
                self.assertEqual(
                    claim_id(value) != claim_id_naive(value),
                    name in {"supplementary_minimal_pair", "payment_metadata_pair"},
                )
        canonical = canonical_bytes(vectors["supplementary_minimal_pair"]).decode("utf-8")
        self.assertLess(canonical.index(chr(0x10000)), canonical.index(chr(0xFFFD)))

    def test_03_local_ordering_examples(self):
        for vector in load("vectors.json")["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assert_parity(vector["intent"])
                self.assertEqual(
                    claim_id(vector["intent"]) != claim_id_naive(vector["intent"]),
                    vector["expect_split"],
                )

    def test_04_numbers_nested_keys_and_representational_drift(self):
        self.assertEqual(claim_id({"amount": 100}), claim_id({"amount": 100.0}))
        self.assertNotEqual(claim_id({"amount": 100}), claim_id({"amount": "100"}))
        self.assertNotEqual(claim_id({"amount": 100}), claim_id({"amount": 101}))
        self.assertEqual(claim_id({"a": 1, "b": 2}), claim_id({"b": 2, "a": 1}))
        for value in [0, -0.0, 1e-7, 1e-6, 1e20, 1e21, 333333333.3333333,
                      {"2": "two", "10": "ten"},
                      [{"metadata": {chr(0xFFFD): 1, chr(0x10000): 2}}]]:
            with self.subTest(value=repr(value)):
                self.assert_parity(value)

    def test_05_invalid_jcs_inputs(self):
        for value in [float("nan"), float("inf"), -float("inf"), 2**53]:
            with self.subTest(value=repr(value)):
                with self.assertRaises(rfc8785.CanonicalizationError):
                    canonical_bytes(value)
        for value in ["\ud800", {"\udc00": "x"}]:
            with self.subTest(value=repr(value)):
                with self.assertRaises((rfc8785.CanonicalizationError, UnicodeError)):
                    canonical_bytes(value)
                self.assertNotEqual(node_result(value).returncode, 0)

    def test_06_argentum_pinned_baseline_bytes_and_hashes(self):
        for group in load("vendor/argentum/action-ref-v1-baseline.fixture.json")["vectors"]:
            refs = []
            for vector in group.get("vectors", [group]):
                with self.subTest(vector=group["id"], label=vector.get("label")):
                    value = vector["preimage"]
                    self.assertEqual(canonical_bytes(value).hex(), vector["preimage_canonical_bytes_hex"])
                    self.assertEqual(compute_action_ref(value), vector["action_ref"])
                    self.assert_parity(value)
                    refs.append(compute_action_ref(value))
            if len(refs) > 1:
                self.assertEqual(len(set(refs)), len(refs))
            if "envelope" in group:
                self.assertEqual(canonical_bytes(group["envelope"]).hex(), group["envelope_canonical_bytes_hex"])
                self.assertEqual(identity.payload_digest(group["envelope"]), group["envelope_canonical_sha256"])
                self.assert_parity(group["envelope"])

    def test_07_argentum_domain_rejected_before_hashing(self):
        vectors = load("vendor/argentum/action-ref-v1-domain-negative.fixture.json")["vectors"]
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                self.assertFalse(vector["expect_valid"])
                with patch.object(identity, "payload_digest") as hasher:
                    with self.assertRaises(identity.OutOfProfileDomainError) as error:
                        compute_action_ref(vector["preimage"])
                    self.assertEqual(error.exception.field, vector["expect_error_field"])
                    hasher.assert_not_called()

    def test_08_local_ascii_examples_are_separate(self):
        for vector in load("vectors.json")["local_ascii_examples"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(compute_action_ref(vector["intent"]), vector["expected_sha256"])
                self.assert_parity(vector["intent"])

    def test_09_local_domain_edges(self):
        valid = load("vectors.json")["local_ascii_examples"][0]["intent"]
        invalids = [dict(valid, scope=chr(0x10000)), dict(valid, timestamp="2026-02-30T00:00:00.000Z"),
                    dict(valid, timestamp=valid["timestamp"] + "\n"), dict(valid, extra="field"),
                    dict(valid, agent_id=None), dict(valid, scope={"nested": "object"})]
        for value in invalids:
            with self.subTest(value=repr(value)), patch.object(identity, "payload_digest") as hasher:
                with self.assertRaises(identity.OutOfProfileDomainError):
                    compute_action_ref(value)
                hasher.assert_not_called()

    def test_10_mock_replay_drift_readback_and_counters(self):
        with mock_api() as request:
            intent = {"amount": 100, "currency": "usd", "metadata": {chr(0xFFFD): "a", chr(0x10000): "b"}}
            first = request("/v1/payment_intents", intent)
            reordered = {"metadata": dict(reversed(list(intent["metadata"].items()))), "currency": "usd", "amount": 100.0}
            second = request("/v1/payment_intents", reordered)
            self.assertEqual(first, second)
            drifted = request("/v1/payment_intents", dict(intent, amount=101))
            self.assertNotEqual(first["id"], drifted["id"])
            readback = request("/v1/payment_intents/" + second["id"])
            self.assertEqual(readback, first)
            self.assertEqual(readback["claim_id"], claim_id(intent))
            self.assertEqual(request("/__metrics"), {"created": 2, "replayed": 1, "retrieved": 1})

    def test_11_mock_concurrent_replay(self):
        with mock_api() as request:
            with ThreadPoolExecutor(max_workers=4) as pool:
                records = list(pool.map(lambda _: request("/v1/payment_intents", {"amount": 100}), range(12)))
            self.assertEqual(len({record["id"] for record in records}), 1)
            self.assertEqual(request("/__metrics"), {"created": 1, "replayed": 11, "retrieved": 0})

    def test_12_mock_rejects_invalid_inputs_without_creation(self):
        with mock_api() as request:
            for raw in [b'[]', b'{"amount":NaN}', b'{"amount":1,"amount":2}', b'{"x":"\\ud800"}', b'\xff']:
                with self.subTest(raw=raw):
                    with self.assertRaises(HTTPError) as raised:
                        request("/v1/payment_intents", raw=raw)
                    with raised.exception as response:
                        self.assertEqual(response.code, 400)
                        response.read()
            self.assertEqual(request("/__metrics")["created"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)