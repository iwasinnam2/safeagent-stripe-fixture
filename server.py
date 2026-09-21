"""Loopback-only, in-memory replay demonstration. Not Stripe or SafeAgent.

No durable permit, provider calls, signed receipt, or crash recovery. Changed
payloads create a new mock object; that is NOT fresh payment authorization.
Restart loses state. Synthetic 'succeeded' is not evidence of settlement.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from identity import claim_id
import rfc8785

HOST, PORT = "127.0.0.1", 8812

_LOCK = threading.Lock()
_INTENTS = {}          # id -> stored record
_BY_CLAIM = {}         # claim_id -> id (one winner per canonical intent)
_METRICS = {"created": 0, "replayed": 0, "retrieved": 0}


def _record_for(intent):
    cid = claim_id(intent)
    with _LOCK:
        if cid in _BY_CLAIM:
            _METRICS["replayed"] += 1
            return _INTENTS[_BY_CLAIM[cid]]
        pi_id = "pi_local_" + uuid.uuid4().hex[:12]
        record = {
            "id": pi_id,
            "object": "payment_intent",
            "status": "succeeded",
            "amount_received": intent.get("amount"),
            "currency": intent.get("currency"),
            "claim_id": cid,
            "created": int(time.time()),
        }
        _INTENTS[pi_id] = record
        _BY_CLAIM[cid] = pi_id
        _METRICS["created"] += 1
        return record


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/v1/payment_intents/"):
            pi_id = self.path.rsplit("/", 1)[-1]
            with _LOCK:
                record = _INTENTS.get(pi_id)
                if record is None:
                    self._send(404, {"error": "resource_missing", "id": pi_id})
                    return
                _METRICS["retrieved"] += 1
                self._send(200, record)
        elif self.path == "/__metrics":
            with _LOCK:
                self._send(200, dict(_METRICS))
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        try:
            length = int(self.headers.get("content-length", 0))
            if not 0 <= length <= 65536:
                raise ValueError("payload too large")
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            intent = json.loads(raw, object_pairs_hook=_unique_object)
            if not isinstance(intent, dict):
                raise ValueError("object required")
        except (ValueError, UnicodeError):
            self._send(400, {"error": "invalid_json"})
            return
        if self.path == "/v1/payment_intents":
            try:
                record = _record_for(intent)
            except (rfc8785.CanonicalizationError, UnicodeError):
                self._send(400, {"error": "invalid_canonical_payload"})
                return
            self._send(200, record)
        elif self.path == "/__reset":
            with _LOCK:
                _INTENTS.clear()
                _BY_CLAIM.clear()
                _METRICS.update(created=0, replayed=0, retrieved=0)
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not_found"})

    def log_message(self, *args):
        pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


if __name__ == "__main__":
    with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
        print("safeagent-stripe fixture on http://%s:%d" % (HOST, PORT))
        httpd.serve_forever()
