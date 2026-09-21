"""Offline fixture identities, not SafeAgent permits or Metrecept cache keys."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime

import rfc8785


def canonical_bytes(value):
    """Pinned JCS library, including ECMAScript number serialization."""
    return rfc8785.dumps(value)


def payload_digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def claim_id(intent):
    """Mock-only content key. NOT SafeAgent's random, one-use permit_id."""
    return "cid_" + payload_digest(intent)


def naive_bytes(value):
    """Deliberately wrong key ordering, with identical scalar serialization.

    Isolates the UTF-16 versus code-point sorting defect, recursively.
    Never use this negative control to authorize an action.
    """
    if isinstance(value, dict):
        return b"{" + b",".join(
            canonical_bytes(key) + b":" + naive_bytes(value[key])
            for key in sorted(value)
        ) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(naive_bytes(item) for item in value) + b"]"
    return canonical_bytes(value)


def claim_id_naive(intent):
    return "cid_" + hashlib.sha256(naive_bytes(intent)).hexdigest()


class OutOfProfileDomainError(ValueError):
    def __init__(self, field, reason):
        self.field = field
        super().__init__(f"OUT_OF_PROFILE_DOMAIN: {field}: {reason}")


def compute_action_ref(preimage):
    """Fixture-only v1 verifier against the commit-pinned ASCII profile.

    Reject before hashing. Not the gateway implementation, an authorization
    decision, or proof of settlement.
    """
    fields = {"agent_id", "action_type", "scope", "timestamp"}
    if not isinstance(preimage, dict) or set(preimage) != fields:
        raise OutOfProfileDomainError("preimage", "exactly four fields required")
    for field in ("agent_id", "action_type", "scope"):
        value = preimage[field]
        if not isinstance(value, str) or not value or not value.isascii():
            raise OutOfProfileDomainError(field, "non-empty ASCII string required")
    timestamp = preimage["timestamp"]
    if not isinstance(timestamp, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
        timestamp,
    ):
        raise OutOfProfileDomainError("timestamp", "UTC millisecond timestamp required")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise OutOfProfileDomainError("timestamp", "invalid calendar instant") from exc
    return payload_digest(preimage)
