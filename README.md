# SafeAgent × Metrecept cross-check fixture

Bounded, offline harness for [stripe/ai#402](https://github.com/stripe/ai/issues/402).
It pins one narrow question: does a JCS (RFC 8785) canonicalizer order object
keys by **UTF-16 code units** — and does a naive code-point sort produce a
different digest on the same payload?

This repository is a **cross-check harness**. It is not SafeAgent, not
Metrecept, and not the `action_ref` reference implementation.

## The vector

RFC 8785 §3.2.3 sorts object members on their UTF-16 code units. Naive Python
`sorted()` and Rust `Vec<&str>::sort()` sort by code point. The two agree
across the whole Basic Multilingual Plane and then **invert** above it: a
supplementary character encodes as a surrogate pair led by `U+D800`, which is
numerically below `U+E000..U+FFFF`.

So `{U+FFFD, U+10000}` gets two different keys:

| Implementation | Order | Consequence |
|---|---|---|
| UTF-16 code units (RFC 8785, Node `Array#sort`, `rfc8785`) | `U+10000` first | spec-correct |
| Code point (naive Python, naive Rust) | `U+FFFD` first | **wrong** |

A Python↔Rust parity suite cannot catch this: both implementations move the
same wrong way. The failure direction is a duplicate charge — a retry that
computes a fresh claim key does not recognize the original claim.

## What this proves

- Python (`rfc8785==0.1.4`) and Node agree on every pinned vector.
- The naive code-point sort diverges **only** on the supplementary-plane
  vectors, and agrees on both controls (ASCII, all-BMP).
- The `action_ref` v1 preimage is exactly four fixed ASCII keys, so it is
  immune to this class by domain restriction. Its byte-exact digests are
  checked against upstream fixtures.
- Out-of-domain `action_ref` inputs are rejected **before** hashing, with the
  upstream-expected field named.
- A loopback mock replays an identical canonical payload and gives a drifted
  payload a distinct id.

## What this does not prove

- **Not SafeAgent.** No signed permit, no durable consume, no one-use
  authority. A `permit_id` is random and separate from any content digest.
- **Not Stripe.** The mock never contacts a provider; a synthetic `succeeded`
  is not evidence of settlement. No idempotency key reaches a real API.
- **Not crash recovery.** Loopback state is in-memory and lost on restart;
  `PENDING_RECONCILIATION` semantics are out of scope here.
- **Not Metrecept.** No gateway, cache, receipt, or metering code is present.
  Metrecept's replay identity is exact-match normalization, not JCS.
- **Not fuzzy matching.** Canonicalization removes representational drift
  (`100`/`100.0`, key order, CRLF). It must not merge materially different
  intents — `100` vs `101` is a new identity, by design.

Local vectors in `vectors.json` are labelled separately from the pinned
upstream files in `vendor/`. They are cross-check inputs, not upstream
conformance evidence.

## Run

```bash
python -m pip install -r requirements.txt
python run_check.py
```

Python 3.10+ and Node.js are required. **No parity check is skipped** — a
missing `node` is a failure, not a pass. Everything runs offline; the only
socket is a loopback HTTP server on an ephemeral port.

## Layout

| Path | Role |
|---|---|
| `identity.py` | Python side. Pinned JCS via `rfc8785`, plus the deliberate code-point negative control. |
| `identity.js` | Node side. Independent canonicalizer; native sort is UTF-16. |
| `server.py` | Loopback-only in-memory mock. Not Stripe, not durable. |
| `run_check.py` | The harness: 12 offline tests. |
| `vectors.json` | Local splitting vectors + locally generated ASCII examples. |
| `vendor/safeagent/` | Commit-pinned upstream vectors and license (Apache-2.0). |
| `vendor/argentum/` | Commit-pinned upstream conformance fixtures and license (Apache-2.0). |
| `SOURCES.json` | Provenance and SHA-256 for every vendored file. |

## Provenance

Upstream files are copied unmodified at pinned commits and verified by hash in
`run_check.py::test_01_upstream_file_integrity`. See `SOURCES.json`.

- UTF-16 vector: [tonydzi](https://github.com/tonydzi) (Mycroft, Palo Alto AI Research Lab)
- `action_ref` v1 profile: [giskard09/argentum-core](https://github.com/giskard09/argentum-core)
- SafeAgent fixture data: [azender1/SafeAgent](https://github.com/azender1/SafeAgent)

## License

MIT for this harness. Vendored files keep their upstream Apache-2.0 license —
see [`NOTICE`](NOTICE) and `vendor/*/LICENSE`.

