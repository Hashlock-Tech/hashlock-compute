# Examples

Valid, signed evidence events for one example trade, plus one deliberately invalid event.

| File | What it is |
|---|---|
| `usage_measured_1.json` | Window 1 of 2. Provider feed and telemetry agree (variance 0.0156). |
| `usage_measured_2.json` | Window 2 of 2. Telemetry saw 36 GPU-hours, provider reported 48 (variance 0.25). Consolidated by `min`. |
| `sla_evaluated_final.json` | Final verdict over both windows under the reference policy: PARTIAL, 8671 bps, with the settlement attestation the escrow program verifies. |
| `invalid_sla_evaluated_out_of_range.json` | Same verdict with `payout_bps` tampered to 12000. Fails schema validation, payload hash, envelope signature and attestation checks. |
| `test_key.json` | Throwaway Ed25519 key used to sign the examples. Examples and conformance tests only. |

Regenerate and verify:

```
pip install jsonschema cryptography rfc8785
python3 examples/generate_examples.py
python3 examples/verify_examples.py
```

`verify_examples.py` is the reference consumer. It needs only the schemas and the public key for `key_id`: schema validation, canonical JSON (RFC 8785) payload hash, Ed25519 envelope signature, and for a final `SLA_EVALUATED` the 147-byte settlement attestation defined in [docs/escrow-spec.md](../docs/escrow-spec.md).
