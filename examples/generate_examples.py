#!/usr/bin/env python3
"""Generate the example evidence events in this directory.

Uses a throwaway Ed25519 key (examples/test_key.json). The key is for
examples and conformance tests only. It has no role in production.

Run from the repository root:
    python3 examples/generate_examples.py
    python3 examples/verify_examples.py
"""

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(HERE, "test_key.json")
KEY_ID = "hashlock-compute-test-2026-09"
DOMAIN_TAG = b"HLCSETL1"
OUTCOME_CODE = {"FAIL": 0, "PARTIAL": 1, "PASS": 2}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def canonical(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_or_create_key() -> Ed25519PrivateKey:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            data = json.load(f)
        raw = base64.urlsafe_b64decode(data["private_key_b64url"] + "==")
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    with open(KEY_FILE, "w") as f:
        json.dump(
            {
                "key_id": KEY_ID,
                "purpose": "examples and conformance tests only, never production",
                "private_key_b64url": b64url(priv),
                "public_key_b64url": b64url(pub),
                "public_key_hex": pub.hex(),
            },
            f,
            indent=2,
        )
        f.write("\n")
    return key


def uuid7(ts: datetime) -> str:
    """Minimal UUID v7: 48-bit ms timestamp, version 7, variant 10, random tail."""
    ms = int(ts.timestamp() * 1000)
    rand = os.urandom(10)
    b = ms.to_bytes(6, "big") + rand
    b = bytearray(b)
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def envelope(key: Ed25519PrivateKey, event_type: str, payload: dict, emitted_at: datetime) -> dict:
    payload_bytes = canonical(payload)
    return {
        "schema_version": "1.0.0",
        "event_type": event_type,
        "event_id": uuid7(emitted_at),
        "emitted_at": emitted_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key_id": KEY_ID,
        "signature_alg": "ed25519",
        "signature": b64url(key.sign(payload_bytes)),
        "payload_hash": sha256_hex(payload_bytes),
        "payload": payload,
    }


def attestation(key: Ed25519PrivateKey, payload: dict) -> dict:
    """Fixed-layout settlement attestation, see docs/escrow-spec.md."""
    body = dict(payload)
    body.pop("settlement_attestation", None)
    sla_payload_hash = hashlib.sha256(canonical(body)).digest()
    evaluated_at = datetime.strptime(payload["evaluated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    msg = (
        DOMAIN_TAG
        + bytes.fromhex(payload["trade_id"])
        + bytes.fromhex(payload["terms_hash"])
        + bytes.fromhex(payload["policy"]["hash"])
        + payload["payout_bps"].to_bytes(2, "big")
        + bytes([OUTCOME_CODE[payload["outcome"]]])
        + int(evaluated_at.timestamp()).to_bytes(8, "big")
        + sla_payload_hash
    )
    assert len(msg) == 147, len(msg)
    return {"message_hex": msg.hex(), "signature": b64url(key.sign(msg)), "key_id": KEY_ID}


def main() -> None:
    key = load_or_create_key()

    trade_id = sha256_hex(b"example-trade-0001")
    terms_hash = sha256_hex(b"example-terms-0001")
    policy = {
        "id": "hashlock-compute-reference",
        "version": "1.0.0",
        "hash": sha256_hex(b"example-policy-document-1.0.0"),
    }

    # Two measurement windows of 12 hours each, 4 x H100 contracted, 96 GPU-hours total.
    windows = [
        ("2026-09-22T00:00:00Z", "2026-09-22T12:00:00Z", 1, "48.000000", "47.250000", "1.000000", "0.984375"),
        ("2026-09-22T12:00:00Z", "2026-09-23T00:00:00Z", 2, "48.000000", "36.000000", "1.000000", "0.750000"),
    ]
    usage_events = []
    for start, end, seq, prov_hours, tel_hours, prov_up, tel_up in windows:
        consolidated_hours = min(float(prov_hours), float(tel_hours))
        consolidated_up = min(float(prov_up), float(tel_up))
        abs_var = abs(float(prov_hours) - float(tel_hours))
        rel_var = abs_var / max(float(prov_hours), float(tel_hours))
        payload = {
            "trade_id": trade_id,
            "terms_hash": terms_hash,
            "window": {"start": start, "end": end},
            "sequence": seq,
            "gpu_spec_contracted": "H100-SXM-80GB",
            "sources": {
                "provider_reported": {
                    "source_id": "provider:example-cloud:billing-api",
                    "gpu_hours": prov_hours,
                    "uptime_ratio": prov_up,
                    "gpu_model_observed": "NVIDIA H100 80GB HBM3",
                    "gpu_count_observed": 4,
                    "samples": 720,
                    "collected_at": end,
                },
                "telemetry": {
                    "source_id": "telemetry:dcgm-exporter:cluster-7",
                    "gpu_hours": tel_hours,
                    "uptime_ratio": tel_up,
                    "gpu_model_observed": "NVIDIA H100 80GB HBM3",
                    "gpu_count_observed": 4,
                    "samples": 43200,
                    "collected_at": end,
                    "raw_digest": sha256_hex(f"raw-samples-{seq}".encode()),
                },
            },
            "consolidated": {
                "gpu_hours": f"{consolidated_hours:.6f}",
                "uptime_ratio": f"{consolidated_up:.6f}",
                "gpu_identity_match": True,
                "method": "min",
            },
            "variance": {
                "gpu_hours_abs": f"{abs_var:.6f}",
                "gpu_hours_rel": f"{rel_var:.6f}",
                "uptime_abs": f"{abs(float(prov_up) - float(tel_up)):.6f}",
            },
        }
        if seq == 2:
            payload["notes"] = ["telemetry: 2 of 4 GPUs reported no load 18:00 to 24:00; provider feed reported full load"]
        emitted = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        usage_events.append(envelope(key, "USAGE_MEASURED", payload, emitted))

    for ev in usage_events:
        with open(os.path.join(HERE, f"usage_measured_{ev['payload']['sequence']}.json"), "w") as f:
            json.dump(ev, f, indent=2)
            f.write("\n")

    # Reference policy: uptime >= 0.95, identity must match every window,
    # variance tolerance 0.30 relative. Payout on PARTIAL = delivery_ratio in bps, rounded down.
    delivered = sum(float(e["payload"]["consolidated"]["gpu_hours"]) for e in usage_events)
    contracted = 96.0
    delivery_ratio = min(1.0, delivered / contracted)
    uptime_measured = sum(float(e["payload"]["consolidated"]["uptime_ratio"]) for e in usage_events) / len(usage_events)
    variance_rel_max = max(float(e["payload"]["variance"]["gpu_hours_rel"]) for e in usage_events)

    uptime_result = "PASS" if uptime_measured >= 0.95 else "FAIL"
    identity_result = "PASS"
    hours_result = "PASS" if (variance_rel_max <= 0.30 and delivery_ratio >= 0.999999) else "FAIL"

    if identity_result == "FAIL" or variance_rel_max > 0.30:
        outcome, payout_bps = "FAIL", 0
    elif uptime_result == "PASS" and hours_result == "PASS":
        outcome, payout_bps = "PASS", 10000
    else:
        outcome = "PARTIAL"
        payout_bps = int(delivery_ratio * 10000)  # rounded down
        if payout_bps == 0:
            outcome = "FAIL"

    sla_payload = {
        "trade_id": trade_id,
        "terms_hash": terms_hash,
        "policy": policy,
        "inputs": [
            {"event_id": e["event_id"], "payload_hash": e["payload_hash"], "sequence": e["payload"]["sequence"]}
            for e in usage_events
        ],
        "period": {"start": windows[0][0], "end": windows[-1][1]},
        "dimensions": {
            "uptime": {"measured_ratio": f"{uptime_measured:.6f}", "required_ratio": "0.950000", "result": uptime_result},
            "gpu_identity": {"contracted": "H100-SXM-80GB", "matched_windows": 2, "total_windows": 2, "result": identity_result},
            "consumed_hours": {
                "delivered": f"{delivered:.6f}",
                "contracted": f"{contracted:.6f}",
                "delivery_ratio": f"{delivery_ratio:.6f}",
                "variance_rel_max": f"{variance_rel_max:.6f}",
                "variance_tolerance": "0.300000",
                "result": hours_result,
            },
        },
        "outcome": outcome,
        "payout_bps": payout_bps,
        "payout_rule": "PARTIAL payout_bps = floor(min(1, delivered / contracted) * 10000); FAIL if identity mismatch or variance above tolerance; PASS if all dimensions pass",
        "final": True,
        "evaluated_at": "2026-09-23T00:05:00Z",
    }
    sla_payload["settlement_attestation"] = attestation(key, sla_payload)
    sla_event = envelope(
        key, "SLA_EVALUATED", sla_payload,
        datetime(2026, 9, 23, 0, 5, 0, tzinfo=timezone.utc),
    )
    with open(os.path.join(HERE, "sla_evaluated_final.json"), "w") as f:
        json.dump(sla_event, f, indent=2)
        f.write("\n")

    # A deliberately invalid event: terms_hash does not match, and payout_bps is out of range.
    bad = json.loads(json.dumps(sla_event))
    bad["payload"]["payout_bps"] = 12000
    with open(os.path.join(HERE, "invalid_sla_evaluated_out_of_range.json"), "w") as f:
        json.dump(bad, f, indent=2)
        f.write("\n")

    print("wrote", len(usage_events), "USAGE_MEASURED,", "1 SLA_EVALUATED (", outcome, payout_bps, "bps ), 1 invalid")


if __name__ == "__main__":
    main()
