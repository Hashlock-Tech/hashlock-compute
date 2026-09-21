#!/usr/bin/env python3
"""Validate every example against the schemas and verify every signature.

This is the reference consumer: anything that can run this file can verify
an evidence event with nothing but the schemas and the public key for key_id.

    python3 examples/verify_examples.py
"""

import base64
import glob
import hashlib
import json
import os
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCHEMAS = os.path.join(ROOT, "schemas")
OUTCOME_CODE = {"FAIL": 0, "PARTIAL": 1, "PASS": 2}


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_registry():
    registry = Registry()
    for path in glob.glob(os.path.join(SCHEMAS, "*.schema.json")):
        with open(path) as f:
            schema = json.load(f)
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(schema["$id"], resource)
        registry = registry.with_resource(os.path.basename(path), resource)
    return registry


def public_keys() -> dict:
    with open(os.path.join(HERE, "test_key.json")) as f:
        k = json.load(f)
    return {k["key_id"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(k["public_key_hex"]))}


def verify_file(path: str, validator: Draft202012Validator, keys: dict) -> list:
    problems = []
    with open(path) as f:
        event = json.load(f)
    for err in sorted(validator.iter_errors(event), key=lambda e: list(e.path)):
        problems.append(f"schema: {'/'.join(str(p) for p in err.path) or '<root>'}: {err.message}")

    payload_bytes = rfc8785.dumps(event["payload"])
    if event.get("payload_hash") and event["payload_hash"] != hashlib.sha256(payload_bytes).hexdigest():
        problems.append("payload_hash does not match canonical payload")

    key = keys.get(event.get("key_id"))
    if key is None:
        problems.append(f"unknown key_id {event.get('key_id')}")
        return problems
    try:
        key.verify(b64url_decode(event["signature"]), payload_bytes)
    except InvalidSignature:
        problems.append("envelope signature invalid")

    if event["event_type"] == "SLA_EVALUATED" and event["payload"].get("final"):
        att = event["payload"].get("settlement_attestation")
        if not att:
            problems.append("final SLA_EVALUATED without settlement_attestation")
        else:
            body = dict(event["payload"])
            body.pop("settlement_attestation")
            expected = (
                b"HLCSETL1"
                + bytes.fromhex(body["trade_id"])
                + bytes.fromhex(body["terms_hash"])
                + bytes.fromhex(body["policy"]["hash"])
                + body["payout_bps"].to_bytes(2, "big", signed=False)
                if 0 <= body["payout_bps"] <= 65535 else b""
            )
            msg = bytes.fromhex(att["message_hex"])
            if expected and not msg.startswith(expected):
                problems.append("attestation message does not match payload fields")
            if len(msg) != 147:
                problems.append(f"attestation message length {len(msg)}, expected 147")
            if msg[-32:] != hashlib.sha256(rfc8785.dumps(body)).digest():
                problems.append("attestation sla_payload_hash does not match payload")
            att_key = keys.get(att["key_id"])
            try:
                att_key.verify(b64url_decode(att["signature"]), msg)
            except (InvalidSignature, AttributeError):
                problems.append("attestation signature invalid")
    return problems


def main() -> int:
    registry = load_registry()
    with open(os.path.join(SCHEMAS, "envelope.schema.json")) as f:
        envelope_schema = json.load(f)
    validator = Draft202012Validator(envelope_schema, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER)
    keys = public_keys()

    failures = 0
    for path in sorted(glob.glob(os.path.join(HERE, "*.json"))):
        name = os.path.basename(path)
        if name == "test_key.json":
            continue
        problems = verify_file(path, validator, keys)
        expect_invalid = name.startswith("invalid_")
        ok = (not problems) if not expect_invalid else bool(problems)
        status = "OK " if ok else "BAD"
        print(f"{status} {name}" + (f"  (expected invalid, {len(problems)} problem(s))" if expect_invalid and problems else ""))
        for p in problems:
            print(f"      {p}")
        if not ok:
            failures += 1
    print("failures:", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
