# HashLock Compute

Delivery-versus-payment for GPU compute, enforced by a Solana program.

A buyer locks funds in an escrow account whose address is derived from the trade terms. Independent metering measures what the provider actually delivered against the agreed SLA and emits signed evidence. The escrow program consumes that evidence and does one of three things: releases on verified delivery, refunds on non-delivery, or settles partially on partial delivery. Metered pay-as-you-go, not prepaid blocks.

This repository is the HashLock Compute entry to the Colosseum Crypto World's Fair hackathon (September 14 to October 12, 2026). It contains the work built during the hackathon window. See [Scope and provenance](#scope-and-provenance) for what is and is not built here.

## Why

Compute is being financialized faster than its plumbing. Index-settled GPU rental futures are listing on regulated exchanges. Every one of those contracts is cash-settled against an index; the physical leg, the actual delivery of GPU-hours to a buyer, has no neutral settlement rail. Buyers prepay by the hour and absorb idle capacity. Providers invoice on their own telemetry and ask to be believed.

Delivery-versus-payment is the precondition for a market to exist. HashLock Compute is that precondition for compute: payment is released by a program against evidence that neither side of the trade controls.

## Architecture

```
 Buyer                         Provider
   |                               |
   | lock(terms)                   | delivers GPU-hours
   v                               v
+---------------------+     +---------------------------+
| Solana escrow       |     | Metering                  |
| program             |     |  provider usage feed  --+ |
|  PDA = f(terms)     |     |  GPU telemetry feed   --+ |
|  holds SOL / SPL    |     |  correlate, normalize     |
+----------+----------+     |  usage variance           |
           ^                +-------------+-------------+
           |                              |
           |                              v
           |                +---------------------------+
           |                | SLA evaluation            |
           |                |  versioned policy         |
           |                |  uptime, GPU identity,    |
           |                |  consumed hours           |
           |                +-------------+-------------+
           |                              |
           |            signed events:    | USAGE_MEASURED
           |            canonical JSON,   | SLA_EVALUATED
           |            Ed25519           |
           |                              v
           |                +---------------------------+
           +----------------+ Settlement adapter        |
             settle         |  verifies signature       |
             (release,      |  maps evidence to outcome |
             refund, partial)|  submits instruction      |
                            +---------------------------+
```

### Components

| Component | What it does | Where |
|---|---|---|
| Escrow program | Holds buyer funds in a PDA seeded with the hash of the trade terms. Exposes `lock`, `settle` (release, refund or partial settlement, chosen by the signed attestation) and `refund_on_deadline`. Verifies the attestation's Ed25519 signature on-chain. | `programs/escrow` (spec: [docs/escrow-spec.md](docs/escrow-spec.md)) |
| Event schemas | The two data contracts the whole system runs on: `USAGE_MEASURED` and `SLA_EVALUATED`. Canonical JSON, versioned, signed. | [schemas/](schemas/) |
| Settlement adapter | Off-chain service. Consumes signed evidence, checks it against the escrow's terms, and submits the matching instruction. | `adapter/` |
| Metering and SLA evaluation | Ingests a provider-reported usage feed and an independent GPU telemetry feed, correlates them, computes usage variance, evaluates the SLA policy, and emits the signed events. | Implemented against the schemas in this repo. See provenance below. |

### Trade terms

Every trade is defined by a terms object. Its canonical hash seeds the escrow PDA, so changing any term produces a different escrow address. The trade cannot be silently rewritten after funding.

| Field | Meaning |
|---|---|
| `trade_id` | 32-byte identifier chosen by the buyer's client |
| `buyer` | Solana public key that funds the escrow |
| `provider` | Solana public key that receives released funds |
| `mint` | SPL token mint, or the native SOL sentinel |
| `amount` | Total locked amount, base units |
| `gpu_spec` | Contracted GPU class, for example `H100-SXM-80GB` |
| `contracted_hours_micro` | GPU-hours purchased, times 10^6 |
| `sla_policy_id`, `sla_policy_version` | Which SLA policy governs evaluation |
| `sla_policy_hash` | Hash of the policy document, so the policy cannot drift |
| `fee_bps` | Settlement fee in basis points, taken at release |
| `fee_recipient` | Public key receiving the fee |
| `evidence_signer` | Ed25519 public key whose signatures the program accepts |
| `evidence_key_id` | Key identifier carried in every event |
| `delivery_deadline` | Unix time after which the buyer may refund on missing evidence |

The full definition is in [docs/escrow-spec.md](docs/escrow-spec.md).

### Outcomes

| Evidence | Program instruction | Funds |
|---|---|---|
| `SLA_EVALUATED` with `outcome = PASS` (`payout_bps = 10000`) | `settle`, release path | Provider receives `amount` minus fee; fee to `fee_recipient` |
| `SLA_EVALUATED` with `outcome = FAIL` (`payout_bps = 0`) | `settle`, refund path | Buyer receives `amount` |
| `SLA_EVALUATED` with `outcome = PARTIAL` | `settle`, partial path | Provider receives `amount * payout_bps / 10000` minus fee on that part; buyer receives the remainder |
| No evidence by `delivery_deadline` | `refund_on_deadline` (buyer-initiated) | Buyer receives `amount` |

`payout_bps` is computed by the SLA evaluation, carried in the signed event and in a 147-byte settlement attestation, and enforced by the program, which never computes a ratio itself. The rule is defined in [docs/escrow-spec.md](docs/escrow-spec.md#partial-credit).

## Evidence events

Two event types. Both are canonical JSON (RFC 8785, JCS) signed with Ed25519. The signature covers the canonical bytes of the `payload` object; the envelope carries the key identifier so that keys can rotate without changing the schema.

- [`schemas/envelope.schema.json`](schemas/envelope.schema.json): the signed envelope shared by both events
- [`schemas/usage_measured.schema.json`](schemas/usage_measured.schema.json): what was delivered, from two sources, with the variance between them
- [`schemas/sla_evaluated.schema.json`](schemas/sla_evaluated.schema.json): the policy verdict, the per-dimension results, and the payout ratio the program enforces

Worked examples are in [examples/](examples/).

Design rules for the events:

1. A consumer must be able to verify an event with nothing but the envelope, the public key registered for `key_id`, and the schema. No callbacks.
2. Every event references the `trade_id` and the `terms_hash`, so an event for one trade cannot be replayed against another.
3. `USAGE_MEASURED` reports both sources and the variance; it does not decide. `SLA_EVALUATED` decides; it references the `USAGE_MEASURED` event it was computed from by content hash.
4. The SLA policy is identified by id, version and hash in both the trade terms and the event. The program rejects evidence evaluated under a different policy than the one the buyer funded against.

## Scope and provenance

Judges and readers should know exactly what is what.

Built during the hackathon, by the team listed on the Colosseum submission, in this repository: the event schemas and examples, the escrow program specification and its implementation, the settlement adapter, the provider adapter SDK and conformance suite, and the end-to-end devnet demonstration.

Implemented by a contracted engineering vendor under a signed statement of work, against the schemas in this repository: the metering collector (dual-source ingestion, correlation, normalization, usage variance) and the SLA evaluation service that emits the signed events. All right, title and interest in that work product vests in HashLock Corp. The vendor holds no equity and no claim. It is disclosed on the submission form. It is not part of what this repository claims as hackathon work.

Pre-existing and not judged here: HashLock's settlement stack for institutional OTC (HTLC contracts on Ethereum, Bitcoin and Tron, the RFQ and sealed-bid auction engine, the intent solver, the MIT-licensed MCP server and SDK). Those live in separate repositories under the Hashlock-Tech organization and predate the hackathon.

Not claimed, deliberately: trustless proof of compute. The evidence here is neutral measurement from two independent sources under a versioned policy, signed by a key that neither counterparty controls, and enforced by a program. It is narrower than proof of compute and it is shippable.

## Build plan

| Week | Dates | Deliverable | Proof |
|---|---|---|---|
| 1 | Sep 14 to 21 | Repository, event schemas, escrow specification | This commit |
| 2 | Sep 22 to 28 | Escrow program on devnet, `lock` and `release` working | Program ID and a funded escrow transaction in the README |
| 3 | Sep 29 to Oct 5 | `refund`, `partial_settle`, on-chain evidence signature verification, settlement adapter | Devnet transactions for all three outcomes |
| 4 | Oct 6 to 12 | End-to-end run: lock, evidence, settle, in one flow. Demo video, pitch video, final submission | Demo video and transaction links |

Each week's proof is written into this README when it exists, with the transaction signature. Nothing is listed as done before it is on devnet.

## Repository layout

```
schemas/      JSON Schema (2020-12) for the envelope and the two events
examples/     valid example events and a deliberately invalid one
docs/         escrow program specification
programs/     Solana escrow program (week 2)
adapter/      settlement adapter (week 3)
sdk/          provider adapter SDK and conformance suite (week 3 to 4)
```

## Team

HashLock Corp, a Delaware C corporation. Barış Sözen (co-founder, CEO) and Aleksei Diakonov (co-founder, CTO). Website: [hashlock.markets](https://hashlock.markets).

## License

MIT. See [LICENSE](LICENSE).
