# HashLock Compute escrow program: specification v0.1

Status: draft, written September 21, 2026, before implementation. The program is implemented against this document in weeks 2 and 3 of the hackathon. Where the implementation diverges, this document is updated in the same pull request.

Target: Solana, Anchor framework, devnet first. Native SOL and SPL tokens.

## 1. Purpose

One escrow per trade. The buyer locks the full notional up front. The program pays out only against a settlement attestation signed by the evidence key named in the trade terms, or refunds the buyer after the delivery deadline if no attestation ever arrives. Nobody, including HashLock, can move funds any other way.

## 2. Trade terms

The terms object is agreed off-chain (RFQ, auction, or bilateral) and passed to `lock` in full. The program hashes it and uses the hash as a PDA seed, so the escrow address commits to every term.

| # | Field | Type | Bytes | Notes |
|---|---|---|---|---|
| 1 | `trade_id` | `[u8; 32]` | 32 | Chosen by the buyer's client. Unique per buyer. |
| 2 | `buyer` | `Pubkey` | 32 | Signer of `lock`. |
| 3 | `provider` | `Pubkey` | 32 | Recipient of released funds. |
| 4 | `mint` | `Pubkey` | 32 | SPL mint. All-zero public key means native SOL. |
| 5 | `amount` | `u64` | 8 | Total locked, base units. |
| 6 | `gpu_spec` | `[u8; 32]` | 32 | UTF-8, zero padded, for example `H100-SXM-80GB`. |
| 7 | `contracted_hours_micro` | `u64` | 8 | GPU-hours times 10^6. |
| 8 | `sla_policy_id` | `[u8; 32]` | 32 | UTF-8, zero padded. |
| 9 | `sla_policy_version` | `[u8; 16]` | 16 | UTF-8, zero padded, semantic version. |
| 10 | `sla_policy_hash` | `[u8; 32]` | 32 | SHA-256 of the canonical policy document. |
| 11 | `fee_bps` | `u16` | 2 | Settlement fee, basis points, on the provider's share. |
| 12 | `fee_recipient` | `Pubkey` | 32 | Receives the fee. |
| 13 | `evidence_signer` | `Pubkey` | 32 | Ed25519 public key of the evidence key. |
| 14 | `evidence_key_id` | `[u8; 32]` | 32 | UTF-8, zero padded. Informational; the program checks the public key. |
| 15 | `delivery_deadline` | `i64` | 8 | Unix seconds. Buyer may refund after this if no attestation was applied. |
| 16 | `terms_version` | `u8` | 1 | Fixed at 1 for this specification. |

`terms_hash = SHA-256(borsh_serialize(terms))`, 363 bytes serialized in the field order above. The off-chain JSON form of the same terms (used by the metering layer and the settlement adapter) must hash to the same value: the adapter serializes the JSON terms into this exact layout before hashing. There is one hash, not two.

## 3. Accounts

### 3.1 Escrow state

PDA seeds: `["escrow", terms_hash]`.

| Field | Type | Notes |
|---|---|---|
| `terms_hash` | `[u8; 32]` | Copy of the seed for convenience. |
| `trade_id` | `[u8; 32]` | |
| `buyer`, `provider`, `mint`, `fee_recipient`, `evidence_signer` | `Pubkey` | Copied from terms. |
| `amount` | `u64` | Locked at creation. Never changes. |
| `fee_bps` | `u16` | |
| `sla_policy_hash` | `[u8; 32]` | |
| `delivery_deadline` | `i64` | |
| `state` | `u8` | 0 Funded, 1 Released, 2 Refunded, 3 PartiallySettled. Terminal states are 1, 2, 3. |
| `settled_at` | `i64` | 0 until terminal. |
| `payout_bps` | `u16` | 0 until terminal. 10000 on release, 0 on refund, the attested value on partial settlement. |
| `attestation_hash` | `[u8; 32]` | SHA-256 of the 147-byte attestation message that closed the trade. Zero for deadline refunds. |
| `bump` | `u8` | |

Storing the full terms on-chain is unnecessary: the hash commits to them and the adapter holds the plaintext. The fields above are the ones the program needs to enforce outcomes.

### 3.2 Vault

For SPL: an associated token account owned by the escrow PDA, seeds `["vault", terms_hash]`.
For native SOL: lamports are held in the escrow PDA itself above its rent-exempt minimum.

## 4. Instructions

### 4.1 `lock(terms)`

Signer: `buyer`.

1. Compute `terms_hash` from `terms`. Derive the escrow PDA; fail if it already exists.
2. Check `terms.buyer == signer`, `terms.amount > 0`, `terms.fee_bps <= 10000`, `terms.delivery_deadline > now`.
3. Create the escrow account and, for SPL, the vault.
4. Transfer `amount` from the buyer to the vault (SPL) or to the PDA (SOL).
5. Set `state = Funded`. Emit `Locked { terms_hash, trade_id, amount }`.

### 4.2 `settle(attestation_message, ed25519_ix_index)`

Signer: anyone. Settlement is permissionless because the attestation carries all authority; the settlement adapter is simply the party that normally submits it.

`release`, `refund` and `partial_settle` are one instruction with three outcomes, chosen by the attestation. Three names, one code path, so there is no way to reach a payout without an attestation.

1. Require `state == Funded`.
2. Parse `attestation_message` (147 bytes, layout in section 5).
3. Require `domain_tag == "HLCSETL1"`, `trade_id == escrow.trade_id`, `terms_hash == escrow.terms_hash`, `policy_hash == escrow.sla_policy_hash`.
4. Require `outcome` in {0, 1, 2}. Require `payout_bps == 10000` if outcome is PASS (2), `payout_bps == 0` if FAIL (0), `0 < payout_bps < 10000` if PARTIAL (1).
5. Verify the Ed25519 signature. Solana programs do not verify Ed25519 in-program; the transaction must include an instruction to the Ed25519 native program (`Ed25519SigVerify111111111111111111111111111`) at index `ed25519_ix_index`, and this program uses instruction introspection (`sysvar::instructions`) to check that the verified message equals `attestation_message`, the verified public key equals `escrow.evidence_signer`, and the instruction is the native Ed25519 program. Any mismatch fails.
6. Compute payouts with integer arithmetic, no floats:
   - `provider_gross = amount * payout_bps / 10000` (u128 intermediate, floor)
   - `fee = provider_gross * fee_bps / 10000` (floor)
   - `provider_net = provider_gross - fee`
   - `buyer_refund = amount - provider_gross`
7. Transfer `provider_net` to `provider`, `fee` to `fee_recipient`, `buyer_refund` to `buyer`. Zero-amount transfers are skipped.
8. Set `state` to Released, Refunded or PartiallySettled according to `outcome`; set `payout_bps`, `settled_at = now`, `attestation_hash = SHA-256(attestation_message)`.
9. Emit `Settled { terms_hash, outcome, payout_bps, provider_net, fee, buyer_refund, attestation_hash }`.
10. Close the vault (SPL) to the buyer for rent.

### 4.3 `refund_on_deadline()`

Signer: `buyer`.

1. Require `state == Funded` and `now > escrow.delivery_deadline`.
2. Transfer `amount` to `buyer`. Set `state = Refunded`, `payout_bps = 0`, `settled_at = now`, `attestation_hash = 0`.
3. Emit `Settled` with `outcome = 0` and a zero attestation hash.

This is the only path that moves funds without an attestation, and it only ever returns them to the buyer. A provider who delivered but whose evidence was never issued has recourse against the evidence operator, not against the buyer's funds; that is the correct place for that risk.

### 4.4 Not in v0.1

- Extending the deadline (would need both signatures; deferred).
- Disputes and arbitration (the policy is the arbiter; a dispute is a new trade).
- Streaming or per-window settlement (v0.1 settles once per trade; the schemas already support per-window evidence so this can be added without changing them).
- Multi-attestor or threshold signatures (the schema's `key_id` allows it later).

## 5. Settlement attestation

Emitted by the SLA evaluation service inside a final `SLA_EVALUATED` event (`settlement_attestation` field). Fixed layout, 147 bytes, so it fits comfortably in a transaction next to the Ed25519 instruction and needs no JSON parsing on-chain.

| Offset | Length | Field | Encoding |
|---|---|---|---|
| 0 | 8 | `domain_tag` | ASCII `HLCSETL1` |
| 8 | 32 | `trade_id` | raw |
| 40 | 32 | `terms_hash` | raw |
| 72 | 32 | `policy_hash` | raw |
| 104 | 2 | `payout_bps` | u16 big-endian |
| 106 | 1 | `outcome` | 0 FAIL, 1 PARTIAL, 2 PASS |
| 107 | 8 | `evaluated_at` | i64 big-endian, unix seconds |
| 115 | 32 | `sla_payload_hash` | SHA-256 of `canonical_json(payload without settlement_attestation)` |

Signature: Ed25519 over the 147 raw bytes, by `evidence_signer`.

The domain tag prevents a signature made for any other HashLock purpose from being replayed here. `trade_id` plus `terms_hash` bind the attestation to one escrow. `policy_hash` prevents settling under a policy the buyer did not fund against. `sla_payload_hash` ties the compact message to the full JSON verdict, so an auditor can go from the on-chain `attestation_hash` to the exact evidence and from there to the raw samples via `raw_digest`.

Replay within the same escrow is impossible because the escrow reaches a terminal state on first use. Replay against a different escrow fails on `terms_hash`.

## 6. Partial credit

The program does not compute the payout ratio. The SLA policy does, off-chain, deterministically, from the `USAGE_MEASURED` inputs, and signs it. The program enforces the signed number. This split is deliberate: the policy can evolve (new dimensions, different tolerances) by publishing a new policy version and hash, and the program never changes.

The reference policy `hashlock-compute-reference` v1.0.0 used in the examples:

1. GPU identity: every window must match the contracted model and count. One mismatch makes the outcome FAIL, `payout_bps = 0`. Substituting hardware is not partial delivery.
2. Variance: if the largest relative disagreement between the provider feed and telemetry across the inputs exceeds `variance_tolerance` (0.30), the readings are not trusted and the outcome is FAIL. The provider's remedy is a telemetry feed that agrees with its billing.
3. Consumed hours: `delivery_ratio = min(1, delivered / contracted)`, 6 decimals, rounded down.
4. Uptime: time-weighted consolidated uptime over the period against `required_ratio` (0.95).
5. Outcome:
   - PASS if identity passes, variance is within tolerance, `delivery_ratio >= 0.999999` and uptime passes. `payout_bps = 10000`.
   - Otherwise PARTIAL with `payout_bps = floor(delivery_ratio * 10000)`. If that is 0, the outcome is FAIL.

Uptime failure alone does not cut the payout below `delivery_ratio` in v1.0.0: hours that were not delivered are already excluded by `delivery_ratio`, and penalizing them twice would double count. A policy that wants an uptime penalty on top publishes a new version.

Worked example (examples/): 96 contracted GPU-hours, telemetry saw 83.25, provider reported 96, consolidated uptime 0.867188, largest relative variance 0.25 (within tolerance), identity matched in both windows. Outcome PARTIAL, `payout_bps = 8671`. On a 1,000 USDC escrow (1,000,000,000 base units) with `fee_bps = 25`: provider gross 867.100000, fee 2.167750, provider net 864.932250, buyer refund 132.900000. The three transfers sum to the locked amount exactly.

## 7. Errors

| Code | Condition |
|---|---|
| `EscrowExists` | `lock` on an existing `terms_hash` |
| `BuyerMismatch` | `terms.buyer != signer` |
| `InvalidTerms` | zero amount, fee over 10000 bps, deadline in the past |
| `NotFunded` | settle or refund on a terminal escrow |
| `BadAttestationLength` | message not 147 bytes |
| `BadDomainTag` | |
| `TradeMismatch` | `trade_id` or `terms_hash` differ |
| `PolicyMismatch` | `policy_hash` differs |
| `BadOutcome` | outcome code or `payout_bps` inconsistent |
| `SignatureNotVerified` | no matching Ed25519 instruction, wrong key, or wrong message |
| `DeadlineNotReached` | `refund_on_deadline` too early |

## 8. Security notes for review

- The only two ways out of Funded are a valid attestation or the buyer after the deadline. There is no admin key, no upgrade-authority path to funds, no pause.
- Ed25519 verification by instruction introspection must check the instruction's program id, the exact message bytes, the exact public key, and that the verified instruction is in the same transaction. Checking only the signature count is a known mistake.
- Integer math: `amount * payout_bps` fits in u128 for any u64 amount. All divisions floor. Rounding always favors the buyer (gross is floored) and then the provider (fee is floored).
- The program does not trust `evaluated_at`; it is recorded for audit, not used for logic. The deadline check uses the cluster clock.
- Upgrade authority for the devnet program is a HashLock multisig; before mainnet it is burned or moved to a governance program, to be decided after the external audit.

## 9. Test plan (week 3)

1. lock, settle PASS: provider gets amount minus fee, fee recipient gets fee.
2. lock, settle FAIL: buyer gets amount back.
3. lock, settle PARTIAL 8671 bps: three transfers, sums equal amount exactly.
4. Attestation from the wrong key: rejected.
5. Attestation with a different `terms_hash`: rejected.
6. Attestation replayed after settlement: rejected (`NotFunded`).
7. Missing Ed25519 instruction, or one that verifies a different message: rejected.
8. `refund_on_deadline` one second before and after the deadline.
9. Native SOL and SPL variants of tests 1 to 3.
10. Fee 0 and fee 10000 edge cases; amount 1 base unit.
