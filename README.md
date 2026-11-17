# Uniswap Labs × Cantina — Security Research Report (Rounds 1–8)

> **Researcher:** [maximbase](https://github.com/borneocurrency) (@maximbase)
> **Payout address (if rewarded):** `0xb2E273EBA2eca582257858d8312b763B0DE1D26a` (Binance Agentic Wallet, EVM)
> **Program:** [Uniswap Labs on Cantina](https://cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be)
> **Hunt period:** 16–17 November 2026
> **Status:** ⚠️ **INTERNAL RESEARCH DOCUMENT — NOT SUBMITTED to Cantina. No fee paid.**

## TL;DR

| Metric | Value |
|---|---|
| Rounds | 8 |
| Foundry tests | **1,563 passed / 0 failed** |
| Random fuzz steps | **340,000+** (state-machine + dApp flow), 0 invariant violations |
| Valid findings passing the 7-Question Gate | **0** |
| Reports submitted to Cantina | **0** |
| Live mainnet / testnet testing | **None** — all PoCs on local Foundry/Anvil forks |

Three guards were never breached: the unlock-end zero-delta check, PoolManager balance conservation, and explicit authorization. Every mechanism proven in PoC needs a precondition outside Uniswap's code — a non-standard token, a trusted-party misconfiguration, or an integrator's design choice. This report documents all of them anyway, because they are real warnings for Uniswap and its users.

**Strongest candidate of the whole hunt: D8d1** — `executeSigned` nonce-max replay. One victim signature executed 3× by 3 different submitters. It becomes a submittable finding the moment a named integrator is found whose default is nonce-max + long deadline.

## Scope

| Component | Critical | High | Medium |
|---|---|---|---|
| v4 Core | up to $15,500,000 | $1,000,000 | $100,000 |
| v3 Core + Periphery | $2,250,000 | $500,000 | $50,000 |
| v2 Factory / Pair | $500,000 | $100,000 | $30,000 |
| Permit2, Universal Router, Swap Router, NPM | up to $2,250,000 | — | — |
| Unichain L1 | $2,250,000 | $100,000 | — |
| Web app / infra | $250,000 | $50,000 / — | $10,000 / — |

Payout = Base Severity Reward × (0.60 Impact + 0.25 Likelihood + 0.10 Exploit Maturity + 0.05 Report Quality). Paid only if Uniswap Labs deploys a fix. Rewards in USDC on Ethereum mainnet; KYC + sanctions screening + tax form required before payout.

**Out of scope:** gas optimization, theoretical bugs, third-party bugs not caused by Uniswap code, intended MEV (public-mempool sandwich), social engineering, bugs needing compromised admin keys, testnet-only issues, best-practice critiques. UniswapX `Reactor.sol` is carved out. **TWAP manipulation is explicitly out of scope.**

**Rules followed:** PoC mandatory as Foundry/Forge tests on a local mainnet fork. No testing on live mainnet or public testnets. No exploitation, no exfiltration, no public disclosure before resolution + payout + written permission.

## Methodology

```
Round 1  Recon (8 repos) + 2 PoC angles
Round 2  Extreme fuzzing (14,000 cases + 128,000 invariant calls),
         differential v4/v3/v2, assumption-breaking, chaining
Round 3  Bait contracts: 11 malicious tokens, evil hooks, DeFi vault,
         NFT wrappers — trigger every system
Round 4  Radical combos: 1-tx combos + multi-block economics +
         TokenJar + Across + Permit2
Round 5  Stranded AMPL balance + real TokenJar deployments + Across + NPM
Round 6  Extreme randomization: state-machine fuzzing >240,000 calls,
         read-only victim hunting, diff-hunt
Round 7  v4-hooks-public + scope confirmation (6 aggregator hooks read)
Round 8  Total combination + dApp harness (real user flows, Node + ethers
         v6 + Anvil local fork) + latest materials (11/11 repos, 0 new commits)
```

Every candidate was scored against a **7-Question Gate** (real bug? real victim without weird actions? concrete impact? not a duplicate/known? exploitable? in program scope? would a triager call it a real bug?) and 4 Pre-Submission Gates. **No candidate reached the Pre-Submission Gates.**

Test counts per round: R1: 4 · R2: 42 · R3: 139 · R4: 181 · R5: 245 · R6: 284 · R7: 314 · R8: 354 — **1,563 total, 0 failed** (including all regressions).

## Findings

All findings below are **proven in PoC but GATE-FAILED** — documented as warnings, not as valid bounty reports.

### Summary table

| ID | Finding | Severity if live | Gate verdict |
|---|---|---|---|
| D8d1 | `executeSigned` nonce-max replay (3×) | Critical | ❌ No named integrator defaults to nonce-max |
| R4-1 | Piggyback drain in rebasing pool (LP −50%) | Critical | ❌ Needs rebasing pool |
| A1 | TWAP → vault drain (+$24,288 on $100K vault) | Critical | ❌ TWAP explicitly out of scope |
| T6 | TokenJar `recipient == jar` drain (+500e18, ~0 cost) | Critical | ❌ Needs trusted deployer misconfig; fix exists in new TJAR |
| R6_1i | Dust-kill defeated via exact-out + afterSwap rounding hook | High | ❌ Needs real rebasing pool + rounding hook |
| R2-A | Standing 6909 claim drained via `UNWIND_WITH_FALLBACK` | High | ❌ Victim must use unsupported internal-only action |
| R3-N | v2 rebase skim, zero capital | High | ❌ Needs non-standard token |
| T05 | Rebase mid-settle drains LP 25% | High | ❌ Known limitation, non-standard token |
| T16 | Mint-on-call free output | High | ❌ Same as T05 |
| B5 | `feeTo = pair` burner profits ~148e15 | High | ❌ Needs governance misconfig; **dead** (feeTo = TokenJar, timelock) |
| S8 | Public `AMPL.policy.rebase()` harvests next rebase yield | Medium | ❌ No liquid v4 AMPL pool; principal stranded |
| R3-J | Returndata bomb (~10M gas / 1MB) | Low | ❌ Generic EVM footgun, needs attacker token |
| R3-U3 | FeeSplitter bricked by one reverting recipient | Low | ❌ Trusted deployer, liveness only |
| A7/A8 | NPM `mint` uses `_mint`, not `_safeMint` | Info | ❌ Observation, no exploit path |
| C6 | 1-wei rounding (rebasing token, `IIA` revert) | Info | ❌ DoS/liveness only |

---

### D8d1 — `executeSigned` nonce-max replay ⭐ Strongest candidate

**Status:** GATE-FAILED — missing exactly one thing: a named dApp/integrator that defaults to nonce-max + long deadline.

```solidity
// Universal Router — executeSigned with NONCE_SKIP_CHECK
// Victim signature: nonce = bytes32(type(uint256).max), deadline = 30 days
// Result: the SAME signature executed 3x by 3 different submitters
// Victim sold 3e15 (3x intended). Nonce never marked as used.
// Reproduced in two independent harnesses (Foundry + dApp/Anvil).
```

**Impact:** A victim's single intent is executed multiple times; funds move 3× the signed amount.
**Root cause:** The SDK exposes `NONCE_SKIP_CHECK` and the design permits nonce-max signatures; nothing in the router prevents replay of a nonce-max signature.
**Why not submittable:** app.uniswap.org uses permit + direct swap. No named integrator defaults to nonce-max.
**Next step:** audit public signing code of popular Universal Router integrators and SDK defaults. If one defaults to nonce-max, this becomes submittable.

### R4-1 — Piggyback drain (rebasing pool)

```solidity
// Attacker (third party) rides the victim's settle:
//   sync skipped -> rebase x2 -> settleFor + take everything
// Victim tx still SUCCEEDS, victim output identical to control.
// Attacker net = B0 + amt (exact). LP loses 50% of shares.
```

**Gate verdict:** needs a pool whose token rebases (Q2/Q5/Q7).

### A1 — TWAP → vault drain

```solidity
// Thin pool (1e11), sell 1e9 -> spot tick 0 -> 887271, hold 60s
// -> TWAP follows -> borrow 1e18 (entire vault)
// Lender loss ~1e18 (99.9999%). Attack cost = TIME (60s), not capital.
// With real v3 AMPL liquidity (TVL $9,168):
//   profit +$149.71 ($1K) / +$2,344.11 ($10K) / +$24,288.29 ($100K) after gas.
```

**Gate verdict:** TWAP manipulation is explicitly out of scope (Q2/Q4/Q5/Q7). Warning for any lending/vault reading TWAP from a thin pool as a sole oracle.

### T6 — TokenJar `recipient == jar` drain

```solidity
// Attacker pays 100 RES -> receives 600 RES + A 1000e18 + B 2000e18
// Net +500e18, net cost ~0. Entire jar drained.
// Old protocol-fees code lacks the _validateConfig guard present in new TJAR.
```

**Gate verdict:** needs a trusted deployer misconfiguration (Q2/Q5). **Killed on real deployments** — all live protocol-fees deployments use safe recipients (0xdead / address(this) + bridge).

### R6_1i — Dust-kill defeated

```solidity
// exact-out + afterSwap rounding hook:
//   output 1,000,000,000,001 -> victim pays P - rem (divisible by 4)
//   attacker net = 17,948,222,311,619,271 = 3*B0 + 3*P EXACTLY
// The only path in 6 rounds that beat the C7b dust kill.
```

**Gate verdict:** needs a real rebasing pool + attacker-triggerable rebase + rounding hook + liquidity — no v4 AMPL pool exists (Q1/Q2/Q7).

### R2-A — Standing 6909 claim drained

```solidity
// 50e18 claim parked in PermPosm between calls
// Attacker (no approval) drains it fully via UNWIND_WITH_FALLBACK
```

**Gate verdict:** victim must use an internal-only action declared "not supported" — triager reads it as a footgun, not a bug (Q2/Q7).

### T05 / T16 / R3-N — Rebasing / mint-on-call family

```solidity
// T05: LP deposits 5.98e15; attacker rebases x2 mid-settle
//      -> profit 2.94e15 + 9.97e13; LP withdraws 8.92e15 of 1.196e16 (-25%)
// T16: swap 1e14 -> balance stays 1e14, receive 99,690,060,900,928 free tokens
// R3-N: v2 rebase skim with ZERO capital — steal entire rebase gain (1e18)
```

**Gate verdict:** victim must LP in a non-standard token whose accounting Uniswap does not support — known limitation (Q2/Q5/Q7). Real-world check: AMPL transfers don't trigger rebase, stETH has no Uniswap pool, OHM rebasing ended 2023, SafeMoon bankrupt. Docs: *"Fee-on-Transfer, Rebase, and Reflection tokens are not supported by Uniswap v3."*

### S8 — Stranded AMPL pile

```solidity
// 5,981,737,760,509,664 AMPL units stranded in PoolManager
// 13+ extraction routes tested: principal CANNOT be taken.
// Only the NEXT rebase yield is harvestable:
//   AMPL policy.rebase() is publicly callable (max 1x/24h, oracle-driven)
//   attacker: solo unlock -> rebase -> settle -> take; gain = pile size.
```

**Gate verdict:** no liquid v4 AMPL pool (Q2/Q4/Q5/Q6/Q7).

### B5 — `feeTo = pair` burner

```solidity
// First burner (2e15 capital) nets 147,971,254,852,237,933
// Verified DEAD: V2 mainnet feeTo = TokenJar, feeToSetter = timelock.
```

### Minor / informational

- **R3-J — Returndata bomb:** v4 1MB → 10,355,083 gas; v3 TransferHelper 1MB → 10,161,676 gas; ~2–3MB exceeds the 30M block gas limit. Generic EVM footgun, needs an attacker token.
- **R3-U3 — FeeSplitter brick:** one reverting recipient bricks the whole splitter. Recipients are immutable, owned by a trusted deployer; liveness, not theft.
- **A7/A8 — NPM mint:** `mint` uses `_mint`, not `_safeMint` — `onERC721Received` is NEVER called on mint. Observation, no exploit path.
- **C6 — 1-wei rounding:** rebasing token, post-rebase ×2 payment of 107,205,060,582,176,839 credits 107,205,060,582,176,838 (1 wei short) → `IIA` revert. DoS/liveness only.
- **D8d5 — FluidDexT1 exact-out dust:** 1e12 wei/swap, not extractable (1,000,000 swaps for 1 token).
- **D8d6 — C6 fee-ceil:** ~0.49 wei/swap to the protocol TokenJar.
- **R7 — Lying V3 venue:** swapper overpays 2×; venue is a trust anchor by design.
- **R7 — LP2 vs locked value:** all routes net ≤ 0. Path definitively closed.

## Killed / closed (for the record)

| Item | Result |
|---|---|
| R1-1 sync-slot overwrite | Griefing proven, theft impossible — settle resets slot + unlock-end zero-delta check reverts whole tx |
| R1-2 nested router as victim | `AlreadyUnlocked` — proven impossible |
| R2-B sentinel-address withdraw + public sweep | Victim must deliberately choose sentinel; standard router model |
| R2 TWAP | Fully manipulable — explicitly out of scope |
| T7 Wormhole refund frontrun (1 ETH + A 1000e18) | Duplicate of OZ finding, May 2026 |
| R5 T6 on real deployments | All safe recipients — killed |
| R6 B5 | Definitively dead (feeTo = TokenJar, timelock) |
| R7 StablePair ($3.1B) | Locked — killed |
| R8 D8d7 combo (S8 + R6_1i + R4-1 in one dApp flow) | Attacker ~2×B0, victim unharmed, needs non-existent rebasing pool |
| R8 D8d8 combo TWAP → dApp | User loses 60.62% — out of scope |
| R8 D8d9 combo LP2 | Also locked, attacker loses −12.03e15 — definitively closed |
| R8 dApp sandwich | Attacker loses money |
| R8 callback token / evil hook | DoS only, no funds move |
| R8 FoT output gap 10% | By design |

## Warnings & hardening suggestions

1. **Replay of nonce-max `executeSigned` (D8d1)** — document nonce-max as a dangerous pattern; SDK should default to single-use nonces.
2. **Rebasing pools are not prevented by code (R4-1, R6_1i, S8)** — Uniswap only documents that rebasing tokens are unsupported; anyone can create such a pool. Consider a guard at pool creation or an explicit UI warning.
3. **TWAP from thin pools (A1)** — drain proven profitable with real liquidity (+$24,288 on a $100K vault), attack cost is 60 seconds of time. Educate integrators not to use a thin-pool TWAP as a sole oracle; consider TWAP clamping at the integration layer.
4. **TokenJar without guard in old code (T6)** — backport `_validateConfig` to all legacy protocol-fees deployments.
5. **Parked 6909 claims (R2-A)** — consider extra guards on `UNWIND_WITH_FALLBACK` or warnings for integrations that park claims.
6. **FeeSplitter liveness (R3-U3)** — pull-payment pattern or per-recipient isolation.
7. **Returndata bomb (~10M gas / 1MB) (R3-J)** — cap returndata size on callbacks that call external tokens.
8. **NPM mint without callback (A7/A8)** — align `mint` with `_safeMint` or document the behavior.
9. **v4-hooks-public scope is UNCERTAIN** — leaning IN SCOPE for Uniswap Labs' own hook code (Cantina page lists "Integration vulnerabilities in hooks" and "Hook Bypass" as Critical examples; only UniswapX Reactor is carved out), but the repo is never named and venue-rooted bugs are almost certainly OUT. Confirm in the Cantina submit UI before reporting any hook bug.

## Invariants tested (fuzzing)

- **Round 6 state-machine fuzzing:** >240,000 random calls (50,000 + 128,000 invariant + 30,000 sequence + 15,000 FoT + 15,000 rebasing + 200 hook combos) — **0 violations of invariants I1–I7**.
- **Round 8 dApp-flow fuzzing:** 100,000 random steps (connect → quote → approve/Permit2 → swap exact-in/out + multi-hop → LP mint → collect → decrease → burn → multicall → executeSigned) — **0 violations**.
- **Round 2:** 14,000 fuzz cases + 128,000 invariant calls — 0 violations.
- **Diff-hunt:** 8 repos, 0 commits since audited SHAs.

## Appendix

### Repositories audited (HEAD identical rounds 6–8)

```
v4-core            bea7f6d
v3-core            5ea68a7
v3-periphery       24ccf01
v2-core            6a9e7c9
universal-router   3be05ae
permit2            cc56ad0
v4-periphery       c6e4754
unichain-contracts d5557a7
protocol-fees      eacc9c0
tjar               f7642c6
v4-hooks-public    e354058
```

### Mainnet contracts referenced

```
PoolManager          0x000000000004444c5dc75cB358380D2e3dE08A90
Permit2              0x000000000022D473030F116dDEE9F6B43aC78BA3
v3 Factory           0x1F98431c8aD98523631AE4a59f267346ea31F984
v2 Factory           0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f
Universal Router v2 0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85
```

### Evidence

The following are local working files kept with the researcher and not published in this repository:

- Full hunt log: `hunt-notes.md` (1,161 lines, rounds 1–8)
- Foundry PoC project: `poc/` (40 suites, 354 passed, 0 failed in round 8)
- Per-round reports: `round2-*.md` … `round8-*.md`
- dApp harness: `dapp/` + `dapp-deploy/` (Node + ethers v6 + Anvil local fork)
- Full report (PDF, English, 14 pages): `laporan-temuan-uniswap-cantina.pdf`

## Closing

8 rounds, 1,563 Foundry tests passed, 340,000+ random fuzz steps, zero invariant violations in Uniswap core. The three guards — unlock-end zero-delta check, PoolManager balance conservation, explicit authorization — were never breached. Every proven mechanism needs a precondition outside Uniswap's code, so nothing was submitted.

The single lead worth continuing: **find a real integrator that signs Universal Router `executeSigned` with nonce-max by default** — if one exists, D8d1 becomes a submittable Critical finding.

---
*Research by maximbase, 17 November 2026. Internal document — not submitted to Cantina. Payout address (if rewarded): `0xb2E273EBA2eca582257858d8312b763B0DE1D26a`.*
