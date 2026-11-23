# Case study: a signed overflow in Dash Core's superblock payment total, found by reading

## Summary

While mapping Dash Core's functions to the statements of our verified model of Dash payout rules, we
read the superblock check in Dash Core v24.0.2, `CSuperblock::GetPaymentsTotalAmount()`
(`src/governance/superblock.cpp`). It adds a governance trigger's payment amounts as signed 64-bit
integers, with no overflow check and no explicit bound on the number of payments. 4,393 payments of
the maximum money amount overflow the sum; 4,392 do not. On Dash Core's develop branch the same sum
sits in `IsSuperblockValid()` (`src/masternode/payments.cpp`).

The severity is **low**:
- in v24.0.2, as read, there is no inflation path: the wrapped total passes the payments-limit check,
  and the block is then rejected by the block-value check or the payment matching;
- we found no way for release builds to diverge from one another;
- in v24.0.2 the only new effect is that builds with `-ftrapv` (debug builds) or trapping UBSan abort
  at the addition;
- the fix pull request adds that under the payment matching used before V24, one coinbase output can
  match several identical payments. The older code could therefore, in theory, accept a wrapped total,
  which needs a funded trigger and millions of DASH in fees in the same block.

Reaching it needs a block at the superblock height whose coinbase has at least as many outputs as the
trigger has payments, and a trigger funded by net yes votes of about 10% of the weighted masternode
count (or `nGovernanceMinQuorum`, if larger).

The Dash Core developers confirmed the issue and opened a fix,
[dashpay/dash#8229](https://github.com/dashpay/dash/pull/8229). It adds the payments one at a time
and refuses the block as soon as one does not fit under the limit, so the running total cannot
overflow. Its tests cover the boundary and schedules of `n` and `n + 1` maximum amounts.

c2pool's own restatement of the same check had the same shape. Its fix is in
[frstrtr/c2pool#2312](https://github.com/frstrtr/c2pool/pull/2312).

The harness's fuzzer did **not** find this. Reading the upstream code during the mapping step did.

## How it was confirmed

1. **An offline test.** The function body, compiled verbatim under UndefinedBehaviorSanitizer:
   4,392 maximum-money entries are clean, and 4,393 report a signed overflow. A plain build wraps the
   sum to a negative total.
2. **A second, independent reading** confirmed every sub-claim from source:
   - the sum and its only caller;
   - the per-amount bound and the missing count bound;
   - the boundary;
   - the rejection path and the absence of inflation in v24.0.2.

   It also added one consequence: debug builds abort at the addition.
3. **c2pool's restatement** refused 4,392 and accepted 4,393 before its fix (the sum wrapped and passed
   the budget check), the same boundary as Dash Core's. After the fix it refuses both.

## Why the fuzzer did not find it

The fuzzer never ran this code on a schedule length it chose:
- The differential fuzzer for c2pool's Dash coinbase code builds the coinbase from a superblock
  schedule it **takes as given**.
- The superblock acceptance check is **restated** in the binding, not called; the coverage line of
  that fuzzer lists it that way.
- Dash Core itself was not a fuzz target.

## What the harness takes from it

- **A coverage line in every review note.** For each statement, the note says which code the fuzzer
  *calls*, which it *restates*, and which it *takes as input*. "Model = implementation" holds only for
  the first kind.
- **A mapping step that reads upstream code.** Before an upstream project becomes a fuzz target, each
  statement is mapped to the upstream function behind it, by reading, with its bounds and its callers.
- **A candidate statement for c2pool's fixed code:** *the superblock schedule total never exceeds the
  budget cap.* To be proved over the bounded total and fuzzed against the C++, with the fuzzer choosing
  the schedule length.

## Timeline (2026-11-23, UTC)

- 04:25: reported privately to the Dash Core security contact. The maintainers asked for it to be
  handled in public.
- 06:11: the Dash Core fix opened, [dashpay/dash#8229](https://github.com/dashpay/dash/pull/8229).
- c2pool's fix: [frstrtr/c2pool#2312](https://github.com/frstrtr/c2pool/pull/2312).

## Credits

The c2pool project; the Dash Core developers.
