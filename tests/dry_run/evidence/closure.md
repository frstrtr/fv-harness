# Closure report: dryrun-conservation-02

Closed 2026-11-22T01:22:42+0400. Gate **PASS**, fuzz **PASS**.

## Digests
- lock manifest: `64e0f8f79ee7b9abab6b94b3add35c36602463db041cb5c7fb626cf0bb6173e2`
- spec/solution/Solution.lean: `25eff609467a6568997d11032099452246bcd949ec8c24501d9a41b0c973af10`
- $FV_ROOT/harness/fixtures/conservation_cpp/impl/ledger.hpp: `49d9871606d004acf56a35f6a1ffd94ec39c8b639d3d6716b698580cfdca00b5`
- export challenge: `96c6c5e6f5754cf98d4f1039ea5e5806b4ef58131ed3f9e4720a7f830d7f6c3f`
- export solution: `5f9f938a8bb22afbbae29b97fcd4fa26e0edb8a7394ffc74c855abaa03cd0b31`

## Gate stages
- comparator_export: PASS
- comparator_native: PASS
- con_leche: PASS
- con_leche_compare: PASS
- con_ron: PASS
- config: PASS
- export: PASS
- lint: PASS
- lock: PASS
- netns: PASS

## Kernel verdicts
- con-leche: accepted 1426 declarations (--verified)
- con-ron: accepted 1426 declarations (--verified)
- con-leche: accepted 484 declarations, 2 axioms justified by the solution $FV_ROOT/tasks/dryrun-conservation-02/audit-1/exports/solution.ndjson (1430 declarations accepted) (--verified)
- con-leche: theorem FV.transfer_conserves justified by the solution
- con-leche: theorem FV.transfer_source_le justified by the solution

## Differential fuzz
- stat::number_of_executed_units: 1000000 stat::average_exec_per_sec:     8474 stat::new_units_added:          45
- 118.936493200 s

## Timeline
- 2026-11-22T00:29:32+0400 SPEC_LOCK -> DECOMPOSE: spec locked: manifest digest 64e0f8f79ee7b9abab6b94b3add35c36602463db041cb5c7fb626cf0bb6173e2
- 2026-11-22T00:29:32+0400 DECOMPOSE -> DISCHARGE: skeleton by Tier-1 planner: tests/dry_run/skeleton/Solution.lean: 2 open stub(s) ['feeOf_le', 'transfer_source_le']
- 2026-11-22T01:18:55+0400 DISCHARGE -> DECOMPOSE: wall event: ['feeOf_le'] not closed after 2 x budget 8; Tier 1 re-decomposes
- 2026-11-22T01:19:40+0400 DECOMPOSE -> DISCHARGE: skeleton by Tier-1 planner: tests/dry_run/redecompose_feeOf_le.py after wall event on feeOf_le: 1 open stub(s) ['mul_min_le']
- 2026-11-22T01:20:09+0400 DISCHARGE -> AUDIT: all 1 stub(s) closed by Tier 2
- 2026-11-22T01:20:40+0400 AUDIT -> COUPLE: gate PASS: comparator_export=PASS comparator_native=PASS con_leche=PASS con_leche_compare=PASS con_ron=PASS config=PASS export=PASS lint=PASS lock=PASS netns=PASS
- 2026-11-22T01:22:42+0400 COUPLE -> CLOSE: fuzz PASS: stat::number_of_executed_units: 1000000 stat::average_exec_per_sec:     8474 stat::new_units_added:          45 in 118.936493200s
