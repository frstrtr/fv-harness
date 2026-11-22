// Binding for diff_oracle_template.cpp: ledger::transfer (production) vs FVSpec.Oracle (Lean).
#pragma once
#include <cinttypes>
#include <cstdint>
#include <cstdio>

#include "ledger.hpp"

extern "C" {
uint64_t fv_oracle_transfer_a(uint64_t a, uint64_t b, uint64_t fee, uint64_t amt, uint64_t bps);
uint64_t fv_oracle_transfer_b(uint64_t a, uint64_t b, uint64_t fee, uint64_t amt, uint64_t bps);
uint64_t fv_oracle_transfer_fee(uint64_t a, uint64_t b, uint64_t fee, uint64_t amt, uint64_t bps);
}

namespace binding {

using State = ledger::Ledger;
struct Op {
  uint64_t amt;
  uint64_t bps;
};

inline State initial_state(FuzzedDataProvider& in) {
  return State{fvfuzz::pick_u64(in), fvfuzz::pick_u64(in), fvfuzz::pick_u64(in)};
}

inline Op make_op(FuzzedDataProvider& in, const State&) {
  return Op{fvfuzz::pick_u64(in), fvfuzz::pick_u64(in)};
}

inline State oracle_step(const State& s, const Op& op) {
  return State{fv_oracle_transfer_a(s.a, s.b, s.fee, op.amt, op.bps),
               fv_oracle_transfer_b(s.a, s.b, s.fee, op.amt, op.bps),
               fv_oracle_transfer_fee(s.a, s.b, s.fee, op.amt, op.bps)};
}

inline State impl_step(const State& s, const Op& op) { return ledger::transfer(s, op.amt, op.bps); }

inline bool same(const State& x, const State& y) {
  return x.a == y.a && x.b == y.b && x.fee == y.fee;
}

inline void print_state(FILE* f, const char* tag, const State& s) {
  std::fprintf(f, "  %s a=%" PRIu64 " b=%" PRIu64 " fee=%" PRIu64 "\n", tag, s.a, s.b, s.fee);
}

inline void print_op(FILE* f, const Op& op) {
  std::fprintf(f, "  op     transfer amt=%" PRIu64 " bps=%" PRIu64 "\n", op.amt, op.bps);
}

// Edge-case classification (labels only; fuzz/fv_classify.hpp). Declares what matters about one
// step, from the input and the ORACLE's state after it; the C++ result is never consulted.
#define FV_BINDING_DESCRIBE 1
inline void describe(fvfuzz::Sink& k, const State& before, const Op& op, const State& after) {
  k.field("state.a", before.a);
  k.field("state.b", before.b);
  k.field("state.fee", before.fee);
  k.field("op.amt", op.amt);
  k.field("op.bps", op.bps);
  const uint64_t x = op.amt < before.a ? op.amt : before.a;          // amount moved
  const uint64_t rate = op.bps < 10000 ? op.bps : 10000;
  k.division("fee = x*rate/10000", static_cast<fvfuzz::u128>(x) * rate, 10000);
  k.outcome(x == 0 ? "nothing moved" : (op.amt >= before.a ? "whole balance moved" : "partial transfer"));
  (void)after;
}

// Runs under LSan's ScopedDisabler in LLVMFuzzerInitialize: one oracle call with values above
// 2^63, so the Lean runtime's big-number paths are initialised before fuzzing starts.
inline void warm_up() {
  const uint64_t m = UINT64_MAX;
  (void)oracle_step(State{m, m, m}, Op{m, 9999});
}

}  // namespace binding
