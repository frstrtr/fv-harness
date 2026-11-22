// Binding for diff_oracle_template.cpp: risk::step (production) vs RiskSpec.Oracle (Lean).
#pragma once
#include <cinttypes>
#include <cstdint>
#include <cstdio>

#include "risk.hpp"

extern "C" {
uint64_t fv_risk_pos(uint64_t limit, uint64_t pos, uint64_t open, uint64_t op, uint64_t q);
uint64_t fv_risk_open(uint64_t limit, uint64_t pos, uint64_t open, uint64_t op, uint64_t q);
uint64_t fv_risk_last(uint64_t limit, uint64_t pos, uint64_t open, uint64_t op, uint64_t q);
}

namespace binding {

using State = risk::State;
struct Op {
  uint64_t op;
  uint64_t q;
};

// Only admissible states: pos + open <= limit (the invariant the statements assume). The fuzzer
// then checks that the C++ keeps agreeing with the model along any event sequence from there.
inline State initial_state(FuzzedDataProvider& in) {
  const uint64_t limit = fvfuzz::pick_u64(in);
  const uint64_t pos = in.ConsumeIntegralInRange<uint64_t>(0, limit);
  const uint64_t open = in.ConsumeIntegralInRange<uint64_t>(0, limit - pos);
  return State{limit, pos, open, 0};
}

inline Op make_op(FuzzedDataProvider& in, const State&) {
  return Op{in.ConsumeIntegralInRange<uint64_t>(0, 3), fvfuzz::pick_u64(in)};
}

inline State oracle_step(const State& s, const Op& o) {
  return State{s.limit, fv_risk_pos(s.limit, s.pos, s.open, o.op, o.q),
               fv_risk_open(s.limit, s.pos, s.open, o.op, o.q),
               fv_risk_last(s.limit, s.pos, s.open, o.op, o.q)};
}

inline State impl_step(const State& s, const Op& o) { return risk::step(s, o.op, o.q); }

inline bool same(const State& x, const State& y) {
  return x.limit == y.limit && x.pos == y.pos && x.open == y.open && x.last == y.last;
}

inline void print_state(FILE* f, const char* tag, const State& s) {
  std::fprintf(f, "  %s limit=%" PRIu64 " pos=%" PRIu64 " open=%" PRIu64 " last=%" PRIu64 "\n", tag,
               s.limit, s.pos, s.open, s.last);
}

inline void print_op(FILE* f, const Op& o) {
  static const char* kName[] = {"submit", "cancel", "fill", "reduce"};
  std::fprintf(f, "  op     %s q=%" PRIu64 "\n", kName[o.op % 4], o.q);
}

// Runs under LSan's ScopedDisabler: one oracle call with values above 2^63.
inline void warm_up() {
  const uint64_t m = UINT64_MAX;
  (void)oracle_step(State{m, m / 2, m / 4, 0}, Op{0, m / 8});
}

}  // namespace binding
