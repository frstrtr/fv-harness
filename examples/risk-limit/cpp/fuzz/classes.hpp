// Domain edge-case classes for the pre-trade risk check (labels only; fuzz/fv_classify.hpp).
// Each predicate sees `before`, `op` and `after` = the ORACLE's state after the step.
// Predicates are C++ too: compute sums that could pass 2^64 in fvfuzz::u128.
#pragma once
#include <vector>

namespace fvclasses {
inline const std::vector<fvfuzz::Class<binding::State, binding::Op>>& table() {
  static const std::vector<fvfuzz::Class<binding::State, binding::Op>> t = {
      FV_CLASS("order exactly fills the headroom",
               op.op % 4 == 0 && op.q == before.limit - before.pos - before.open),
      FV_CLASS("order exceeds the headroom by one unit",  // u128: headroom + 1 must not wrap
               op.op % 4 == 0 &&
                   fvfuzz::u128(op.q) == fvfuzz::u128(before.limit - before.pos - before.open) + 1),
      FV_CLASS("limit exactly reached after the step", after.pos + after.open == after.limit),
      FV_CLASS("zero-quantity order", op.op % 4 == 0 && op.q == 0),
      FV_CLASS("cancel more than is open", op.op % 4 == 1 && op.q > before.open),
      FV_CLASS("fill more than is open", op.op % 4 == 2 && op.q > before.open),
      FV_CLASS("reduce more than the position", op.op % 4 == 3 && op.q > before.pos),
  };
  return t;
}
}  // namespace fvclasses
