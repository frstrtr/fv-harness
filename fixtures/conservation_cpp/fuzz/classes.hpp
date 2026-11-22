// Domain edge-case classes for the ledger transfer (labels only; fuzz/fv_classify.hpp).
// Each predicate sees `before`, `op` and `after` = the ORACLE's state after the step.
#pragma once
#include <vector>

namespace fvclasses {
inline const std::vector<fvfuzz::Class<binding::State, binding::Op>>& table() {
  static const std::vector<fvfuzz::Class<binding::State, binding::Op>> t = {
      FV_CLASS("fee rounds to zero on a nonzero transfer",
               (op.amt < before.a ? op.amt : before.a) > 0 && after.fee == before.fee),
      FV_CLASS("fee rate exactly at the cap (bps = 10000)", op.bps == 10000),
      FV_CLASS("fee rate above the cap (bps > 10000)", op.bps > 10000),
      FV_CLASS("amount exceeds the balance (amt > a)", op.amt > before.a),
      FV_CLASS("destination balance wraps past 2^64", after.b < before.b),
  };
  return t;
}
}  // namespace fvclasses
