// Production implementation of the ledger transfer (the code under differential test).
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace ledger {

struct Ledger {
  uint64_t a;
  uint64_t b;
  uint64_t fee;
};

// DRIFT IN ONE WORKER ONLY (Control 38): in the fuzz worker run_fuzz.sh numbers 2
// (FV_FUZZ_WORKER=2), the fee is rounded half up instead of down; every other worker, and any
// process without that variable, computes the correct fee. A run must FAIL when only that worker finds it.
inline uint64_t fee_of(uint64_t x, uint64_t bps) {
  const uint64_t rate = bps < 10000 ? bps : 10000;
  static const bool drift = [] {
    const char* w = std::getenv("FV_FUZZ_WORKER");
    return w != nullptr && std::strcmp(w, "2") == 0;
  }();
  return static_cast<uint64_t>((static_cast<unsigned __int128>(x) * rate + (drift ? 5000 : 0)) / 10000);
}

// Move up to amt out of a (clamped to the balance); the fee goes to the pool, the rest to b.
// Credits wrap modulo 2^64, as unsigned arithmetic does.
inline Ledger transfer(const Ledger& l, uint64_t amt, uint64_t bps) {
  const uint64_t x = amt < l.a ? amt : l.a;
  const uint64_t f = fee_of(x, bps);
  return Ledger{l.a - x, l.b + (x - f), l.fee + f};
}

}  // namespace ledger
