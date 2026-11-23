// Production implementation of the ledger transfer (the code under differential test).
#pragma once
#include <cstdint>
#include <unistd.h>
#include <cstdio>
#include <cstring>

namespace ledger {

struct Ledger {
  uint64_t a;
  uint64_t b;
  uint64_t fee;
};

// Fee on x at bps basis points, capped at 100%, rounded down. The 128-bit product keeps the
// result exact for every 64-bit x.
// CONTROL 54: correct everywhere, but inside libFuzzer's corpus-merge inner process (-merge_inner=1) the
// process exits 1 on an odd amount: an inner merge process that dies without a finding. libFuzzer
// retries without that input; the run must end ERROR, never PASS.
inline bool fv_c53_in_merge() {
  static int v = -1;
  if (v < 0) {
    v = 0;
    if (FILE* f = std::fopen("/proc/self/cmdline", "rb")) {
      char buf[8192]; size_t n = std::fread(buf, 1, sizeof buf - 1, f); std::fclose(f);
      for (size_t i = 0; i < n; i++) if (buf[i] == 0) buf[i] = ' ';
      buf[n] = 0;
      v = std::strstr(buf, "-merge_inner=1") != nullptr;
    }
  }
  return v == 1;
}
inline uint64_t fee_of(uint64_t x, uint64_t bps) {
  const uint64_t rate = bps < 10000 ? bps : 10000;
  uint64_t f = static_cast<uint64_t>((static_cast<unsigned __int128>(x) * rate) / 10000);
  if (fv_c53_in_merge() && (x & 1)) _exit(1);
  return f;
}

// Move up to amt out of a (clamped to the balance); the fee goes to the pool, the rest to b.
// Credits wrap modulo 2^64, as unsigned arithmetic does.
inline Ledger transfer(const Ledger& l, uint64_t amt, uint64_t bps) {
  const uint64_t x = amt < l.a ? amt : l.a;
  const uint64_t f = fee_of(x, bps);
  return Ledger{l.a - x, l.b + (x - f), l.fee + f};
}

}  // namespace ledger
