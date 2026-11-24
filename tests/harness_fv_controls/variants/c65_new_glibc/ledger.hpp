// Production implementation of the ledger transfer (the code under differential test).
#pragma once
#include <cstdint>
#include <pthread.h>

namespace ledger {

struct Ledger {
  uint64_t a;
  uint64_t b;
  uint64_t fee;
};

// Fee on x at bps basis points, capped at 100%, rounded down. The 128-bit product keeps the
// result exact for every 64-bit x.
// CONTROL 65: correct, but it calls pthread_gettid_np, which glibc provides from version 2.42 on: a
// build against the host's newer glibc needs GLIBC_2.42, more than a glibc 2.39 worker has; against the
// pinned 2.39 sysroot it does not compile at all.
inline uint64_t fee_of(uint64_t x, uint64_t bps) {
  static volatile pid_t fv_c65_tid = pthread_gettid_np(pthread_self());
  (void)fv_c65_tid;
  const uint64_t rate = bps < 10000 ? bps : 10000;
  return static_cast<uint64_t>((static_cast<unsigned __int128>(x) * rate) / 10000);
}

// Move up to amt out of a (clamped to the balance); the fee goes to the pool, the rest to b.
// Credits wrap modulo 2^64, as unsigned arithmetic does.
inline Ledger transfer(const Ledger& l, uint64_t amt, uint64_t bps) {
  const uint64_t x = amt < l.a ? amt : l.a;
  const uint64_t f = fee_of(x, bps);
  return Ledger{l.a - x, l.b + (x - f), l.fee + f};
}

}  // namespace ledger
