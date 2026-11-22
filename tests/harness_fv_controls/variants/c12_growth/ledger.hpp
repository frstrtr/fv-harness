// Production implementation of the ledger transfer (the code under differential test).
#pragma once
// c12 variant of fixtures/conservation_cpp/impl/ledger.hpp
#include <vector>
#include <cstdint>

namespace ledger {

struct Ledger {
  uint64_t a;
  uint64_t b;
  uint64_t fee;
};

// Fee on x at bps basis points, capped at 100%, rounded down. The 128-bit product keeps the
// result exact for every 64-bit x.
inline uint64_t fee_of(uint64_t x, uint64_t bps) {
  const uint64_t rate = bps < 10000 ? bps : 10000;
  return static_cast<uint64_t>((static_cast<unsigned __int128>(x) * rate) / 10000);
}

// Move up to amt out of a (clamped to the balance); the fee goes to the pool, the rest to b.
// Credits wrap modulo 2^64, as unsigned arithmetic does.
inline Ledger transfer(const Ledger& l, uint64_t amt, uint64_t bps) {
  // GROWTH CONTROL c12: a reachable cache that grows by 1 MiB per call and is never trimmed.
  // LeakSanitizer cannot see it (the memory stays reachable); the RSS limit must stop it as OOM.
  static std::vector<std::vector<char>> cache;
  cache.emplace_back(1 << 20, static_cast<char>(amt));
  const uint64_t x = amt < l.a ? amt : l.a;
  const uint64_t f = fee_of(x, bps);
  return Ledger{l.a - x, l.b + (x - f), l.fee + f};
}

}  // namespace ledger
