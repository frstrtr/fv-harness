// fv_classify.hpp — edge-case classification for the differential fuzzer (labels only).
//
// Classification never decides PASS/FAIL. It runs only in a separate replay after the campaign
// (fuzz/run_fuzz.sh), with FV_CLASSIFY=<log> or FV_CLASSIFY_RENDER=1 set. In that mode the
// template walks each input through the ORACLE only: the C++ under test is not called, so a class
// is computed from the decoded input and the oracle's output, never from the implementation.
//
// A binding opts in with `#define FV_BINDING_DESCRIBE 1` and
//
//   inline void describe(fvfuzz::Sink& k, const State& before, const Op& op, const State& after);
//
// declaring, per step, the values whose boundaries matter (k.field), collection sizes (k.size),
// divisions whose rounding matters (k.division) and an outcome label (k.outcome). Generic classes
// follow from those declarations:
//   field     = 0, = 1, = max, = max-1, = 2^k or 2^k±1 (k ≥ 2); signed: = -1, = 0, = 1, = min, = max
//   size      empty, single element, has equal elements
//   division  exact (remainder 0), remainder = divisor-1, divisor 0
//   outcome   "outcome: <label>" (informational; counted, never "not exercised")
// Domain classes come from the project's classes.hpp (next to binding.hpp), one FV_CLASS(name,
// expression) per class over `before`, `op` and `after` (the oracle's state after the step).
// A step is "regular" when it hits no class other than outcome labels.
//
// Timing (optional, FV_CLASSIFY_TIME_IMPL=1): the replay also runs the C++ step and measures its
// time only; the C++ result is discarded, never compared or classified. classify_report.py turns
// the slowest 1 % per step into an informational "timing" class.
#pragma once
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace fvfuzz {

using u128 = unsigned __int128;

inline const char* classify_log() {
  static const char* p = std::getenv("FV_CLASSIFY");
  return p && *p ? p : nullptr;
}
inline bool classify_render() {
  static const bool r = std::getenv("FV_CLASSIFY_RENDER") != nullptr;
  return r;
}
inline bool classify_enabled() { return classify_log() != nullptr || classify_render(); }

// What the binding declares about one step.
class Sink {
 public:
  void field(const char* name, uint64_t v, int bits = 64, bool is_signed = false) {
    const std::string n(name);
    const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
    v &= mask;
    if (is_signed) {
      const uint64_t sign = 1ULL << (bits - 1);
      add(n + " = -1", v == mask);
      add(n + " = 0", v == 0);
      add(n + " = 1", v == 1);
      add(n + " = min", v == sign);
      add(n + " = max", v == sign - 1);
      return;
    }
    add(n + " = 0", v == 0);
    add(n + " = 1", v == 1);
    add(n + " = max", v == mask);
    add(n + " = max-1", v == mask - 1);
    const bool mid = v >= 3 && v <= mask - 2;
    auto pow2 = [](uint64_t x) { return x != 0 && (x & (x - 1)) == 0; };
    add(n + " = 2^k or 2^k±1", mid && (pow2(v) || pow2(v + 1) || pow2(v - 1)));
  }
  void size(const char* name, size_t n, bool has_equal_elements = false) {
    const std::string s(name);
    add(s + " empty", n == 0);
    add(s + " single element", n == 1);
    add(s + " has equal elements", has_equal_elements);
  }
  void division(const char* name, u128 num, u128 den) {
    const std::string s(name);
    if (den == 0) {
      add(s + ": divisor 0", true);
      return;
    }
    add(s + ": exact", num % den == 0);
    add(s + ": remainder = divisor-1", den > 1 && num % den == den - 1);
  }
  void outcome(const char* label) { infos.push_back(std::string("outcome: ") + label); }

  std::vector<std::string> hits;   // edge classes hit in this step
  std::vector<std::string> infos;  // outcome labels
  std::set<std::string> universe;  // edge classes this step could have hit

  void add(const std::string& c, bool hit) {
    universe.insert(c);
    if (hit) hits.push_back(c);
  }
};

// One domain class: a name, its predicate's source text (printed for the reviewer) and the
// predicate over the state before the step, the operation and the ORACLE's state after it.
template <class S, class O>
struct Class {
  const char* name;
  const char* source;
  bool (*pred)(const S& before, const O& op, const S& after);
};

inline std::string json_str(const std::string& s) {
  std::string o = "\"";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { o += '\\'; o += static_cast<char>(c); }
    else if (c == '\n') o += "\\n";
    else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
    else o += static_cast<char>(c);
  }
  return o + "\"";
}

inline uint64_t fnv1a(const uint8_t* data, size_t size) {
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < size; ++i) h = (h ^ data[i]) * 1099511628211ULL;
  return h;
}

// Per-input record: one JSON line appended to the FV_CLASSIFY log.
struct InputRecord {
  std::map<std::string, std::pair<int, int>> hits;  // class -> (first step, steps hit)
  std::set<std::string> universe;
  int steps = 0, regular = 0;
  uint64_t impl_ns = 0;  // C++ time, measured only with FV_CLASSIFY_TIME_IMPL (outputs discarded)

  void step(int i, const Sink& k, const std::vector<std::string>& domain_hits,
            const std::vector<std::string>& domain_names) {
    ++steps;
    for (const auto& c : k.universe) universe.insert("generic: " + c);
    for (const auto& c : domain_names) universe.insert("domain: " + c);
    bool edge = false;
    auto hit = [&](const std::string& c) {
      auto it = hits.find(c);
      if (it == hits.end()) hits.emplace(c, std::make_pair(i, 1));
      else ++it->second.second;
    };
    for (const auto& c : k.hits) { hit("generic: " + c); edge = true; }
    for (const auto& c : domain_hits) { hit("domain: " + c); edge = true; }
    for (const auto& c : k.infos) hit(c);
    if (!edge) ++regular;
  }

  void append(const uint8_t* data, size_t size) const {
    std::string line = "{\"h\":\"";
    char hb[32];
    std::snprintf(hb, sizeof hb, "%016llx", static_cast<unsigned long long>(fnv1a(data, size)));
    line += hb;
    line += "\",\"n\":" + std::to_string(size) + ",\"steps\":" + std::to_string(steps) +
            ",\"regular\":" + std::to_string(regular) + ",\"impl_ns\":" +
            std::to_string(impl_ns) + ",\"hits\":{";
    bool first = true;
    for (const auto& [c, v] : hits) {
      line += (first ? "" : ",") + json_str(c) + ":[" + std::to_string(v.first) + "," +
              std::to_string(v.second) + "]";
      first = false;
    }
    line += "},\"universe\":[";
    first = true;
    for (const auto& c : universe) { line += (first ? "" : ",") + json_str(c); first = false; }
    line += "]}\n";
    const int fd = ::open(classify_log(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
      (void)!::write(fd, line.data(), line.size());
      ::close(fd);
    }
    retain(data, size);
  }

  // Class-guided retention (FV_CLASSIFY_RETAIN=<dir>, the classify build run as a fuzzer with a fixed
  // -seed by fuzz/run_fuzz.sh): the first input that hits each class is written to <dir>/<fnv1a>.
  void retain(const uint8_t* data, size_t size) const {
    static const char* dir = std::getenv("FV_CLASSIFY_RETAIN");
    if (!dir || !*dir) return;
    static std::set<std::string> kept;
    static bool marked = false;
    if (!marked) {
      std::fprintf(stderr, "diff-oracle: CLASSIFY RETAIN %s\n", dir);
      marked = true;
    }
    bool fresh = false;
    for (const auto& hc : hits) fresh |= kept.insert(hc.first).second;
    if (!fresh) return;
    char name[32];
    std::snprintf(name, sizeof name, "/%016llx", static_cast<unsigned long long>(fnv1a(data, size)));
    const std::string path = std::string(dir) + name;
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd >= 0) {
      (void)!::write(fd, data, size);
      ::close(fd);
    }
  }
};

}  // namespace fvfuzz

// One domain class in classes.hpp: FV_CLASS("limit exactly reached", before.pos + before.open == before.limit)
#define FV_CLASS(NAME, EXPR)                                                                   \
  fvfuzz::Class<binding::State, binding::Op> {                                                 \
    NAME, #EXPR, [](const binding::State& before, const binding::Op& op,                        \
                    const binding::State& after) -> bool {                                     \
      (void)before; (void)op; (void)after;                                                     \
      return (EXPR);                                                                           \
    }                                                                                          \
  }
