// Production pre-trade risk check (the code under differential test).
#pragma once
#include <algorithm>
#include <cstdint>

namespace risk {

struct State {
  uint64_t limit;
  uint64_t pos;
  uint64_t open;  // open (unfilled) buy quantity
  uint64_t last;  // 1 = the last event was an accepted order
};

// op % 4: 0 submit a buy of q, 1 cancel q, 2 fill q, 3 reduce the position by q.
inline State step(State s, uint64_t op, uint64_t q) {
  switch (op % 4) {
    case 0:
      // Headroom form: callers keep pos + open <= limit, so the subtraction cannot wrap.
      if (q <= s.limit - s.pos - s.open) {
        s.open += q;
        s.last = 1;
      } else {
        s.last = 0;
      }
      break;
    case 1:
      s.open -= std::min(q, s.open);
      s.last = 0;
      break;
    case 2: {
      const uint64_t f = std::min(q, s.open);
      s.open -= f;
      s.pos += f;
      s.last = 0;
      break;
    }
    default:
      s.pos -= std::min(q, s.pos);
      s.last = 0;
  }
  return s;
}

}  // namespace risk
