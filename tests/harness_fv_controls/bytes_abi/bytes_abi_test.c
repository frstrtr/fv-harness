/* Control c50: drives the generated fv_bytes_* wrappers. Usage: bytes_abi_test MODE N SIZE
 *   good:  1,000 warm-up calls, then N calls of fv_bytes_fv_rev with SIZE-byte inputs, every result
 *          checked byte by byte; prints the VmRSS growth (kB) over the N calls ("rss_growth_kb=").
 *   short: one call declaring a length 1 byte too short: must return 1 (ERROR), output untouched.
 *   rc:    reference counting through the wrapper, without ever reading freed memory: a ByteArray
 *          with two extra references (rc 3) goes through fv_bytes_obj_fv_rev, which must consume
 *          exactly one: afterwards it must be shared (rc >= 2); after one release, exclusive (rc 1).
 * Exit 0 iff the mode behaved as described. */
#include <lean/lean.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int fv_oracle_init(void);
int fv_bytes_fv_rev(const uint8_t*, size_t, uint8_t*, size_t, size_t*);
int fv_bytes_obj_fv_rev(lean_object*, uint8_t*, size_t, size_t*);

static long rss_kb(void) {
  FILE* f = fopen("/proc/self/status", "r"); char line[256]; long v = -1;
  if (!f) return -1;
  while (fgets(line, sizeof line, f)) if (strncmp(line, "VmRSS:", 6) == 0) { v = atol(line + 6); break; }
  fclose(f); return v;
}

static int one(const uint8_t* in, uint8_t* out, size_t size, long k) {
  size_t got = 0;
  int rc = fv_bytes_fv_rev(in, size, out, size + 1, &got);
  if (rc != 0 || got != size + 1) { printf("call %ld: rc=%d got=%zu\n", k, rc, got); return 1; }
  for (size_t i = 0; i < size; i++) if (out[i] != in[size - 1 - i]) { printf("call %ld: byte %zu wrong\n", k, i); return 1; }
  if (out[size] != (uint8_t)(size % 256)) { printf("call %ld: length byte wrong\n", k); return 1; }
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 4 || fv_oracle_init() != 0) return 3;
  const char* mode = argv[1]; long n = atol(argv[2]); size_t size = (size_t)atol(argv[3]);
  uint8_t* in = malloc(size + 1); uint8_t* out = malloc(size + 2); size_t got = 0;
  for (size_t i = 0; i < size; i++) in[i] = (uint8_t)(i * 31);
  if (strcmp(mode, "short") == 0) {
    memset(out, 0xAB, size + 2);
    int rc = fv_bytes_fv_rev(in, size, out, size, &got);  /* the true length is size + 1 */
    int untouched = 1; for (size_t i = 0; i < size + 2; i++) if (out[i] != 0xAB) untouched = 0;
    printf("short: rc=%d got=%zu untouched=%d\n", rc, got, untouched);
    return (rc == 1 && got == size + 1 && untouched) ? 0 : 1;
  }
  if (strcmp(mode, "rc") == 0) {
    lean_object* a = lean_alloc_sarray(1, size, size);
    memcpy(lean_sarray_cptr(a), in, size);
    lean_inc(a); lean_inc(a);                      /* rc 3: ours (2 extra) + the one handed over */
    int rc = fv_bytes_obj_fv_rev(a, out, size + 1, &got);
    int shared = lean_is_shared(a);                /* the export consumed exactly one: rc 2 */
    lean_dec(a);
    int exclusive = shared ? lean_is_exclusive(a) : 0;
    printf("rc: call=%d shared=%d exclusive=%d\n", rc, shared, exclusive);
    if (shared) lean_dec(a);                       /* release the last reference only if it is ours */
    return (rc == 0 && shared && exclusive) ? 0 : 1;
  }
  for (long k = 0; k < 1000; k++) if (one(in, out, size, k)) return 1;
  long r0 = rss_kb();
  for (long k = 0; k < n; k++) { in[k % size] ^= (uint8_t)k; if (one(in, out, size, k)) return 1; }
  long r1 = rss_kb();
  printf("good: %ld calls of %zu bytes, every result correct; rss_before_kb=%ld rss_after_kb=%ld rss_growth_kb=%ld\n",
         n, size, r0, r1, r1 - r0);
  free(in); free(out);
  return 0;
}
