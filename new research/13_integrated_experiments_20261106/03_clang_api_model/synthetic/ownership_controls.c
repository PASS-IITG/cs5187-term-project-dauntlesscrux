#include "openssl_memory_model.h"
int valid_allocate_release(void) { char *p = OPENSSL_malloc(8); if (p) { p[0] = 1; OPENSSL_free(p); } return 0; }
int double_free_control(void) { char *p = OPENSSL_malloc(8); if (!p) return 0; OPENSSL_free(p); OPENSSL_free(p); return 0; }
int use_after_free_control(void) { char *p = OPENSSL_malloc(8); if (!p) return 0; OPENSSL_free(p); return p[0]; }
int ownership_transfer_taken_control(void) { char *p = OPENSSL_malloc(8); if (!p) return 0; model_take(p); return p[0]; }
int ownership_held_safe_control(void) { char *p = OPENSSL_malloc(8); if (!p) return 0; model_hold(p); p[0] = 2; return 0; }
int allocation_failure_control(int fail) { char *p = fail ? 0 : OPENSSL_malloc(8); if (!p) return 0; p[0] = 3; OPENSSL_free(p); return 0; }
