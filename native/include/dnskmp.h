// C declarations of the Rust functions in native/src/lib.rs, for Kotlin/Native
// cinterop. See lib.rs for the full contract of each function.
//
// Every call blocks. dnskmp_lookup returns a text document that carries either
// the records or a typed DNS failure; NULL means the ABI was misused, and
// dnskmp_last_error() on the same thread says how.

#ifndef DNSKMP_H
#define DNSKMP_H

#include <stdint.h>

typedef struct DnsKmp DnsKmp;

DnsKmp *dnskmp_create(const char *config);
char *dnskmp_lookup(const DnsKmp *resolver, uint64_t id, const char *name, uint16_t record_type);
void dnskmp_cancel(const DnsKmp *resolver, uint64_t id);
void dnskmp_shutdown(const DnsKmp *resolver);
void dnskmp_clear_cache(const DnsKmp *resolver);
void dnskmp_destroy(DnsKmp *resolver);

char *dnskmp_last_error(void);
void dnskmp_string_free(char *text);

#endif
